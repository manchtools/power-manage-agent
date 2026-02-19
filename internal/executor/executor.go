// Package executor provides implementations for action executors.
package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/agent/internal/store"
	"github.com/manchtools/power-manage/agent/internal/verify"
	"github.com/manchtools/power-manage/sdk/go/pkg"
	sysnotify "github.com/manchtools/power-manage/sdk/go/sys/notify"
	syssystemd "github.com/manchtools/power-manage/sdk/go/sys/systemd"
	sysuser "github.com/manchtools/power-manage/sdk/go/sys/user"
)

// resolveAndValidatePath resolves symlinks in the parent directory of the given
// path and returns the cleaned, resolved absolute path. This prevents symlink
// traversal attacks where a symlink could redirect writes to sensitive locations.
func resolveAndValidatePath(path string) (string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("path must be absolute: %s", path)
	}

	// Walk up from the target file to find the first existing parent directory
	// This handles cases where intermediate directories don't exist yet
	dir := filepath.Dir(clean)
	var existingParent, missingTail string

	for dir != "/" && dir != "." {
		if _, err := os.Stat(dir); err == nil {
			existingParent = dir
			break
		} else if os.IsNotExist(err) {
			// Directory doesn't exist, add to missing tail and continue up
			missingTail = filepath.Join(filepath.Base(dir), missingTail)
			dir = filepath.Dir(dir)
		} else {
			// Permission denied or other error - continue up the tree
			missingTail = filepath.Join(filepath.Base(dir), missingTail)
			dir = filepath.Dir(dir)
		}
	}

	if existingParent == "" {
		existingParent = "/"
	}

	// Resolve symlinks only in the existing portion of the path
	resolved, err := filepath.EvalSymlinks(existingParent)
	if err != nil {
		// If we still can't resolve the root parent, just use clean path
		return clean, nil
	}

	// Rebuild the full path with resolved parent + missing components + filename
	if missingTail != "" {
		return filepath.Join(resolved, missingTail, filepath.Base(clean)), nil
	}
	return filepath.Join(resolved, filepath.Base(clean)), nil
}

// validRepoName restricts repository names to safe characters only.
// This prevents path traversal, shell injection, and sed/regex injection.
var validRepoName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// validEnvVarName matches safe environment variable names (letters, digits, underscore).
var validEnvVarName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]*$`)

// blockedEnvVars are environment variable names that must never be overridden
// because they can hijack process execution (library injection, path manipulation).
var blockedEnvVars = map[string]bool{
	"LD_PRELOAD":      true,
	"LD_LIBRARY_PATH": true,
	"LD_AUDIT":        true,
	"LD_DEBUG":        true,
	"LD_PROFILE":      true,
	"PATH":            true,
	"IFS":             true,
	"ENV":             true,
	"BASH_ENV":        true,
	"CDPATH":          true,
	"GLOBIGNORE":      true,
	"BASH_FUNC_":      true,
}

// isAllowedEnvVar returns true if the environment variable name is safe to set.
func isAllowedEnvVar(name string) bool {
	if !validEnvVarName.MatchString(name) {
		return false
	}
	upper := strings.ToUpper(name)
	if blockedEnvVars[upper] {
		return false
	}
	// Block LD_* and BASH_FUNC_* prefixes
	if strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "BASH_FUNC_") {
		return false
	}
	return true
}

// Executor handles the execution of actions.
type Executor struct {
	httpClient   *http.Client
	pkgManager   *pkg.PackageManager
	verifier     *verify.ActionVerifier
	logger       *slog.Logger
	luksKeyStore LuksKeyStore
	store        *store.Store
	actionStore  ActionStore
}

// NewExecutor creates a new action executor.
// If verifier is non-nil, action signatures will be checked before execution.
func NewExecutor(verifier *verify.ActionVerifier) *Executor {
	pm, _ := pkg.New() // May be nil if no supported package manager found
	return &Executor{
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
		pkgManager: pm,
		verifier:   verifier,
		logger:     slog.Default(),
	}
}

// SetLuksKeyStore sets the LUKS key store for stream-based key operations.
func (e *Executor) SetLuksKeyStore(ks LuksKeyStore) {
	e.luksKeyStore = ks
}

// SetStore sets the agent store for LUKS state persistence.
func (e *Executor) SetStore(s *store.Store) {
	e.store = s
}

// SetActionStore sets the action store for LUKS conflict resolution.
func (e *Executor) SetActionStore(as ActionStore) {
	e.actionStore = as
}

// Execute runs an action and returns the result.
func (e *Executor) Execute(ctx context.Context, action *pb.Action) *pb.ActionResult {
	return e.ExecuteWithStreaming(ctx, action, nil)
}

// ExecuteWithStreaming runs an action with optional output streaming.
// The callback is called for each line of output as it's produced (for shell actions).
func (e *Executor) ExecuteWithStreaming(ctx context.Context, action *pb.Action, callback OutputCallback) *pb.ActionResult {
	start := time.Now()

	result := &pb.ActionResult{
		ActionId: action.Id,
		Status:   pb.ExecutionStatus_EXECUTION_STATUS_RUNNING,
		Changed:  true, // Default to true; scheduler may override based on output comparison
	}

	// Apply timeout if specified
	if action.TimeoutSeconds > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(action.TimeoutSeconds)*time.Second)
		defer cancel()
	}

	// Verify action signature before execution (skip for instant actions — they have no params to sign)
	if e.verifier != nil && !isInstantAction(action.Type) {
		actionID := ""
		if action.Id != nil {
			actionID = action.Id.Value
		}
		verifyErr := e.verifier.Verify(actionID, int32(action.Type), action.ParamsCanonical, action.Signature)
		if verifyErr != nil {
			// Shell scripts and sudo policies: hard reject unsigned/tampered actions
			if action.Type == pb.ActionType_ACTION_TYPE_SHELL || action.Type == pb.ActionType_ACTION_TYPE_SUDO || action.Type == pb.ActionType_ACTION_TYPE_LPS {
				result.Status = pb.ExecutionStatus_EXECUTION_STATUS_FAILED
				result.Error = fmt.Sprintf("refusing to execute unsigned/tampered shell script: %v", verifyErr)
				result.CompletedAt = timestamppb.Now()
				result.DurationMs = time.Since(start).Milliseconds()
				return result
			}
			// Other types: log warning (grace period for rollout)
			e.logger.Warn("action signature verification failed",
				"action_id", actionID,
				"action_type", action.Type.String(),
				"error", verifyErr,
			)
		}
	}

	var execErr error
	var output *pb.CommandOutput

	switch action.Type {
	case pb.ActionType_ACTION_TYPE_PACKAGE:
		var changed bool
		output, changed, execErr = e.executePackage(ctx, action.GetPackage(), action.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_UPDATE:
		output, execErr = e.executeUpdate(ctx, action.GetUpdate())
	case pb.ActionType_ACTION_TYPE_APP_IMAGE:
		var changed bool
		output, changed, execErr = e.executeAppImage(ctx, action.GetApp(), action.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_FLATPAK:
		var changed bool
		output, changed, execErr = e.executeFlatpak(ctx, action.GetFlatpak(), action.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_DEB:
		var changed bool
		output, changed, execErr = e.executeDeb(ctx, action.GetApp(), action.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_RPM:
		var changed bool
		output, changed, execErr = e.executeRpm(ctx, action.GetApp(), action.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_SHELL:
		output, execErr = e.executeShellStreaming(ctx, action.GetShell(), callback)
	case pb.ActionType_ACTION_TYPE_SYSTEMD:
		var changed bool
		output, changed, execErr = e.executeSystemd(ctx, action.GetSystemd())
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_FILE:
		var changed bool
		output, changed, execErr = e.executeFile(ctx, action.GetFile(), action.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_DIRECTORY:
		var changed bool
		output, changed, execErr = e.executeDirectory(ctx, action.GetDirectory(), action.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_REPOSITORY:
		var changed bool
		output, changed, execErr = e.executeRepository(ctx, action.GetRepository(), action.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_USER:
		var changed bool
		var metadata map[string]string
		output, changed, metadata, execErr = e.executeUser(ctx, action.GetUser(), action.DesiredState)
		result.Changed = changed
		if len(metadata) > 0 {
			result.Metadata = metadata
		}
	case pb.ActionType_ACTION_TYPE_GROUP:
		var changed bool
		output, changed, execErr = e.executeGroup(ctx, action.GetGroup(), action.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_SSH:
		var changed bool
		sshActionID := ""
		if action.Id != nil {
			sshActionID = action.Id.Value
		}
		output, changed, execErr = e.executeSsh(ctx, action.GetSsh(), action.DesiredState, sshActionID)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_SSHD:
		var changed bool
		sshdActionID := ""
		if action.Id != nil {
			sshdActionID = action.Id.Value
		}
		output, changed, execErr = e.executeSshd(ctx, action.GetSshd(), action.DesiredState, sshdActionID)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_SUDO:
		var changed bool
		sudoActionID := ""
		if action.Id != nil {
			sudoActionID = action.Id.Value
		}
		output, changed, execErr = e.executeSudo(ctx, action.GetSudo(), action.DesiredState, sudoActionID)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_LPS:
		var changed bool
		var metadata map[string]string
		lpsActionID := ""
		if action.Id != nil {
			lpsActionID = action.Id.Value
		}
		output, changed, metadata, execErr = e.executeLps(ctx, action.GetLps(), action.DesiredState, lpsActionID)
		result.Changed = changed
		if len(metadata) > 0 {
			result.Metadata = metadata
		}
	case pb.ActionType_ACTION_TYPE_LUKS:
		var changed bool
		var metadata map[string]string
		luksActionID := ""
		if action.Id != nil {
			luksActionID = action.Id.Value
		}
		output, changed, metadata, execErr = e.executeLuks(ctx, action.GetLuks(), action.DesiredState, luksActionID)
		result.Changed = changed
		if len(metadata) > 0 {
			result.Metadata = metadata
		}
	case pb.ActionType_ACTION_TYPE_REBOOT:
		output, execErr = e.executeReboot(ctx)
	default:
		execErr = fmt.Errorf("unsupported action type: %v", action.Type)
	}

	result.Output = output
	result.CompletedAt = timestamppb.Now()
	result.DurationMs = time.Since(start).Milliseconds()

	// Check context errors first - distinguish between timeout and cancellation
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		result.Status = pb.ExecutionStatus_EXECUTION_STATUS_TIMEOUT
		result.Error = fmt.Sprintf("action timed out after %d seconds", action.TimeoutSeconds)
	case ctx.Err() == context.Canceled:
		result.Status = pb.ExecutionStatus_EXECUTION_STATUS_FAILED
		result.Error = "action cancelled"
	case execErr != nil:
		result.Status = pb.ExecutionStatus_EXECUTION_STATUS_FAILED
		result.Error = execErr.Error()
	default:
		result.Status = pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS
	}

	return result
}

func (e *Executor) executePackage(ctx context.Context, params *pb.PackageParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("package params required")
	}

	if e.pkgManager == nil {
		return nil, false, fmt.Errorf("no supported package manager found")
	}

	// Determine the package name for the current package manager
	pkgName := e.getPackageNameForManager(params)
	if pkgName == "" {
		// No package name for this manager - skip silently with success
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   "skipped: no package name configured for this package manager",
		}, false, nil
	}

	var result *pkg.CommandResult
	var err error

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Check if package is already installed with correct version
		isInstalled, _ := e.pkgManager.IsInstalled(pkgName)
		if isInstalled {
			// Check version if specified
			if params.Version != "" {
				installedVersion, _ := e.pkgManager.GetInstalledVersion(pkgName)
				if installedVersion == params.Version {
					// Version matches, check if we need to pin
					if params.Pin {
						changed, pinErr := e.ensurePackagePinned(ctx, pkgName)
						if pinErr != nil {
							return &pb.CommandOutput{
								ExitCode: 1,
								Stderr:   fmt.Sprintf("failed to pin package: %v", pinErr),
							}, false, pinErr
						}
						if changed {
							return &pb.CommandOutput{
								ExitCode: 0,
								Stdout:   fmt.Sprintf("package %s version %s was already installed, pinned", pkgName, params.Version),
							}, true, nil
						}
						return &pb.CommandOutput{
							ExitCode: 0,
							Stdout:   fmt.Sprintf("package %s version %s is already installed and pinned", pkgName, params.Version),
						}, false, nil
					}
					return &pb.CommandOutput{
						ExitCode: 0,
						Stdout:   fmt.Sprintf("package %s version %s is already installed", pkgName, params.Version),
					}, false, nil
				}
				// Version mismatch, need to install specific version
			} else {
				// No specific version requested, package is installed
				if params.Pin {
					changed, pinErr := e.ensurePackagePinned(ctx, pkgName)
					if pinErr != nil {
						return &pb.CommandOutput{
							ExitCode: 1,
							Stderr:   fmt.Sprintf("failed to pin package: %v", pinErr),
						}, false, pinErr
					}
					if changed {
						return &pb.CommandOutput{
							ExitCode: 0,
							Stdout:   fmt.Sprintf("package %s was already installed, pinned", pkgName),
						}, true, nil
					}
					return &pb.CommandOutput{
						ExitCode: 0,
						Stdout:   fmt.Sprintf("package %s is already installed and pinned", pkgName),
					}, false, nil
				}
				return &pb.CommandOutput{
					ExitCode: 0,
					Stdout:   fmt.Sprintf("package %s is already installed", pkgName),
				}, false, nil
			}
		}

		// Repair filesystem if mounted read-only (common after kernel errors)
		if !e.repairFilesystem(ctx) {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   "filesystem is read-only and could not be remounted - system may need reboot and fsck",
			}, false, fmt.Errorf("filesystem is read-only")
		}

		// Repair any broken package manager state before proceeding
		e.repairPackageManager(ctx)

		// Update package index first to avoid stale package references
		if _, updateErr := e.pkgManager.Update(); updateErr != nil {
			// Log update failure but continue with install attempt
			_ = updateErr
		}

		// Install the package
		if params.Version != "" || params.AllowDowngrade {
			result, err = e.pkgManager.Install(pkgName).
				Version(params.Version).
				AllowDowngrade().
				Run()
		} else {
			result, err = e.pkgManager.Install(pkgName).Run()
		}

		// Pin if requested
		if err == nil && params.Pin {
			if _, pinErr := e.pinPackage(pkgName); pinErr != nil {
				result.Stderr += fmt.Sprintf("\nwarning: failed to pin package: %v", pinErr)
			}
		}

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		// Check if package is already not installed
		isInstalled, _ := e.pkgManager.IsInstalled(pkgName)
		if !isInstalled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("package %s is already not installed", pkgName),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if !e.repairFilesystem(ctx) {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   "filesystem is read-only and could not be remounted - system may need reboot and fsck",
			}, false, fmt.Errorf("filesystem is read-only")
		}

		// Repair any broken package manager state before proceeding
		e.repairPackageManager(ctx)

		// Unpin first if it was pinned (ignore errors)
		e.ensurePackageUnpinned(pkgName)
		result, err = e.pkgManager.Remove(pkgName).Run()

	default:
		return nil, false, fmt.Errorf("unknown desired state: %v", state)
	}

	if err != nil {
		if result == nil {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   err.Error(),
			}, false, err
		}
		return &pb.CommandOutput{
			ExitCode: int32(result.ExitCode),
			Stdout:   result.Stdout,
			Stderr:   result.Stderr,
		}, false, err
	}

	return &pb.CommandOutput{
		ExitCode: int32(result.ExitCode),
		Stdout:   result.Stdout,
		Stderr:   result.Stderr,
	}, true, nil
}

// getPackageNameForManager returns the appropriate package name for the current package manager.
// It checks for manager-specific names first, then falls back to the generic name.
// Returns empty string if no name is available for the current manager.
func (e *Executor) getPackageNameForManager(params *pb.PackageParams) string {
	// Check for manager-specific names first
	switch {
	case pkg.IsApt():
		if params.AptName != "" {
			return params.AptName
		}
	case pkg.IsDnf():
		if params.DnfName != "" {
			return params.DnfName
		}
	case pkg.IsPacman():
		if params.PacmanName != "" {
			return params.PacmanName
		}
	case pkg.IsZypper():
		if params.ZypperName != "" {
			return params.ZypperName
		}
	}

	// Check if any manager-specific names are set
	// If so, and we don't have one for this manager, return empty (skip)
	hasManagerSpecificNames := params.AptName != "" || params.DnfName != "" ||
		params.PacmanName != "" || params.ZypperName != ""

	if hasManagerSpecificNames {
		// Manager-specific names are being used, but none for this manager
		return ""
	}

	// Fall back to generic name
	return params.Name
}

func (e *Executor) executeAppImage(ctx context.Context, params *pb.AppInstallParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("app params required")
	}

	installPath := params.InstallPath
	if installPath == "" {
		installPath = "/opt/appimages"
	}

	filename := filepath.Base(params.Url)
	fullPath := filepath.Join(installPath, filename)

	// Resolve symlinks to prevent traversal attacks
	resolvedPath, err := resolveAndValidatePath(fullPath)
	if err != nil {
		return nil, false, fmt.Errorf("invalid path: %w", err)
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Check if file already exists with correct checksum
		if params.ChecksumSha256 != "" {
			if content, err := os.ReadFile(resolvedPath); err == nil {
				actualHash := hex.EncodeToString(sha256.New().Sum(content)[:])
				if actualHash == params.ChecksumSha256 {
					return &pb.CommandOutput{
						ExitCode: 0,
						Stdout:   fmt.Sprintf("appimage %s already installed with correct checksum", filename),
					}, false, nil
				}
			}
		} else if _, err := os.Stat(resolvedPath); err == nil {
			// No checksum specified, file exists
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("appimage %s already installed", filename),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if !e.repairFilesystem(ctx) {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   "filesystem is read-only and could not be remounted - system may need reboot and fsck",
			}, false, fmt.Errorf("filesystem is read-only")
		}

		// Create directory
		if err := os.MkdirAll(filepath.Dir(resolvedPath), 0755); err != nil {
			return nil, false, fmt.Errorf("create directory: %w", err)
		}

		// Download file
		if err := e.downloadFile(ctx, params.Url, resolvedPath, params.ChecksumSha256); err != nil {
			return nil, false, fmt.Errorf("download: %w", err)
		}

		// Make executable
		if err := os.Chmod(resolvedPath, 0755); err != nil {
			return nil, false, fmt.Errorf("chmod: %w", err)
		}

		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("installed %s to %s", filename, resolvedPath),
		}, true, nil

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		// Check if file already doesn't exist
		if _, err := os.Stat(resolvedPath); os.IsNotExist(err) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("appimage %s already not present", filename),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if !e.repairFilesystem(ctx) {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   "filesystem is read-only",
			}, false, fmt.Errorf("filesystem is read-only")
		}

		if err := os.Remove(resolvedPath); err != nil {
			return nil, false, fmt.Errorf("remove: %w", err)
		}
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("removed %s", resolvedPath),
		}, true, nil
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

func (e *Executor) executeFlatpak(ctx context.Context, params *pb.FlatpakParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("flatpak params required")
	}

	if params.AppId == "" {
		return nil, false, fmt.Errorf("flatpak app_id is required")
	}

	// Default to flathub if no remote specified
	remote := params.Remote
	if remote == "" {
		remote = "flathub"
	}

	// Build base args - system-wide by default
	systemFlag := "--system"
	if !params.SystemWide {
		systemFlag = "--user"
	}

	// Check if flatpak is installed
	isInstalled := e.isFlatpakInstalled(params.AppId, systemFlag)

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		if isInstalled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("flatpak %s is already installed", params.AppId),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if !e.repairFilesystem(ctx) {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   "filesystem is read-only and could not be remounted - system may need reboot and fsck",
			}, false, fmt.Errorf("filesystem is read-only")
		}

		// Install the flatpak application
		output, err := runSudoCmd(ctx, "flatpak", "install", "-y", "--noninteractive", systemFlag, remote, params.AppId)
		if err != nil {
			return output, false, fmt.Errorf("flatpak install failed: %w", err)
		}

		// Pin if requested (mask prevents updates)
		if params.Pin {
			pinOutput, pinErr := runSudoCmd(ctx, "flatpak", "mask", systemFlag, params.AppId)
			if pinErr != nil {
				if output != nil {
					output.Stdout += "\nWarning: failed to pin application: " + pinErr.Error()
				}
			} else if pinOutput != nil {
				output.Stdout += "\n" + pinOutput.Stdout
			}
		}

		return output, true, nil

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		if !isInstalled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("flatpak %s is already not installed", params.AppId),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if !e.repairFilesystem(ctx) {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   "filesystem is read-only",
			}, false, fmt.Errorf("filesystem is read-only")
		}

		// Remove pin first if it exists
		runSudoCmd(ctx, "flatpak", "mask", "--remove", systemFlag, params.AppId)

		// Uninstall the flatpak application
		output, err := runSudoCmd(ctx, "flatpak", "uninstall", "-y", "--noninteractive", systemFlag, params.AppId)
		return output, true, err
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// isFlatpakInstalled checks if a flatpak app is installed.
func (e *Executor) isFlatpakInstalled(appId, systemFlag string) bool {
	return checkCmdSuccess("flatpak", "info", systemFlag, appId)
}

func (e *Executor) executeDeb(ctx context.Context, params *pb.AppInstallParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("app params required")
	}

	// Extract package name from URL for checking
	filename := filepath.Base(params.Url)
	pkgName := strings.Split(filename, "_")[0]

	// Check if package is already installed
	isInstalled := e.isDebInstalled(pkgName)

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		if isInstalled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("deb package %s is already installed", pkgName),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if !e.repairFilesystem(ctx) {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   "filesystem is read-only and could not be remounted - system may need reboot and fsck",
			}, false, fmt.Errorf("filesystem is read-only")
		}

		// Download to temp file
		tmpFile, err := os.CreateTemp("", "*.deb")
		if err != nil {
			return nil, false, fmt.Errorf("create temp file: %w", err)
		}
		defer os.Remove(tmpFile.Name())
		_ = tmpFile.Close()

		if err := e.downloadFile(ctx, params.Url, tmpFile.Name(), params.ChecksumSha256); err != nil {
			return nil, false, fmt.Errorf("download: %w", err)
		}

		// Install with dpkg (requires sudo)
		output, err := runSudoCmd(ctx, "dpkg", "-i", tmpFile.Name())
		if err != nil {
			// Try to fix dependencies
			aptFixBroken(ctx)
		}
		return output, true, err

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		if !isInstalled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("deb package %s is already not installed", pkgName),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if !e.repairFilesystem(ctx) {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   "filesystem is read-only",
			}, false, fmt.Errorf("filesystem is read-only")
		}

		output, err := runSudoCmd(ctx, "dpkg", "-r", pkgName)
		return output, true, err
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// isDebInstalled checks if a deb package is installed.
func (e *Executor) isDebInstalled(pkgName string) bool {
	return checkCmdSuccess("dpkg", "-s", pkgName)
}

func (e *Executor) executeRpm(ctx context.Context, params *pb.AppInstallParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("app params required")
	}

	// Extract package name from URL for checking
	filename := filepath.Base(params.Url)
	pkgName := strings.Split(filename, "-")[0]

	// Check if package is already installed
	isInstalled := e.isRpmInstalled(pkgName)

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		if isInstalled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("rpm package %s is already installed", pkgName),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if !e.repairFilesystem(ctx) {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   "filesystem is read-only and could not be remounted - system may need reboot and fsck",
			}, false, fmt.Errorf("filesystem is read-only")
		}

		// Download to temp file
		tmpFile, err := os.CreateTemp("", "*.rpm")
		if err != nil {
			return nil, false, fmt.Errorf("create temp file: %w", err)
		}
		defer os.Remove(tmpFile.Name())
		_ = tmpFile.Close()

		if err := e.downloadFile(ctx, params.Url, tmpFile.Name(), params.ChecksumSha256); err != nil {
			return nil, false, fmt.Errorf("download: %w", err)
		}

		// Install with rpm (requires sudo)
		output, err := runSudoCmd(ctx, "rpm", "-i", tmpFile.Name())
		return output, true, err

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		if !isInstalled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("rpm package %s is already not installed", pkgName),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if !e.repairFilesystem(ctx) {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   "filesystem is read-only",
			}, false, fmt.Errorf("filesystem is read-only")
		}

		output, err := runSudoCmd(ctx, "rpm", "-e", pkgName)
		return output, true, err
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// isRpmInstalled checks if an rpm package is installed.
func (e *Executor) isRpmInstalled(pkgName string) bool {
	return checkCmdSuccess("rpm", "-q", pkgName)
}

func (e *Executor) executeShell(ctx context.Context, params *pb.ShellParams) (*pb.CommandOutput, error) {
	return e.executeShellStreaming(ctx, params, nil)
}

// executeShellStreaming executes a shell script with optional output streaming.
func (e *Executor) executeShellStreaming(ctx context.Context, params *pb.ShellParams, callback OutputCallback) (*pb.CommandOutput, error) {
	if params == nil {
		return nil, fmt.Errorf("shell params required")
	}

	interpreter := params.Interpreter
	if interpreter == "" {
		interpreter = "/bin/sh"
	}

	// Build command name and args
	var name string
	var args []string
	if params.RunAsRoot {
		name = "sudo"
		args = []string{"-n", interpreter, "-c", params.Script}
	} else {
		name = interpreter
		args = []string{"-c", params.Script}
	}

	// Build environment — reject dangerous variable names that could
	// hijack the child process (e.g. LD_PRELOAD, PATH, LD_LIBRARY_PATH).
	var envVars []string
	if len(params.Environment) > 0 {
		envVars = os.Environ()
		for k, v := range params.Environment {
			if !isAllowedEnvVar(k) {
				return nil, fmt.Errorf("environment variable %q is not allowed", k)
			}
			envVars = append(envVars, fmt.Sprintf("%s=%s", k, v))
		}
	}

	// Use streaming execution if callback provided, otherwise fall back to standard
	if callback != nil {
		return runCmdStreaming(ctx, name, args, envVars, params.WorkingDirectory, callback)
	}

	// Non-streaming fallback - use runCmdStreaming with nil callback for consistent behavior
	return runCmdStreaming(ctx, name, args, envVars, params.WorkingDirectory, nil)
}

func (e *Executor) executeSystemd(ctx context.Context, params *pb.SystemdParams) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("systemd params required")
	}

	// Never allow managing the agent's own service
	if params.UnitName == "power-manage-agent.service" || params.UnitName == "power-manage-agent" {
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   "refusing to manage the power-manage-agent service\n",
		}, false, fmt.Errorf("cannot manage protected service: power-manage-agent")
	}

	var output strings.Builder
	changed := false

	// Check and update unit file content if provided
	if params.UnitContent != "" {
		unitPath := filepath.Join("/etc/systemd/system", params.UnitName)

		// Check if unit file already has the correct content
		needsUpdate := true
		if existingContent, err := os.ReadFile(unitPath); err == nil {
			existingHash := sha256.Sum256(existingContent)
			desiredHash := sha256.Sum256([]byte(params.UnitContent))
			if existingHash == desiredHash {
				needsUpdate = false
				output.WriteString(fmt.Sprintf("unit file %s is already up to date\n", unitPath))
			}
		}

		if needsUpdate {
			// Repair filesystem if mounted read-only
			if !e.repairFilesystem(ctx) {
				return &pb.CommandOutput{
					ExitCode: 1,
					Stderr:   "filesystem is read-only and could not be remounted - system may need reboot and fsck",
				}, false, fmt.Errorf("filesystem is read-only")
			}

			// Write unit file using sudo tee
			if cmdOutput, err := writeFileWithSudo(ctx, unitPath, params.UnitContent); err != nil {
				return cmdOutput, false, fmt.Errorf("write unit file: %s", formatCmdError(err, cmdOutput))
			}
			output.WriteString(fmt.Sprintf("updated unit file %s\n", unitPath))
			changed = true

			// Reload systemd
			if _, err := runSudoCmd(ctx, "systemctl", "daemon-reload"); err != nil {
				return nil, changed, fmt.Errorf("daemon-reload failed")
			}
			output.WriteString("reloaded systemd daemon\n")
		}
	}

	// Check and update enable/disable status
	isEnabled := e.isUnitEnabled(params.UnitName)
	if params.Enable && !isEnabled {
		// Check if unit is masked - provide helpful error
		if e.isUnitMasked(params.UnitName) {
			return nil, changed, fmt.Errorf("enable: unit %s is masked (run 'systemctl unmask %s' first)", params.UnitName, params.UnitName)
		}
		if _, err := runSudoCmd(ctx, "systemctl", "enable", params.UnitName); err != nil {
			return nil, changed, fmt.Errorf("enable: %v", err)
		}
		output.WriteString("enabled unit\n")
		changed = true
	} else if !params.Enable && isEnabled {
		if _, err := runSudoCmd(ctx, "systemctl", "disable", params.UnitName); err != nil {
			// Ignore errors for disable (unit might not exist)
			output.WriteString("disable failed (unit may not exist)\n")
		} else {
			output.WriteString("disabled unit\n")
			changed = true
		}
	}

	// Handle running state
	isActive := e.isUnitActive(params.UnitName)
	switch params.DesiredState {
	case pb.SystemdUnitState_SYSTEMD_UNIT_STATE_STARTED:
		if !isActive {
			if _, err := runSudoCmd(ctx, "systemctl", "start", params.UnitName); err != nil {
				return nil, changed, fmt.Errorf("start: %v", err)
			}
			output.WriteString("started unit\n")
			changed = true
		} else {
			output.WriteString("unit is already running\n")
		}
	case pb.SystemdUnitState_SYSTEMD_UNIT_STATE_STOPPED:
		if isActive {
			if _, err := runSudoCmd(ctx, "systemctl", "stop", params.UnitName); err != nil {
				return nil, changed, fmt.Errorf("stop: %v", err)
			}
			output.WriteString("stopped unit\n")
			changed = true
		} else {
			output.WriteString("unit is already stopped\n")
		}
	case pb.SystemdUnitState_SYSTEMD_UNIT_STATE_RESTARTED:
		// Restart always runs (not idempotent by design)
		if _, err := runSudoCmd(ctx, "systemctl", "restart", params.UnitName); err != nil {
			return nil, changed, fmt.Errorf("restart: %v", err)
		}
		output.WriteString("restarted unit\n")
		changed = true
	default:
		if !changed {
			output.WriteString("unit is already in desired state\n")
		}
	}

	return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, changed, nil
}

// isUnitEnabled checks if a systemd unit is enabled or in a state where
// enabling is not needed (static, indirect, generated units).
func (e *Executor) isUnitEnabled(unitName string) bool {
	return syssystemd.IsEnabled(unitName)
}

// isUnitMasked checks if a systemd unit is masked.
func (e *Executor) isUnitMasked(unitName string) bool {
	return syssystemd.IsMasked(unitName)
}

// isUnitActive checks if a systemd unit is currently active (running).
func (e *Executor) isUnitActive(unitName string) bool {
	return syssystemd.IsActive(unitName)
}

func (e *Executor) executeFile(ctx context.Context, params *pb.FileParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("file params required")
	}

	// Resolve symlinks to prevent traversal attacks
	resolvedPath, err := resolveAndValidatePath(params.Path)
	if err != nil {
		return nil, false, fmt.Errorf("invalid path: %w", err)
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Check if file already exists with correct content, mode, and ownership
		if e.fileMatchesDesired(resolvedPath, params) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("file %s is already in desired state", resolvedPath),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if !e.repairFilesystem(ctx) {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   "filesystem is read-only and could not be remounted - system may need reboot and fsck",
			}, false, fmt.Errorf("filesystem is read-only")
		}

		// Create parent directories using sudo
		parentDir := filepath.Dir(resolvedPath)
		if err := createDirectory(ctx, parentDir, true); err != nil {
			return nil, false, fmt.Errorf("create directory %s: %w", parentDir, err)
		}

		// Determine final content based on managed block mode
		var finalContent string
		actionVerb := "created"
		if params.ManagedBlock {
			// For managed block: read existing content and append block if not present
			// Use sudo cat to read files with restrictive permissions
			var existingContent []byte
			if output, err := runSudoCmd(ctx, "cat", resolvedPath); err == nil {
				existingContent = []byte(output.Stdout)
			} else if output != nil && strings.Contains(output.Stderr, "No such file") {
				// File doesn't exist, that's fine
				existingContent = nil
			} else {
				return nil, false, fmt.Errorf("read existing file: %w", err)
			}
			// Ensure there's a newline before appending block if file exists and doesn't end with newline
			existing := string(existingContent)
			if len(existing) > 0 && !strings.HasSuffix(existing, "\n") {
				existing += "\n"
			}
			finalContent = existing + params.Content
			actionVerb = "added block to"
		} else {
			finalContent = params.Content
		}

		// Atomic write: write to temp file, set permissions, then move into place.
		// This avoids TOCTOU race conditions.
		if err := atomicWriteFile(ctx, resolvedPath, finalContent, params.Mode, params.Owner, params.Group); err != nil {
			return nil, false, err
		}

		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("%s %s", actionVerb, resolvedPath),
		}, true, nil

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		// Check if file already doesn't exist
		if _, err := os.Stat(resolvedPath); os.IsNotExist(err) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("file %s does not exist, nothing to remove", resolvedPath),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if !e.repairFilesystem(ctx) {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   "filesystem is read-only and could not be remounted - system may need reboot and fsck",
			}, false, fmt.Errorf("filesystem is read-only")
		}

		// For managed block mode, remove only the specified content block from the file
		if params.ManagedBlock {
			// Read file with restrictive permissions
			existingContent, err := readFileWithSudo(ctx, resolvedPath)
			if err != nil {
				return nil, false, fmt.Errorf("read file: %w", err)
			}

			// Check if content exists in file
			if !strings.Contains(existingContent, params.Content) {
				return &pb.CommandOutput{
					ExitCode: 0,
					Stdout:   fmt.Sprintf("content not found in %s, nothing to remove", resolvedPath),
				}, false, nil
			}

			// Remove the content block from the file
			newContent := strings.Replace(existingContent, params.Content, "", 1)
			// Clean up any resulting double newlines
			for strings.Contains(newContent, "\n\n\n") {
				newContent = strings.ReplaceAll(newContent, "\n\n\n", "\n\n")
			}

			// Write the modified content back using atomic write
			if err := atomicWriteFile(ctx, resolvedPath, newContent, params.Mode, params.Owner, params.Group); err != nil {
				return nil, false, err
			}

			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("removed content block from %s", resolvedPath),
			}, true, nil
		}

		// For regular mode, delete the entire file
		if err := removeFileStrict(ctx, resolvedPath); err != nil {
			return nil, false, fmt.Errorf("remove: %w", err)
		}
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("removed %s", resolvedPath),
		}, true, nil
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// fileMatchesDesired checks if a file already has the desired content, mode, and ownership.
func (e *Executor) fileMatchesDesired(path string, params *pb.FileParams) bool {
	// Check if file exists
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	// Check if it's a regular file
	if !info.Mode().IsRegular() {
		return false
	}

	// Check content
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	if params.ManagedBlock {
		// For managed block mode, check if content block is already present in file
		if !strings.Contains(string(content), params.Content) {
			return false
		}
	} else {
		// For regular mode, check exact content match via hash
		currentHash := sha256.Sum256(content)
		desiredHash := sha256.Sum256([]byte(params.Content))
		if currentHash != desiredHash {
			return false
		}
	}

	// Check mode if specified
	if params.Mode != "" {
		// Parse desired mode
		var desiredMode uint64
		if _, err := fmt.Sscanf(params.Mode, "%o", &desiredMode); err == nil {
			currentMode := info.Mode().Perm()
			if uint32(currentMode) != uint32(desiredMode) {
				return false
			}
		}
	}

	// Check owner/group if specified
	if params.Owner != "" || params.Group != "" {
		currentOwner, currentGroup := getFileOwnership(path)
		if currentOwner == "" && currentGroup == "" {
			return false
		}
		// Handle case where only owner is specified
		if params.Group == "" {
			if currentOwner != params.Owner {
				return false
			}
		} else if currentOwner != params.Owner || currentGroup != params.Group {
			return false
		}
	}

	return true
}

// protectedPaths contains paths that should never be deleted.
// These are checked as prefixes after path cleaning.
var protectedPaths = []string{
	"/",
	"/bin",
	"/boot",
	"/dev",
	"/etc",
	"/home",
	"/lib",
	"/lib32",
	"/lib64",
	"/libx32",
	"/media",
	"/mnt",
	"/opt",
	"/proc",
	"/root",
	"/run",
	"/sbin",
	"/srv",
	"/sys",
	"/tmp",
	"/usr",
	"/var",
}

// isProtectedPath checks if a path is a protected system directory.
// Returns true if the path should not be deleted.
func isProtectedPath(path string) bool {
	// Clean and get absolute path
	cleanPath := filepath.Clean(path)

	// Check exact matches against protected paths
	for _, protected := range protectedPaths {
		if cleanPath == protected {
			return true
		}
	}

	// Also protect immediate children of / that aren't in our list
	// (e.g., /lost+found, or any other top-level directory)
	parts := strings.Split(strings.TrimPrefix(cleanPath, "/"), "/")
	if len(parts) == 1 && parts[0] != "" {
		// This is a top-level directory like /something
		return true
	}

	return false
}

func (e *Executor) executeDirectory(ctx context.Context, params *pb.DirectoryParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("directory params required")
	}

	if params.Path == "" {
		return nil, false, fmt.Errorf("directory path is required")
	}

	// Resolve symlinks to prevent traversal attacks
	cleanPath, err := resolveAndValidatePath(params.Path)
	if err != nil {
		return nil, false, fmt.Errorf("invalid path: %w", err)
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Check if directory already exists with correct mode and ownership
		if e.directoryMatchesDesired(cleanPath, params) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("directory %s is already in desired state", cleanPath),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if !e.repairFilesystem(ctx) {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   "filesystem is read-only and could not be remounted - system may need reboot and fsck",
			}, false, fmt.Errorf("filesystem is read-only")
		}

		// Create directory with permissions (handles mkdir, chmod, and chown)
		if err := createDirectoryWithPermissions(ctx, cleanPath, params.Mode, params.Owner, params.Group, params.Recursive); err != nil {
			return nil, false, err
		}

		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("created directory %s", cleanPath),
		}, true, nil

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		// Check if directory already doesn't exist
		if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("directory %s does not exist, nothing to remove", cleanPath),
			}, false, nil
		}

		// Safety check: refuse to delete protected system directories
		if isProtectedPath(cleanPath) {
			return nil, false, fmt.Errorf("refusing to delete protected system path: %s", cleanPath)
		}

		// Repair filesystem if mounted read-only
		if !e.repairFilesystem(ctx) {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   "filesystem is read-only and could not be remounted - system may need reboot and fsck",
			}, false, fmt.Errorf("filesystem is read-only")
		}

		// Remove directory (use -r for recursive removal if it has contents)
		if err := removeDirectory(ctx, cleanPath); err != nil {
			return nil, false, fmt.Errorf("remove directory: %w", err)
		}
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("removed directory %s", cleanPath),
		}, true, nil
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// directoryMatchesDesired checks if a directory already has the desired mode and ownership.
func (e *Executor) directoryMatchesDesired(path string, params *pb.DirectoryParams) bool {
	// Check if directory exists
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	// Check if it's a directory
	if !info.IsDir() {
		return false
	}

	// Check mode if specified
	if params.Mode != "" {
		var desiredMode uint64
		if _, err := fmt.Sscanf(params.Mode, "%o", &desiredMode); err == nil {
			currentMode := info.Mode().Perm()
			if uint32(currentMode) != uint32(desiredMode) {
				return false
			}
		}
	}

	// Check owner/group if specified
	if params.Owner != "" || params.Group != "" {
		currentOwner, currentGroup := getFileOwnership(path)
		if currentOwner == "" && currentGroup == "" {
			return false
		}
		if params.Group == "" {
			if currentOwner != params.Owner {
				return false
			}
		} else if currentOwner != params.Owner || currentGroup != params.Group {
			return false
		}
	}

	return true
}

// maxDownloadSize is the maximum allowed download size (2 GiB).
const maxDownloadSize = 2 << 30

func (e *Executor) downloadFile(ctx context.Context, url, dest, expectedChecksum string) error {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return err
	}

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download failed: %s", resp.Status)
	}

	// Reject downloads that advertise a size larger than the limit.
	if resp.ContentLength > maxDownloadSize {
		return fmt.Errorf("download rejected: Content-Length %d exceeds maximum %d bytes", resp.ContentLength, maxDownloadSize)
	}

	// Wrap the body with a size limit to protect against servers that
	// lie about Content-Length or use chunked encoding.
	body := io.LimitReader(resp.Body, maxDownloadSize+1)

	file, err := os.Create(dest)
	if err != nil {
		return err
	}

	var written int64
	if expectedChecksum != "" {
		hasher := sha256.New()
		reader := io.TeeReader(body, hasher)
		if written, err = io.Copy(file, reader); err != nil {
			_ = file.Close()
			return err
		}
		if written > maxDownloadSize {
			_ = file.Close()
			os.Remove(dest)
			return fmt.Errorf("download exceeded maximum size of %d bytes", maxDownloadSize)
		}
		actual := hex.EncodeToString(hasher.Sum(nil))
		if actual != expectedChecksum {
			_ = file.Close()
			os.Remove(dest)
			return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actual)
		}
	} else {
		if written, err = io.Copy(file, body); err != nil {
			_ = file.Close()
			return err
		}
		if written > maxDownloadSize {
			_ = file.Close()
			os.Remove(dest)
			return fmt.Errorf("download exceeded maximum size of %d bytes", maxDownloadSize)
		}
	}

	return file.Close()
}

// getAptCommand returns the preferred apt command ("apt" or "apt-get").
// Prefers "apt" if available as it provides better progress output.
func getAptCommand() string {
	if _, err := exec.LookPath("apt"); err == nil {
		return "apt"
	}
	return "apt-get"
}

// =============================================================================
// APT Helper Functions
// =============================================================================

// aptUpdate runs apt update to refresh package lists.
func aptUpdate(ctx context.Context) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, getAptCommand(), "update")
}

// aptUpgrade runs apt upgrade -y to upgrade all packages.
func aptUpgrade(ctx context.Context) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, getAptCommand(), "upgrade", "-y")
}

// aptDistUpgrade runs apt dist-upgrade -y for held-back packages.
func aptDistUpgrade(ctx context.Context) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, getAptCommand(), "dist-upgrade", "-y")
}

// aptAutoremove runs apt autoremove -y to remove unused packages.
func aptAutoremove(ctx context.Context) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, getAptCommand(), "autoremove", "-y")
}

// aptFixBroken runs apt --fix-broken install -y to repair broken dependencies.
func aptFixBroken(ctx context.Context) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, getAptCommand(), "--fix-broken", "install", "-y")
}

// =============================================================================
// DNF Helper Functions
// =============================================================================

// dnfMakecache runs dnf makecache to refresh package metadata.
func dnfMakecache(ctx context.Context) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "dnf", "-y", "makecache")
}

// dnfUpgrade runs dnf upgrade. If securityOnly is true, only security updates are applied.
func dnfUpgrade(ctx context.Context, securityOnly bool) (*pb.CommandOutput, error) {
	if securityOnly {
		return runSudoCmd(ctx, "dnf", "-y", "upgrade", "--security")
	}
	return runSudoCmd(ctx, "dnf", "-y", "upgrade")
}

// dnfAutoremove runs dnf autoremove -y to remove unused packages.
func dnfAutoremove(ctx context.Context) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "dnf", "-y", "autoremove")
}

// =============================================================================
// Zypper Helper Functions
// =============================================================================

// zypperRefresh runs zypper refresh to update repository metadata.
func zypperRefresh(ctx context.Context) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "zypper", "--non-interactive", "refresh")
}

// zypperUpdate runs zypper update to upgrade all packages.
func zypperUpdate(ctx context.Context) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "zypper", "--non-interactive", "update")
}

// =============================================================================
// Pacman Helper Functions
// =============================================================================

// pacmanSync runs pacman -Sy to sync package databases.
func pacmanSync(ctx context.Context) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "pacman", "-Sy", "--noconfirm")
}

// pacmanUpgrade runs pacman -Syu to sync and upgrade all packages.
func pacmanUpgrade(ctx context.Context) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "pacman", "-Syu", "--noconfirm")
}

// =============================================================================
// Package Pinning Helper Functions
// =============================================================================

// isPackagePinned checks if a package is pinned (held from upgrades).
// Uses the underlying package manager's pinning mechanism:
// - APT: apt-mark hold
// - DNF: dnf versionlock
// - Pacman: IgnorePkg in pacman.conf
// - Zypper: zypper lock
// - Flatpak: flatpak mask
func (e *Executor) isPackagePinned(pkgName string) (bool, error) {
	if e.pkgManager == nil {
		return false, fmt.Errorf("no package manager available")
	}
	return e.pkgManager.IsPinned(pkgName)
}

// pinPackage pins a package to prevent it from being upgraded.
// Returns (changed, error) where changed is true if the package was newly pinned.
func (e *Executor) pinPackage(pkgName string) (bool, error) {
	if e.pkgManager == nil {
		return false, fmt.Errorf("no package manager available")
	}

	// Check if already pinned
	isPinned, err := e.pkgManager.IsPinned(pkgName)
	if err != nil {
		return false, fmt.Errorf("check pin status: %w", err)
	}
	if isPinned {
		return false, nil // Already pinned, no change
	}

	// Pin the package
	_, err = e.pkgManager.Pin(pkgName).Run()
	if err != nil {
		return false, fmt.Errorf("pin package: %w", err)
	}
	return true, nil
}

// unpinPackage unpins a package to allow it to be upgraded.
// Returns (changed, error) where changed is true if the package was unpinned.
func (e *Executor) unpinPackage(pkgName string) (bool, error) {
	if e.pkgManager == nil {
		return false, fmt.Errorf("no package manager available")
	}

	// Check if currently pinned
	isPinned, err := e.pkgManager.IsPinned(pkgName)
	if err != nil {
		return false, fmt.Errorf("check pin status: %w", err)
	}
	if !isPinned {
		return false, nil // Already unpinned, no change
	}

	// Unpin the package
	_, err = e.pkgManager.Unpin(pkgName).Run()
	if err != nil {
		return false, fmt.Errorf("unpin package: %w", err)
	}
	return true, nil
}

// ensurePackagePinned ensures a package is pinned. Returns true if a change was made.
// This is a convenience method that handles filesystem repair before pinning.
func (e *Executor) ensurePackagePinned(ctx context.Context, pkgName string) (bool, error) {
	// Check if already pinned first (no filesystem write needed)
	isPinned, _ := e.isPackagePinned(pkgName)
	if isPinned {
		return false, nil
	}

	// Repair filesystem if needed before writing
	if !e.repairFilesystem(ctx) {
		return false, fmt.Errorf("filesystem is read-only")
	}

	return e.pinPackage(pkgName)
}

// ensurePackageUnpinned ensures a package is unpinned. Returns true if a change was made.
func (e *Executor) ensurePackageUnpinned(pkgName string) (bool, error) {
	return e.unpinPackage(pkgName)
}

// repairFilesystem attempts to fix read-only filesystem issues.
// This can happen when the kernel remounts the filesystem as read-only due to errors.
// It checks all real (non-virtual) filesystem mounts, not just /, because partitions
// like /usr may be mounted separately and go read-only independently.
// Returns true if all filesystems are writable, false if any repair failed.
func (e *Executor) repairFilesystem(ctx context.Context) bool {
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		e.logger.Warn("could not read /proc/mounts", "error", err)
		return true // Assume writable, let operations fail naturally
	}

	allOk := true
	for _, line := range strings.Split(string(mounts), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		device := fields[0]
		mountPoint := fields[1]
		options := fields[3]

		// Only check real block device filesystems (skip virtual: proc, sys, cgroup, etc.)
		if !strings.HasPrefix(device, "/dev/") {
			continue
		}

		isReadOnly := false
		for _, opt := range strings.Split(options, ",") {
			if opt == "ro" {
				isReadOnly = true
				break
			}
		}
		if !isReadOnly {
			continue
		}

		e.logger.Warn("filesystem is mounted read-only, attempting remount",
			"mount", mountPoint, "device", device,
		)

		output, err := runSudoCmd(ctx, "mount", "-o", "remount,rw", mountPoint)
		if err != nil {
			e.logger.Error("failed to remount filesystem as read-write",
				"mount", mountPoint, "device", device,
				"error", err, "output", output,
			)
			e.logger.Error("filesystem may have errors - system likely needs reboot and fsck",
				"mount", mountPoint,
			)
			allOk = false
		} else {
			e.logger.Info("successfully remounted filesystem as read-write",
				"mount", mountPoint, "device", device,
			)
		}
	}

	return allOk
}

// repairPackageManager attempts to fix common broken package manager states.
// This handles issues like interrupted dpkg operations, broken dependencies,
// and stale lock files that can prevent package operations from succeeding.
func (e *Executor) repairPackageManager(ctx context.Context) {
	// Detect which package manager we're using and run appropriate repairs
	if pkg.IsApt() {
		e.repairApt(ctx)
	} else if pkg.IsDnf() {
		e.repairDnf(ctx)
	} else if pkg.IsPacman() {
		e.repairPacman(ctx)
	} else if pkg.IsZypper() {
		e.repairZypper(ctx)
	}

	// Flatpak can coexist with any traditional package manager
	if pkg.IsFlatpak() {
		e.repairFlatpak(ctx)
	}
}

// repairApt fixes common apt/dpkg issues:
// - Stale lock files from interrupted operations
// - Interrupted dpkg operations (dpkg --configure -a)
// - Broken dependencies (apt -f install)
// - Stale package lists
func (e *Executor) repairApt(ctx context.Context) {
	// Remove stale lock files that may be left from interrupted operations
	runSudoCmd(ctx, "rm", "-f", "/var/lib/dpkg/lock-frontend")
	runSudoCmd(ctx, "rm", "-f", "/var/lib/dpkg/lock")
	runSudoCmd(ctx, "rm", "-f", "/var/lib/apt/lists/lock")
	runSudoCmd(ctx, "rm", "-f", "/var/cache/apt/archives/lock")

	// Fix any interrupted dpkg operations
	// This handles "dpkg was interrupted, you must manually run 'dpkg --configure -a'"
	runSudoCmd(ctx, "dpkg", "--configure", "-a")

	// Update package lists to get latest dependency info
	// This is crucial for resolving dependency version mismatches
	aptUpdate(ctx)

	// Fix broken dependencies and install missing ones
	// This handles "unmet dependencies" and "held broken packages" issues
	aptFixBroken(ctx)
}

// repairDnf fixes common dnf/rpm issues:
// - Incomplete transactions (dnf-automatic, interrupted updates)
// - Corrupted rpm database
// - Duplicate packages
func (e *Executor) repairDnf(ctx context.Context) {
	// Complete any interrupted transactions
	// This is similar to "dnf-automatic" leaving things half-done
	runSudoCmd(ctx, "dnf", "-y", "history", "redo", "last")

	// Clean up any duplicate packages
	runSudoCmd(ctx, "dnf", "-y", "remove", "--duplicates")

	// Rebuild rpm database if corrupted
	// First try to verify, if that fails, rebuild
	if output, err := runSudoCmd(ctx, "rpm", "--verifydb"); err != nil || output.ExitCode != 0 {
		runSudoCmd(ctx, "rpm", "--rebuilddb")
	}
}

// repairPacman fixes common pacman issues:
// - Stale lock files from interrupted operations
// - Corrupted package database
// - Keyring issues
func (e *Executor) repairPacman(ctx context.Context) {
	// Remove stale lock file if it exists
	// This handles "unable to lock database" errors from interrupted operations
	runSudoCmd(ctx, "rm", "-f", "/var/lib/pacman/db.lck")

	// Refresh package database to fix potential corruption
	// Using -Syy to force refresh even if recently updated
	runSudoCmd(ctx, "pacman", "-Syy", "--noconfirm")

	// Reinitialize keyring if there are signature issues
	// This fixes "signature is unknown trust" errors
	runSudoCmd(ctx, "pacman-key", "--init")
	runSudoCmd(ctx, "pacman-key", "--populate", "archlinux")
}

// repairZypper fixes common zypper/rpm issues:
// - Stale lock files
// - Corrupted rpm database
// - Repository metadata issues
// - Broken dependencies
func (e *Executor) repairZypper(ctx context.Context) {
	// Remove stale lock files
	runSudoCmd(ctx, "rm", "-f", "/var/run/zypp.pid")

	// Clean repository metadata cache to fix stale metadata issues
	runSudoCmd(ctx, "zypper", "--non-interactive", "clean", "--all")

	// Refresh repositories to get fresh metadata
	runSudoCmd(ctx, "zypper", "--non-interactive", "refresh")

	// Verify and fix dependency issues
	runSudoCmd(ctx, "zypper", "--non-interactive", "verify", "--recommends")

	// Rebuild rpm database if corrupted
	if output, err := runSudoCmd(ctx, "rpm", "--verifydb"); err != nil || output.ExitCode != 0 {
		runSudoCmd(ctx, "rpm", "--rebuilddb")
	}
}

// repairFlatpak fixes common Flatpak issues:
// - Stale metadata cache
// - Broken remotes
func (e *Executor) repairFlatpak(ctx context.Context) {
	// Repair any broken installations (removes partial/orphaned refs)
	runSudoCmd(ctx, "flatpak", "repair", "--system")

	// Update appstream metadata to fix stale cache issues
	runSudoCmd(ctx, "flatpak", "update", "--appstream", "-y", "--noninteractive", "--system")
}

// executeUpdate performs a system-wide package update.
// It respects version pinning (apt-mark hold / dnf versionlock).
func (e *Executor) executeUpdate(ctx context.Context, params *pb.UpdateParams) (*pb.CommandOutput, error) {
	if e.pkgManager == nil {
		return nil, fmt.Errorf("no supported package manager found")
	}

	// Repair filesystem if mounted read-only (common after kernel errors)
	if !e.repairFilesystem(ctx) {
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   "filesystem is read-only and could not be remounted - system may need reboot and fsck",
		}, fmt.Errorf("filesystem is read-only")
	}

	// Repair any broken package manager state first
	e.repairPackageManager(ctx)

	var allOutput strings.Builder
	var lastErr error

	// Update package index
	if updateResult, err := e.pkgManager.Update(); err != nil {
		allOutput.WriteString("=== Package Index Update ===\n")
		if updateResult != nil {
			allOutput.WriteString(updateResult.Stdout)
			allOutput.WriteString(updateResult.Stderr)
		}
		allOutput.WriteString(fmt.Sprintf("Warning: update failed: %v\n\n", err))
	} else if updateResult != nil {
		allOutput.WriteString("=== Package Index Update ===\n")
		allOutput.WriteString(updateResult.Stdout)
		if updateResult.Stderr != "" {
			allOutput.WriteString(updateResult.Stderr)
		}
		allOutput.WriteString("\n")
	}

	// Perform the upgrade
	allOutput.WriteString("=== Package Upgrade ===\n")

	if pkg.IsApt() {
		lastErr = e.executeAptUpgrade(ctx, params, &allOutput)
	} else if pkg.IsDnf() {
		lastErr = e.executeDnfUpgrade(ctx, params, &allOutput)
	} else {
		// Fallback to generic upgrade via the builder
		upgradeResult, err := e.pkgManager.Upgrade().Run()
		if err != nil {
			allOutput.WriteString(fmt.Sprintf("Error: %v\n", err))
			if upgradeResult != nil {
				allOutput.WriteString(upgradeResult.Stdout)
				allOutput.WriteString(upgradeResult.Stderr)
			}
			lastErr = err
		} else if upgradeResult != nil {
			allOutput.WriteString(upgradeResult.Stdout)
			allOutput.WriteString(upgradeResult.Stderr)
		}
	}

	// Autoremove if requested
	if params != nil && params.Autoremove {
		allOutput.WriteString("\n=== Autoremove Unused Packages ===\n")
		if pkg.IsApt() {
			if output, err := aptAutoremove(ctx); err == nil {
				allOutput.WriteString(output.Stdout)
			} else if output != nil {
				allOutput.WriteString(output.Stderr)
			}
		} else if pkg.IsDnf() {
			if output, err := dnfAutoremove(ctx); err == nil {
				allOutput.WriteString(output.Stdout)
			} else if output != nil {
				allOutput.WriteString(output.Stderr)
			}
		}
	}

	// Check if reboot is required
	rebootRequired := e.checkRebootRequired()
	if rebootRequired {
		allOutput.WriteString("\n*** REBOOT REQUIRED ***\n")
		if params != nil && params.RebootIfRequired {
			sysnotify.NotifyAll(ctx, "System Reboot", "A system update requires a reboot. This system will reboot in 1 minute.")
			allOutput.WriteString("Scheduling reboot in 1 minute...\n")
			runSudoCmd(ctx, "shutdown", "-r", "+1", "System update requires reboot")
		}
	}

	exitCode := int32(0)
	if lastErr != nil {
		exitCode = 1
	}

	return &pb.CommandOutput{
		ExitCode: exitCode,
		Stdout:   allOutput.String(),
	}, lastErr
}

// executeAptUpgrade performs apt-specific upgrade.
func (e *Executor) executeAptUpgrade(ctx context.Context, params *pb.UpdateParams, output *strings.Builder) error {
	if params != nil && params.SecurityOnly {
		// Use unattended-upgrades for security-only updates if available
		if _, err := exec.LookPath("unattended-upgrade"); err == nil {
			cmdOutput, err := runSudoCmd(ctx, "unattended-upgrade", "-v")
			if cmdOutput != nil {
				output.WriteString(cmdOutput.Stdout)
				output.WriteString(cmdOutput.Stderr)
			}
			return err
		}
		// Fallback: try apt with security pocket only
		// This is distribution-specific and may not work everywhere
		output.WriteString("Note: security-only updates requested but unattended-upgrade not available\n")
	}

	// Standard upgrade
	cmdOutput, err := aptUpgrade(ctx)
	if cmdOutput != nil {
		output.WriteString(cmdOutput.Stdout)
		output.WriteString(cmdOutput.Stderr)
	}

	// Also run dist-upgrade for held-back packages (still respects holds)
	output.WriteString("\n=== Dist-Upgrade ===\n")
	distOutput, _ := aptDistUpgrade(ctx)
	if distOutput != nil {
		output.WriteString(distOutput.Stdout)
		output.WriteString(distOutput.Stderr)
	}

	return err
}

// executeDnfUpgrade performs dnf-specific upgrade.
func (e *Executor) executeDnfUpgrade(ctx context.Context, params *pb.UpdateParams, output *strings.Builder) error {
	securityOnly := params != nil && params.SecurityOnly
	cmdOutput, err := dnfUpgrade(ctx, securityOnly)
	if cmdOutput != nil {
		output.WriteString(cmdOutput.Stdout)
		output.WriteString(cmdOutput.Stderr)
	}

	return err
}

// checkRebootRequired checks if the system requires a reboot after updates.
func (e *Executor) checkRebootRequired() bool {
	// Debian/Ubuntu: check for reboot-required file
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		return true
	}

	// RHEL/Fedora: check needs-restarting
	if pkg.IsDnf() {
		_, exitCode, _ := queryCmdOutput("needs-restarting", "-r")
		// Exit code 1 means reboot required
		if exitCode == 1 {
			return true
		}
	}

	return false
}

// executeRepository configures an external package repository.
func (e *Executor) executeRepository(ctx context.Context, params *pb.RepositoryParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("repository params required")
	}

	if params.Name == "" {
		return nil, false, fmt.Errorf("repository name required")
	}

	// Repair filesystem if mounted read-only
	if !e.repairFilesystem(ctx) {
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   "filesystem is read-only and could not be remounted - system may need reboot and fsck",
		}, false, fmt.Errorf("filesystem is read-only")
	}

	if !validRepoName.MatchString(params.Name) {
		return nil, false, fmt.Errorf("invalid repository name %q: must match [a-zA-Z0-9][a-zA-Z0-9._-]*", params.Name)
	}
	if len(params.Name) > 128 {
		return nil, false, fmt.Errorf("repository name too long: max 128 characters")
	}

	// Detect package manager and execute the appropriate configuration
	// Repository actions always report changed=true since they write config files
	switch {
	case pkg.IsApt():
		if params.Apt == nil || params.Apt.Disabled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   "skipped: no APT repository configuration provided",
			}, false, nil
		}
		return e.executeAptRepository(ctx, params.Name, params.Apt, state)

	case pkg.IsDnf():
		if params.Dnf == nil || params.Dnf.Disabled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   "skipped: no DNF repository configuration provided",
			}, false, nil
		}
		output, err := e.executeDnfRepository(ctx, params.Name, params.Dnf, state)
		return output, err == nil, err

	case pkg.IsPacman():
		if params.Pacman == nil || params.Pacman.Disabled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   "skipped: no Pacman repository configuration provided",
			}, false, nil
		}
		output, err := e.executePacmanRepository(ctx, params.Name, params.Pacman, state)
		return output, err == nil, err

	case pkg.IsZypper():
		if params.Zypper == nil || params.Zypper.Disabled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   "skipped: no Zypper repository configuration provided",
			}, false, nil
		}
		output, err := e.executeZypperRepository(ctx, params.Name, params.Zypper, state)
		return output, err == nil, err

	default:
		return nil, false, fmt.Errorf("no supported package manager found for repository configuration")
	}
}

// cleanupConflictingAptRepos scans /etc/apt/sources.list.d/ for any repository configs
// that contain the given URL and removes them along with their associated GPG keys.
// This prevents "conflicting values set for option Signed-By" errors when the same
// repository URL was previously configured under a different name or with different keys.
// The skipRepoFile and skipKeyFile parameters specify files that should NOT be deleted
// (typically the target repository being configured).
func (e *Executor) cleanupConflictingAptRepos(ctx context.Context, url, skipRepoFile, skipKeyFile string, output *strings.Builder) {
	sourcesDir := "/etc/apt/sources.list.d"
	entries, err := os.ReadDir(sourcesDir)
	if err != nil {
		return // Directory might not exist, that's fine
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		filename := entry.Name()
		if !strings.HasSuffix(filename, ".sources") && !strings.HasSuffix(filename, ".list") {
			continue
		}

		filePath := filepath.Join(sourcesDir, filename)

		// Skip the target repository file we're about to create/update
		if filePath == skipRepoFile {
			continue
		}
		// Also skip if it's a legacy .list version of the same repo
		if strings.TrimSuffix(filePath, ".list")+".sources" == skipRepoFile {
			continue
		}

		content, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		// Check if this file contains our URL
		if !strings.Contains(string(content), url) {
			continue
		}

		output.WriteString(fmt.Sprintf("removing conflicting repository config: %s\n", filePath))

		// Extract Signed-By path from DEB822 format (.sources files)
		if strings.HasSuffix(filename, ".sources") {
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "Signed-By:") {
					keyPath := strings.TrimSpace(strings.TrimPrefix(line, "Signed-By:"))
					// Skip if this is our target key file
					if keyPath == skipKeyFile {
						continue
					}
					if keyPath != "" && strings.HasPrefix(keyPath, "/") {
						output.WriteString(fmt.Sprintf("removing associated GPG key: %s\n", keyPath))
						runSudoCmd(ctx, "rm", "-f", keyPath)
					}
				}
			}
		}

		// Extract signed-by from one-line format (.list files)
		// Format: deb [signed-by=/path/to/key.gpg] https://...
		if strings.HasSuffix(filename, ".list") {
			re := regexp.MustCompile(`signed-by=([^\s\]]+)`)
			matches := re.FindAllStringSubmatch(string(content), -1)
			for _, match := range matches {
				keyPath := match[1]
				// Skip if this is our target key file
				if keyPath == skipKeyFile {
					continue
				}
				if len(match) > 1 && strings.HasPrefix(keyPath, "/") {
					output.WriteString(fmt.Sprintf("removing associated GPG key: %s\n", keyPath))
					runSudoCmd(ctx, "rm", "-f", keyPath)
				}
			}
		}

		// Remove the repository file
		runSudoCmd(ctx, "rm", "-f", filePath)
	}
}

// executeAptRepository configures an APT repository.
// This function is idempotent - it checks if files already exist with correct content
// and only updates them if they differ.
func (e *Executor) executeAptRepository(ctx context.Context, name string, repo *pb.AptRepository, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	var output strings.Builder
	repoFile := fmt.Sprintf("/etc/apt/sources.list.d/%s.sources", name)
	keyFile := fmt.Sprintf("/etc/apt/keyrings/%s.gpg", name)

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		// Remove repository file
		if _, err := runSudoCmd(ctx, "rm", "-f", repoFile); err != nil {
			return nil, false, fmt.Errorf("failed to remove repo file: %w", err)
		}
		// Also try to remove legacy .list format
		legacyFile := fmt.Sprintf("/etc/apt/sources.list.d/%s.list", name)
		runSudoCmd(ctx, "rm", "-f", legacyFile)
		// Remove GPG key
		runSudoCmd(ctx, "rm", "-f", keyFile)
		output.WriteString(fmt.Sprintf("removed repository: %s\n", name))
		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, true, nil

	case pb.DesiredState_DESIRED_STATE_PRESENT:
		changed := false

		// First, scan for and remove any existing repository configs that use the same URL
		// This prevents "conflicting values set for option Signed-By" errors when the same
		// repository was previously configured under a different name or with different keys
		// We skip our own repo file and key file to allow the comparison logic to work
		e.cleanupConflictingAptRepos(ctx, repo.Url, repoFile, keyFile, &output)

		// Clean up legacy .list file if it exists
		legacyFile := fmt.Sprintf("/etc/apt/sources.list.d/%s.list", name)
		if _, err := os.Stat(legacyFile); err == nil {
			output.WriteString(fmt.Sprintf("removing legacy repository file: %s\n", legacyFile))
			runSudoCmd(ctx, "rm", "-f", legacyFile)
			changed = true
		}
		// Clean up legacy GPG key location
		legacyKeyFile := fmt.Sprintf("/etc/apt/trusted.gpg.d/%s.gpg", name)
		if _, err := os.Stat(legacyKeyFile); err == nil {
			output.WriteString(fmt.Sprintf("removing legacy GPG key: %s\n", legacyKeyFile))
			runSudoCmd(ctx, "rm", "-f", legacyKeyFile)
			changed = true
		}

		// Ensure keyrings directory exists
		if _, err := runSudoCmd(ctx, "mkdir", "-p", "/etc/apt/keyrings"); err != nil {
			return nil, false, fmt.Errorf("failed to create keyrings directory: %w", err)
		}

		// Import GPG key if provided
		// We download/process to a temp file first and only update if content differs
		if repo.GpgKeyUrl != "" || repo.GpgKey != "" {
			keyUpdated, keyErr := e.updateGpgKeyIfNeeded(ctx, keyFile, repo.GpgKeyUrl, repo.GpgKey, &output)
			if keyErr != nil {
				return &pb.CommandOutput{ExitCode: 1, Stdout: output.String(), Stderr: keyErr.Error()}, false, keyErr
			}
			if keyUpdated {
				output.WriteString("GPG key updated\n")
				changed = true
			} else {
				output.WriteString("GPG key unchanged\n")
			}
		}

		// Build DEB822 format sources file (modern format)
		var content strings.Builder
		content.WriteString(fmt.Sprintf("# Repository: %s\n", name))
		content.WriteString("Types: deb\n")
		content.WriteString(fmt.Sprintf("URIs: %s\n", repo.Url))

		if repo.Distribution != "" {
			content.WriteString(fmt.Sprintf("Suites: %s\n", repo.Distribution))
		} else {
			content.WriteString("Suites: /\n")
		}

		if len(repo.Components) > 0 {
			content.WriteString(fmt.Sprintf("Components: %s\n", strings.Join(repo.Components, " ")))
		}

		if repo.Arch != "" {
			content.WriteString(fmt.Sprintf("Architectures: %s\n", repo.Arch))
		}

		if repo.GpgKeyUrl != "" || repo.GpgKey != "" {
			content.WriteString(fmt.Sprintf("Signed-By: %s\n", keyFile))
		} else if repo.Trusted {
			content.WriteString("Trusted: yes\n")
		}

		// Compare with existing file — skip write and apt update if unchanged
		desiredContent := content.String()
		existing, _ := readFileWithSudo(ctx, repoFile)
		if existing == desiredContent && !changed {
			output.WriteString(fmt.Sprintf("repository already up to date: %s\n", name))
			return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, false, nil
		}

		// Write the sources file
		if existing != desiredContent {
			if _, err := writeFileWithSudo(ctx, repoFile, desiredContent); err != nil {
				return nil, false, fmt.Errorf("failed to write repo file: %w", err)
			}
			output.WriteString(fmt.Sprintf("configured repository: %s\n", name))
			changed = true
		}

		// Update package index only when something changed
		if changed {
			updateOutput, _ := aptUpdate(ctx)
			if updateOutput != nil {
				output.WriteString(updateOutput.Stdout)
			}
		}

		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, changed, nil

	default:
		return nil, false, fmt.Errorf("unknown desired state: %v", state)
	}
}

// updateGpgKeyIfNeeded downloads/processes a GPG key and only updates the target file if content differs.
// Returns true if the key was updated, false if unchanged.
func (e *Executor) updateGpgKeyIfNeeded(ctx context.Context, keyFile, keyUrl, keyContent string, output *strings.Builder) (bool, error) {
	// Validate URL scheme to prevent file:// or other protocol abuse
	if keyUrl != "" {
		if !strings.HasPrefix(keyUrl, "https://") {
			return false, fmt.Errorf("GPG key URL must use https:// scheme, got: %s", keyUrl)
		}
	}

	// Create a temp file for the new key
	tempFile, err := os.CreateTemp("", "gpgkey-*.gpg")
	if err != nil {
		return false, fmt.Errorf("failed to create temp file: %w", err)
	}
	tempPath := tempFile.Name()
	_ = tempFile.Close()
	defer os.Remove(tempPath)

	// Obtain raw key bytes (download or use provided content)
	var rawKey []byte
	if keyUrl != "" {
		output.WriteString(fmt.Sprintf("downloading GPG key from %s\n", keyUrl))
		req, err := http.NewRequestWithContext(ctx, "GET", keyUrl, nil)
		if err != nil {
			return false, fmt.Errorf("failed to create GPG key request: %w", err)
		}
		resp, err := e.httpClient.Do(req)
		if err != nil {
			return false, fmt.Errorf("failed to download GPG key: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false, fmt.Errorf("GPG key download failed: HTTP %d", resp.StatusCode)
		}
		rawKey, err = io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB limit
		if err != nil {
			return false, fmt.Errorf("failed to read GPG key response: %w", err)
		}
	} else if keyContent != "" {
		output.WriteString("processing GPG key from content\n")
		rawKey = []byte(keyContent)
	} else {
		return false, nil // No key to process
	}

	// Dearmor the key using gpg with stdin piping (no shell involved)
	if _, err := runCmdWithStdin(ctx, bytes.NewReader(rawKey), "gpg", "--yes", "--dearmor", "-o", tempPath); err != nil {
		return false, fmt.Errorf("failed to dearmor GPG key: %w", err)
	}

	// Read the new key content
	newKey, err := os.ReadFile(tempPath)
	if err != nil {
		return false, fmt.Errorf("failed to read temp key file: %w", err)
	}

	// Check if existing key file exists and compare content
	existingKey, err := os.ReadFile(keyFile)
	if err == nil {
		// File exists, compare content
		if bytes.Equal(existingKey, newKey) {
			output.WriteString("GPG key already installed and matches\n")
			return false, nil
		}
		output.WriteString("GPG key differs, updating\n")
	} else if os.IsNotExist(err) {
		output.WriteString("GPG key not found, installing\n")
	} else {
		// Other error reading the file - try to read with sudo
		cmdOutput, sudoErr := runSudoCmd(ctx, "cat", keyFile)
		if sudoErr == nil && cmdOutput != nil {
			if bytes.Equal([]byte(cmdOutput.Stdout), newKey) {
				output.WriteString("GPG key already installed and matches\n")
				return false, nil
			}
			output.WriteString("GPG key differs, updating\n")
		} else {
			output.WriteString("GPG key not found, installing\n")
		}
	}

	// Copy the new key to the target location with sudo
	_, err = runSudoCmd(ctx, "cp", tempPath, keyFile)
	if err != nil {
		return false, fmt.Errorf("failed to install GPG key: %w", err)
	}

	// Set proper permissions
	runSudoCmd(ctx, "chmod", "644", keyFile)

	return true, nil
}

// executeDnfRepository configures a DNF/YUM repository.
func (e *Executor) executeDnfRepository(ctx context.Context, name string, repo *pb.DnfRepository, state pb.DesiredState) (*pb.CommandOutput, error) {
	var output strings.Builder
	repoFile := fmt.Sprintf("/etc/yum.repos.d/%s.repo", name)

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		if _, err := runSudoCmd(ctx, "rm", "-f", repoFile); err != nil {
			return nil, fmt.Errorf("failed to remove repo file: %w", err)
		}
		output.WriteString(fmt.Sprintf("removed repository: %s\n", name))
		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil

	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Clean up any existing repository configuration to ensure clean state
		// This handles cases where the repository was previously configured with different settings
		if _, err := os.Stat(repoFile); err == nil {
			output.WriteString(fmt.Sprintf("replacing existing repository: %s\n", name))
			runSudoCmd(ctx, "rm", "-f", repoFile)
		}

		// Build repo file content
		var content strings.Builder
		content.WriteString(fmt.Sprintf("[%s]\n", name))

		if repo.Description != "" {
			content.WriteString(fmt.Sprintf("name=%s\n", repo.Description))
		} else {
			content.WriteString(fmt.Sprintf("name=%s\n", name))
		}

		content.WriteString(fmt.Sprintf("baseurl=%s\n", repo.Baseurl))

		if repo.Enabled {
			content.WriteString("enabled=1\n")
		} else {
			content.WriteString("enabled=0\n")
		}

		if repo.Gpgcheck {
			content.WriteString("gpgcheck=1\n")
			if repo.Gpgkey != "" {
				content.WriteString(fmt.Sprintf("gpgkey=%s\n", repo.Gpgkey))
			}
		} else {
			content.WriteString("gpgcheck=0\n")
		}

		if repo.ModuleHotfixes {
			content.WriteString("module_hotfixes=1\n")
		}

		// Write the repo file
		if _, err := writeFileWithSudo(ctx, repoFile, content.String()); err != nil {
			return nil, fmt.Errorf("failed to write repo file: %w", err)
		}

		output.WriteString(fmt.Sprintf("configured repository: %s\n", name))

		// Import GPG key if provided
		// rpm --import is idempotent - re-importing an existing key is a no-op
		if repo.Gpgkey != "" {
			keyOutput, _ := runSudoCmd(ctx, "rpm", "--import", repo.Gpgkey)
			if keyOutput != nil && keyOutput.Stdout != "" {
				output.WriteString(keyOutput.Stdout)
			}
		}

		// Refresh metadata (use -y for non-interactive mode)
		refreshOutput, _ := runSudoCmd(ctx, "dnf", "-y", "makecache", "--repo", name)
		if refreshOutput != nil {
			output.WriteString(refreshOutput.Stdout)
		}

		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil

	default:
		return nil, fmt.Errorf("unknown desired state: %v", state)
	}
}

// removePacmanSection removes a [name] section from pacman.conf content.
// A section extends from [name] to the next [section] line (exclusive) or end of file.
func removePacmanSection(content, name string) string {
	sectionHeader := "[" + name + "]"
	lines := strings.Split(content, "\n")
	var result []string
	inSection := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == sectionHeader {
			inSection = true
			continue
		}
		if inSection && strings.HasPrefix(trimmed, "[") {
			inSection = false
		}
		if !inSection {
			result = append(result, line)
		}
	}
	return strings.Join(result, "\n")
}

// executePacmanRepository configures a Pacman repository.
func (e *Executor) executePacmanRepository(ctx context.Context, name string, repo *pb.PacmanRepository, state pb.DesiredState) (*pb.CommandOutput, error) {
	var output strings.Builder
	confFile := "/etc/pacman.conf"

	// Read current pacman.conf
	confContent, err := os.ReadFile(confFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read pacman.conf: %w", err)
	}
	confStr := string(confContent)

	// Check if repo section exists
	repoSection := fmt.Sprintf("[%s]", name)
	hasRepo := strings.Contains(confStr, repoSection)

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		if !hasRepo {
			output.WriteString(fmt.Sprintf("repository %s not found, nothing to remove\n", name))
			return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil
		}

		// Remove the repository section in Go (no sed, no shell injection risk)
		newConf := removePacmanSection(confStr, name)
		if _, err := writeFileWithSudo(ctx, confFile, newConf); err != nil {
			return nil, fmt.Errorf("failed to update pacman.conf: %w", err)
		}

		output.WriteString(fmt.Sprintf("removed repository: %s\n", name))
		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil

	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Build new repo section
		var section strings.Builder
		section.WriteString(fmt.Sprintf("\n[%s]\n", name))
		if repo.SigLevel != "" {
			section.WriteString(fmt.Sprintf("SigLevel = %s\n", repo.SigLevel))
		}
		section.WriteString(fmt.Sprintf("Server = %s\n", repo.Server))

		// Remove old section if it exists, then append new one (single atomic write)
		newConf := confStr
		if hasRepo {
			newConf = removePacmanSection(confStr, name)
		}
		newConf += section.String()

		if _, err := writeFileWithSudo(ctx, confFile, newConf); err != nil {
			return nil, fmt.Errorf("failed to write pacman.conf: %w", err)
		}

		output.WriteString(fmt.Sprintf("configured repository: %s\n", name))

		// Sync database (--noconfirm for non-interactive mode)
		syncOutput, _ := runSudoCmd(ctx, "pacman", "-Sy", "--noconfirm")
		if syncOutput != nil {
			output.WriteString(syncOutput.Stdout)
		}

		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil

	default:
		return nil, fmt.Errorf("unknown desired state: %v", state)
	}
}

// executeZypperRepository configures a Zypper repository.
func (e *Executor) executeZypperRepository(ctx context.Context, name string, repo *pb.ZypperRepository, state pb.DesiredState) (*pb.CommandOutput, error) {
	var output strings.Builder

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		cmdOutput, err := runSudoCmd(ctx, "zypper", "--non-interactive", "removerepo", name)
		if err != nil {
			// Ignore if repo doesn't exist
			if cmdOutput != nil && strings.Contains(cmdOutput.Stderr, "not found") {
				output.WriteString(fmt.Sprintf("repository %s not found, nothing to remove\n", name))
				return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil
			}
			return nil, fmt.Errorf("failed to remove repository: %w", err)
		}
		output.WriteString(fmt.Sprintf("removed repository: %s\n", name))
		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil

	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Build zypper addrepo command
		args := []string{"--non-interactive", "addrepo", "--refresh"}

		if !repo.Gpgcheck {
			args = append(args, "--no-gpgcheck")
		}

		if repo.Type != "" {
			args = append(args, "--type", repo.Type)
		}

		// Check if repo exists, remove first if it does
		runSudoCmd(ctx, "zypper", "--non-interactive", "removerepo", name)

		args = append(args, repo.Url, name)
		cmdOutput, err := runSudoCmd(ctx, "zypper", args...)
		if err != nil {
			if cmdOutput != nil {
				output.WriteString(cmdOutput.Stderr)
			}
			return nil, fmt.Errorf("failed to add repository: %w", err)
		}

		output.WriteString(fmt.Sprintf("configured repository: %s\n", name))

		// Set description if provided
		if repo.Description != "" {
			runSudoCmd(ctx, "zypper", "--non-interactive", "modifyrepo", "--name", repo.Description, name)
		}

		// Enable/disable
		if repo.Enabled {
			runSudoCmd(ctx, "zypper", "--non-interactive", "modifyrepo", "--enable", name)
		} else {
			runSudoCmd(ctx, "zypper", "--non-interactive", "modifyrepo", "--disable", name)
		}

		// Set autorefresh
		if repo.Autorefresh {
			runSudoCmd(ctx, "zypper", "--non-interactive", "modifyrepo", "--refresh", name)
		}

		// Import GPG key if provided
		if repo.Gpgkey != "" {
			keyOutput, _ := runSudoCmd(ctx, "rpm", "--import", repo.Gpgkey)
			if keyOutput != nil && keyOutput.Stdout != "" {
				output.WriteString(keyOutput.Stdout)
			}
		}

		// Refresh repository
		refreshOutput, _ := runSudoCmd(ctx, "zypper", "--non-interactive", "refresh", name)
		if refreshOutput != nil {
			output.WriteString(refreshOutput.Stdout)
		}

		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil

	default:
		return nil, fmt.Errorf("unknown desired state: %v", state)
	}
}

// isInstantAction returns true if the action type is an instant action (agent-builtin, no parameters).
func isInstantAction(t pb.ActionType) bool {
	return t == pb.ActionType_ACTION_TYPE_REBOOT || t == pb.ActionType_ACTION_TYPE_SYNC
}

// IsInstantAction is the exported version for use by the handler.
func IsInstantAction(t pb.ActionType) bool {
	return isInstantAction(t)
}

// executeReboot schedules a system reboot in 5 minutes.
func (e *Executor) executeReboot(ctx context.Context) (*pb.CommandOutput, error) {
	sysnotify.NotifyAll(ctx, "System Reboot", "This system will reboot in 5 minutes. Please save your work.")

	output, err := runSudoCmd(ctx, "shutdown", "-r", "+5", "Power Manage: scheduled reboot")
	if err != nil {
		return output, fmt.Errorf("failed to schedule reboot: %w", err)
	}
	if output == nil {
		output = &pb.CommandOutput{}
	}
	output.Stdout = "Reboot scheduled in 5 minutes\n" + output.Stdout
	return output, nil
}

// executeUser manages user accounts (create, update, disable, remove).
func (e *Executor) executeUser(ctx context.Context, params *pb.UserParams, state pb.DesiredState) (*pb.CommandOutput, bool, map[string]string, error) {
	if params == nil {
		return nil, false, nil, fmt.Errorf("user params required")
	}

	if params.Username == "" {
		return nil, false, nil, fmt.Errorf("username is required")
	}

	// Validate username format (prevent injection)
	if !sysuser.IsValidName(params.Username) {
		return nil, false, nil, fmt.Errorf("invalid username: must be 1-32 alphanumeric characters, starting with a letter")
	}

	// Repair filesystem if mounted read-only
	if !e.repairFilesystem(ctx) {
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   "filesystem is read-only and could not be remounted - system may need reboot and fsck",
		}, false, nil, fmt.Errorf("filesystem is read-only")
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		return e.createOrUpdateUser(ctx, params)
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		output, changed, err := e.removeUser(ctx, params.Username)
		return output, changed, nil, err
	default:
		return nil, false, nil, fmt.Errorf("unknown desired state: %v", state)
	}
}


// createOrUpdateUser creates a new user or updates an existing one.
// Returns the command output, whether changes were made, metadata, and any error.
func (e *Executor) createOrUpdateUser(ctx context.Context, params *pb.UserParams) (*pb.CommandOutput, bool, map[string]string, error) {
	var output strings.Builder
	exists := userExists(params.Username)

	if exists {
		// Update existing user
		cmdOutput, changed, err := e.updateUser(ctx, params, &output)
		return cmdOutput, changed, nil, err
	}

	// Create new user - always a change
	cmdOutput, metadata, err := e.createUser(ctx, params, &output)
	return cmdOutput, true, metadata, err
}

// createUser creates a new user account.
func (e *Executor) createUser(ctx context.Context, params *pb.UserParams, output *strings.Builder) (*pb.CommandOutput, map[string]string, error) {
	args := []string{}

	// UID
	if params.Uid > 0 {
		args = append(args, "-u", fmt.Sprintf("%d", params.Uid))
	}

	// GID or primary group
	if params.Gid > 0 {
		args = append(args, "-g", fmt.Sprintf("%d", params.Gid))
	} else if params.PrimaryGroup != "" {
		// Ensure group exists
		_ = sysuser.GroupEnsureExists(ctx, params.PrimaryGroup)
		args = append(args, "-g", params.PrimaryGroup)
	}

	// Home directory
	if params.HomeDir != "" {
		args = append(args, "-d", params.HomeDir)
	}

	// Shell (default to /bin/bash for normal users, /usr/sbin/nologin for disabled/system)
	shell := params.Shell
	if shell == "" {
		if params.Disabled {
			shell = "/usr/sbin/nologin"
		} else if params.SystemUser {
			shell = "/usr/sbin/nologin"
		} else {
			shell = "/bin/bash"
		}
	}
	args = append(args, "-s", shell)

	// System user
	if params.SystemUser {
		args = append(args, "-r") // Create system account
	}

	// Create home directory (default true for normal users)
	createHome := params.CreateHome
	if !params.SystemUser && !params.CreateHome {
		// For normal users, default to creating home
		createHome = true
	}

	// Determine home directory path to check if it exists
	homeDir := params.HomeDir
	if homeDir == "" {
		homeDir = "/home/" + params.Username
	}

	// Check if home directory already exists - useradd -m fails if it does
	homeExists := false
	if _, err := os.Stat(homeDir); err == nil {
		homeExists = true
	}

	if createHome && !homeExists {
		args = append(args, "-m")
	} else {
		args = append(args, "-M")
	}

	// Comment/GECOS
	if params.Comment != "" {
		args = append(args, "-c", params.Comment)
	}

	// Add username as last argument
	args = append(args, params.Username)

	// Create the user
	cmdOutput, err := runSudoCmd(ctx, "useradd", args...)
	if err != nil {
		if cmdOutput != nil {
			output.WriteString(cmdOutput.Stderr)
		}
		return &pb.CommandOutput{ExitCode: 1, Stderr: output.String()}, nil, fmt.Errorf("failed to create user: %w", err)
	}
	output.WriteString(fmt.Sprintf("created user: %s\n", params.Username))

	// If home directory already existed, fix ownership
	if homeExists && createHome {
		if chownOutput, chownErr := runSudoCmd(ctx, "chown", "-R", params.Username+":"+params.Username, homeDir); chownErr != nil {
			output.WriteString(fmt.Sprintf("warning: failed to fix home directory ownership: %v\n", chownErr))
			if chownOutput != nil {
				output.WriteString(chownOutput.Stderr)
			}
		} else {
			output.WriteString(fmt.Sprintf("fixed ownership of existing home directory: %s\n", homeDir))
		}
	}

	// Generate and set temporary password for non-system users
	var metadata map[string]string
	if !params.SystemUser && !params.Disabled {
		tempPassword, err := sysuser.GeneratePassword(16, false)
		if err != nil {
			output.WriteString(fmt.Sprintf("warning: failed to generate temporary password: %v\n", err))
		} else {
			// Set password using chpasswd
			if chpasswdOutput, chpasswdErr := runSudoCmdWithStdin(ctx, strings.NewReader(fmt.Sprintf("%s:%s", params.Username, tempPassword)), "chpasswd"); chpasswdErr != nil {
				output.WriteString(fmt.Sprintf("warning: failed to set temporary password: %v\n", chpasswdErr))
				if chpasswdOutput != nil {
					output.WriteString(chpasswdOutput.Stderr)
				}
			} else {
				// Force password change on first login
				if _, chageErr := runSudoCmd(ctx, "chage", "-d", "0", params.Username); chageErr != nil {
					output.WriteString(fmt.Sprintf("warning: failed to expire password: %v\n", chageErr))
				}
				output.WriteString(fmt.Sprintf("temporary password set for %s (must be changed on first login)\n", params.Username))

				// Report password via lps.rotations metadata so it's stored in the LPS table
				rotations := []lpsRotationEntry{{
					Username:  params.Username,
					Password:  tempPassword,
					RotatedAt: time.Now().UTC().Format(time.RFC3339),
					Reason:    "user_created",
				}}
				if rotationsJSON, err := json.Marshal(rotations); err == nil {
					metadata = map[string]string{"lps.rotations": string(rotationsJSON)}
				}
			}
		}
	}

	// Setup SSH authorized keys
	if len(params.SshAuthorizedKeys) > 0 {
		if _, err := e.setupSSHKeys(ctx, params, output); err != nil {
			output.WriteString(fmt.Sprintf("warning: failed to setup SSH keys: %v\n", err))
		}
	}

	// Handle disabled state (lock the account)
	if params.Disabled {
		if lockOutput, lockErr := runSudoCmd(ctx, "usermod", "-L", params.Username); lockErr != nil {
			output.WriteString(fmt.Sprintf("warning: failed to lock user account: %v\n", lockErr))
			if lockOutput != nil {
				output.WriteString(lockOutput.Stderr)
			}
		} else {
			output.WriteString("account locked (disabled)\n")
		}
	}

	// Hide from login screen if requested
	if params.Hidden {
		setUserHidden(ctx, params.Username, true, output)
	}

	return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, metadata, nil
}

// updateUser modifies an existing user account.
func (e *Executor) updateUser(ctx context.Context, params *pb.UserParams, output *strings.Builder) (*pb.CommandOutput, bool, error) {
	// Get current user state
	currentInfo, err := sysuser.Get(params.Username)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get current user info: %w", err)
	}

	changed := false
	args := []string{}

	// Determine desired shell
	desiredShell := params.Shell
	if desiredShell == "" {
		if params.Disabled {
			desiredShell = "/usr/sbin/nologin"
		}
		// If not disabled and no shell specified, don't change the existing shell
	}

	// Shell - only change if explicitly set and different
	if desiredShell != "" && currentInfo.Shell != desiredShell {
		args = append(args, "-s", desiredShell)
		output.WriteString(fmt.Sprintf("shell: %s -> %s\n", currentInfo.Shell, desiredShell))
	}

	// Home directory - only if explicitly set and different
	if params.HomeDir != "" && currentInfo.HomeDir != params.HomeDir {
		args = append(args, "-d", params.HomeDir)
		output.WriteString(fmt.Sprintf("home: %s -> %s\n", currentInfo.HomeDir, params.HomeDir))
	}

	// Comment - only if explicitly set and different
	if params.Comment != "" && currentInfo.Comment != params.Comment {
		args = append(args, "-c", params.Comment)
		output.WriteString(fmt.Sprintf("comment: %s -> %s\n", currentInfo.Comment, params.Comment))
	}

	// Primary group - only if explicitly set and different
	if params.Gid > 0 && currentInfo.GID != int(params.Gid) {
		args = append(args, "-g", fmt.Sprintf("%d", params.Gid))
		output.WriteString(fmt.Sprintf("gid: %d -> %d\n", currentInfo.GID, params.Gid))
	} else if params.PrimaryGroup != "" {
		// Check if primary group needs to change (would need to resolve group name to GID)
		_ = sysuser.GroupEnsureExists(ctx, params.PrimaryGroup)
		// For simplicity, always set if specified by name (could be optimized)
		args = append(args, "-g", params.PrimaryGroup)
	}

	// Apply usermod if we have changes
	if len(args) > 0 {
		args = append(args, params.Username)
		cmdOutput, err := runSudoCmd(ctx, "usermod", args...)
		if err != nil {
			if cmdOutput != nil {
				output.WriteString(cmdOutput.Stderr)
			}
			return &pb.CommandOutput{ExitCode: 1, Stderr: output.String()}, false, fmt.Errorf("failed to update user: %w", err)
		}
		changed = true
	}

	// Ensure home directory exists (may be missing if a prior run failed)
	createHome := params.CreateHome
	if !params.SystemUser && !params.CreateHome {
		createHome = true
	}
	if createHome {
		homeDir := params.HomeDir
		if homeDir == "" {
			homeDir = currentInfo.HomeDir
		}
		if homeDir == "" {
			homeDir = "/home/" + params.Username
		}
		if _, err := os.Stat(homeDir); os.IsNotExist(err) {
			if _, mkErr := runSudoCmd(ctx, "mkdir", "-p", homeDir); mkErr != nil {
				output.WriteString(fmt.Sprintf("warning: failed to create home directory: %v\n", mkErr))
			} else {
				runSudoCmd(ctx, "cp", "-a", "/etc/skel/.", homeDir)
				runSudoCmd(ctx, "chown", "-R", params.Username+":"+params.Username, homeDir)
				runSudoCmd(ctx, "chmod", "0700", homeDir)
				output.WriteString(fmt.Sprintf("created missing home directory: %s\n", homeDir))
				changed = true
			}
		}
	}

	// Handle disabled/locked state - only change if different
	desiredLocked := params.Disabled
	if desiredLocked != currentInfo.Locked {
		if desiredLocked {
			if lockOutput, err := runSudoCmd(ctx, "usermod", "-L", params.Username); err != nil {
				output.WriteString(fmt.Sprintf("warning: failed to lock user: %v\n", err))
				if lockOutput != nil {
					output.WriteString(lockOutput.Stderr)
				}
			} else {
				output.WriteString("account locked (disabled)\n")
				changed = true
			}
		} else {
			if unlockOutput, err := runSudoCmd(ctx, "usermod", "-U", params.Username); err != nil {
				output.WriteString(fmt.Sprintf("warning: failed to unlock user: %v\n", err))
				if unlockOutput != nil {
					output.WriteString(unlockOutput.Stderr)
				}
			} else {
				output.WriteString("account unlocked\n")
				changed = true
			}
		}
	}

	// Setup SSH authorized keys
	if len(params.SshAuthorizedKeys) > 0 {
		if keysChanged, err := e.setupSSHKeys(ctx, params, output); err != nil {
			output.WriteString(fmt.Sprintf("warning: failed to setup SSH keys: %v\n", err))
		} else if keysChanged {
			changed = true
		}
	}

	// Hide/show on login screen
	if setUserHidden(ctx, params.Username, params.Hidden, output) {
		changed = true
	}

	if !changed {
		output.WriteString(fmt.Sprintf("user %s is already in desired state\n", params.Username))
	}

	return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, changed, nil
}

// removeUser removes a user account from the system.
// Returns the command output, whether changes were made, and any error.
func (e *Executor) removeUser(ctx context.Context, username string) (*pb.CommandOutput, bool, error) {
	// Never allow removal of the agent's own service user
	if username == "power-manage" {
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   "refusing to remove the power-manage service user\n",
		}, false, fmt.Errorf("cannot remove protected user: power-manage")
	}

	if !userExists(username) {
		// User doesn't exist, no change needed
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("user %s does not exist, nothing to remove\n", username),
		}, false, nil
	}

	// Kill all processes and sessions for this user before removal
	killUserSessions(ctx, username)

	// Clean up AccountsService override if present
	removeAccountsServiceFile(ctx, username)

	// Remove user and their home directory
	output, err := runSudoCmd(ctx, "userdel", "-r", username)
	if err != nil {
		// If home directory doesn't exist, userdel -r may still succeed
		// but report an error. Check if user is actually removed.
		if !userExists(username) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("removed user: %s (home directory may not have existed)\n", username),
			}, true, nil
		}
		if output != nil {
			return &pb.CommandOutput{ExitCode: 1, Stderr: output.Stderr}, false, fmt.Errorf("failed to remove user: %w", err)
		}
		return nil, false, fmt.Errorf("failed to remove user: %w", err)
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   fmt.Sprintf("removed user: %s\n", username),
	}, true, nil
}

// accountsServicePath returns the AccountsService override file path for a user.
const accountsServiceDir = "/var/lib/AccountsService/users"

// setUserHidden writes or removes the AccountsService override to hide/show a user
// on graphical login screens. Returns whether a change was made. Skips silently if
// AccountsService is not installed (headless systems).
func setUserHidden(ctx context.Context, username string, hidden bool, output *strings.Builder) bool {
	filePath := accountsServiceDir + "/" + username

	if _, err := os.Stat(accountsServiceDir); os.IsNotExist(err) {
		return false // AccountsService not installed, skip
	}

	desiredContent := "[User]\nSystemAccount=true\n"

	if hidden {
		// Check idempotency
		existing, _ := readFileWithSudo(ctx, filePath)
		if existing == desiredContent {
			return false
		}
		if err := atomicWriteFile(ctx, filePath, desiredContent, "0644", "root", "root"); err != nil {
			output.WriteString(fmt.Sprintf("warning: failed to hide user from login screen: %v\n", err))
			return false
		}
		output.WriteString("hidden from login screen (AccountsService)\n")
		return true
	}

	// hidden=false: remove the file if it exists and was set by us
	existing, err := readFileWithSudo(ctx, filePath)
	if err != nil || existing != desiredContent {
		return false // File doesn't exist or wasn't ours
	}
	if err := removeFileStrict(ctx, filePath); err != nil {
		output.WriteString(fmt.Sprintf("warning: failed to unhide user from login screen: %v\n", err))
		return false
	}
	output.WriteString("visible on login screen (AccountsService removed)\n")
	return true
}

// removeAccountsServiceFile removes the AccountsService override for a user during user deletion.
func removeAccountsServiceFile(ctx context.Context, username string) {
	filePath := accountsServiceDir + "/" + username
	if fileExistsWithSudo(ctx, filePath) {
		removeFileStrict(ctx, filePath)
	}
}

// setupSSHKeys configures SSH authorized keys for a user.
func (e *Executor) setupSSHKeys(ctx context.Context, params *pb.UserParams, output *strings.Builder) (bool, error) {
	// Determine home directory
	homeDir := params.HomeDir
	if homeDir == "" {
		if params.SystemUser {
			homeDir = "/"
		} else {
			homeDir = filepath.Join("/home", params.Username)
		}
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	authKeysFile := filepath.Join(sshDir, "authorized_keys")

	// Build desired authorized_keys content
	var keysContent strings.Builder
	for _, key := range params.SshAuthorizedKeys {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		if !strings.HasPrefix(trimmedKey, "ssh-") && !strings.HasPrefix(trimmedKey, "ecdsa-") {
			output.WriteString(fmt.Sprintf("warning: skipping invalid SSH key (doesn't start with ssh- or ecdsa-): %s...\n", trimmedKey[:min(30, len(trimmedKey))]))
			continue
		}
		keysContent.WriteString(trimmedKey)
		keysContent.WriteString("\n")
	}
	desiredContent := keysContent.String()

	// Check if authorized_keys already has the desired content (idempotency)
	existing, _ := readFileWithSudo(ctx, authKeysFile)
	if existing == desiredContent {
		return false, nil
	}

	// Create .ssh directory
	if _, err := runSudoCmd(ctx, "mkdir", "-p", sshDir); err != nil {
		return false, fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Set ownership and permissions on .ssh directory
	if _, err := runSudoCmd(ctx, "chown", params.Username+":"+params.Username, sshDir); err != nil {
		return false, fmt.Errorf("failed to set .ssh ownership: %w", err)
	}
	if _, err := runSudoCmd(ctx, "chmod", "700", sshDir); err != nil {
		return false, fmt.Errorf("failed to set .ssh permissions: %w", err)
	}

	// Write authorized_keys file
	if _, err := runSudoCmdWithStdin(ctx, strings.NewReader(desiredContent), "tee", authKeysFile); err != nil {
		return false, fmt.Errorf("failed to write authorized_keys: %w", err)
	}

	// Set ownership and permissions on authorized_keys
	if _, err := runSudoCmd(ctx, "chown", params.Username+":"+params.Username, authKeysFile); err != nil {
		return false, fmt.Errorf("failed to set authorized_keys ownership: %w", err)
	}
	if _, err := runSudoCmd(ctx, "chmod", "600", authKeysFile); err != nil {
		return false, fmt.Errorf("failed to set authorized_keys permissions: %w", err)
	}

	output.WriteString(fmt.Sprintf("configured %d SSH authorized key(s)\n", len(params.SshAuthorizedKeys)))
	return true, nil
}

// sshGroupName creates a valid Linux group name from the action ID for SSH access.
// Linux group names: max 32 chars. pm-ssh- (7 chars) + up to 25 chars of action ID.
func sshGroupName(actionID string) string {
	lower := strings.ToLower(actionID)
	if len(lower) > 25 {
		lower = lower[:25]
	}
	return "pm-ssh-" + lower
}

// sshConfigPath returns the path for an SSH config drop-in file.
func sshConfigPath(actionID string) string {
	return fmt.Sprintf("/etc/ssh/sshd_config.d/pm-ssh-%s.conf", strings.ToLower(actionID))
}

// sshEffectiveUsers returns the merged user list, handling backward compat with the deprecated username field.
func sshEffectiveUsers(params *pb.SshParams) []string {
	users := params.Users
	// Backward compat: if deprecated username is set and not already in users, include it
	if params.Username != "" {
		found := false
		for _, u := range users {
			if u == params.Username {
				found = true
				break
			}
		}
		if !found {
			users = append([]string{params.Username}, users...)
		}
	}
	return users
}

// executeSsh configures SSH access via an sshd_config.d drop-in file with a Match Group directive.
// Each action creates a Linux group pm-ssh-{actionId} and users are added to the group.
func (e *Executor) executeSsh(ctx context.Context, params *pb.SshParams, state pb.DesiredState, actionID string) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("ssh params required")
	}
	if actionID == "" {
		return nil, false, fmt.Errorf("action ID required for ssh group/file naming")
	}

	users := sshEffectiveUsers(params)
	if len(users) == 0 {
		return nil, false, fmt.Errorf("at least one user is required")
	}
	for _, u := range users {
		if !sysuser.IsValidName(u) {
			return nil, false, fmt.Errorf("invalid username: %s", u)
		}
	}

	groupName := sshGroupName(actionID)
	configPath := sshConfigPath(actionID)

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		return e.removeSshAccess(ctx, groupName, configPath)
	default:
		return e.setupSshAccess(ctx, params, users, groupName, configPath)
	}
}

// generateSshGroupConfig generates sshd_config content using Match Group.
func generateSshGroupConfig(groupName string, params *pb.SshParams) string {
	lines := []string{
		"# Managed by Power Manage - do not edit manually",
		fmt.Sprintf("Match Group %s", groupName),
	}
	if params.AllowPubkey {
		lines = append(lines, "    PubkeyAuthentication yes")
		lines = append(lines, "    AuthorizedKeysFile .ssh/authorized_keys")
	} else {
		lines = append(lines, "    PubkeyAuthentication no")
	}
	if params.AllowPassword {
		lines = append(lines, "    PasswordAuthentication yes")
	} else {
		lines = append(lines, "    PasswordAuthentication no")
	}
	return strings.Join(lines, "\n") + "\n"
}

// setupSshAccess creates or updates the SSH access group and sshd_config.d file.
func (e *Executor) setupSshAccess(ctx context.Context, params *pb.SshParams, users []string, groupName, configPath string) (*pb.CommandOutput, bool, error) {
	var output strings.Builder
	changed := false

	// Generate sshd config content
	content := generateSshGroupConfig(groupName, params)

	// Check idempotency: file content + group membership
	fileMatches := e.configMatchesDesired(configPath, content)
	membersMatch := sudoGroupMembersMatch(groupName, users)
	if fileMatches && membersMatch {
		output.WriteString(fmt.Sprintf("SSH config already up to date: %s\n", configPath))
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   output.String(),
		}, false, nil
	}

	if !e.repairFilesystem(ctx) {
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   "filesystem is read-only and could not be remounted",
		}, false, fmt.Errorf("filesystem is read-only")
	}

	// Ensure group exists
	if !groupExists(groupName) {
		if err := sysuser.GroupCreate(ctx, groupName); err != nil {
			return nil, false, fmt.Errorf("create group %s: %v", groupName, err)
		}
		output.WriteString(fmt.Sprintf("created group: %s\n", groupName))
		changed = true
	}

	// Write sshd config file
	if !fileMatches {
		// Ensure /etc/ssh/sshd_config.d exists
		if err := createDirectory(ctx, "/etc/ssh/sshd_config.d", true); err != nil {
			return nil, false, fmt.Errorf("create sshd_config.d: %w", err)
		}
		if err := atomicWriteFile(ctx, configPath, content, "0644", "root", "root"); err != nil {
			return nil, false, fmt.Errorf("write ssh config: %w", err)
		}
		output.WriteString(fmt.Sprintf("wrote SSH config: %s\n", configPath))
		changed = true
	}

	// Add users to group
	for _, username := range users {
		if !userExists(username) {
			output.WriteString(fmt.Sprintf("warning: user %q does not exist, skipping group membership\n", username))
			continue
		}
		if !userInGroup(username, groupName) {
			if err := addUserToGroup(ctx, username, groupName); err != nil {
				output.WriteString(fmt.Sprintf("warning: failed to add user %s to group: %v\n", username, err))
			} else {
				output.WriteString(fmt.Sprintf("added user %s to group %s\n", username, groupName))
				changed = true
			}
		}
	}

	// Remove users that are no longer in the list
	currentMembers := getGroupMembers(groupName)
	desiredSet := make(map[string]bool, len(users))
	for _, u := range users {
		desiredSet[u] = true
	}
	for _, member := range currentMembers {
		if !desiredSet[member] {
			if err := removeUserFromGroup(ctx, member, groupName); err == nil {
				output.WriteString(fmt.Sprintf("removed user %s from group %s\n", member, groupName))
				changed = true
			}
		}
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, changed, nil
}

// removeSshAccess removes the sshd_config.d file, group membership, and group.
func (e *Executor) removeSshAccess(ctx context.Context, groupName, configPath string) (*pb.CommandOutput, bool, error) {
	var output strings.Builder
	changed := false

	// Remove sshd config file
	if fileExistsWithSudo(ctx, configPath) {
		if !e.repairFilesystem(ctx) {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   "filesystem is read-only and could not be remounted",
			}, false, fmt.Errorf("filesystem is read-only")
		}
		if err := removeFileStrict(ctx, configPath); err != nil {
			return nil, false, fmt.Errorf("remove ssh config: %w", err)
		}
		output.WriteString(fmt.Sprintf("removed SSH config: %s\n", configPath))
		changed = true
	}

	// Remove group and membership
	if groupExists(groupName) {
		members := getGroupMembers(groupName)
		for _, member := range members {
			if err := removeUserFromGroup(ctx, member, groupName); err == nil {
				output.WriteString(fmt.Sprintf("removed user %s from group %s\n", member, groupName))
				changed = true
			}
		}
		if err := sysuser.GroupDelete(ctx, groupName); err != nil {
			output.WriteString(fmt.Sprintf("warning: failed to delete group %s: %v\n", groupName, err))
		} else {
			output.WriteString(fmt.Sprintf("deleted group: %s\n", groupName))
			changed = true
		}
	}

	if !changed {
		output.WriteString("SSH access does not exist, nothing to remove\n")
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, changed, nil
}

// configMatchesDesired checks if a config file already has the desired content.
func (e *Executor) configMatchesDesired(path, desiredContent string) bool {
	if !fileExistsWithSudo(context.Background(), path) {
		return false
	}
	existing, err := readFileWithSudo(context.Background(), path)
	if err != nil {
		return false
	}
	return existing == desiredContent
}

// executeSshd configures the SSH daemon via sshd_config.d drop-in files.
func (e *Executor) executeSshd(ctx context.Context, params *pb.SshdParams, state pb.DesiredState, actionID string) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("sshd params required")
	}
	if len(params.Directives) == 0 && state != pb.DesiredState_DESIRED_STATE_ABSENT {
		return nil, false, fmt.Errorf("at least one directive is required")
	}
	if actionID == "" {
		return nil, false, fmt.Errorf("action ID required for sshd config file naming")
	}

	configPath := fmt.Sprintf("/etc/ssh/sshd_config.d/%04d-pm-%s.conf", params.Priority, actionID)

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		return e.removeSshdConfig(ctx, configPath)
	default:
		return e.setupSshdConfig(ctx, params, configPath)
	}
}

// generateSshdGlobalConfig generates sshd_config content from directives.
func generateSshdGlobalConfig(params *pb.SshdParams) string {
	var lines []string
	lines = append(lines, "# Managed by Power Manage - do not edit manually")
	for _, d := range params.Directives {
		lines = append(lines, fmt.Sprintf("%s %s", d.Key, d.Value))
	}
	return strings.Join(lines, "\n") + "\n"
}

// setupSshdConfig creates or updates an sshd_config.d drop-in file and reloads sshd if changed.
func (e *Executor) setupSshdConfig(ctx context.Context, params *pb.SshdParams, configPath string) (*pb.CommandOutput, bool, error) {
	var output strings.Builder

	content := generateSshdGlobalConfig(params)

	// Check idempotency
	if e.configMatchesDesired(configPath, content) {
		output.WriteString(fmt.Sprintf("SSHD config already up to date: %s\n", configPath))
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   output.String(),
		}, false, nil
	}

	if !e.repairFilesystem(ctx) {
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   "filesystem is read-only and could not be remounted",
		}, false, fmt.Errorf("filesystem is read-only")
	}

	// Ensure /etc/ssh/sshd_config.d exists
	if err := createDirectory(ctx, "/etc/ssh/sshd_config.d", true); err != nil {
		return nil, false, fmt.Errorf("create sshd_config.d: %w", err)
	}

	if err := atomicWriteFile(ctx, configPath, content, "0644", "root", "root"); err != nil {
		return nil, false, fmt.Errorf("write sshd config: %w", err)
	}
	output.WriteString(fmt.Sprintf("created SSHD config: %s\n", configPath))

	// Validate config
	validateOut, validateErr := runSudoCmd(ctx, "sshd", "-t")
	if validateErr != nil {
		// Config is invalid — remove it and report error
		removeFileStrict(ctx, configPath)
		errMsg := "sshd config validation failed"
		if validateOut != nil && validateOut.Stderr != "" {
			errMsg = strings.TrimSpace(validateOut.Stderr)
		}
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   errMsg,
		}, false, fmt.Errorf("sshd -t validation failed: %s", errMsg)
	}

	// Reload sshd
	reloadOut, reloadErr := runSudoCmd(ctx, "systemctl", "reload", "sshd")
	if reloadErr != nil {
		// Try ssh.service as fallback (some distros use ssh instead of sshd)
		reloadOut, reloadErr = runSudoCmd(ctx, "systemctl", "reload", "ssh")
	}
	if reloadErr != nil {
		output.WriteString("warning: failed to reload sshd\n")
		if reloadOut != nil && reloadOut.Stderr != "" {
			output.WriteString(strings.TrimSpace(reloadOut.Stderr) + "\n")
		}
	} else {
		output.WriteString("reloaded sshd\n")
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, true, nil
}

// removeSshdConfig removes an sshd_config.d drop-in file and reloads sshd.
func (e *Executor) removeSshdConfig(ctx context.Context, configPath string) (*pb.CommandOutput, bool, error) {
	var output strings.Builder

	if !fileExistsWithSudo(ctx, configPath) {
		output.WriteString(fmt.Sprintf("SSHD config does not exist: %s\n", configPath))
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   output.String(),
		}, false, nil
	}

	if !e.repairFilesystem(ctx) {
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   "filesystem is read-only and could not be remounted",
		}, false, fmt.Errorf("filesystem is read-only")
	}

	if err := removeFileStrict(ctx, configPath); err != nil {
		return nil, false, fmt.Errorf("remove sshd config: %w", err)
	}
	output.WriteString(fmt.Sprintf("removed SSHD config: %s\n", configPath))

	// Reload sshd
	reloadOut, reloadErr := runSudoCmd(ctx, "systemctl", "reload", "sshd")
	if reloadErr != nil {
		reloadOut, reloadErr = runSudoCmd(ctx, "systemctl", "reload", "ssh")
	}
	if reloadErr != nil {
		output.WriteString("warning: failed to reload sshd\n")
		if reloadOut != nil && reloadOut.Stderr != "" {
			output.WriteString(strings.TrimSpace(reloadOut.Stderr) + "\n")
		}
	} else {
		output.WriteString("reloaded sshd\n")
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, true, nil
}


