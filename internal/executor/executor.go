// Package executor provides implementations for action executors.
package executor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/go-cmd/cmd"
	"google.golang.org/protobuf/types/known/timestamppb"

	"log/slog"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/agent/internal/verify"
	"github.com/manchtools/power-manage/sdk/go/pkg"
)

// maxOutputBytes is the maximum number of bytes captured per command output stream.
const maxOutputBytes = 1 << 20 // 1 MiB

// OutputCallback is called for each line of output during streaming execution.
// streamType: 1 = stdout, 2 = stderr
// line: the output line (with newline)
// seq: sequence number for ordering
type OutputCallback func(streamType int, line string, seq int64)

// limitWriter wraps a bytes.Buffer and stops writing after limit bytes.
// It silently discards excess data to avoid failing the underlying command.
type limitWriter struct {
	buf   *bytes.Buffer
	limit int
	n     int
}

func (lw *limitWriter) Write(p []byte) (int, error) {
	remaining := lw.limit - lw.n
	if remaining <= 0 {
		return len(p), nil // discard silently
	}
	toWrite := p
	if len(p) > remaining {
		toWrite = p[:remaining]
	}
	n, err := lw.buf.Write(toWrite)
	lw.n += n
	return len(p), err // report full write to avoid cmd failure
}

// resolveAndValidatePath resolves symlinks in the parent directory of the given
// path and returns the cleaned, resolved absolute path. This prevents symlink
// traversal attacks where a symlink could redirect writes to sensitive locations.
func resolveAndValidatePath(path string) (string, error) {
	clean := filepath.Clean(path)
	if !filepath.IsAbs(clean) {
		return "", fmt.Errorf("path must be absolute: %s", path)
	}
	dir := filepath.Dir(clean)
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return clean, nil // parent doesn't exist yet, clean path is safe
		}
		return "", fmt.Errorf("resolve symlinks: %w", err)
	}
	return filepath.Join(resolved, filepath.Base(clean)), nil
}

// validRepoName restricts repository names to safe characters only.
// This prevents path traversal, shell injection, and sed/regex injection.
var validRepoName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// Executor handles the execution of actions.
type Executor struct {
	httpClient *http.Client
	pkgManager *pkg.PackageManager
	verifier   *verify.ActionVerifier
	logger     *slog.Logger
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
			// Shell scripts: hard reject unsigned/tampered actions
			if action.Type == pb.ActionType_ACTION_TYPE_SHELL {
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
		output, changed, execErr = e.executeUser(ctx, action.GetUser(), action.DesiredState)
		result.Changed = changed
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
					// Check pin status if requested
					if params.Pin {
						isPinned, _ := e.pkgManager.IsPinned(pkgName)
						if isPinned {
							return &pb.CommandOutput{
								ExitCode: 0,
								Stdout:   fmt.Sprintf("package %s version %s is already installed and pinned", pkgName, params.Version),
							}, false, nil
						}
						// Need to pin, fall through to pin only
						if !e.repairFilesystem(ctx) {
							return &pb.CommandOutput{
								ExitCode: 1,
								Stderr:   "filesystem is read-only",
							}, false, fmt.Errorf("filesystem is read-only")
						}
						_, pinErr := e.pkgManager.Pin(pkgName).Run()
						if pinErr != nil {
							return &pb.CommandOutput{
								ExitCode: 1,
								Stderr:   fmt.Sprintf("failed to pin package: %v", pinErr),
							}, false, pinErr
						}
						return &pb.CommandOutput{
							ExitCode: 0,
							Stdout:   fmt.Sprintf("package %s version %s was already installed, pinned", pkgName, params.Version),
						}, true, nil
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
					isPinned, _ := e.pkgManager.IsPinned(pkgName)
					if isPinned {
						return &pb.CommandOutput{
							ExitCode: 0,
							Stdout:   fmt.Sprintf("package %s is already installed and pinned", pkgName),
						}, false, nil
					}
					// Need to pin only
					if !e.repairFilesystem(ctx) {
						return &pb.CommandOutput{
							ExitCode: 1,
							Stderr:   "filesystem is read-only",
						}, false, fmt.Errorf("filesystem is read-only")
					}
					_, pinErr := e.pkgManager.Pin(pkgName).Run()
					if pinErr != nil {
						return &pb.CommandOutput{
							ExitCode: 1,
							Stderr:   fmt.Sprintf("failed to pin package: %v", pinErr),
						}, false, pinErr
					}
					return &pb.CommandOutput{
						ExitCode: 0,
						Stdout:   fmt.Sprintf("package %s was already installed, pinned", pkgName),
					}, true, nil
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
		if updateResult, updateErr := e.pkgManager.Update(); updateErr != nil {
			// Log update failure but continue with install attempt
			if updateResult != nil {
				result = updateResult
			}
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
			_, pinErr := e.pkgManager.Pin(pkgName).Run()
			if pinErr != nil {
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

		// Unpin first if it was pinned
		e.pkgManager.Unpin(pkgName).Run() // Ignore errors
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
		output, err := runSudoCommand(ctx, "flatpak", "install", "-y", "--noninteractive", systemFlag, remote, params.AppId)
		if err != nil {
			return output, false, fmt.Errorf("flatpak install failed: %w", err)
		}

		// Pin if requested (mask prevents updates)
		if params.Pin {
			pinOutput, pinErr := runSudoCommand(ctx, "flatpak", "mask", systemFlag, params.AppId)
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
		runSudoCommand(ctx, "flatpak", "mask", "--remove", systemFlag, params.AppId)

		// Uninstall the flatpak application
		output, err := runSudoCommand(ctx, "flatpak", "uninstall", "-y", "--noninteractive", systemFlag, params.AppId)
		return output, true, err
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// isFlatpakInstalled checks if a flatpak app is installed.
func (e *Executor) isFlatpakInstalled(appId, systemFlag string) bool {
	cmd := exec.Command("flatpak", "info", systemFlag, appId)
	return cmd.Run() == nil
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
		tmpFile.Close()

		if err := e.downloadFile(ctx, params.Url, tmpFile.Name(), params.ChecksumSha256); err != nil {
			return nil, false, fmt.Errorf("download: %w", err)
		}

		// Install with dpkg (requires sudo)
		output, err := runSudoCommand(ctx, "dpkg", "-i", tmpFile.Name())
		if err != nil {
			// Try to fix dependencies
			runSudoCommand(ctx, "apt-get", "-f", "install", "-y")
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

		output, err := runSudoCommand(ctx, "dpkg", "-r", pkgName)
		return output, true, err
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// isDebInstalled checks if a deb package is installed.
func (e *Executor) isDebInstalled(pkgName string) bool {
	cmd := exec.Command("dpkg", "-s", pkgName)
	return cmd.Run() == nil
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
		tmpFile.Close()

		if err := e.downloadFile(ctx, params.Url, tmpFile.Name(), params.ChecksumSha256); err != nil {
			return nil, false, fmt.Errorf("download: %w", err)
		}

		// Install with rpm (requires sudo)
		output, err := runSudoCommand(ctx, "rpm", "-i", tmpFile.Name())
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

		output, err := runSudoCommand(ctx, "rpm", "-e", pkgName)
		return output, true, err
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// isRpmInstalled checks if an rpm package is installed.
func (e *Executor) isRpmInstalled(pkgName string) bool {
	cmd := exec.Command("rpm", "-q", pkgName)
	return cmd.Run() == nil
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

	// Build environment
	var envVars []string
	if len(params.Environment) > 0 {
		envVars = os.Environ()
		for k, v := range params.Environment {
			envVars = append(envVars, fmt.Sprintf("%s=%s", k, v))
		}
	}

	// Use streaming execution if callback provided, otherwise fall back to standard
	if callback != nil {
		return runCommandStreaming(ctx, name, args, envVars, params.WorkingDirectory, callback)
	}

	// Non-streaming fallback
	var cmd *exec.Cmd
	if params.RunAsRoot {
		cmd = exec.CommandContext(ctx, "sudo", "-n", interpreter, "-c", params.Script)
	} else {
		cmd = exec.CommandContext(ctx, interpreter, "-c", params.Script)
	}

	if params.WorkingDirectory != "" {
		cmd.Dir = params.WorkingDirectory
	}

	if len(params.Environment) > 0 {
		cmd.Env = envVars
	}

	return runCommand(cmd)
}

func (e *Executor) executeSystemd(ctx context.Context, params *pb.SystemdParams) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("systemd params required")
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
			cmd := exec.CommandContext(ctx, "sudo", "-n", "tee", unitPath)
			cmd.Stdin = strings.NewReader(params.UnitContent)
			if cmdOutput, err := runCommand(cmd); err != nil {
				return cmdOutput, false, fmt.Errorf("write unit file: %s", formatCmdError(err, cmdOutput))
			}
			output.WriteString(fmt.Sprintf("updated unit file %s\n", unitPath))
			changed = true

			// Reload systemd
			if _, err := runSudoCommand(ctx, "systemctl", "daemon-reload"); err != nil {
				return nil, changed, fmt.Errorf("daemon-reload failed")
			}
			output.WriteString("reloaded systemd daemon\n")
		}
	}

	// Check and update enable/disable status
	isEnabled := e.isUnitEnabled(params.UnitName)
	if params.Enable && !isEnabled {
		if _, err := runSudoCommand(ctx, "systemctl", "enable", params.UnitName); err != nil {
			return nil, changed, fmt.Errorf("enable: %v", err)
		}
		output.WriteString("enabled unit\n")
		changed = true
	} else if !params.Enable && isEnabled {
		if _, err := runSudoCommand(ctx, "systemctl", "disable", params.UnitName); err != nil {
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
			if _, err := runSudoCommand(ctx, "systemctl", "start", params.UnitName); err != nil {
				return nil, changed, fmt.Errorf("start: %v", err)
			}
			output.WriteString("started unit\n")
			changed = true
		} else {
			output.WriteString("unit is already running\n")
		}
	case pb.SystemdUnitState_SYSTEMD_UNIT_STATE_STOPPED:
		if isActive {
			if _, err := runSudoCommand(ctx, "systemctl", "stop", params.UnitName); err != nil {
				return nil, changed, fmt.Errorf("stop: %v", err)
			}
			output.WriteString("stopped unit\n")
			changed = true
		} else {
			output.WriteString("unit is already stopped\n")
		}
	case pb.SystemdUnitState_SYSTEMD_UNIT_STATE_RESTARTED:
		// Restart always runs (not idempotent by design)
		if _, err := runSudoCommand(ctx, "systemctl", "restart", params.UnitName); err != nil {
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

// isUnitEnabled checks if a systemd unit is enabled.
func (e *Executor) isUnitEnabled(unitName string) bool {
	cmd := exec.Command("systemctl", "is-enabled", unitName)
	out, _ := cmd.Output()
	status := strings.TrimSpace(string(out))
	return status == "enabled" || status == "enabled-runtime"
}

// isUnitActive checks if a systemd unit is currently active (running).
func (e *Executor) isUnitActive(unitName string) bool {
	cmd := exec.Command("systemctl", "is-active", unitName)
	out, _ := cmd.Output()
	return strings.TrimSpace(string(out)) == "active"
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
		if _, err := runSudoCommand(ctx, "mkdir", "-p", filepath.Dir(resolvedPath)); err != nil {
			return nil, false, fmt.Errorf("create directories: %w", err)
		}

		// Atomic write: write to temp file, then move into place.
		// This avoids TOCTOU race conditions where the file could be
		// swapped between write and chmod/chown operations.
		tmpPath := resolvedPath + ".pm-tmp"

		// Write content to temp file using sudo tee
		cmd := exec.CommandContext(ctx, "sudo", "-n", "tee", tmpPath)
		cmd.Stdin = strings.NewReader(params.Content)
		if _, err := runCommand(cmd); err != nil {
			runSudoCommand(ctx, "rm", "-f", tmpPath) // cleanup
			return nil, false, fmt.Errorf("write file: %w", err)
		}

		// Set mode on temp file before moving
		if params.Mode != "" {
			if _, err := runSudoCommand(ctx, "chmod", params.Mode, tmpPath); err != nil {
				runSudoCommand(ctx, "rm", "-f", tmpPath) // cleanup
				return nil, false, fmt.Errorf("chmod: %w", err)
			}
		}

		// Set owner on temp file before moving
		if params.Owner != "" || params.Group != "" {
			ownership := params.Owner
			if params.Group != "" {
				ownership += ":" + params.Group
			}
			if _, err := runSudoCommand(ctx, "chown", ownership, tmpPath); err != nil {
				runSudoCommand(ctx, "rm", "-f", tmpPath) // cleanup
				return nil, false, fmt.Errorf("chown: %w", err)
			}
		}

		// Atomic move into place (same filesystem)
		if _, err := runSudoCommand(ctx, "mv", "-f", tmpPath, resolvedPath); err != nil {
			runSudoCommand(ctx, "rm", "-f", tmpPath) // cleanup
			return nil, false, fmt.Errorf("move file into place: %w", err)
		}

		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("created %s", resolvedPath),
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

		if _, err := runSudoCommand(ctx, "rm", "-f", resolvedPath); err != nil {
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

	// Check content by comparing hashes
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	currentHash := sha256.Sum256(content)
	desiredHash := sha256.Sum256([]byte(params.Content))
	if currentHash != desiredHash {
		return false
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

	// Check owner/group if specified (requires stat syscall)
	if params.Owner != "" || params.Group != "" {
		// Use stat command to get current owner:group
		cmd := exec.Command("stat", "-c", "%U:%G", path)
		out, err := cmd.Output()
		if err != nil {
			return false
		}
		currentOwnership := strings.TrimSpace(string(out))
		desiredOwnership := params.Owner
		if params.Group != "" {
			desiredOwnership += ":" + params.Group
		} else {
			desiredOwnership += ":"
		}
		// Handle case where only owner is specified
		if params.Group == "" {
			parts := strings.Split(currentOwnership, ":")
			if len(parts) > 0 && parts[0] != params.Owner {
				return false
			}
		} else if currentOwnership != desiredOwnership {
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

		// Create directory (with -p flag if recursive is true, which is default)
		mkdirArgs := []string{}
		if params.Recursive {
			mkdirArgs = append(mkdirArgs, "-p")
		}
		mkdirArgs = append(mkdirArgs, cleanPath)

		if _, err := runSudoCommand(ctx, "mkdir", mkdirArgs...); err != nil {
			return nil, false, fmt.Errorf("create directory: %w", err)
		}

		// Set mode using sudo chmod
		if params.Mode != "" {
			if _, err := runSudoCommand(ctx, "chmod", params.Mode, cleanPath); err != nil {
				return nil, false, fmt.Errorf("chmod: %w", err)
			}
		}

		// Set owner using sudo chown
		if params.Owner != "" || params.Group != "" {
			ownership := params.Owner
			if params.Group != "" {
				ownership += ":" + params.Group
			}
			if _, err := runSudoCommand(ctx, "chown", ownership, cleanPath); err != nil {
				return nil, false, fmt.Errorf("chown: %w", err)
			}
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
		if _, err := runSudoCommand(ctx, "rm", "-rf", cleanPath); err != nil {
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
		cmd := exec.Command("stat", "-c", "%U:%G", path)
		out, err := cmd.Output()
		if err != nil {
			return false
		}
		currentOwnership := strings.TrimSpace(string(out))
		desiredOwnership := params.Owner
		if params.Group != "" {
			desiredOwnership += ":" + params.Group
		} else {
			desiredOwnership += ":"
		}
		if params.Group == "" {
			parts := strings.Split(currentOwnership, ":")
			if len(parts) > 0 && parts[0] != params.Owner {
				return false
			}
		} else if currentOwnership != desiredOwnership {
			return false
		}
	}

	return true
}

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

	file, err := os.Create(dest)
	if err != nil {
		return err
	}
	defer file.Close()

	if expectedChecksum != "" {
		hasher := sha256.New()
		reader := io.TeeReader(resp.Body, hasher)
		if _, err := io.Copy(file, reader); err != nil {
			return err
		}
		actual := hex.EncodeToString(hasher.Sum(nil))
		if actual != expectedChecksum {
			os.Remove(dest)
			return fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actual)
		}
	} else {
		if _, err := io.Copy(file, resp.Body); err != nil {
			return err
		}
	}

	return nil
}

func runCommand(c *exec.Cmd) (*pb.CommandOutput, error) {
	var stdoutBuf, stderrBuf bytes.Buffer
	stdout := &limitWriter{buf: &stdoutBuf, limit: maxOutputBytes}
	stderr := &limitWriter{buf: &stderrBuf, limit: maxOutputBytes}
	c.Stdout = stdout
	c.Stderr = stderr

	err := c.Run()

	stdoutStr := stdoutBuf.String()
	stderrStr := stderrBuf.String()
	if stdout.n > stdout.limit {
		stdoutStr += "\n[output truncated]"
	}
	if stderr.n > stderr.limit {
		stderrStr += "\n[output truncated]"
	}

	output := &pb.CommandOutput{
		Stdout: stdoutStr,
		Stderr: stderrStr,
	}

	if c.ProcessState != nil {
		output.ExitCode = int32(c.ProcessState.ExitCode())
	}

	return output, err
}

// runCommandStreaming executes a command with real-time output streaming using go-cmd/cmd.
// The callback is called for each line of output as it's produced.
func runCommandStreaming(ctx context.Context, name string, args []string, envVars []string, dir string, callback OutputCallback) (*pb.CommandOutput, error) {
	// Create command with streaming enabled
	c := cmd.NewCmdOptions(cmd.Options{
		Buffered:  false, // Don't buffer, stream instead
		Streaming: true,  // Enable streaming
	}, name, args...)

	if dir != "" {
		c.Dir = dir
	}
	if len(envVars) > 0 {
		c.Env = envVars
	}

	// Start the command
	statusChan := c.Start()

	var stdoutSeq, stderrSeq int64
	var stdoutBuf, stderrBuf strings.Builder
	var stdoutBytes, stderrBytes int64

	// Create done channel for cleanup
	done := make(chan struct{})

	// Stream output in a goroutine
	go func() {
		defer close(done)
		for {
			select {
			case line, ok := <-c.Stdout:
				if !ok {
					// Channel closed, drain stderr and exit
					for line := range c.Stderr {
						lineBytes := int64(len(line) + 1)
						if atomic.AddInt64(&stderrBytes, lineBytes) <= int64(maxOutputBytes) {
							stderrBuf.WriteString(line + "\n")
						}
						if callback != nil {
							callback(2, line+"\n", atomic.AddInt64(&stderrSeq, 1)-1)
						}
					}
					return
				}
				lineBytes := int64(len(line) + 1)
				if atomic.AddInt64(&stdoutBytes, lineBytes) <= int64(maxOutputBytes) {
					stdoutBuf.WriteString(line + "\n")
				}
				if callback != nil {
					callback(1, line+"\n", atomic.AddInt64(&stdoutSeq, 1)-1)
				}
			case line, ok := <-c.Stderr:
				if !ok {
					// Channel closed, drain stdout and exit
					for line := range c.Stdout {
						lineBytes := int64(len(line) + 1)
						if atomic.AddInt64(&stdoutBytes, lineBytes) <= int64(maxOutputBytes) {
							stdoutBuf.WriteString(line + "\n")
						}
						if callback != nil {
							callback(1, line+"\n", atomic.AddInt64(&stdoutSeq, 1)-1)
						}
					}
					return
				}
				lineBytes := int64(len(line) + 1)
				if atomic.AddInt64(&stderrBytes, lineBytes) <= int64(maxOutputBytes) {
					stderrBuf.WriteString(line + "\n")
				}
				if callback != nil {
					callback(2, line+"\n", atomic.AddInt64(&stderrSeq, 1)-1)
				}
			case <-ctx.Done():
				c.Stop()
				return
			}
		}
	}()

	// Wait for command to complete
	status := <-statusChan

	// Wait for streaming goroutine to finish
	<-done

	stdoutStr := stdoutBuf.String()
	stderrStr := stderrBuf.String()
	if atomic.LoadInt64(&stdoutBytes) > int64(maxOutputBytes) {
		stdoutStr += "\n[output truncated]"
	}
	if atomic.LoadInt64(&stderrBytes) > int64(maxOutputBytes) {
		stderrStr += "\n[output truncated]"
	}

	return &pb.CommandOutput{
		Stdout:   stdoutStr,
		Stderr:   stderrStr,
		ExitCode: int32(status.Exit),
	}, status.Error
}

// formatCmdError formats a command error with stderr output for better diagnostics.
func formatCmdError(err error, output *pb.CommandOutput) string {
	if output != nil && output.Stderr != "" {
		return fmt.Sprintf("%v: %s", err, strings.TrimSpace(output.Stderr))
	}
	return err.Error()
}

// runSudoCommand wraps a command with sudo for privileged operations.
// Uses -n (non-interactive) to avoid password prompts that would hang.
func runSudoCommand(ctx context.Context, name string, args ...string) (*pb.CommandOutput, error) {
	// Resolve to absolute path so the command matches sudoers rules,
	// which require full paths (e.g., /usr/bin/cp instead of cp).
	absPath, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("command not found: %s", name)
	}
	sudoArgs := append([]string{"-n", absPath}, args...)
	cmd := exec.CommandContext(ctx, "sudo", sudoArgs...)
	return runCommand(cmd)
}

// repairFilesystem attempts to fix read-only filesystem issues.
// This can happen when the kernel remounts the filesystem as read-only due to errors.
// Returns true if the filesystem is writable, false if repair failed.
func (e *Executor) repairFilesystem(ctx context.Context) bool {
	// Check if root filesystem is mounted read-only
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		e.logger.Warn("could not read /proc/mounts", "error", err)
		return true // Assume writable, let operations fail naturally
	}

	// Look for root filesystem mount options
	for _, line := range strings.Split(string(mounts), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mountPoint := fields[1]
		options := fields[3]

		// Check root filesystem
		if mountPoint == "/" {
			// Check if mounted read-only
			optionList := strings.Split(options, ",")
			isReadOnly := false
			for _, opt := range optionList {
				if opt == "ro" {
					isReadOnly = true
					break
				}
			}

			if !isReadOnly {
				return true // Filesystem is already read-write
			}

			e.logger.Warn("root filesystem is mounted read-only, attempting remount")

			// Try to remount as read-write
			output, err := runSudoCommand(ctx, "mount", "-o", "remount,rw", "/")
			if err != nil {
				e.logger.Error("failed to remount filesystem as read-write",
					"error", err,
					"output", output,
				)

				// Check if there are filesystem errors that need fsck
				e.logger.Error("filesystem may have errors - system likely needs reboot and fsck",
					"hint", "try: sudo fsck -y / (requires reboot to single-user mode)",
				)
				return false
			}

			e.logger.Info("successfully remounted root filesystem as read-write")
			return true
		}
	}

	return true // No issues detected
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
	// Determine preferred apt command (apt if available, apt-get as fallback)
	aptCmd := "apt-get"
	if _, err := exec.LookPath("apt"); err == nil {
		aptCmd = "apt"
	}

	// Remove stale lock files that may be left from interrupted operations
	runSudoCommand(ctx, "rm", "-f", "/var/lib/dpkg/lock-frontend")
	runSudoCommand(ctx, "rm", "-f", "/var/lib/dpkg/lock")
	runSudoCommand(ctx, "rm", "-f", "/var/lib/apt/lists/lock")
	runSudoCommand(ctx, "rm", "-f", "/var/cache/apt/archives/lock")

	// Fix any interrupted dpkg operations
	// This handles "dpkg was interrupted, you must manually run 'dpkg --configure -a'"
	runSudoCommand(ctx, "dpkg", "--configure", "-a")

	// Update package lists to get latest dependency info
	// This is crucial for resolving dependency version mismatches
	runSudoCommand(ctx, aptCmd, "update")

	// Fix broken dependencies and install missing ones
	// This handles "unmet dependencies" and "held broken packages" issues
	runSudoCommand(ctx, aptCmd, "--fix-broken", "install", "-y")

	// Remove unused packages that might be causing conflicts
	runSudoCommand(ctx, aptCmd, "autoremove", "-y")
}

// repairDnf fixes common dnf/rpm issues:
// - Incomplete transactions (dnf-automatic, interrupted updates)
// - Corrupted rpm database
// - Duplicate packages
func (e *Executor) repairDnf(ctx context.Context) {
	// Complete any interrupted transactions
	// This is similar to "dnf-automatic" leaving things half-done
	runSudoCommand(ctx, "dnf", "-y", "history", "redo", "last")

	// Clean up any duplicate packages
	runSudoCommand(ctx, "dnf", "-y", "remove", "--duplicates")

	// Rebuild rpm database if corrupted
	// First try to verify, if that fails, rebuild
	if output, err := runSudoCommand(ctx, "rpm", "--verifydb"); err != nil || output.ExitCode != 0 {
		runSudoCommand(ctx, "rpm", "--rebuilddb")
	}
}

// repairPacman fixes common pacman issues:
// - Stale lock files from interrupted operations
// - Corrupted package database
// - Keyring issues
func (e *Executor) repairPacman(ctx context.Context) {
	// Remove stale lock file if it exists
	// This handles "unable to lock database" errors from interrupted operations
	runSudoCommand(ctx, "rm", "-f", "/var/lib/pacman/db.lck")

	// Refresh package database to fix potential corruption
	// Using -Syy to force refresh even if recently updated
	runSudoCommand(ctx, "pacman", "-Syy", "--noconfirm")

	// Reinitialize keyring if there are signature issues
	// This fixes "signature is unknown trust" errors
	runSudoCommand(ctx, "pacman-key", "--init")
	runSudoCommand(ctx, "pacman-key", "--populate", "archlinux")
}

// repairZypper fixes common zypper/rpm issues:
// - Stale lock files
// - Corrupted rpm database
// - Repository metadata issues
// - Broken dependencies
func (e *Executor) repairZypper(ctx context.Context) {
	// Remove stale lock files
	runSudoCommand(ctx, "rm", "-f", "/var/run/zypp.pid")

	// Clean repository metadata cache to fix stale metadata issues
	runSudoCommand(ctx, "zypper", "--non-interactive", "clean", "--all")

	// Refresh repositories to get fresh metadata
	runSudoCommand(ctx, "zypper", "--non-interactive", "refresh")

	// Verify and fix dependency issues
	runSudoCommand(ctx, "zypper", "--non-interactive", "verify", "--recommends")

	// Rebuild rpm database if corrupted
	if output, err := runSudoCommand(ctx, "rpm", "--verifydb"); err != nil || output.ExitCode != 0 {
		runSudoCommand(ctx, "rpm", "--rebuilddb")
	}
}

// repairFlatpak fixes common Flatpak issues:
// - Stale metadata cache
// - Broken remotes
func (e *Executor) repairFlatpak(ctx context.Context) {
	// Repair any broken installations (removes partial/orphaned refs)
	runSudoCommand(ctx, "flatpak", "repair", "--system")

	// Update appstream metadata to fix stale cache issues
	runSudoCommand(ctx, "flatpak", "update", "--appstream", "-y", "--noninteractive", "--system")
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
			if output, err := runSudoCommand(ctx, "apt-get", "autoremove", "-y"); err == nil {
				allOutput.WriteString(output.Stdout)
			} else if output != nil {
				allOutput.WriteString(output.Stderr)
			}
		} else if pkg.IsDnf() {
			if output, err := runSudoCommand(ctx, "dnf", "-y", "autoremove"); err == nil {
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
			allOutput.WriteString("Scheduling reboot in 1 minute...\n")
			runSudoCommand(ctx, "shutdown", "-r", "+1", "System update requires reboot")
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
	var args []string

	if params != nil && params.SecurityOnly {
		// Use unattended-upgrades for security-only updates if available
		if _, err := exec.LookPath("unattended-upgrade"); err == nil {
			cmdOutput, err := runSudoCommand(ctx, "unattended-upgrade", "-v")
			if cmdOutput != nil {
				output.WriteString(cmdOutput.Stdout)
				output.WriteString(cmdOutput.Stderr)
			}
			return err
		}
		// Fallback: try apt-get with security pocket only
		// This is distribution-specific and may not work everywhere
		output.WriteString("Note: security-only updates requested but unattended-upgrade not available\n")
	}

	// Standard upgrade
	args = []string{"upgrade", "-y"}
	cmdOutput, err := runSudoCommand(ctx, "apt-get", args...)
	if cmdOutput != nil {
		output.WriteString(cmdOutput.Stdout)
		output.WriteString(cmdOutput.Stderr)
	}

	// Also run dist-upgrade for held-back packages (still respects holds)
	output.WriteString("\n=== Dist-Upgrade ===\n")
	distOutput, _ := runSudoCommand(ctx, "apt-get", "dist-upgrade", "-y")
	if distOutput != nil {
		output.WriteString(distOutput.Stdout)
		output.WriteString(distOutput.Stderr)
	}

	return err
}

// executeDnfUpgrade performs dnf-specific upgrade.
func (e *Executor) executeDnfUpgrade(ctx context.Context, params *pb.UpdateParams, output *strings.Builder) error {
	var args []string

	if params != nil && params.SecurityOnly {
		args = []string{"-y", "upgrade", "--security"}
	} else {
		args = []string{"-y", "upgrade"}
	}

	cmdOutput, err := runSudoCommand(ctx, "dnf", args...)
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
		cmd := exec.Command("needs-restarting", "-r")
		if err := cmd.Run(); err != nil {
			// Exit code 1 means reboot required
			if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() == 1 {
				return true
			}
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
		output, err := e.executeAptRepository(ctx, params.Name, params.Apt, state)
		return output, err == nil, err

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
						runSudoCommand(ctx, "rm", "-f", keyPath)
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
					runSudoCommand(ctx, "rm", "-f", keyPath)
				}
			}
		}

		// Remove the repository file
		runSudoCommand(ctx, "rm", "-f", filePath)
	}
}

// executeAptRepository configures an APT repository.
// This function is idempotent - it checks if files already exist with correct content
// and only updates them if they differ.
func (e *Executor) executeAptRepository(ctx context.Context, name string, repo *pb.AptRepository, state pb.DesiredState) (*pb.CommandOutput, error) {
	var output strings.Builder
	repoFile := fmt.Sprintf("/etc/apt/sources.list.d/%s.sources", name)
	keyFile := fmt.Sprintf("/etc/apt/keyrings/%s.gpg", name)

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		// Remove repository file
		if _, err := runSudoCommand(ctx, "rm", "-f", repoFile); err != nil {
			return nil, fmt.Errorf("failed to remove repo file: %w", err)
		}
		// Also try to remove legacy .list format
		legacyFile := fmt.Sprintf("/etc/apt/sources.list.d/%s.list", name)
		runSudoCommand(ctx, "rm", "-f", legacyFile)
		// Remove GPG key
		runSudoCommand(ctx, "rm", "-f", keyFile)
		output.WriteString(fmt.Sprintf("removed repository: %s\n", name))
		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil

	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// First, scan for and remove any existing repository configs that use the same URL
		// This prevents "conflicting values set for option Signed-By" errors when the same
		// repository was previously configured under a different name or with different keys
		// We skip our own repo file and key file to allow the comparison logic to work
		e.cleanupConflictingAptRepos(ctx, repo.Url, repoFile, keyFile, &output)

		// Clean up any existing repository configuration to ensure clean state
		// This handles cases where:
		// - A legacy .list file exists that should be replaced with .sources format
		// - The repository was previously configured with different settings
		// - Stale GPG keys from previous configurations
		legacyFile := fmt.Sprintf("/etc/apt/sources.list.d/%s.list", name)
		if _, err := os.Stat(legacyFile); err == nil {
			output.WriteString(fmt.Sprintf("removing legacy repository file: %s\n", legacyFile))
			runSudoCommand(ctx, "rm", "-f", legacyFile)
		}
		// Also check for old .sources file with potentially different config
		if _, err := os.Stat(repoFile); err == nil {
			output.WriteString(fmt.Sprintf("replacing existing repository: %s\n", name))
		}
		// Note: We don't delete the existing GPG key here - updateGpgKeyIfNeeded
		// will compare the existing key with the new one and only update if different.
		// Also check for keys in the legacy trusted.gpg.d location
		legacyKeyFile := fmt.Sprintf("/etc/apt/trusted.gpg.d/%s.gpg", name)
		if _, err := os.Stat(legacyKeyFile); err == nil {
			output.WriteString(fmt.Sprintf("removing legacy GPG key: %s\n", legacyKeyFile))
			runSudoCommand(ctx, "rm", "-f", legacyKeyFile)
		}

		// Ensure keyrings directory exists
		if _, err := runSudoCommand(ctx, "mkdir", "-p", "/etc/apt/keyrings"); err != nil {
			return nil, fmt.Errorf("failed to create keyrings directory: %w", err)
		}

		// Import GPG key if provided
		// We download/process to a temp file first and only update if content differs
		if repo.GpgKeyUrl != "" || repo.GpgKey != "" {
			keyUpdated, keyErr := e.updateGpgKeyIfNeeded(ctx, keyFile, repo.GpgKeyUrl, repo.GpgKey, &output)
			if keyErr != nil {
				return &pb.CommandOutput{ExitCode: 1, Stdout: output.String(), Stderr: keyErr.Error()}, keyErr
			}
			if keyUpdated {
				output.WriteString("GPG key updated\n")
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

		// Write the sources file
		cmd := exec.CommandContext(ctx, "sudo", "-n", "tee", repoFile)
		cmd.Stdin = strings.NewReader(content.String())
		if _, err := runCommand(cmd); err != nil {
			return nil, fmt.Errorf("failed to write repo file: %w", err)
		}

		output.WriteString(fmt.Sprintf("configured repository: %s\n", name))

		// Update package index
		updateOutput, _ := runSudoCommand(ctx, "apt-get", "update")
		if updateOutput != nil {
			output.WriteString(updateOutput.Stdout)
		}

		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil

	default:
		return nil, fmt.Errorf("unknown desired state: %v", state)
	}
}

// updateGpgKeyIfNeeded downloads/processes a GPG key and only updates the target file if content differs.
// Returns true if the key was updated, false if unchanged.
func (e *Executor) updateGpgKeyIfNeeded(ctx context.Context, keyFile, keyUrl, keyContent string, output *strings.Builder) (bool, error) {
	// Validate URL scheme to prevent file:// or other protocol abuse
	if keyUrl != "" {
		if !strings.HasPrefix(keyUrl, "https://") && !strings.HasPrefix(keyUrl, "http://") {
			return false, fmt.Errorf("GPG key URL must use http:// or https:// scheme, got: %s", keyUrl)
		}
	}

	// Create a temp file for the new key
	tempFile, err := os.CreateTemp("", "gpgkey-*.gpg")
	if err != nil {
		return false, fmt.Errorf("failed to create temp file: %w", err)
	}
	tempPath := tempFile.Name()
	tempFile.Close()
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
	gpgCmd := exec.CommandContext(ctx, "gpg", "--yes", "--dearmor", "-o", tempPath)
	gpgCmd.Stdin = bytes.NewReader(rawKey)
	if _, err := runCommand(gpgCmd); err != nil {
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
		cmdOutput, sudoErr := runSudoCommand(ctx, "cat", keyFile)
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
	_, err = runSudoCommand(ctx, "cp", tempPath, keyFile)
	if err != nil {
		return false, fmt.Errorf("failed to install GPG key: %w", err)
	}

	// Set proper permissions
	runSudoCommand(ctx, "chmod", "644", keyFile)

	return true, nil
}

// executeDnfRepository configures a DNF/YUM repository.
func (e *Executor) executeDnfRepository(ctx context.Context, name string, repo *pb.DnfRepository, state pb.DesiredState) (*pb.CommandOutput, error) {
	var output strings.Builder
	repoFile := fmt.Sprintf("/etc/yum.repos.d/%s.repo", name)

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		if _, err := runSudoCommand(ctx, "rm", "-f", repoFile); err != nil {
			return nil, fmt.Errorf("failed to remove repo file: %w", err)
		}
		output.WriteString(fmt.Sprintf("removed repository: %s\n", name))
		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil

	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Clean up any existing repository configuration to ensure clean state
		// This handles cases where the repository was previously configured with different settings
		if _, err := os.Stat(repoFile); err == nil {
			output.WriteString(fmt.Sprintf("replacing existing repository: %s\n", name))
			runSudoCommand(ctx, "rm", "-f", repoFile)
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
		cmd := exec.CommandContext(ctx, "sudo", "-n", "tee", repoFile)
		cmd.Stdin = strings.NewReader(content.String())
		if _, err := runCommand(cmd); err != nil {
			return nil, fmt.Errorf("failed to write repo file: %w", err)
		}

		output.WriteString(fmt.Sprintf("configured repository: %s\n", name))

		// Import GPG key if provided
		// rpm --import is idempotent - re-importing an existing key is a no-op
		if repo.Gpgkey != "" {
			keyOutput, _ := runSudoCommand(ctx, "rpm", "--import", repo.Gpgkey)
			if keyOutput != nil && keyOutput.Stdout != "" {
				output.WriteString(keyOutput.Stdout)
			}
		}

		// Refresh metadata (use -y for non-interactive mode)
		refreshOutput, _ := runSudoCommand(ctx, "dnf", "-y", "makecache", "--repo", name)
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
		teeCmd := exec.CommandContext(ctx, "sudo", "-n", "tee", confFile)
		teeCmd.Stdin = strings.NewReader(newConf)
		if _, err := runCommand(teeCmd); err != nil {
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

		teeCmd := exec.CommandContext(ctx, "sudo", "-n", "tee", confFile)
		teeCmd.Stdin = strings.NewReader(newConf)
		if _, err := runCommand(teeCmd); err != nil {
			return nil, fmt.Errorf("failed to write pacman.conf: %w", err)
		}

		output.WriteString(fmt.Sprintf("configured repository: %s\n", name))

		// Sync database (--noconfirm for non-interactive mode)
		syncOutput, _ := runSudoCommand(ctx, "pacman", "-Sy", "--noconfirm")
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
		cmdOutput, err := runSudoCommand(ctx, "zypper", "--non-interactive", "removerepo", name)
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
		runSudoCommand(ctx, "zypper", "--non-interactive", "removerepo", name)

		args = append(args, repo.Url, name)
		cmdOutput, err := runSudoCommand(ctx, "zypper", args...)
		if err != nil {
			if cmdOutput != nil {
				output.WriteString(cmdOutput.Stderr)
			}
			return nil, fmt.Errorf("failed to add repository: %w", err)
		}

		output.WriteString(fmt.Sprintf("configured repository: %s\n", name))

		// Set description if provided
		if repo.Description != "" {
			runSudoCommand(ctx, "zypper", "--non-interactive", "modifyrepo", "--name", repo.Description, name)
		}

		// Enable/disable
		if repo.Enabled {
			runSudoCommand(ctx, "zypper", "--non-interactive", "modifyrepo", "--enable", name)
		} else {
			runSudoCommand(ctx, "zypper", "--non-interactive", "modifyrepo", "--disable", name)
		}

		// Set autorefresh
		if repo.Autorefresh {
			runSudoCommand(ctx, "zypper", "--non-interactive", "modifyrepo", "--refresh", name)
		}

		// Import GPG key if provided
		if repo.Gpgkey != "" {
			keyOutput, _ := runSudoCommand(ctx, "rpm", "--import", repo.Gpgkey)
			if keyOutput != nil && keyOutput.Stdout != "" {
				output.WriteString(keyOutput.Stdout)
			}
		}

		// Refresh repository
		refreshOutput, _ := runSudoCommand(ctx, "zypper", "--non-interactive", "refresh", name)
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
	output, err := runSudoCommand(ctx, "shutdown", "-r", "+5", "Power Manage: scheduled reboot")
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
func (e *Executor) executeUser(ctx context.Context, params *pb.UserParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("user params required")
	}

	if params.Username == "" {
		return nil, false, fmt.Errorf("username is required")
	}

	// Validate username format (prevent injection)
	if !isValidUsername(params.Username) {
		return nil, false, fmt.Errorf("invalid username: must be 1-32 alphanumeric characters, starting with a letter")
	}

	// Repair filesystem if mounted read-only
	if !e.repairFilesystem(ctx) {
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   "filesystem is read-only and could not be remounted - system may need reboot and fsck",
		}, false, fmt.Errorf("filesystem is read-only")
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		return e.createOrUpdateUser(ctx, params)
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		return e.removeUser(ctx, params.Username)
	default:
		return nil, false, fmt.Errorf("unknown desired state: %v", state)
	}
}

// isValidUsername checks if a username is valid and safe.
func isValidUsername(username string) bool {
	if len(username) == 0 || len(username) > 32 {
		return false
	}
	// Must start with a lowercase letter
	if username[0] < 'a' || username[0] > 'z' {
		return false
	}
	// Rest can be lowercase letters, digits, underscores, or hyphens
	for _, c := range username[1:] {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// userExists checks if a user already exists on the system.
func userExists(username string) bool {
	cmd := exec.Command("id", username)
	return cmd.Run() == nil
}

// userInfo holds the current state of a user account.
type userInfo struct {
	uid      int
	gid      int
	comment  string
	homeDir  string
	shell    string
	groups   []string
	locked   bool
	sshKeys  []string
}

// getUserInfo retrieves the current state of a user from the system.
func getUserInfo(username string) (*userInfo, error) {
	// Get passwd entry: username:x:uid:gid:comment:home:shell
	cmd := exec.Command("getent", "passwd", username)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	fields := strings.Split(strings.TrimSpace(string(out)), ":")
	if len(fields) < 7 {
		return nil, fmt.Errorf("invalid passwd entry")
	}

	uid, _ := strconv.Atoi(fields[2])
	gid, _ := strconv.Atoi(fields[3])

	info := &userInfo{
		uid:     uid,
		gid:     gid,
		comment: fields[4],
		homeDir: fields[5],
		shell:   fields[6],
	}

	// Get supplementary groups
	cmd = exec.Command("id", "-Gn", username)
	if out, err := cmd.Output(); err == nil {
		groups := strings.Fields(strings.TrimSpace(string(out)))
		// Filter out the primary group (first group returned by id -Gn is usually primary)
		// We need to get primary group name separately
		cmd = exec.Command("id", "-gn", username)
		if primaryOut, err := cmd.Output(); err == nil {
			primaryGroup := strings.TrimSpace(string(primaryOut))
			for _, g := range groups {
				if g != primaryGroup {
					info.groups = append(info.groups, g)
				}
			}
		}
	}

	// Check if account is locked (password field starts with ! or *)
	cmd = exec.Command("sudo", "-n", "getent", "shadow", username)
	if out, err := cmd.Output(); err == nil {
		shadowFields := strings.Split(string(out), ":")
		if len(shadowFields) >= 2 {
			passField := shadowFields[1]
			info.locked = strings.HasPrefix(passField, "!") || strings.HasPrefix(passField, "*")
		}
	}

	// Read SSH authorized keys if they exist
	authKeysPath := filepath.Join(info.homeDir, ".ssh", "authorized_keys")
	if content, err := os.ReadFile(authKeysPath); err == nil {
		lines := strings.Split(strings.TrimSpace(string(content)), "\n")
		for _, line := range lines {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				info.sshKeys = append(info.sshKeys, line)
			}
		}
	}

	return info, nil
}

// sshKeysEqual compares two SSH key slices for equality.
func sshKeysEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	// Create maps for comparison (order doesn't matter)
	aMap := make(map[string]bool)
	for _, key := range a {
		aMap[strings.TrimSpace(key)] = true
	}
	for _, key := range b {
		if !aMap[strings.TrimSpace(key)] {
			return false
		}
	}
	return true
}

// groupsContains checks if all desired groups are present in current groups.
func groupsContains(current, desired []string) bool {
	currentMap := make(map[string]bool)
	for _, g := range current {
		currentMap[g] = true
	}
	for _, g := range desired {
		if !currentMap[g] {
			return false
		}
	}
	return true
}

// createOrUpdateUser creates a new user or updates an existing one.
// Returns the command output, whether changes were made, and any error.
func (e *Executor) createOrUpdateUser(ctx context.Context, params *pb.UserParams) (*pb.CommandOutput, bool, error) {
	var output strings.Builder
	exists := userExists(params.Username)

	if exists {
		// Update existing user
		return e.updateUser(ctx, params, &output)
	}

	// Create new user - always a change
	cmdOutput, err := e.createUser(ctx, params, &output)
	return cmdOutput, true, err
}

// createUser creates a new user account.
func (e *Executor) createUser(ctx context.Context, params *pb.UserParams, output *strings.Builder) (*pb.CommandOutput, error) {
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
		e.ensureGroupExists(ctx, params.PrimaryGroup)
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

	// Additional groups
	if len(params.Groups) > 0 {
		// Validate group names
		for _, g := range params.Groups {
			if !isValidUsername(g) {
				return nil, fmt.Errorf("invalid group name: %s", g)
			}
		}
		args = append(args, "-G", strings.Join(params.Groups, ","))
	}

	// Add username as last argument
	args = append(args, params.Username)

	// Create the user
	cmdOutput, err := runSudoCommand(ctx, "useradd", args...)
	if err != nil {
		if cmdOutput != nil {
			output.WriteString(cmdOutput.Stderr)
		}
		return &pb.CommandOutput{ExitCode: 1, Stderr: output.String()}, fmt.Errorf("failed to create user: %w", err)
	}
	output.WriteString(fmt.Sprintf("created user: %s\n", params.Username))

	// If home directory already existed, fix ownership
	if homeExists && createHome {
		if chownOutput, chownErr := runSudoCommand(ctx, "chown", "-R", params.Username+":"+params.Username, homeDir); chownErr != nil {
			output.WriteString(fmt.Sprintf("warning: failed to fix home directory ownership: %v\n", chownErr))
			if chownOutput != nil {
				output.WriteString(chownOutput.Stderr)
			}
		} else {
			output.WriteString(fmt.Sprintf("fixed ownership of existing home directory: %s\n", homeDir))
		}
	}

	// Handle disabled state (lock the account)
	if params.Disabled {
		if lockOutput, lockErr := runSudoCommand(ctx, "usermod", "-L", params.Username); lockErr != nil {
			output.WriteString(fmt.Sprintf("warning: failed to lock user account: %v\n", lockErr))
			if lockOutput != nil {
				output.WriteString(lockOutput.Stderr)
			}
		} else {
			output.WriteString("account locked (disabled)\n")
		}
	}

	// Setup SSH authorized keys if provided
	if len(params.SshAuthorizedKeys) > 0 {
		if err := e.setupSSHKeys(ctx, params, output); err != nil {
			output.WriteString(fmt.Sprintf("warning: failed to setup SSH keys: %v\n", err))
		}
	}

	return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil
}

// updateUser modifies an existing user account.
func (e *Executor) updateUser(ctx context.Context, params *pb.UserParams, output *strings.Builder) (*pb.CommandOutput, bool, error) {
	// Get current user state
	currentInfo, err := getUserInfo(params.Username)
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
	if desiredShell != "" && currentInfo.shell != desiredShell {
		args = append(args, "-s", desiredShell)
		output.WriteString(fmt.Sprintf("shell: %s -> %s\n", currentInfo.shell, desiredShell))
	}

	// Home directory - only if explicitly set and different
	if params.HomeDir != "" && currentInfo.homeDir != params.HomeDir {
		args = append(args, "-d", params.HomeDir)
		output.WriteString(fmt.Sprintf("home: %s -> %s\n", currentInfo.homeDir, params.HomeDir))
	}

	// Comment - only if explicitly set and different
	if params.Comment != "" && currentInfo.comment != params.Comment {
		args = append(args, "-c", params.Comment)
		output.WriteString(fmt.Sprintf("comment: %s -> %s\n", currentInfo.comment, params.Comment))
	}

	// Primary group - only if explicitly set and different
	if params.Gid > 0 && currentInfo.gid != int(params.Gid) {
		args = append(args, "-g", fmt.Sprintf("%d", params.Gid))
		output.WriteString(fmt.Sprintf("gid: %d -> %d\n", currentInfo.gid, params.Gid))
	} else if params.PrimaryGroup != "" {
		// Check if primary group needs to change (would need to resolve group name to GID)
		e.ensureGroupExists(ctx, params.PrimaryGroup)
		// For simplicity, always set if specified by name (could be optimized)
		args = append(args, "-g", params.PrimaryGroup)
	}

	// Additional groups - only if specified and not already present
	if len(params.Groups) > 0 {
		for _, g := range params.Groups {
			if !isValidUsername(g) {
				return nil, false, fmt.Errorf("invalid group name: %s", g)
			}
		}
		if !groupsContains(currentInfo.groups, params.Groups) {
			args = append(args, "-aG", strings.Join(params.Groups, ","))
			output.WriteString(fmt.Sprintf("groups: adding %v\n", params.Groups))
		}
	}

	// Apply usermod if we have changes
	if len(args) > 0 {
		args = append(args, params.Username)
		cmdOutput, err := runSudoCommand(ctx, "usermod", args...)
		if err != nil {
			if cmdOutput != nil {
				output.WriteString(cmdOutput.Stderr)
			}
			return &pb.CommandOutput{ExitCode: 1, Stderr: output.String()}, false, fmt.Errorf("failed to update user: %w", err)
		}
		changed = true
	}

	// Handle disabled/locked state - only change if different
	desiredLocked := params.Disabled
	if desiredLocked != currentInfo.locked {
		if desiredLocked {
			if lockOutput, err := runSudoCommand(ctx, "usermod", "-L", params.Username); err != nil {
				output.WriteString(fmt.Sprintf("warning: failed to lock user: %v\n", err))
				if lockOutput != nil {
					output.WriteString(lockOutput.Stderr)
				}
			} else {
				output.WriteString("account locked (disabled)\n")
				changed = true
			}
		} else {
			if unlockOutput, err := runSudoCommand(ctx, "usermod", "-U", params.Username); err != nil {
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

	// Update SSH authorized keys if provided and different
	if len(params.SshAuthorizedKeys) > 0 {
		if !sshKeysEqual(currentInfo.sshKeys, params.SshAuthorizedKeys) {
			if err := e.setupSSHKeys(ctx, params, output); err != nil {
				output.WriteString(fmt.Sprintf("warning: failed to setup SSH keys: %v\n", err))
			} else {
				changed = true
			}
		}
	}

	if !changed {
		output.WriteString(fmt.Sprintf("user %s is already in desired state\n", params.Username))
	}

	return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, changed, nil
}

// removeUser removes a user account from the system.
// Returns the command output, whether changes were made, and any error.
func (e *Executor) removeUser(ctx context.Context, username string) (*pb.CommandOutput, bool, error) {
	if !userExists(username) {
		// User doesn't exist, no change needed
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("user %s does not exist, nothing to remove\n", username),
		}, false, nil
	}

	// Remove user and their home directory
	output, err := runSudoCommand(ctx, "userdel", "-r", username)
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

// ensureGroupExists creates a group if it doesn't exist.
func (e *Executor) ensureGroupExists(ctx context.Context, groupName string) {
	// Check if group exists
	cmd := exec.Command("getent", "group", groupName)
	if cmd.Run() == nil {
		return // Group exists
	}

	// Create the group
	runSudoCommand(ctx, "groupadd", groupName)
}

// setupSSHKeys configures SSH authorized keys for a user.
func (e *Executor) setupSSHKeys(ctx context.Context, params *pb.UserParams, output *strings.Builder) error {
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

	// Create .ssh directory
	if _, err := runSudoCommand(ctx, "mkdir", "-p", sshDir); err != nil {
		return fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Set ownership and permissions on .ssh directory
	if _, err := runSudoCommand(ctx, "chown", params.Username+":"+params.Username, sshDir); err != nil {
		return fmt.Errorf("failed to set .ssh ownership: %w", err)
	}
	if _, err := runSudoCommand(ctx, "chmod", "700", sshDir); err != nil {
		return fmt.Errorf("failed to set .ssh permissions: %w", err)
	}

	// Build authorized_keys content
	var keysContent strings.Builder
	for _, key := range params.SshAuthorizedKeys {
		// Basic validation - SSH keys should start with ssh-rsa, ssh-ed25519, etc.
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

	// Write authorized_keys file
	cmd := exec.CommandContext(ctx, "sudo", "-n", "tee", authKeysFile)
	cmd.Stdin = strings.NewReader(keysContent.String())
	if _, err := runCommand(cmd); err != nil {
		return fmt.Errorf("failed to write authorized_keys: %w", err)
	}

	// Set ownership and permissions on authorized_keys
	if _, err := runSudoCommand(ctx, "chown", params.Username+":"+params.Username, authKeysFile); err != nil {
		return fmt.Errorf("failed to set authorized_keys ownership: %w", err)
	}
	if _, err := runSudoCommand(ctx, "chmod", "600", authKeysFile); err != nil {
		return fmt.Errorf("failed to set authorized_keys permissions: %w", err)
	}

	output.WriteString(fmt.Sprintf("configured %d SSH authorized key(s)\n", len(params.SshAuthorizedKeys)))
	return nil
}

