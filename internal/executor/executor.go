// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/manchtools/power-manage/agent/internal/store"
	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/pkg"
	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/verify"
)

// validRepoName restricts repository names to safe characters only.
// This prevents path traversal, shell injection, and sed/regex injection.
var validRepoName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)

// Repo-field shape constraints. These run in addition to the
// newline-rejection pass in validateRepositoryParams — newlines are
// the classic config-injection vector (they let a signed action
// smuggle extra lines into apt/dnf/pacman configuration), but the
// fields below also have a naturally narrow grammar, so an allow-list
// of permitted characters costs nothing and eliminates shell /
// argument-confusion attacks on runSudoCmd calls that splice these
// values into a command line.
var (
	// APT distribution codenames: "jammy", "bookworm", "focal-updates".
	validAptDistribution = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
	// APT components: "main", "contrib", "non-free-firmware".
	validAptComponent = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*$`)
	// APT architecture filter: "amd64", "arm64", comma-separated list.
	validAptArch = regexp.MustCompile(`^[a-z0-9][a-z0-9,_-]*$`)
	// Pacman SigLevel: space-separated tokens, e.g. "Optional TrustAll".
	validPacmanSigLevel = regexp.MustCompile(`^[a-zA-Z ]+$`)
	// Zypper repository type: "rpm-md", "yast2", "plaindir".
	validZypperType = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9-]*$`)
)

// validateRepositoryParams refuses repository configurations that
// contain newlines in any string field the agent later splices into
// a config file or shell argument, plus tight regex grammars on the
// enum-like fields (distribution, component, architecture, siglevel,
// zypper type). Since actions are signed and admin-controlled, this
// is not "untrusted input" in the classic sense — but a compromised
// or malformed admin action should not be able to inject extra
// directives into /etc/apt/sources.list.d/*, /etc/yum.repos.d/*,
// /etc/pacman.conf, or zypper metadata.
func validateRepositoryParams(params *pb.RepositoryParams) error {
	// Field-level errors name the offending field but do NOT echo
	// the rejected value. Repository URLs / GPG key URLs / descriptions
	// can carry secrets or per-deployment URLs that should not leak
	// into task-result payloads, audit projections, or log sinks. A
	// named field tells the operator enough to go check the action
	// definition — the full value is one click away in the UI.
	reject := func(field string) error {
		return fmt.Errorf("repository field %q contains newline or control character", field)
	}
	badShape := func(field string) error {
		return fmt.Errorf("repository field %q has invalid shape", field)
	}

	if apt := params.Apt; apt != nil {
		if containsNewline(apt.Url) {
			return reject("apt.url")
		}
		if containsNewline(apt.Distribution) {
			return reject("apt.distribution")
		}
		if apt.Distribution != "" && !validAptDistribution.MatchString(apt.Distribution) {
			return badShape("apt.distribution")
		}
		for _, c := range apt.Components {
			if containsNewline(c) {
				return reject("apt.components entry")
			}
			if !validAptComponent.MatchString(c) {
				return badShape("apt.components entry")
			}
		}
		if containsNewline(apt.Arch) {
			return reject("apt.arch")
		}
		if apt.Arch != "" && !validAptArch.MatchString(apt.Arch) {
			return badShape("apt.arch")
		}
		if containsNewline(apt.GpgKeyUrl) {
			return reject("apt.gpg_key_url")
		}
	}
	if dnf := params.Dnf; dnf != nil {
		if containsNewline(dnf.Baseurl) {
			return reject("dnf.baseurl")
		}
		if containsNewline(dnf.Description) {
			return reject("dnf.description")
		}
		if containsNewline(dnf.Gpgkey) {
			return reject("dnf.gpgkey")
		}
	}
	if pac := params.Pacman; pac != nil {
		if containsNewline(pac.Server) {
			return reject("pacman.server")
		}
		if containsNewline(pac.SigLevel) {
			return reject("pacman.sig_level")
		}
		if pac.SigLevel != "" && !validPacmanSigLevel.MatchString(pac.SigLevel) {
			return badShape("pacman.sig_level")
		}
	}
	if zyp := params.Zypper; zyp != nil {
		if containsNewline(zyp.Url) {
			return reject("zypper.url")
		}
		if containsNewline(zyp.Description) {
			return reject("zypper.description")
		}
		if containsNewline(zyp.Gpgkey) {
			return reject("zypper.gpgkey")
		}
		if containsNewline(zyp.Type) {
			return reject("zypper.type")
		}
		if zyp.Type != "" && !validZypperType.MatchString(zyp.Type) {
			return badShape("zypper.type")
		}
	}
	return nil
}

// maxScriptSize is the maximum allowed size for shell scripts (1 MiB).
const maxScriptSize = 1 << 20

// maxFileContentSize is the maximum allowed size for file content (10 MiB).
const maxFileContentSize = 10 << 20

// defaultScriptTimeout is applied when no timeout is specified for script actions.
const defaultScriptTimeout int32 = 3600

// containsNewline returns true if s contains \n or \r.
func containsNewline(s string) bool {
	return strings.ContainsAny(s, "\n\r")
}

// Executor handles the execution of actions.
type Executor struct {
	httpClient   *http.Client
	pkgManager   *pkg.PackageManager
	verifier     *verify.ActionVerifier
	logger       *slog.Logger
	mu           sync.RWMutex // protects luksKeyStore, store, actionStore
	luksKeyStore LuksKeyStore
	store        *store.Store
	actionStore  ActionStore
	updateCfg    *AgentUpdateConfig

	// Per-cycle AGENT_UPDATE dedup. Audit F042 + F048: previously
	// package-level globals which made parallel tests serialise on
	// one mutex and let a future second Executor share state with
	// production. Now scoped per-instance.
	agentUpdateExecutedMu sync.Mutex
	agentUpdateExecuted   bool
}

// NewExecutor creates a new action executor.
// If verifier is non-nil, action signatures will be checked before execution.
func NewExecutor(verifier *verify.ActionVerifier) *Executor {
	pm, pmErr := pkg.New()
	logger := slog.Default()
	switch {
	case pmErr != nil || pm == nil:
		// Operators with no supported package manager need to know
		// every package action will fail — silently no-op'ing on
		// boot makes the diagnosis hard later. Audit F031.
		logger.Warn("no supported package manager detected; package actions will fail", "error", pmErr)
	default:
		// Detection is via SDK helpers (IsApt/IsDnf/etc.) so the
		// startup line names whichever shells out at runtime.
		var name string
		switch {
		case pkg.IsApt():
			name = "apt"
		case pkg.IsDnf():
			name = "dnf"
		case pkg.IsPacman():
			name = "pacman"
		case pkg.IsZypper():
			name = "zypper"
		default:
			name = "unknown"
		}
		logger.Info("package manager detected", "manager", name)
	}
	return &Executor{
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
		pkgManager: pm,
		verifier:   verifier,
		logger:     logger,
	}
}

// SetLuksKeyStore sets the LUKS key store for stream-based key operations.
func (e *Executor) SetLuksKeyStore(ks LuksKeyStore) {
	e.mu.Lock()
	e.luksKeyStore = ks
	e.mu.Unlock()
}

// SetStore sets the agent store for LUKS state persistence.
func (e *Executor) SetStore(s *store.Store) {
	e.mu.Lock()
	e.store = s
	e.mu.Unlock()
}

// SetUpdateConfig configures the agent self-update executor.
func (e *Executor) SetUpdateConfig(cfg *AgentUpdateConfig) {
	e.mu.Lock()
	e.updateCfg = cfg
	e.mu.Unlock()
}

// SetActionStore sets the action store for LUKS conflict resolution.
func (e *Executor) SetActionStore(as ActionStore) {
	e.mu.Lock()
	e.actionStore = as
	e.mu.Unlock()
}

// getLuksKeyStore returns the LUKS key store (thread-safe).
func (e *Executor) getLuksKeyStore() LuksKeyStore {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.luksKeyStore
}

// getStore returns the agent store (thread-safe).
func (e *Executor) getStore() *store.Store {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.store
}

// getActionStore returns the action store used for LUKS conflict
// resolution (thread-safe). Audit F003: the LUKS executor used to
// read e.actionStore directly, bypassing e.mu and racing against
// SetActionStore — route the read through this accessor instead.
func (e *Executor) getActionStore() ActionStore {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.actionStore
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

	// Apply timeout. Default to 1 hour for script actions to prevent infinite loops.
	timeout := action.TimeoutSeconds
	if timeout <= 0 && (action.Type == pb.ActionType_ACTION_TYPE_SHELL || action.Type == pb.ActionType_ACTION_TYPE_SCRIPT_RUN) {
		timeout = defaultScriptTimeout
	}
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()
	}

	// Verify action signature before execution (skip for instant actions — they have no params to sign)
	if e.verifier != nil && !IsInstantAction(action.Type) {
		actionID := getActionID(action)
		if verifyErr := e.verifier.Verify(actionID, int32(action.Type), action.ParamsCanonical, action.Signature); verifyErr != nil {
			result.Status = pb.ExecutionStatus_EXECUTION_STATUS_FAILED
			result.Error = fmt.Sprintf("refusing to execute unsigned/tampered action: %v", verifyErr)
			result.CompletedAt = timestamppb.Now()
			result.DurationMs = time.Since(start).Milliseconds()
			return result
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
		var changed bool
		output, changed, execErr = e.executeUpdate(ctx, action.GetUpdate())
		result.Changed = changed
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
	case pb.ActionType_ACTION_TYPE_SHELL, pb.ActionType_ACTION_TYPE_SCRIPT_RUN:
		var detectionOutput *pb.CommandOutput
		var changed bool
		output, detectionOutput, changed, execErr = e.executeShellStreaming(ctx, action.GetShell(), callback)
		result.Changed = changed
		result.DetectionOutput = detectionOutput
		if action.GetShell().GetIsCompliance() {
			result.Compliant = detectionOutput != nil && detectionOutput.ExitCode == 0 && execErr == nil
		}
	case pb.ActionType_ACTION_TYPE_SERVICE:
		var changed bool
		output, changed, execErr = e.executeService(ctx, action.GetService())
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
		output, changed, execErr = e.executeSsh(ctx, action.GetSsh(), action.DesiredState, getActionID(action))
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_SSHD:
		var changed bool
		output, changed, execErr = e.executeSshd(ctx, action.GetSshd(), action.DesiredState, getActionID(action))
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_ADMIN_POLICY:
		var changed bool
		output, changed, execErr = e.executeSudo(ctx, action.GetAdminPolicy(), action.DesiredState, getActionID(action))
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_LPS:
		var changed bool
		var metadata map[string]string
		output, changed, metadata, execErr = e.executeLps(ctx, action.GetLps(), action.DesiredState, getActionID(action))
		result.Changed = changed
		if len(metadata) > 0 {
			result.Metadata = metadata
		}
	case pb.ActionType_ACTION_TYPE_ENCRYPTION:
		var changed bool
		var metadata map[string]string
		output, changed, metadata, execErr = e.executeLuks(ctx, action.GetEncryption(), action.DesiredState, getActionID(action))
		result.Changed = changed
		if len(metadata) > 0 {
			result.Metadata = metadata
		}
	case pb.ActionType_ACTION_TYPE_WIFI:
		var changed bool
		output, changed, execErr = e.executeWifi(ctx, action.GetWifi(), action.DesiredState, getActionID(action))
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_REBOOT:
		output, execErr = e.executeReboot(ctx)
	case pb.ActionType_ACTION_TYPE_AGENT_UPDATE:
		var changed bool
		output, changed, execErr = e.executeAgentUpdate(ctx, action.GetAgentUpdate())
		result.Changed = changed
	default:
		execErr = fmt.Errorf("unsupported action type: %v", action.Type)
	}

	result.Output = output
	result.CompletedAt = timestamppb.Now()
	result.DurationMs = time.Since(start).Milliseconds()

	// Check context errors first - distinguish between timeout and cancellation
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		result.Status = pb.ExecutionStatus_EXECUTION_STATUS_TIMEOUT
		result.Error = fmt.Sprintf("action timed out after %d seconds", timeout)
	case errors.Is(ctx.Err(), context.Canceled):
		result.Status = pb.ExecutionStatus_EXECUTION_STATUS_FAILED
		result.Error = "action cancelled"
	case execErr != nil:
		result.Status = pb.ExecutionStatus_EXECUTION_STATUS_FAILED
		result.Error = execErr.Error()
	default:
		result.Status = pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS
	}

	// For shell/script actions, non-zero exit codes indicate failure
	if result.Status == pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS {
		if action.Type == pb.ActionType_ACTION_TYPE_SHELL || action.Type == pb.ActionType_ACTION_TYPE_SCRIPT_RUN {
			if result.DetectionOutput != nil && result.DetectionOutput.ExitCode != 0 {
				result.Status = pb.ExecutionStatus_EXECUTION_STATUS_FAILED
				result.Error = fmt.Sprintf("script exited with code %d", result.DetectionOutput.ExitCode)
			} else if result.Output != nil && result.Output.ExitCode != 0 {
				result.Status = pb.ExecutionStatus_EXECUTION_STATUS_FAILED
				result.Error = fmt.Sprintf("script exited with code %d", result.Output.ExitCode)
			}
		}
	}

	return result
}

// runShellScript executes a single shell script string using the shared interpreter,
// environment, sudo, and working directory settings from ShellParams.
//
// RunAsRoot dispatches through sysexec.PrivilegedStreaming, which
// goes through the SDK's privilege-backend resolution
// (sudo/doas + -n flag + absolute-path + backend-installed check)
// so the agent stays consistent with the rest of the SDK's
// privilege contract instead of hard-coding "sudo -n".
func (e *Executor) runShellScript(ctx context.Context, params *pb.ShellParams, script string, callback OutputCallback) (*pb.CommandOutput, error) {
	interpreter := params.Interpreter
	if interpreter == "" {
		interpreter = "/bin/sh"
	}

	// Build environment from a curated baseline plus only the
	// caller-supplied entries that pass IsAllowedEnvVar. The
	// previous shape (`os.Environ()` baseline + per-entry validation)
	// defeated the guard: any dangerous variable already set in the
	// agent's own environment (LD_PRELOAD, LD_LIBRARY_PATH, PATH
	// hijacks, etc.) would leak through unchecked, because validation
	// only ran for *new* additions. Empty `params.Environment` was
	// even worse — `envVars` stayed nil, so the child silently
	// inherited the *full* ambient environment.
	//
	// The baseline below is the minimum needed for a useful shell:
	// PATH (to find common binaries) and LANG/HOME/USER (to keep
	// locale-aware tools and `~` expansion sane). Anything else the
	// action needs goes through `params.Environment` and the
	// IsAllowedEnvVar gate.
	envVars := []string{
		"PATH=" + os.Getenv("PATH"),
		"LANG=" + os.Getenv("LANG"),
		"HOME=" + os.Getenv("HOME"),
		"USER=" + os.Getenv("USER"),
	}
	for k, v := range params.Environment {
		if !sysexec.IsAllowedEnvVar(k) {
			return nil, fmt.Errorf("environment variable %q is not allowed", k)
		}
		envVars = append(envVars, fmt.Sprintf("%s=%s", k, v))
	}

	args := []string{"-c", script}
	if params.RunAsRoot {
		r, err := sysexec.PrivilegedStreaming(ctx, interpreter, args, envVars, params.WorkingDirectory, callback)
		return toOutput(r), err
	}
	return runCmdStreaming(ctx, interpreter, args, envVars, params.WorkingDirectory, callback)
}

// executeShellStreaming executes a shell action with optional detection/execution/verification flow.
// Returns (executionOutput, detectionOutput, changed, error).
//
// Flow:
//  1. No detection_script: run script as-is (current behavior)
//  2. Run detection_script. Exit 0 = compliant, skip execution.
//  3. No script (detection-only): return non-compliant status
//  4. Run script (remediation)
//  5. Re-run detection_script to verify
func (e *Executor) executeShellStreaming(ctx context.Context, params *pb.ShellParams, callback OutputCallback) (*pb.CommandOutput, *pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, nil, false, fmt.Errorf("shell params required")
	}
	if len(params.Script) > maxScriptSize {
		return nil, nil, false, fmt.Errorf("script exceeds maximum size (%d bytes)", maxScriptSize)
	}
	if len(params.DetectionScript) > maxScriptSize {
		return nil, nil, false, fmt.Errorf("detection script exceeds maximum size (%d bytes)", maxScriptSize)
	}

	// No detection script — run execution script directly (original behavior)
	if params.DetectionScript == "" {
		if params.Script == "" {
			return nil, nil, false, fmt.Errorf("at least one of script or detection_script is required")
		}
		output, err := e.runShellScript(ctx, params, params.Script, callback)
		return output, nil, true, err
	}

	// Compliance mode: run detection only, never execute remediation
	if params.GetIsCompliance() {
		e.logger.Debug("compliance mode: running detection script only")
		detectionOutput, err := e.runShellScript(ctx, params, params.DetectionScript, nil)
		if err != nil {
			return nil, detectionOutput, false, err
		}
		return nil, detectionOutput, false, nil
	}

	// Step 1: Run detection script
	e.logger.Debug("running detection script")
	detectionOutput, err := e.runShellScript(ctx, params, params.DetectionScript, nil)
	if err != nil {
		return nil, detectionOutput, false, fmt.Errorf("detection script error: %w", err)
	}

	// Step 2: If detection exits 0, system is compliant — skip execution
	if detectionOutput.ExitCode == 0 {
		e.logger.Debug("detection script passed (exit 0), system is compliant")
		return nil, detectionOutput, false, nil
	}

	// Step 3: No execution script (detection-only) — report non-compliant
	if params.Script == "" {
		e.logger.Debug("detection script failed (non-zero), no execution script — reporting non-compliant")
		return nil, detectionOutput, false, nil
	}

	// Step 4: Run execution/remediation script
	e.logger.Debug("detection script failed (non-zero), running remediation script")
	execOutput, execErr := e.runShellScript(ctx, params, params.Script, callback)
	if execErr != nil {
		return execOutput, detectionOutput, true, execErr
	}

	// Step 5: Re-run detection script to verify remediation
	e.logger.Debug("re-running detection script to verify remediation")
	verifyOutput, verifyErr := e.runShellScript(ctx, params, params.DetectionScript, nil)
	if verifyErr != nil {
		return execOutput, verifyOutput, true, fmt.Errorf("verification detection script error: %w", verifyErr)
	}

	if verifyOutput.ExitCode != 0 {
		return execOutput, verifyOutput, true, fmt.Errorf("remediation did not resolve the issue (detection still exits %d)", verifyOutput.ExitCode)
	}

	e.logger.Debug("verification passed, remediation successful")
	return execOutput, verifyOutput, true, nil
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

	if err := file.Close(); err != nil {
		// A late Close() error (fsync failure on a full disk, network
		// FS hiccup) means the on-disk file is potentially partial.
		// Remove it so the next run re-downloads instead of silently
		// treating a truncated file as a valid artifact.
		os.Remove(dest)
		return fmt.Errorf("close downloaded file %s: %w", dest, err)
	}
	return nil
}

// IsInstantAction returns true if the action type is an instant action (agent-builtin, no parameters).
func IsInstantAction(t pb.ActionType) bool {
	return t == pb.ActionType_ACTION_TYPE_REBOOT || t == pb.ActionType_ACTION_TYPE_SYNC
}
