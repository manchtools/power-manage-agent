// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/pkg"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/verify"
	"github.com/manchtools/power-manage/agent/internal/store"
)

// Repository configuration validation (name grammar, per-backend URL/baseurl
// shape, control-char/newline rejection on every field, gpgkey ref) is owned by
// the SDK's repo.Manager.Validate, which executeRepository calls as its
// pre-flight gate. The agent no longer re-derives the field regexes here.

// maxScriptSize is the maximum allowed size for shell scripts (1 MiB).
const maxScriptSize = 1 << 20

// maxFileContentSize is the maximum allowed size for file content (10 MiB).
const maxFileContentSize = 10 << 20

// defaultScriptTimeout is applied when no timeout is specified for script actions.
const defaultScriptTimeout int32 = 3600

// defaultPackageTimeout bounds PACKAGE/UPDATE actions that carry no explicit
// timeout. Without it these ran under an unbounded context, so a wedged
// apt/dnf operation (mirror outage, lock contention) could pin the action
// forever (WS16 #3). 30 minutes is generous for a slow mirror + large upgrade
// set yet refuses to hang indefinitely.
const defaultPackageTimeout int32 = 1800

// defaultTimeoutForAction returns the timeout (seconds) to apply to an action
// when the operator set one (requested > 0 wins) or a default ceiling for the
// long-running action classes. 0 means "no timeout" (the previous behaviour
// for non-script, non-package actions).
func defaultTimeoutForAction(actionType pb.ActionType, requested int32) int32 {
	if requested > 0 {
		return requested
	}
	switch actionType {
	case pb.ActionType_ACTION_TYPE_SHELL, pb.ActionType_ACTION_TYPE_SCRIPT_RUN:
		return defaultScriptTimeout
	case pb.ActionType_ACTION_TYPE_PACKAGE, pb.ActionType_ACTION_TYPE_UPDATE:
		return defaultPackageTimeout
	default:
		return 0
	}
}

// Executor handles the execution of actions.
type Executor struct {
	httpClient *http.Client
	pkgManager pkg.Manager // nil when no supported package manager is present
	pkgBackend pkg.Backend // the detected backend driving pkgManager (zero when nil)
	// runner is the privilege runner this executor was constructed with, or nil
	// when NewExecutor was called without one (the unit-test convention,
	// NewExecutor(_, nil)). The destructive reboot path uses it DIRECTLY and
	// fails closed when it is nil — never the process-global Direct default — so
	// a test that dispatches a REBOOT through a no-runner executor can never
	// issue a real `shutdown` on the host (it once rebooted a workstation).
	runner       sysexec.Runner
	verifier     *verify.ActionVerifier
	logger       *slog.Logger
	mu           sync.RWMutex // protects luksKeyStore, store, actionStore, deviceID
	luksKeyStore LuksKeyStore
	store        *store.Store
	actionStore  ActionStore
	updateCfg    *AgentUpdateConfig
	// deviceID is this agent's own device ULID, used as part of the LPS
	// seal context (device|action|username) so the sealed password binds to
	// the exact record the control server unseals it into. Set from
	// credentials in main.go.
	deviceID string

	// Per-cycle AGENT_UPDATE dedup. Audit F042 + F048: previously
	// package-level globals which made parallel tests serialise on
	// one mutex and let a future second Executor share state with
	// production. Now scoped per-instance.
	agentUpdateExecutedMu sync.Mutex
	agentUpdateExecuted   bool

	// Per-action LUKS rotation-timestamp persistence failure counter.
	// Tracks consecutive SetLuksLastRotatedAt failures per action ID
	// so the agent escalates from Warn to Error after
	// luksTimestampFailureThreshold consecutive failures (#80). The
	// failure mode it surfaces — silent rotation hot-loop or rotation
	// never starting because the timestamp never persists — was easy
	// to miss when buried in journald Warn-level lines.
	luksTimestampFailMu    sync.Mutex
	luksTimestampFailCount map[string]int

	now func() time.Time // clock seam; defaults to time.Now, overridden in tests

	// repairFS is a seam over repairFilesystem so tests can record
	// whether a privileged remount/repair was attempted (proving that a
	// malformed/rejected action never reaches the privileged side
	// effects). nil in production → requireWritableFS calls the real
	// e.repairFilesystem.
	repairFS func(ctx context.Context) bool
}

// pkgManagerForCtx returns the package manager for this action. The reworked SDK
// Manager takes a context on every call, so the per-action timeout reaches the
// package-manager subprocesses directly — there is no longer a per-action
// manager to rebuild. It returns nil (fail closed) once the action context is
// already cancelled, so a wedged or expired action never starts a privileged
// package operation.
func (e *Executor) pkgManagerForCtx(ctx context.Context) pkg.Manager {
	if ctx.Err() != nil {
		return nil
	}
	return e.pkgManager
}

// NewExecutor creates a new action executor. If verifier is non-nil, action
// signatures are checked before execution. runner is the privilege-backend
// runner the package manager dispatches through; a nil runner leaves the package
// manager unset (package actions fail) — used by unit tests that inject their
// own pkg.Manager into e.pkgManager.
// executorGlobalsAdopted latches the first runner-bearing construction
// so re-adoption of the package-global managers is logged (#173).
var executorGlobalsAdopted atomic.Bool

func NewExecutor(verifier *verify.ActionVerifier, runner sysexec.Runner) *Executor {
	logger := slog.Default()
	var (
		mgr     pkg.Manager
		backend pkg.Backend
	)
	// Adopt the configured runner process-wide so the cmd.go helpers (notably
	// the escalating runSudoCmd) and the desktop fan-out dispatch through it. A
	// nil runner (unit tests) leaves the Direct defaults in place.
	//
	// ONE executor per process is the supported shape (#173 review
	// finding): these are package globals, so a second runner-bearing
	// NewExecutor re-points every previously constructed Executor's
	// free-function dispatch at the NEW runner. That re-adoption is now
	// loud instead of silent; the full de-globalization is tracked with
	// the #150 SDK-delegation refactor.
	if runner != nil {
		if !executorGlobalsAdopted.CompareAndSwap(false, true) {
			logger.Warn("NewExecutor called again with a privilege runner; re-pointing the process-global managers — all executors in this process now dispatch through the newest runner (one runner-bearing executor per process is the supported shape)")
		}
		executorRunner = runner
		desktopMgr = mustDesktopManager(runner)
		serviceMgr = mustServiceManager(runner)
		networkMgr = mustNetworkManager(runner)
		userMgr = mustUserManager(runner)
		fsMgr = mustFSManager(runner)
		encMgr = mustEncManager(runner)
	}
	switch {
	case runner == nil:
		logger.Warn("no privilege runner provided; package actions will fail")
	default:
		// Detect lists installed backends in priority order (native managers
		// before flatpak); pick the first. An empty list means no supported
		// package manager — operators need to know every package action will
		// fail rather than silently no-op on boot (Audit F031).
		if backends := pkg.Detect(context.Background()); len(backends) == 0 {
			logger.Warn("no supported package manager detected; package actions will fail")
		} else {
			backend = backends[0]
			m, err := pkg.New(backend, runner)
			if err != nil {
				logger.Warn("failed to build package manager; package actions will fail",
					"backend", backend.String(), "error", err)
			} else {
				mgr = m
				logger.Info("package manager detected", "manager", backend.String())
			}
		}
	}
	return &Executor{
		httpClient: &http.Client{
			Timeout: 5 * time.Minute,
		},
		pkgManager: mgr,
		pkgBackend: backend,
		runner:     runner,
		verifier:   verifier,
		logger:     logger,
		now:        time.Now,
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

// SetDeviceID sets this agent's own device ULID, used in the LPS seal context.
func (e *Executor) SetDeviceID(id string) {
	e.mu.Lock()
	e.deviceID = id
	e.mu.Unlock()
}

// getDeviceID returns the configured device ULID under the read lock.
func (e *Executor) getDeviceID() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.deviceID
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

// ExecuteEnvelope runs a previously-VERIFIED action envelope and returns the
// result. Callers must pass only an envelope returned by VerifyEnvelope — the
// executed bytes must be the verified bytes (sdk#82).
func (e *Executor) ExecuteEnvelope(ctx context.Context, env *pb.SignedActionEnvelope) *pb.ActionResult {
	return e.ExecuteWithStreaming(ctx, env, nil)
}

// VerifyEnvelope is the single verify-then-unmarshal seam every execution
// path funnels through (sdk#82). It verifies the CA signature over the EXACT
// envelope bytes it received and, on success, unmarshals THOSE SAME bytes
// into a SignedActionEnvelope — so the message that executes is byte-for-byte
// the message that was verified. A compromised gateway/Valkey relay cannot
// flip desired_state, swap params, change the timeout/schedule, lift the type
// onto SYNC, or retarget the device under a still-valid signature, because
// every one of those fields is inside the signed bytes.
//
// Fail-closed: a nil verifier returns an error rather than passing the
// envelope through unverified. In production the agent always has a verifier
// (the CA cert is required at startup); a nil verifier means misconfiguration
// or a test that forgot to wire one, and either way must NOT become a silent
// "execute everything unsigned" hole. The caller must treat any error here as
// a hard refusal and never execute.
func (e *Executor) VerifyEnvelope(envelopeBytes, signature []byte) (*pb.SignedActionEnvelope, error) {
	if e.verifier == nil {
		return nil, fmt.Errorf("no action verifier configured; refusing to execute unverified action")
	}
	if err := e.verifier.Verify(envelopeBytes, signature); err != nil {
		return nil, err
	}
	env := &pb.SignedActionEnvelope{}
	if err := proto.Unmarshal(envelopeBytes, env); err != nil {
		return nil, fmt.Errorf("unmarshal verified envelope: %w", err)
	}
	// Enforce the SIGNED target binding. target_device_id exists precisely to
	// stop a compromised gateway/relay from replaying one device's validly-signed
	// (CA-covered) action onto another device that trusts the same CA
	// (PMSEC-001). Verification alone proves the bytes are authentic, not that
	// this device is their intended target — so make verification an
	// authorization step. The control server's single signing seam
	// (actionparams.BuildAndSignEnvelope) always binds the target device, so a
	// legitimate envelope for this device always matches. The same helper guards
	// the four non-action stream-RPC surfaces (see enforceTargetDevice).
	if err := e.enforceTargetDevice(env.GetTargetDeviceId()); err != nil {
		return nil, err
	}
	return env, nil
}

// ExecuteWithStreaming runs a VERIFIED action envelope with optional output
// streaming. The callback is called for each line of output as it's produced
// (for shell actions).
//
// Signature verification is NOT done here — it happens in VerifyEnvelope,
// which the caller MUST run first and whose returned envelope is the only
// thing this method should ever receive. Passing a hand-built (unverified)
// envelope is a caller bug: the whole point of sdk#82 is that the executed
// bytes are the verified bytes. WHAT runs (type, params, desired_state,
// timeout) is read exclusively off env.
func (e *Executor) ExecuteWithStreaming(ctx context.Context, env *pb.SignedActionEnvelope, callback OutputCallback) *pb.ActionResult {
	start := e.now()

	result := &pb.ActionResult{
		ActionId: env.GetActionId(),
		Status:   pb.ExecutionStatus_EXECUTION_STATUS_RUNNING,
		Changed:  true, // Default to true; scheduler may override based on output comparison
	}

	// Apply a per-action timeout. Long-running classes (scripts, and — WS16 #3
	// — package/update operations) get a default ceiling when none is set so
	// they cannot run unbounded. parentCtx is kept so the result
	// classification below can tell "the parent deadline fired" apart
	// from "the per-action timeout fired" (CR catch on #179).
	parentCtx := ctx
	timeout := defaultTimeoutForAction(env.ActionType, env.GetTimeoutSeconds())
	if timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(timeout)*time.Second)
		defer cancel()
	}

	var execErr error
	var output *pb.CommandOutput

	switch env.ActionType {
	case pb.ActionType_ACTION_TYPE_PACKAGE:
		var changed bool
		output, changed, execErr = e.executePackage(ctx, env.GetPackage(), env.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_UPDATE:
		var changed bool
		output, changed, execErr = e.executeUpdate(ctx, env.GetUpdate())
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_APP_IMAGE:
		var changed bool
		output, changed, execErr = e.executeAppImage(ctx, env.GetApp(), env.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_FLATPAK:
		var changed bool
		output, changed, execErr = e.executeFlatpak(ctx, env.GetFlatpak(), env.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_DEB:
		var changed bool
		output, changed, execErr = e.executeDeb(ctx, env.GetApp(), env.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_RPM:
		var changed bool
		output, changed, execErr = e.executeRpm(ctx, env.GetApp(), env.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_SHELL, pb.ActionType_ACTION_TYPE_SCRIPT_RUN:
		var detectionOutput *pb.CommandOutput
		var changed bool
		output, detectionOutput, changed, execErr = e.executeShellStreaming(ctx, env.GetShell(), callback)
		result.Changed = changed
		result.DetectionOutput = detectionOutput
		if env.GetShell().GetIsCompliance() {
			result.Compliant = detectionOutput != nil && detectionOutput.ExitCode == 0 && execErr == nil
		}
	case pb.ActionType_ACTION_TYPE_SERVICE:
		var changed bool
		output, changed, execErr = e.executeService(ctx, env.GetService())
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_FILE:
		var changed bool
		output, changed, execErr = e.executeFile(ctx, env.GetFile(), env.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_DIRECTORY:
		var changed bool
		output, changed, execErr = e.executeDirectory(ctx, env.GetDirectory(), env.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_REPOSITORY:
		var changed bool
		output, changed, execErr = e.executeRepository(ctx, env.GetRepository(), env.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_USER:
		var changed bool
		var metadata map[string]string
		output, changed, metadata, execErr = e.executeUser(ctx, env.GetUser(), env.DesiredState, envActionID(env))
		result.Changed = changed
		if len(metadata) > 0 {
			result.Metadata = metadata
		}
	case pb.ActionType_ACTION_TYPE_GROUP:
		var changed bool
		output, changed, execErr = e.executeGroup(ctx, env.GetGroup(), env.DesiredState)
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_SSH:
		var changed bool
		output, changed, execErr = e.executeSsh(ctx, env.GetSsh(), env.DesiredState, envActionID(env))
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_SSHD:
		var changed bool
		output, changed, execErr = e.executeSshd(ctx, env.GetSshd(), env.DesiredState, envActionID(env))
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_ADMIN_POLICY:
		var changed bool
		output, changed, execErr = e.executeSudo(ctx, env.GetAdminPolicy(), env.DesiredState, envActionID(env))
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_LPS:
		var changed bool
		var metadata map[string]string
		output, changed, metadata, execErr = e.executeLps(ctx, env.GetLps(), env.DesiredState, envActionID(env))
		result.Changed = changed
		if len(metadata) > 0 {
			result.Metadata = metadata
		}
	case pb.ActionType_ACTION_TYPE_ENCRYPTION:
		var changed bool
		var metadata map[string]string
		output, changed, metadata, execErr = e.executeLuks(ctx, env.GetEncryption(), env.DesiredState, envActionID(env))
		result.Changed = changed
		if len(metadata) > 0 {
			result.Metadata = metadata
		}
	case pb.ActionType_ACTION_TYPE_WIFI:
		var changed bool
		output, changed, execErr = e.executeWifi(ctx, env.GetWifi(), env.DesiredState, envActionID(env))
		result.Changed = changed
	case pb.ActionType_ACTION_TYPE_REBOOT:
		output, execErr = e.executeReboot(ctx)
	case pb.ActionType_ACTION_TYPE_AGENT_UPDATE:
		var changed bool
		output, changed, execErr = e.executeAgentUpdate(ctx, env.GetAgentUpdate())
		result.Changed = changed
	default:
		execErr = fmt.Errorf("unsupported action type: %v", env.ActionType)
	}

	result.Output = output
	completed := e.now()
	result.CompletedAt = timestamppb.New(completed)
	result.DurationMs = completed.Sub(start).Milliseconds()

	// Check context errors first - distinguish between timeout and cancellation
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		result.Status = pb.ExecutionStatus_EXECUTION_STATUS_TIMEOUT
		// Distinguish the PARENT deadline from the per-action timeout —
		// "timed out after N seconds" when the parent cancelled first
		// (or when no action timeout existed at all) was a lie (#173 +
		// CR catch on #179).
		if errors.Is(parentCtx.Err(), context.DeadlineExceeded) {
			result.Error = "action deadline exceeded (parent context)"
		} else {
			result.Error = fmt.Sprintf("action timed out after %d seconds", timeout)
		}
	case errors.Is(ctx.Err(), context.Canceled):
		result.Status = pb.ExecutionStatus_EXECUTION_STATUS_FAILED
		result.Error = "action cancelled"
	case errors.Is(execErr, errNotApplicable):
		// Spec 23: structural inapplicability is a first-class terminal
		// outcome, not a failure. The reason travels in the result error.
		result.Status = pb.ExecutionStatus_EXECUTION_STATUS_NOT_APPLICABLE
		result.Error = execErr.Error()
	case execErr != nil:
		result.Status = pb.ExecutionStatus_EXECUTION_STATUS_FAILED
		result.Error = execErr.Error()
	default:
		result.Status = pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS
	}

	// For shell/script actions, non-zero exit codes indicate failure
	if result.Status == pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS {
		if env.ActionType == pb.ActionType_ACTION_TYPE_SHELL || env.ActionType == pb.ActionType_ACTION_TYPE_SCRIPT_RUN {
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
//
// RunAsRoot=false fans the script out to every active graphical
// desktop session via desktop.ActiveSessions + runAsUserStreaming
// (#79). Pre-fix this branch silently ran the script as the agent's
// own UID (root in production) — exactly the bug profile that
// SystemWide=false suffered for Flatpak. The new contract: an
// admin who explicitly turns RunAsRoot off gets a per-user
// execution, NOT a "still root, just without going through sudo"
// fallback. Empty-set policy matches the Flatpak path: log Warn
// and return success no-op so the next reconciliation tick retries
// once a user signs in.
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
	// Neither PATH nor the locale family is set here. The reworked SDK
	// Runner injects its own sanitized PATH (derived from the agent's
	// environment, since envVars is non-empty) and FORCES the deterministic
	// locale (LC_ALL=C/LANG=C/NO_COLOR=1) on every command — and REJECTS any
	// attempt to set LANG/LC_*/LANGUAGE/NO_COLOR via Command.Env. This used
	// to set `LANG=<host LANG>`, which made EVERY shell action fail with
	// ErrReservedEnvVar once the agent moved onto the reworked Runner. PATH
	// is likewise blocklisted and supplied by the Runner. HOME/USER keep
	// `~`-expansion and user-context tools sane; anything else goes through
	// `params.Environment` and the IsAllowedEnvVar gate.
	envVars := []string{
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
		r, err := executorRunner.Stream(ctx, sysexec.Command{
			Name:     interpreter,
			Args:     args,
			Env:      envVars,
			Dir:      params.WorkingDirectory,
			Escalate: true,
		}, callback)
		return toOutput(&r), err
	}
	// RunAsRoot=false → per-user fan-out.
	return e.runShellScriptPerUser(ctx, params, interpreter, args, envVars, callback)
}

// runShellScriptPerUser implements the RunAsRoot=false path: fans
// the script over every active desktop session, prefixing each
// streamed line with `[user=<name>] ` so the operator can attribute
// output. Returns the merged output and the first per-user error
// encountered (the loop continues on failure so one broken user
// doesn't block the rest, matching the per-user Flatpak shape).
//
// The merged output's ExitCode is 0 if every user succeeded,
// otherwise the first non-zero exit so the action result can still
// drive the changed/failed bookkeeping in executeShellStreaming.
func (e *Executor) runShellScriptPerUser(ctx context.Context, params *pb.ShellParams, interpreter string, args []string, envVars []string, callback OutputCallback) (*pb.CommandOutput, error) {
	sessions, err := desktopMgr.ActiveSessions(ctx)
	if err != nil {
		return nil, fmt.Errorf("enumerate active desktop sessions: %w", err)
	}
	if len(sessions) == 0 {
		e.logger.Warn("shell RunAsRoot=false: no active desktop sessions; per-user run deferred until a user signs in")
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   "skipped: no signed-in desktop users; will run again on next reconciliation",
		}, nil
	}

	// Strip HOME / USER from the caller-supplied env baseline —
	// desktop.EnvFor sets the per-user values inside
	// runAsUserStreaming, and a duplicate from envVars would only
	// confuse readers (Go's exec.Cmd takes the last occurrence,
	// which is the per-user one, but the duplicates make the env
	// list noisy in audit logs).
	extraEnv := stripHomeAndUser(envVars)

	merged := &pb.CommandOutput{}
	var firstFailure error
	for _, s := range sessions {
		userPrefix := "[user=" + s.Username + "] "
		var wrappedCB OutputCallback
		if callback != nil {
			wrappedCB = func(streamType sysexec.StreamType, line string, seq int64) {
				callback(streamType, userPrefix+line, seq)
			}
		}
		out, runErr := runAsUserStreaming(ctx, s, extraEnv, params.WorkingDirectory, interpreter, args, wrappedCB)
		if out != nil {
			if out.Stdout != "" {
				merged.Stdout += userPrefix + out.Stdout
				if !strings.HasSuffix(out.Stdout, "\n") {
					merged.Stdout += "\n"
				}
			}
			if out.Stderr != "" {
				merged.Stderr += userPrefix + out.Stderr
				if !strings.HasSuffix(out.Stderr, "\n") {
					merged.Stderr += "\n"
				}
			}
			if out.ExitCode != 0 && merged.ExitCode == 0 {
				merged.ExitCode = out.ExitCode
			}
		}
		if runErr != nil && firstFailure == nil {
			firstFailure = fmt.Errorf("user %s: %w", s.Username, runErr)
		}
	}
	return merged, firstFailure
}

// stripHomeAndUser drops HOME=/USER= entries from envVars. The
// per-user runner sets these from the session, and leaving the
// agent-derived defaults in extraEnv would only add noise (Go's
// exec.Cmd uses last-write-wins so the per-user value still wins,
// but the duplicates clutter audit logs and confuse reviewers).
//
// Allocates a fresh backing array rather than aliasing envVars
// (envVars[:0:0]) — the [:0:0] form has zero capacity so an append
// immediately reallocates and the aliasing is moot in practice,
// but a future tweak toward [:0] or [:0:n] would silently start
// mutating the caller's slice. Pin "no aliasing" explicitly so the
// hazard can't creep back in.
func stripHomeAndUser(envVars []string) []string {
	out := make([]string, 0, len(envVars))
	for _, kv := range envVars {
		if strings.HasPrefix(kv, "HOME=") || strings.HasPrefix(kv, "USER=") {
			continue
		}
		out = append(out, kv)
	}
	return out
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

// IsInstantAction returns true if the action type is an instant action (agent-builtin, no parameters).
func IsInstantAction(t pb.ActionType) bool {
	return t == pb.ActionType_ACTION_TYPE_REBOOT || t == pb.ActionType_ACTION_TYPE_SYNC
}
