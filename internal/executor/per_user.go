// per_user.go — agent-side wrappers around sdk/go/sys/desktop's
// per-user fan-out. The package-local helpers convert between the
// SDK's *exec.Cmd shape and the agent's *pb.CommandOutput shape so
// per-user execution paths match the existing runSudoCmd ergonomics
// instead of forcing every caller to learn a parallel API.
package executor

import (
	"bytes"
	"context"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/sys/desktop"
	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// runuserPath mirrors desktop.runuserPath. Pinned here as well so a
// future move of the runuser invocation off the helper layer (e.g.
// streaming variant below) doesn't have to import the SDK constant.
const runuserPath = "/usr/sbin/runuser"

// runAsUserCmd runs `name args...` as the user owning the given
// session and returns the result as a *pb.CommandOutput, matching
// runSudoCmd's signature so per-user call sites don't need a
// different result-handling path.
//
// Caller-supplied extraEnv is merged on top of the desktop default
// env (HOME / USER / LOGNAME / XDG_RUNTIME_DIR / DBUS_SESSION_BUS_ADDRESS);
// duplicate keys win on the extraEnv side, matching Go's exec.Cmd
// last-write-wins semantics. Pass nil for extraEnv when the
// desktop defaults suffice.
func runAsUserCmd(ctx context.Context, s desktop.Session, extraEnv []string, name string, args ...string) (*pb.CommandOutput, error) {
	cmd, err := desktop.RunAsCommand(ctx, s, extraEnv, name, args...)
	if err != nil {
		return nil, err
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	out := &pb.CommandOutput{
		Stdout: stdout.String(),
		Stderr: stderr.String(),
	}
	if cmd.ProcessState != nil {
		out.ExitCode = int32(cmd.ProcessState.ExitCode())
	}
	return out, runErr
}

// runAsUserCheck runs `name args...` as the given session's user
// and reports whether the command exited 0. Mirrors checkCmdSuccess
// for the per-user execution path — used for "is X installed for
// this user" idempotency probes where stdout/stderr would be
// discarded anyway.
//
// A failure to construct the command (zero-value session, etc.) is
// reported as "false" rather than a separate error path because the
// callers (idempotency checks) treat any inability-to-determine as
// "not installed, attempt the install."
func runAsUserCheck(ctx context.Context, s desktop.Session, name string, args ...string) bool {
	cmd, err := desktop.RunAsCommand(ctx, s, nil, name, args...)
	if err != nil {
		return false
	}
	return cmd.Run() == nil
}

// runAsUserStreaming runs `name args...` as the given session's user
// with real-time line-streaming via callback, mirroring
// runCmdStreaming for the per-user execution path. The wrapper
// builds `runuser -u <user> -- <name> <args...>` and hands the
// resulting args + env (desktop defaults plus extraEnv) to the
// SDK's RunStreaming so callers don't need a separate streaming
// pipeline implementation.
//
// The callback receives lines tagged with the underlying child's
// stream type (stdout/stderr); if the caller wants to multiplex
// multiple users into one stream they should wrap the callback to
// prepend a per-user prefix before forwarding.
func runAsUserStreaming(ctx context.Context, s desktop.Session, extraEnv []string, dir string, name string, args []string, callback OutputCallback) (*pb.CommandOutput, error) {
	if name == "" {
		return nil, errEmptyName
	}
	if s.Username == "" {
		return nil, errEmptyUsername
	}
	full := append([]string{"-u", s.Username, "--", name}, args...)
	env := append(desktop.EnvFor(s), extraEnv...)
	if dir == "" {
		dir = s.Home
	}
	// Run with the target user's curated PATH, not the agent's (root's).
	// PATH is blocklisted from envVars, so it must be passed as the
	// trusted child PATH — otherwise the user script inherits root's
	// PATH and ~/.local/bin is ignored (see desktop.UserPath).
	r, err := sysexec.RunStreamingChildPath(ctx, runuserPath, full, env, desktop.UserPath(s), dir, callback)
	return toOutput(r), err
}

// errEmptyName / errEmptyUsername are sentinel errors so the
// callers can distinguish "caller bug" from "runuser execution
// failure." Pinned as vars rather than fmt.Errorf'd inline so a
// test can errors.Is() against them without string matching.
var (
	errEmptyName     = errPerUser("name is required")
	errEmptyUsername = errPerUser("session has empty Username")
)

type errPerUser string

func (e errPerUser) Error() string { return "executor.runAsUserStreaming: " + string(e) }
