// per_user.go — agent-side wrappers around sdk/go/sys/desktop's
// per-user fan-out. The package-local helpers convert between the
// SDK's *exec.Cmd shape and the agent's *pb.CommandOutput shape so
// per-user execution paths match the existing runSudoCmd ergonomics
// instead of forcing every caller to learn a parallel API.
package executor

import (
	"context"
	"os/exec"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/sys/desktop"
	sysenc "github.com/manchtools/power-manage-sdk/sys/encryption"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	sysfs "github.com/manchtools/power-manage-sdk/sys/fs"
	"github.com/manchtools/power-manage-sdk/sys/network"
	sysservice "github.com/manchtools/power-manage-sdk/sys/service"
	sysuser "github.com/manchtools/power-manage-sdk/sys/user"
)

// runuserPath mirrors desktop.runuserPath. Pinned here as well so a
// future move of the runuser invocation off the helper layer (e.g.
// streaming variant below) doesn't have to import the SDK constant.
const runuserPath = "/usr/sbin/runuser"

// desktopMgr is the process-wide desktop fan-out Manager (session enumeration +
// run-as-user). It defaults to a Direct-runner Manager and is rebuilt by
// NewExecutor with the configured backend so loginctl probes escalate when the
// agent is not already root. A package var so a test can substitute a fake.
var desktopMgr = mustDesktopManager(executorRunner)

func mustDesktopManager(r sysexec.Runner) desktop.Manager {
	m, err := desktop.New(r)
	if err != nil {
		panic("executor: desktop manager must construct: " + err.Error())
	}
	return m
}

// serviceMgr is the process-wide systemd service Manager; rebuilt by NewExecutor
// with the configured backend. Package var so tests can substitute a fake.
var serviceMgr = mustServiceManager(executorRunner)

func mustServiceManager(r sysexec.Runner) sysservice.Manager {
	m, err := sysservice.New(sysservice.Systemd, r)
	if err != nil {
		panic("executor: service manager must construct: " + err.Error())
	}
	return m
}

// networkMgr is the process-wide NetworkManager (nmcli) Manager; rebuilt by
// NewExecutor with the configured backend. Package var so tests can substitute.
var networkMgr = mustNetworkManager(executorRunner)

func mustNetworkManager(r sysexec.Runner) network.Manager {
	m, err := network.New(network.NetworkManager, r)
	if err != nil {
		panic("executor: network manager must construct: " + err.Error())
	}
	return m
}

// userMgr is the process-wide user/group (shadow-utils) Manager; rebuilt by
// NewExecutor with the configured backend. Package var so tests can substitute.
var userMgr = mustUserManager(executorRunner)

func mustUserManager(r sysexec.Runner) sysuser.Manager {
	m, err := sysuser.New(sysuser.ShadowUtils, r)
	if err != nil {
		panic("executor: user manager must construct: " + err.Error())
	}
	return m
}

// fsMgr is the process-wide filesystem Manager; rebuilt by NewExecutor with the
// configured backend. Used for ownership operations (e.g. recursive chown of a
// new home directory). Package var so tests can substitute.
var fsMgr = mustFSManager(executorRunner)

func mustFSManager(r sysexec.Runner) sysfs.Manager {
	m, err := sysfs.New(r)
	if err != nil {
		panic("executor: fs manager must construct: " + err.Error())
	}
	return m
}

// encMgr is the process-wide LUKS encryption Manager; rebuilt by NewExecutor
// with the configured backend. Package var so tests can substitute a fake.
var encMgr = mustEncManager(executorRunner)

func mustEncManager(r sysexec.Runner) sysenc.Manager {
	m, err := sysenc.New(sysenc.LUKS, r)
	if err != nil {
		panic("executor: encryption manager must construct: " + err.Error())
	}
	return m
}

// runCapturedCapped runs cmd, capturing stdout/stderr through the SDK's
// MaxOutputBytes-bounded buffer so a child emitting unbounded output
// cannot exhaust the root agent's memory (WS6 #14). Truncated streams
// carry the "[output truncated]" marker. Extracted so the cap is testable
// without runuser/root.
func runCapturedCapped(cmd *exec.Cmd) (*pb.CommandOutput, error) {
	stdout := sysexec.NewCappedBuffer(sysexec.MaxOutputBytes)
	stderr := sysexec.NewCappedBuffer(sysexec.MaxOutputBytes)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
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
	r, err := executorRunner.Stream(ctx, sysexec.Command{
		Name:      runuserPath,
		Args:      full,
		Env:       env,
		ChildPath: desktop.UserPath(s),
		Dir:       dir,
	}, callback)
	return toOutput(&r), err
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
