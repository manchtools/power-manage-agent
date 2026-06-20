package executor

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/pkg"
)

// probeErrPkgManager fails the IsInstalled state probe, standing in for a
// cancelled context or a backend lookup failure.
type probeErrPkgManager struct{ pkg.Manager }

func (probeErrPkgManager) IsInstalled(context.Context, string) (bool, error) {
	return false, errors.New("backend probe failed")
}

// TestExecutePackage_FailsClosedOnProbeError pins that a failed package-state
// probe fails the action CLOSED for both PRESENT and ABSENT, rather than
// silently proceeding to a privileged install/remove against an unknown state
// (CR finding: discarded IsInstalled errors at action_package.go:43/117).
func TestExecutePackage_FailsClosedOnProbeError(t *testing.T) {
	e := &Executor{logger: slog.Default(), now: time.Now, pkgBackend: pkg.Apt, pkgManager: probeErrPkgManager{}}
	for _, state := range []pb.DesiredState{
		pb.DesiredState_DESIRED_STATE_PRESENT,
		pb.DesiredState_DESIRED_STATE_ABSENT,
	} {
		if _, _, err := e.executePackage(context.Background(), &pb.PackageParams{Name: "anything"}, state); err == nil {
			t.Errorf("state %v: a probe error must fail closed, not proceed to a privileged mutation", state)
		}
	}
}

// WS16 #3: PACKAGE/UPDATE actions previously got no default timeout (only
// SHELL/SCRIPT_RUN did) and ran their package-manager operations under
// context.Background, so a per-action timeout never bit. defaultTimeoutForAction
// now covers package/update, and — in the reworked SDK — the pkg.Manager takes a
// context on EVERY call, so the action ctx reaches the package-manager
// subprocesses directly (no per-action manager rebuild).

func TestDefaultTimeoutForAction(t *testing.T) {
	cases := []struct {
		name      string
		actType   pb.ActionType
		requested int32
		want      int32
	}{
		{"explicit timeout always wins", pb.ActionType_ACTION_TYPE_PACKAGE, 42, 42},
		{"shell default", pb.ActionType_ACTION_TYPE_SHELL, 0, defaultScriptTimeout},
		{"script default", pb.ActionType_ACTION_TYPE_SCRIPT_RUN, 0, defaultScriptTimeout},
		{"package default (was unbounded)", pb.ActionType_ACTION_TYPE_PACKAGE, 0, defaultPackageTimeout},
		{"update default (was unbounded)", pb.ActionType_ACTION_TYPE_UPDATE, 0, defaultPackageTimeout},
		{"other action: no timeout", pb.ActionType_ACTION_TYPE_FILE, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := defaultTimeoutForAction(tc.actType, tc.requested); got != tc.want {
				t.Errorf("defaultTimeoutForAction(%v, %d) = %d, want %d", tc.actType, tc.requested, got, tc.want)
			}
		})
	}
}

// fakePkgManager embeds pkg.Manager (every method nil-panics) and overrides only
// IsInstalled, which the executePackage PRESENT path reaches first. It reports
// the package already installed so executePackage returns at the version/pin
// check with no privileged side effects, and captures the ctx it was called with
// so a test can prove the action ctx propagates to the manager (WS16 #3).
type fakePkgManager struct {
	pkg.Manager
	captured chan context.Context
}

func (f fakePkgManager) IsInstalled(ctx context.Context, _ string) (bool, error) {
	if f.captured != nil {
		select {
		case f.captured <- ctx:
		default:
		}
	}
	return true, nil
}

// TestExecutePackage_PassesActionContextToManager proves the action's
// (timeout-bearing) context reaches the package manager's calls — not the
// construction-time Background context — so a cancelled action ctx propagates to
// the manager's subprocesses. The reworked SDK passes ctx per call, so we assert
// the ctx the injected manager received IS the action ctx.
func TestExecutePackage_PassesActionContextToManager(t *testing.T) {
	capturedCh := make(chan context.Context, 1)
	e := &Executor{
		logger:     slog.Default(),
		now:        time.Now,
		pkgBackend: pkg.Apt,
		pkgManager: fakePkgManager{captured: capturedCh},
	}

	actionCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		// PACKAGE present, no version/pin → returns "already installed".
		_, _, _ = e.executePackage(actionCtx, &pb.PackageParams{Name: "anything"}, pb.DesiredState_DESIRED_STATE_PRESENT)
	}()

	var captured context.Context
	select {
	case captured = <-capturedCh:
	case <-time.After(2 * time.Second):
		t.Fatal("executePackage never called the package manager with the action context (WS16 #3)")
	}

	if captured == context.Background() {
		t.Fatal("manager was called with context.Background, not the action context (WS16 #3)")
	}

	// Cancelling the action context must propagate to the captured context —
	// proving it is the action's ctx, which the backend uses for its subprocess
	// deadlines.
	cancel()
	select {
	case <-captured.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("captured manager context did not observe the action-context cancel")
	}
}

// TestPkgManagerForCtx_CancelledCtx_FailsClosed pins that pkgManagerForCtx
// returns nil (fail closed) once the action context is already cancelled, so a
// wedged or expired action never starts a privileged package operation. With a
// live ctx it returns the configured manager.
func TestPkgManagerForCtx_CancelledCtx_FailsClosed(t *testing.T) {
	mgr := fakePkgManager{}
	e := &Executor{pkgManager: mgr}

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := e.pkgManagerForCtx(cancelledCtx); got != nil {
		t.Error("a cancelled action ctx must fail closed (nil), not return a usable manager")
	}

	if got := e.pkgManagerForCtx(context.Background()); got != mgr {
		t.Error("with a live ctx, pkgManagerForCtx must return the configured manager")
	}
}
