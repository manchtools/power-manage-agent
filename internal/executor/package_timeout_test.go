package executor

import (
	"context"
	"log/slog"
	"testing"
	"time"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/pkg"
)

// WS16 #3: PACKAGE/UPDATE actions previously got no default timeout (only
// SHELL/SCRIPT_RUN did) and ran their package-manager operations under
// context.Background, so a per-action timeout never bit. defaultTimeoutForAction
// now covers package/update, and executePackage/executeUpdate re-bind a
// ctx-aware manager.

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

// TestExecutePackage_BindsManagerToActionContext proves the package-manager is
// re-bound to the action's (timeout-bearing) context, not the construction-time
// Background context — so a cancelled action ctx propagates to the manager's
// subprocesses. The stub reports the package already installed so executePackage
// returns at the version/pin check without any privileged side effects.
func TestExecutePackage_BindsManagerToActionContext(t *testing.T) {
	capturedCh := make(chan context.Context, 1)
	e := &Executor{
		logger: slog.Default(),
		now:    time.Now,
		newPkgManager: func(ctx context.Context) (*pkg.PackageManager, error) {
			select {
			case capturedCh <- ctx:
			default:
			}
			return pkg.NewPackageManager(alreadyInstalledManager{}), nil
		},
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
		t.Fatal("executePackage never requested a context-bound package manager (WS16 #3)")
	}

	if captured == context.Background() {
		t.Fatal("manager was bound to context.Background, not the action context (WS16 #3)")
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

// TestPkgManagerForCtx_CancelledCtx_FailsClosed pins that when the per-action
// manager cannot be built and the action context is already cancelled/expired,
// pkgManagerForCtx returns nil (fail closed) rather than falling back to the
// construction-time Background-bound manager — which would silently bypass the
// timeout/cancel guarantee. With a live ctx, a builder error still falls back.
func TestPkgManagerForCtx_CancelledCtx_FailsClosed(t *testing.T) {
	fallback := pkg.NewPackageManager(alreadyInstalledManager{})
	e := &Executor{
		pkgManager: fallback,
		newPkgManager: func(context.Context) (*pkg.PackageManager, error) {
			return nil, context.Canceled // simulate a creation failure
		},
	}

	cancelledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if mgr := e.pkgManagerForCtx(cancelledCtx); mgr != nil {
		t.Error("a cancelled action ctx must fail closed (nil), not fall back to the Background-bound manager")
	}

	if mgr := e.pkgManagerForCtx(context.Background()); mgr != fallback {
		t.Error("with a live ctx, a builder error should fall back to the construction-time manager")
	}
}

// alreadyInstalledManager implements pkg.Manager reporting the package present,
// so executePackage returns at the version/pin check without touching the
// filesystem or shelling out. Only IsInstalled is reached.
type alreadyInstalledManager struct{ pkg.Manager }

func (alreadyInstalledManager) IsInstalled(string) (bool, error) { return true, nil }
