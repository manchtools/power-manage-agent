package executor

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage-sdk/pkg"
	pmexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// fakeFlatpakPinMgr is a minimal pkg.Manager that drives ensureFlatpakPinned's
// IsPinned/Pin contract. Embedding the interface means any OTHER method panics
// (none are called by ensureFlatpakPinned), keeping the fake honest and the test
// decoupled from the SDK's `flatpak mask` argv.
type fakeFlatpakPinMgr struct {
	pkg.Manager
	pinned    bool
	pinnedErr error
	pinErr    error
	pinCalls  []string
}

func (f *fakeFlatpakPinMgr) IsPinned(ctx context.Context, name string) (bool, error) {
	return f.pinned, f.pinnedErr
}

func (f *fakeFlatpakPinMgr) Pin(ctx context.Context, packages ...string) (pmexec.Result, error) {
	f.pinCalls = append(f.pinCalls, packages...)
	return pmexec.Result{}, f.pinErr
}

// Pinning is part of the requested desired state. ensureFlatpakPinned must
// (a) converge — pin an already-installed-but-unpinned app, not skip it;
// (b) be idempotent — not re-pin an already-pinned app; and (c) surface a pin
// failure OR an IsPinned probe failure as a real error, never a silent success.
func TestEnsureFlatpakPinned(t *testing.T) {
	const app = "org.example.App"
	ctx := context.Background()

	t.Run("already pinned -> no change, Pin not run", func(t *testing.T) {
		f := &fakeFlatpakPinMgr{pinned: true}
		changed, err := ensureFlatpakPinned(ctx, f, app)
		require.NoError(t, err)
		assert.False(t, changed, "an already-pinned app must not report a change")
		assert.Empty(t, f.pinCalls, "must not re-pin an already-pinned app")
	})

	t.Run("not pinned -> applies pin and reports change", func(t *testing.T) {
		f := &fakeFlatpakPinMgr{pinned: false}
		changed, err := ensureFlatpakPinned(ctx, f, app)
		require.NoError(t, err)
		assert.True(t, changed, "newly pinning an unpinned app must report a change")
		assert.Equal(t, []string{app}, f.pinCalls, "must pin the requested app id")
	})

	t.Run("pin failure is a real error, not a success", func(t *testing.T) {
		f := &fakeFlatpakPinMgr{pinned: false, pinErr: errors.New("permission denied")}
		_, err := ensureFlatpakPinned(ctx, f, app)
		require.Error(t, err, "a failed pin must surface as an error so the action reports FAILED")
	})

	t.Run("IsPinned probe failure surfaces as an error", func(t *testing.T) {
		f := &fakeFlatpakPinMgr{pinnedErr: errors.New("flatpak unavailable")}
		_, err := ensureFlatpakPinned(ctx, f, app)
		require.Error(t, err, "an inability to determine pin state must not be treated as 'pinned'")
		assert.Empty(t, f.pinCalls, "must not attempt Pin when the pin-state probe failed")
	})
}
