package handler

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/sys/exec"
	sysuser "github.com/manchtools/power-manage/sdk/go/sys/user"
)

const setupTestULID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

// TestOnTerminalStart_BoundedSetupContext pins WS13 #2: the privileged setup
// steps run under a BOUNDED context, so a hung step surfaces a STATE_ERROR
// within the deadline and the call returns — it cannot wedge the dispatch loop
// indefinitely. Driven via the sysuser seams so it needs no real pm-tty account.
func TestOnTerminalStart_BoundedSetupContext(t *testing.T) {
	h, sender := newTestHandlerWithTTY(t, true)

	origGet, origModify, origTimeout := sysuserGet, sysuserModify, terminalSetupTimeout
	t.Cleanup(func() {
		sysuserGet, sysuserModify, terminalSetupTimeout = origGet, origModify, origTimeout
	})

	// A valid, unlocked user so we reach the setup steps.
	sysuserGet = func(string) (*sysuser.Info, error) { return &sysuser.Info{Locked: false}, nil }
	// Modify hangs, respecting ctx — it returns only when the bounded setup ctx
	// fires. This is the "hung sudo" the bound defends against.
	modifyEntered := make(chan struct{})
	sysuserModify = func(ctx context.Context, _ string, _ ...string) (*exec.Result, error) {
		close(modifyEntered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	terminalSetupTimeout = 100 * time.Millisecond // fast test

	done := make(chan error, 1)
	go func() {
		done <- h.OnTerminalStart(context.Background(), &pb.TerminalStart{
			SessionId: setupTestULID, TtyUser: "pm-tty-test", Cols: 80, Rows: 24,
		})
	}()

	// Prove we actually exercised the setup path (reached Modify).
	select {
	case <-modifyEntered:
	case <-time.After(2 * time.Second):
		t.Fatal("setup never reached the Modify step")
	}

	// OnTerminalStart must RETURN shortly after the deadline — the dispatch loop
	// goroutine is freed, not blocked on the hung step.
	select {
	case err := <-done:
		require.NoError(t, err, "OnTerminalStart returns nil; failures surface via STATE_ERROR, not a returned error")
	case <-time.After(2 * time.Second):
		t.Fatal("OnTerminalStart did not return after the setup deadline — the dispatch loop would be wedged")
	}

	last := sender.lastState()
	require.NotNil(t, last, "a setup timeout must emit a TerminalStateChange")
	assert.Equal(t, pb.TerminalSessionState_TERMINAL_SESSION_STATE_ERROR, last.State,
		"a setup timeout must surface STATE_ERROR")

	h.mu.Lock()
	_, exists := h.terminals[setupTestULID]
	h.mu.Unlock()
	assert.False(t, exists, "the half-built session must be removed after a setup failure")
}
