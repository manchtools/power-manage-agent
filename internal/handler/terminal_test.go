package handler

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// fakeSender records every TerminalOutput / TerminalStateChange so
// the tests can assert against it without an actual SDK Client.
type fakeSender struct {
	mu      sync.Mutex
	outputs []*pb.TerminalOutput
	states  []*pb.TerminalStateChange
}

func (f *fakeSender) SendTerminalOutput(ctx context.Context, out *pb.TerminalOutput) error {
	f.mu.Lock()
	f.outputs = append(f.outputs, out)
	f.mu.Unlock()
	return nil
}

func (f *fakeSender) SendTerminalStateChange(ctx context.Context, change *pb.TerminalStateChange) error {
	f.mu.Lock()
	f.states = append(f.states, change)
	f.mu.Unlock()
	return nil
}

func (f *fakeSender) lastState() *pb.TerminalStateChange {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.states) == 0 {
		return nil
	}
	return f.states[len(f.states)-1]
}

func newTestHandler(t *testing.T) (*Handler, *fakeSender) {
	t.Helper()
	h := &Handler{
		logger:      slog.Default(),
		connectedCh: make(chan struct{}),
	}
	sender := &fakeSender{}
	h.SetTerminalSender(sender)
	return h, sender
}

// addTestSession injects a fake session into the registry without
// going through OnTerminalStart, so tests can exercise registry
// behaviour (limits, lookup, idle sweep, close) without needing
// real sudo/usermod/PTY access.
func addTestSession(h *Handler, id, ttyUser string, lastActivity time.Time) *terminalSession {
	ts := &terminalSession{
		id:           id,
		ttyUser:      ttyUser,
		lastActivity: lastActivity,
	}
	h.mu.Lock()
	h.terminals[id] = ts
	h.mu.Unlock()
	return ts
}

func TestTerminal_LookupUnknown(t *testing.T) {
	h, _ := newTestHandler(t)
	if got := h.lookupTerminal("nope"); got != nil {
		t.Errorf("lookupTerminal(unknown) = %v, want nil", got)
	}
}

func TestTerminal_OnInput_UnknownIsNoOp(t *testing.T) {
	h, _ := newTestHandler(t)
	err := h.OnTerminalInput(context.Background(), &pb.TerminalInput{
		SessionId: "01ABC",
		Data:      []byte("hello"),
	})
	if err != nil {
		t.Errorf("OnTerminalInput(unknown) = %v, want nil", err)
	}
}

func TestTerminal_OnResize_UnknownIsNoOp(t *testing.T) {
	h, _ := newTestHandler(t)
	err := h.OnTerminalResize(context.Background(), &pb.TerminalResize{
		SessionId: "01ABC",
		Cols:      120,
		Rows:      40,
	})
	if err != nil {
		t.Errorf("OnTerminalResize(unknown) = %v, want nil", err)
	}
}

func TestTerminal_OnStop_UnknownIsNoOp(t *testing.T) {
	h, _ := newTestHandler(t)
	err := h.OnTerminalStop(context.Background(), &pb.TerminalStop{SessionId: "01ABC"})
	if err != nil {
		t.Errorf("OnTerminalStop(unknown) = %v, want nil", err)
	}
}

func TestTerminal_CloseRemovesFromRegistry(t *testing.T) {
	h, _ := newTestHandler(t)
	addTestSession(h, "01ABC", "pm-tty-test", time.Now())

	if got := len(h.terminals); got != 1 {
		t.Fatalf("len(terminals) before close = %d, want 1", got)
	}

	h.closeTerminal(context.Background(), "01ABC", "")

	if got := len(h.terminals); got != 0 {
		t.Errorf("len(terminals) after close = %d, want 0", got)
	}
	if got := h.lookupTerminal("01ABC"); got != nil {
		t.Error("lookup after close should return nil")
	}
}

func TestTerminal_CloseIsIdempotent(t *testing.T) {
	h, _ := newTestHandler(t)
	addTestSession(h, "01ABC", "pm-tty-test", time.Now())

	h.closeTerminal(context.Background(), "01ABC", "")
	// Second close should be a clean no-op (no panic, no error path).
	h.closeTerminal(context.Background(), "01ABC", "")

	if got := len(h.terminals); got != 0 {
		t.Errorf("len(terminals) = %d, want 0", got)
	}
}

func TestTerminal_SweepIdle_ClosesStaleSessions(t *testing.T) {
	h, _ := newTestHandler(t)
	// Force a tight idle window so the test runs without sleeping
	// for the default 30 minutes.
	h.mu.Lock()
	h.terminalIdleTimeout = 50 * time.Millisecond
	h.mu.Unlock()

	stale := time.Now().Add(-1 * time.Hour)
	fresh := time.Now()
	addTestSession(h, "stale", "pm-tty-a", stale)
	addTestSession(h, "fresh", "pm-tty-b", fresh)

	h.sweepIdleTerminals()

	if h.lookupTerminal("stale") != nil {
		t.Error("stale session should have been swept")
	}
	if h.lookupTerminal("fresh") == nil {
		t.Error("fresh session should still be present")
	}
}

func TestTerminal_SweepIdle_LeavesEverythingWhenNothingIsStale(t *testing.T) {
	h, _ := newTestHandler(t)
	h.mu.Lock()
	h.terminalIdleTimeout = 1 * time.Hour
	h.mu.Unlock()

	addTestSession(h, "a", "pm-tty-a", time.Now())
	addTestSession(h, "b", "pm-tty-b", time.Now())

	h.sweepIdleTerminals()

	if got := len(h.terminals); got != 2 {
		t.Errorf("len(terminals) after no-op sweep = %d, want 2", got)
	}
}

func TestTerminal_SetTerminalSender_AppliesDefaults(t *testing.T) {
	h := &Handler{
		logger:      slog.Default(),
		connectedCh: make(chan struct{}),
	}
	h.SetTerminalSender(&fakeSender{})

	if h.terminalLimit != defaultTerminalLimit {
		t.Errorf("terminalLimit = %d, want %d", h.terminalLimit, defaultTerminalLimit)
	}
	if h.terminalIdleTimeout != defaultTerminalIdleTimeout {
		t.Errorf("terminalIdleTimeout = %v, want %v", h.terminalIdleTimeout, defaultTerminalIdleTimeout)
	}
	if h.terminals == nil {
		t.Error("terminals map should be initialized")
	}
	if !h.terminalSweeperStarted {
		t.Error("sweeper should have been started")
	}
}

func TestTerminal_SetTerminalSender_DoesNotResetExistingValues(t *testing.T) {
	h := &Handler{
		logger:              slog.Default(),
		connectedCh:         make(chan struct{}),
		terminalLimit:       7,
		terminalIdleTimeout: 5 * time.Minute,
	}
	h.SetTerminalSender(&fakeSender{})

	if h.terminalLimit != 7 {
		t.Errorf("terminalLimit was reset to %d", h.terminalLimit)
	}
	if h.terminalIdleTimeout != 5*time.Minute {
		t.Errorf("terminalIdleTimeout was reset to %v", h.terminalIdleTimeout)
	}
}

// failTerminalStart should send STATE_ERROR via the sender. The
// validation/limit/duplicate paths in OnTerminalStart all funnel
// through this helper.
func TestTerminal_FailStart_EmitsErrorState(t *testing.T) {
	h, sender := newTestHandler(t)
	h.failTerminalStart(context.Background(), "01ABC", "test failure")

	last := sender.lastState()
	if last == nil {
		t.Fatal("expected a state change to be sent")
	}
	if last.SessionId != "01ABC" {
		t.Errorf("session_id = %q, want 01ABC", last.SessionId)
	}
	if last.State != pb.TerminalSessionState_TERMINAL_SESSION_STATE_ERROR {
		t.Errorf("state = %v, want ERROR", last.State)
	}
	if last.Error != "test failure" {
		t.Errorf("error = %q, want %q", last.Error, "test failure")
	}
}
