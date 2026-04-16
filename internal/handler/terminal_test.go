package handler

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/manchtools/power-manage/agent/internal/store"
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
	// Default to a TTY-enabled store so existing tests exercise the
	// full start path without being blocked by the toggle gate. Tests
	// that want to exercise the gate itself use newTestHandlerWithTTY.
	return newTestHandlerWithTTY(t, true)
}

func newTestHandlerWithTTY(t *testing.T, ttyEnabled bool) (*Handler, *fakeSender) {
	t.Helper()
	st, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("new store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	if err := st.SetTTYEnabled(ttyEnabled); err != nil {
		t.Fatalf("set tty toggle: %v", err)
	}
	h := &Handler{
		logger:      slog.Default(),
		connectedCh: make(chan struct{}),
		store:       st,
	}
	sender := &fakeSender{}
	h.SetTerminalSender(sender)
	return h, sender
}

// addTestSession injects a fake active session into the registry
// without going through OnTerminalStart, so tests can exercise
// registry behaviour (limits, lookup, idle sweep, close) without
// needing real sudo/usermod/PTY access. The session is created in
// the active state so the idle sweeper picks it up the same way it
// would for a real running session.
func addTestSession(h *Handler, id, ttyUser string, lastActivity time.Time) *terminalSession {
	ts := &terminalSession{
		id:           id,
		ttyUser:      ttyUser,
		state:        sessionStateActive,
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

// failTerminalStart should send STATE_ERROR via the supplied sender.
// The validation/limit/duplicate paths in OnTerminalStart all funnel
// through this helper, passing the sender they snapshotted at the
// start of the call so the helper never has to re-acquire h.mu.
func TestTerminal_FailStart_EmitsErrorState(t *testing.T) {
	h, sender := newTestHandler(t)
	h.failTerminalStart(context.Background(), sender, "01ABC", "test failure")

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

// OnTerminalStart must reject any TTY username that does not start
// with the dedicated pm-tty- prefix, even when the username is
// otherwise syntactically valid. This guards against the agent ever
// operating on an arbitrary system account if the control server's
// resolution is buggy or compromised.
func TestTerminal_Start_RejectsNonPrefixedUsername(t *testing.T) {
	h, sender := newTestHandler(t)
	err := h.OnTerminalStart(context.Background(), &pb.TerminalStart{
		SessionId: "01ABC",
		TtyUser:   "alice", // valid syntax, NOT a pm-tty-* user
		Cols:      80,
		Rows:      24,
	})
	if err != nil {
		t.Fatalf("OnTerminalStart returned %v", err)
	}
	last := sender.lastState()
	if last == nil {
		t.Fatal("expected STATE_ERROR for non-prefixed username")
	}
	if last.State != pb.TerminalSessionState_TERMINAL_SESSION_STATE_ERROR {
		t.Errorf("state = %v, want ERROR", last.State)
	}
	if !strings.Contains(last.Error, "invalid tty username") {
		t.Errorf("error = %q, want substring 'invalid tty username'", last.Error)
	}
	// The session must NOT have been registered, so a subsequent
	// limit check still has room.
	if got := len(h.terminals); got != 0 {
		t.Errorf("registry should be empty, got %d entries", got)
	}
}

// OnTerminalStart must reject all sessions when the device-local TTY
// toggle is off. The rejection uses an opaque error message so the
// server cannot distinguish "disabled" from other failure modes.
func TestTerminal_Start_RejectsWhenTTYDisabled(t *testing.T) {
	h, sender := newTestHandlerWithTTY(t, false)
	err := h.OnTerminalStart(context.Background(), &pb.TerminalStart{
		SessionId: "01ABC",
		TtyUser:   "pm-tty-test",
		Cols:      80,
		Rows:      24,
	})
	if err != nil {
		t.Fatalf("OnTerminalStart returned %v", err)
	}
	last := sender.lastState()
	if last == nil {
		t.Fatal("expected STATE_ERROR when TTY is disabled")
	}
	if last.State != pb.TerminalSessionState_TERMINAL_SESSION_STATE_ERROR {
		t.Errorf("state = %v, want ERROR", last.State)
	}
	if !strings.Contains(last.Error, "disabled on this device") {
		t.Errorf("error = %q, want opaque disabled message", last.Error)
	}
	if got := len(h.terminals); got != 0 {
		t.Errorf("registry should be empty, got %d entries", got)
	}
}

// A handler constructed without a store must fail-closed — any
// TerminalStart request is rejected. This protects against a wiring
// regression where the handler is created before the store.
func TestTerminal_Start_RejectsWhenStoreMissing(t *testing.T) {
	h := &Handler{
		logger:      slog.Default(),
		connectedCh: make(chan struct{}),
		// intentionally no store
	}
	sender := &fakeSender{}
	h.SetTerminalSender(sender)

	err := h.OnTerminalStart(context.Background(), &pb.TerminalStart{
		SessionId: "01ABC",
		TtyUser:   "pm-tty-test",
		Cols:      80,
		Rows:      24,
	})
	if err != nil {
		t.Fatalf("OnTerminalStart returned %v", err)
	}
	last := sender.lastState()
	if last == nil {
		t.Fatal("expected STATE_ERROR when store is missing")
	}
	if last.State != pb.TerminalSessionState_TERMINAL_SESSION_STATE_ERROR {
		t.Errorf("state = %v, want ERROR", last.State)
	}
	if !strings.Contains(last.Error, "disabled on this device") {
		t.Errorf("error = %q, want opaque disabled message", last.Error)
	}
}

// closeTerminal on a session that's still in the starting state
// must transition it to stopping (not delete it from the registry —
// OnTerminalStart owns cleanup of partial state). The session must
// have its cancel func invoked so any in-flight sudo call wakes up.
func TestTerminal_CloseDuringStart_MarksStoppingButLeavesRegistryEntry(t *testing.T) {
	h, _ := newTestHandler(t)

	cancelCalled := make(chan struct{}, 1)
	_, cancel := context.WithCancel(context.Background())
	wrappedCancel := func() {
		cancel()
		select {
		case cancelCalled <- struct{}{}:
		default:
		}
	}
	ts := &terminalSession{
		id:      "01ABC",
		ttyUser: "pm-tty-test",
		state:   sessionStateStarting,
		cancel:  wrappedCancel,
	}
	h.mu.Lock()
	h.terminals["01ABC"] = ts
	h.mu.Unlock()

	h.closeTerminal(context.Background(), "01ABC", "user stopped")

	// State must be stopping.
	if !ts.isStopping() {
		t.Error("expected session state = stopping after close-during-start")
	}
	// Cancel must have been invoked.
	select {
	case <-cancelCalled:
	default:
		t.Error("expected ts.cancel to have been called")
	}
	// Registry entry must still be present so OnTerminalStart can see
	// the state on its next isStopping() check and clean up.
	if h.lookupTerminal("01ABC") == nil {
		t.Error("registry entry must still be present until Start cleans up")
	}
}

// closeTerminal on an active session must delete it from the
// registry and proceed with the full cleanup path. (Mirror of the
// existing TestTerminal_CloseRemovesFromRegistry test, but explicit
// about the new state-aware path.)
func TestTerminal_CloseDuringActive_RemovesFromRegistry(t *testing.T) {
	h, _ := newTestHandler(t)
	addTestSession(h, "01ABC", "pm-tty-test", time.Now())

	h.closeTerminal(context.Background(), "01ABC", "")

	if h.lookupTerminal("01ABC") != nil {
		t.Error("active session should have been removed from registry")
	}
}

// SetTerminalSender's race-safe snapshot path must be used by
// OnTerminalStart. We cannot trivially exercise the race itself in a
// unit test, but we can confirm that snapshotTerminalSender returns
// the most recently installed value under the lock.
func TestTerminal_SnapshotTerminalSender_ReturnsLatest(t *testing.T) {
	h := &Handler{
		logger:      slog.Default(),
		connectedCh: make(chan struct{}),
	}
	if got := h.snapshotTerminalSender(); got != nil {
		t.Errorf("snapshot before SetTerminalSender = %v, want nil", got)
	}

	first := &fakeSender{}
	h.SetTerminalSender(first)
	if got := h.snapshotTerminalSender(); got != first {
		t.Errorf("snapshot = %v, want first sender", got)
	}

	second := &fakeSender{}
	h.SetTerminalSender(second)
	if got := h.snapshotTerminalSender(); got != second {
		t.Errorf("snapshot = %v, want second sender (latest wins)", got)
	}
}

// anySessionForUserExcept correctly returns true when another active
// session for the same TTY user exists, and false otherwise. This
// powers the OnTerminalStart cleanup path's decision about whether
// to revert the user's shell.
func TestTerminal_AnySessionForUserExcept(t *testing.T) {
	h, _ := newTestHandler(t)
	addTestSession(h, "a", "pm-tty-alice", time.Now())
	addTestSession(h, "b", "pm-tty-alice", time.Now())
	addTestSession(h, "c", "pm-tty-bob", time.Now())

	if !h.anySessionForUserExcept("pm-tty-alice", "a") {
		t.Error("session b for alice should be visible when excluding a")
	}
	if h.anySessionForUserExcept("pm-tty-alice", "a") && !h.anySessionForUserExcept("pm-tty-alice", "b") {
		// trivially true; here for symmetry
	}
	if h.anySessionForUserExcept("pm-tty-bob", "c") {
		t.Error("excluding the only bob session should return false")
	}
	if h.anySessionForUserExcept("pm-tty-eve", "any") {
		t.Error("user with no sessions should return false")
	}
}
