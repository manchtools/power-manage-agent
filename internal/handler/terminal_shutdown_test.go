package handler

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// WS16 #5: live terminal sessions were not torn down on agent shutdown — the
// pm-tty shell stayed activated and the temp home leaked. CloseAllTerminals
// reverts every live session.

// registerLiveSession injects an active session with a real temp home and a
// cancel spy, mirroring addTestSession but with the teardown-observable fields.
func registerLiveSession(t *testing.T, h *Handler, id, ttyUser string, cancelled *int32) string {
	t.Helper()
	tempHome := filepath.Join(t.TempDir(), "home-"+id)
	if err := os.MkdirAll(tempHome, 0o700); err != nil {
		t.Fatalf("mkdir temp home: %v", err)
	}
	ts := &terminalSession{
		id:       id,
		ttyUser:  ttyUser,
		state:    sessionStateActive,
		tempHome: tempHome,
		cancel:   func() { atomic.StoreInt32(cancelled, 1) },
		now:      time.Now,
	}
	h.mu.Lock()
	if h.terminals == nil {
		h.terminals = make(map[string]*terminalSession)
	}
	h.terminals[id] = ts
	h.mu.Unlock()
	return tempHome
}

func TestCloseAllTerminals_RevertsLiveSessions(t *testing.T) {
	h, _ := newTestHandler(t)

	var cancelledA, cancelledB int32
	homeA := registerLiveSession(t, h, "01ARZ3NDEKTSV4RRFFQ69G5FAV", "pm-tty-a", &cancelledA)
	homeB := registerLiveSession(t, h, "01ARZ3NDEKTSV4RRFFQ69G5FAW", "pm-tty-b", &cancelledB)

	h.CloseAllTerminals(context.Background())

	// Registry must be empty — every live session was closed.
	h.mu.Lock()
	n := len(h.terminals)
	h.mu.Unlock()
	if n != 0 {
		t.Errorf("registry has %d sessions after CloseAllTerminals, want 0", n)
	}

	// Each session's ctx must have been cancelled (so its pump goroutine unblocks).
	if atomic.LoadInt32(&cancelledA) != 1 || atomic.LoadInt32(&cancelledB) != 1 {
		t.Error("CloseAllTerminals did not cancel every session context")
	}

	// Temp homes must be removed.
	for _, home := range []string{homeA, homeB} {
		if _, err := os.Stat(home); !os.IsNotExist(err) {
			t.Errorf("temp home %s not removed (stat err=%v)", home, err)
		}
	}
}

func TestCloseAllTerminals_NoSessions_IsNoOp(t *testing.T) {
	h, _ := newTestHandler(t)
	// Must not panic with an empty/unset registry.
	h.CloseAllTerminals(context.Background())

	h.mu.Lock()
	n := len(h.terminals)
	h.mu.Unlock()
	if n != 0 {
		t.Errorf("registry should be empty, got %d", n)
	}
}

func TestCloseAllTerminals_AlreadyStopping_NotDoubleReverted(t *testing.T) {
	h, _ := newTestHandler(t)

	tempHome := filepath.Join(t.TempDir(), "stopping-home")
	if err := os.MkdirAll(tempHome, 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	ts := &terminalSession{
		id:       "01ARZ3NDEKTSV4RRFFQ69G5FAX",
		ttyUser:  "pm-tty-stop",
		state:    sessionStateStopping, // already being torn down elsewhere
		tempHome: tempHome,
		now:      time.Now,
	}
	h.mu.Lock()
	h.terminals[ts.id] = ts
	h.mu.Unlock()

	h.CloseAllTerminals(context.Background())

	// A session already in the stopping state must NOT be torn down again:
	// its temp home stays (the in-flight teardown owns it).
	if _, err := os.Stat(tempHome); err != nil {
		t.Errorf("a stopping session must not be double-reverted; temp home gone: %v", err)
	}
}

// TestMain_ShutdownClosesLiveTerminals is a self-discovering guard: the agent
// main shutdown path must invoke CloseAllTerminals, or a session left open at
// shutdown leaks its activated shell. Fails if the caller is removed.
func TestMain_ShutdownClosesLiveTerminals(t *testing.T) {
	src, err := os.ReadFile("../../cmd/power-manage-agent/main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	if len(src) == 0 {
		t.Fatal("main.go empty — guard would pass vacuously")
	}
	if !strings.Contains(string(src), "CloseAllTerminals(") {
		t.Error("agent main shutdown must call h.CloseAllTerminals (WS16 #5)")
	}
}
