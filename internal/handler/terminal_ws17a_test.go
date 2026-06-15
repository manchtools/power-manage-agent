package handler

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
	sysuser "github.com/manchtools/power-manage/sdk/go/sys/user"
)

func ws17aULID() string { return ulid.Make().String() }

// The IsValidName conjunct of the username guard is exercised independently of
// the HasPrefix conjunct the existing test covers: usernames that HAVE the
// pm-tty- prefix but FAIL IsValidName (uppercase, separators, control chars,
// over length) must be refused with STATE_ERROR before any system call, and no
// session may be registered. The wrong inputs are sourced from the IsValidName
// contract (lowercase letters/digits/_/-, ≤32 chars), not from the regex.
func TestTerminal_Start_RejectsPrefixedButInvalidUsername(t *testing.T) {
	cases := map[string]string{
		"uppercase":  "pm-tty-Abc",
		"slash":      "pm-tty-a/b",
		"newline":    "pm-tty-a\nb",
		"colon":      "pm-tty-a:b",
		"over-32":    "pm-tty-" + strings.Repeat("a", 40),
		"whitespace": "pm-tty-a b",
	}
	for name, user := range cases {
		t.Run(name, func(t *testing.T) {
			h, sender := newTestHandler(t)
			err := h.OnTerminalStart(context.Background(), &pb.TerminalStart{
				SessionId: ws17aULID(), // valid ULID so the failure is the username, not the id
				TtyUser:   user,
				Cols:      80,
				Rows:      24,
			})
			if err != nil {
				t.Fatalf("OnTerminalStart returned %v", err)
			}
			last := sender.lastState()
			if last == nil || last.State != pb.TerminalSessionState_TERMINAL_SESSION_STATE_ERROR {
				t.Fatalf("expected STATE_ERROR, got %v", last)
			}
			if !strings.Contains(last.Error, "invalid tty username") {
				t.Errorf("error = %q, want 'invalid tty username'", last.Error)
			}
			if got := len(h.terminals); got != 0 {
				t.Errorf("registry must stay empty, got %d entries", got)
			}
		})
	}
}

// session_id flows into filepath.Join("/tmp", ttyUser+"."+session_id) and is
// then created + chowned as root. It must be a valid ULID (the proto declares
// validate:"required,ulid"); the agent must enforce that on inbound stream
// messages. Cases are sourced from ULID intent (path-meaningful values, the
// empty string, wrong length), not from ulid.Parse's own rules.
func TestTerminal_Start_RejectsNonUlidSessionId(t *testing.T) {
	bad := map[string]string{
		"parent-traversal": "../../etc",
		"embedded-slash":   "a/b",
		"dotted":           "a.b",
		"empty":            "",
		"too-long":         strings.Repeat("Z", 40),
		"embedded-nul":     "01ARZ3NDEKTSV4RRFFQ69G5F\x00",
	}
	for name, sid := range bad {
		t.Run(name, func(t *testing.T) {
			h, sender := newTestHandler(t)
			err := h.OnTerminalStart(context.Background(), &pb.TerminalStart{
				SessionId: sid,
				TtyUser:   "pm-tty-test",
				Cols:      80,
				Rows:      24,
			})
			if err != nil {
				t.Fatalf("OnTerminalStart returned %v", err)
			}
			last := sender.lastState()
			if last == nil || last.State != pb.TerminalSessionState_TERMINAL_SESSION_STATE_ERROR {
				t.Fatalf("expected STATE_ERROR for session id %q, got %v", sid, last)
			}
			if !strings.Contains(last.Error, "invalid session id") {
				t.Errorf("error = %q, want 'invalid session id'", last.Error)
			}
			if got := len(h.terminals); got != 0 {
				t.Errorf("registry must stay empty, got %d entries", got)
			}
		})
	}

	// correct: a real ULID passes the session-id gate (it then fails later for
	// other reasons, but NOT with the session-id message).
	t.Run("valid ULID passes the session-id gate", func(t *testing.T) {
		origGet := sysuserGet
		origModify := sysuserModify
		t.Cleanup(func() { sysuserGet = origGet; sysuserModify = origModify })
		sysuserGet = func(string) (*sysuser.Info, error) { return &sysuser.Info{Locked: false}, nil }
		sysuserModify = func(context.Context, string, ...string) (*sysexec.Result, error) {
			return nil, fmt.Errorf("usermod unavailable in test")
		}
		h, sender := newTestHandler(t)
		err := h.OnTerminalStart(context.Background(), &pb.TerminalStart{
			SessionId: ws17aULID(), TtyUser: "pm-tty-test", Cols: 80, Rows: 24,
		})
		if err != nil {
			t.Fatalf("OnTerminalStart returned %v", err)
		}
		if last := sender.lastState(); last != nil && strings.Contains(last.Error, "invalid session id") {
			t.Errorf("a valid ULID must pass the session-id gate, got %q", last.Error)
		}
	})
}

// The session-limit and duplicate-session guards sit AFTER the real user lookup
// (which shells out), so they are driven through the sysuserGet seam returning a
// healthy account.
func TestTerminal_Start_RejectsAtSessionLimit(t *testing.T) {
	origGet := sysuserGet
	t.Cleanup(func() { sysuserGet = origGet })
	sysuserGet = func(string) (*sysuser.Info, error) { return &sysuser.Info{Locked: false}, nil }

	h, sender := newTestHandler(t)
	h.terminalLimit = 2
	addTestSession(h, ws17aULID(), "pm-tty-test", time.Now())
	addTestSession(h, ws17aULID(), "pm-tty-test", time.Now())

	err := h.OnTerminalStart(context.Background(), &pb.TerminalStart{
		SessionId: ws17aULID(), TtyUser: "pm-tty-test", Cols: 80, Rows: 24,
	})
	if err != nil {
		t.Fatalf("OnTerminalStart returned %v", err)
	}
	last := sender.lastState()
	if last == nil || last.State != pb.TerminalSessionState_TERMINAL_SESSION_STATE_ERROR {
		t.Fatalf("expected STATE_ERROR at the session limit, got %v", last)
	}
	if !strings.Contains(last.Error, "session limit reached") {
		t.Errorf("error = %q, want 'session limit reached'", last.Error)
	}
	if got := len(h.terminals); got != 2 {
		t.Errorf("a rejected over-limit start must not be registered; registry size = %d, want 2", got)
	}
}

func TestTerminal_Start_RejectsDuplicateSession(t *testing.T) {
	origGet := sysuserGet
	t.Cleanup(func() { sysuserGet = origGet })
	sysuserGet = func(string) (*sysuser.Info, error) { return &sysuser.Info{Locked: false}, nil }

	h, sender := newTestHandler(t)
	dup := ws17aULID()
	addTestSession(h, dup, "pm-tty-test", time.Now())

	err := h.OnTerminalStart(context.Background(), &pb.TerminalStart{
		SessionId: dup, TtyUser: "pm-tty-test", Cols: 80, Rows: 24,
	})
	if err != nil {
		t.Fatalf("OnTerminalStart returned %v", err)
	}
	last := sender.lastState()
	if last == nil || last.State != pb.TerminalSessionState_TERMINAL_SESSION_STATE_ERROR {
		t.Fatalf("expected STATE_ERROR for a duplicate session, got %v", last)
	}
	if !strings.Contains(last.Error, "session already exists") {
		t.Errorf("error = %q, want 'session already exists'", last.Error)
	}
	if got := len(h.terminals); got != 1 {
		t.Errorf("the duplicate must not add a second entry; registry size = %d, want 1", got)
	}
}

// A locked/disabled pm-tty-* user must be refused; an unlocked user is the
// distinguishing factor — it gets PAST the locked gate (and then fails at shell
// activation, a different error), proving info.Locked is what gates here.
func TestTerminal_Start_RejectsLockedTtyUser(t *testing.T) {
	origGet := sysuserGet
	origModify := sysuserModify
	t.Cleanup(func() { sysuserGet = origGet; sysuserModify = origModify })

	t.Run("locked user is rejected, nothing reserved", func(t *testing.T) {
		sysuserGet = func(string) (*sysuser.Info, error) { return &sysuser.Info{Locked: true}, nil }
		h, sender := newTestHandler(t)
		err := h.OnTerminalStart(context.Background(), &pb.TerminalStart{
			SessionId: ws17aULID(), TtyUser: "pm-tty-test", Cols: 80, Rows: 24,
		})
		if err != nil {
			t.Fatalf("OnTerminalStart returned %v", err)
		}
		last := sender.lastState()
		if last == nil || last.State != pb.TerminalSessionState_TERMINAL_SESSION_STATE_ERROR {
			t.Fatalf("expected STATE_ERROR for a locked user, got %v", last)
		}
		if !strings.Contains(last.Error, "is disabled") {
			t.Errorf("error = %q, want 'is disabled'", last.Error)
		}
		if got := len(h.terminals); got != 0 {
			t.Errorf("a locked-user rejection must reserve no slot, got %d", got)
		}
	})

	t.Run("unlocked user passes the locked gate (fails later at shell activation)", func(t *testing.T) {
		sysuserGet = func(string) (*sysuser.Info, error) { return &sysuser.Info{Locked: false}, nil }
		sysuserModify = func(context.Context, string, ...string) (*sysexec.Result, error) {
			return nil, fmt.Errorf("usermod boom")
		}
		h, sender := newTestHandler(t)
		err := h.OnTerminalStart(context.Background(), &pb.TerminalStart{
			SessionId: ws17aULID(), TtyUser: "pm-tty-test", Cols: 80, Rows: 24,
		})
		if err != nil {
			t.Fatalf("OnTerminalStart returned %v", err)
		}
		last := sender.lastState()
		if last == nil || last.State != pb.TerminalSessionState_TERMINAL_SESSION_STATE_ERROR {
			t.Fatalf("expected STATE_ERROR at shell activation, got %v", last)
		}
		if strings.Contains(last.Error, "is disabled") {
			t.Errorf("an unlocked user must pass the locked gate, got %q", last.Error)
		}
		if !strings.Contains(last.Error, "activate shell") {
			t.Errorf("error = %q, want it to fail at shell activation (proving the locked gate was passed)", last.Error)
		}
		if got := len(h.terminals); got != 0 {
			t.Errorf("a failed start must unwind its reserved slot, got %d", got)
		}
	})
}
