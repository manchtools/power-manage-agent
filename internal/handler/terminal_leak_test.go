package handler

import (
	"context"
	"testing"
	"time"
)

// #173 review finding: removeTerminal only deleted the map entry and
// never cancelled the session context — every start-abort after
// registration (abortFail / abortStopped route through cleanup →
// removeTerminal) leaked its sessionCtx. removeTerminal must cancel.
func TestRemoveTerminal_CancelsSessionContext(t *testing.T) {
	h := &Handler{}
	sessionCtx, cancel := context.WithCancel(context.Background())
	h.terminals = map[string]*terminalSession{
		"s1": {id: "s1", cancel: cancel, now: time.Now},
	}

	h.removeTerminal("s1")

	select {
	case <-sessionCtx.Done():
	default:
		t.Fatal("removeTerminal must cancel the session context — aborted starts leaked it")
	}
	if _, exists := h.terminals["s1"]; exists {
		t.Fatal("session must be removed from the registry")
	}

	// Unknown ids stay a no-op.
	h.removeTerminal("does-not-exist")
}
