package executor

import (
	"context"
	"testing"
)

// WS7 #7: compareAgentVersion parses vYYYY.MM.PP and orders releases.
// Comparisons sourced from the documented scheme, not the parser.
func TestCompareAgentVersion_Table(t *testing.T) {
	cases := []struct {
		a, b string
		want int // sign of compare(a,b): -1 a<b, 0 equal, +1 a>b
	}{
		{"v2026.06.01", "v2026.06.02", -1},
		{"v2026.06.02", "v2026.06.01", 1},
		{"v2026.06.01", "v2026.06.01", 0},
		{"2026.06.01", "v2026.06.01", 0}, // leading v optional
		{"v2026.10.00", "v2026.09.99", 1},
		{"v2027.01.00", "v2026.12.31", 1},
		{"v2026.06.10", "v2026.06.09", 1},
	}
	for _, tc := range cases {
		got, err := compareAgentVersion(tc.a, tc.b)
		if err != nil {
			t.Errorf("compareAgentVersion(%q,%q) error: %v", tc.a, tc.b, err)
			continue
		}
		if sign(got) != tc.want {
			t.Errorf("compareAgentVersion(%q,%q) sign = %d, want %d", tc.a, tc.b, sign(got), tc.want)
		}
	}

	// Malformed → error (never silently treated as comparable).
	for _, bad := range []string{"", "garbage", "v2026.06", "v2026.06.01.02", "vYYYY.MM.PP", "2026-06-01"} {
		if _, err := compareAgentVersion("v2026.06.01", bad); err == nil {
			t.Errorf("compareAgentVersion with malformed %q must error", bad)
		}
	}
}

func sign(n int) int {
	switch {
	case n < 0:
		return -1
	case n > 0:
		return 1
	default:
		return 0
	}
}

// WS7 #7: a staged binary OLDER than the running version is refused
// (anti-rollback), unchanged binary, no shutdown — unless allow_downgrade
// is set in the signed action.
func TestExecuteAgentUpdate_RefusesOlderVersion(t *testing.T) {
	staged := agentScript("v2026.05.01", 0)
	h := newUpdateHarness(t, "v2026.06.02", staged, nil) // running newer than staged

	_, changed, err := h.e.executeAgentUpdate(context.Background(), h.params(sha256hex(staged)))
	if err == nil {
		t.Fatal("a downgrade must be refused by default")
	}
	if changed {
		t.Error("changed must be false on a refused downgrade")
	}
	if got := h.currentBinary(t); string(got) != string(h.oldBytes) {
		t.Error("live binary must be unchanged on a refused downgrade")
	}
}

// A malformed staged version is refused fail-closed (never treated as
// newer).
func TestExecuteAgentUpdate_RefusesMalformedVersion(t *testing.T) {
	staged := agentScript("garbage", 0)
	h := newUpdateHarness(t, "v2026.06.02", staged, nil)

	_, changed, err := h.e.executeAgentUpdate(context.Background(), h.params(sha256hex(staged)))
	if err == nil {
		t.Fatal("an unparseable staged version must be refused fail-closed")
	}
	if changed {
		t.Error("changed must be false")
	}
}

// A malformed RUNNING version is also refused fail-closed — if the agent
// cannot parse its own version it cannot prove the candidate is not a
// downgrade, so it must not swap.
func TestExecuteAgentUpdate_RefusesMalformedRunningVersion(t *testing.T) {
	staged := agentScript("v2026.06.02", 0)
	h := newUpdateHarness(t, "garbage", staged, nil) // running version unparseable

	_, changed, err := h.e.executeAgentUpdate(context.Background(), h.params(sha256hex(staged)))
	if err == nil {
		t.Fatal("an unparseable running version must be refused fail-closed")
	}
	if changed {
		t.Error("changed must be false")
	}
	if got := h.currentBinary(t); string(got) != string(h.oldBytes) {
		t.Error("live binary must be unchanged when the running version is unparseable")
	}
}

// allow_downgrade in the signed action is the ONLY bypass: an older staged
// version then proceeds (swaps + shuts down).
func TestExecuteAgentUpdate_AllowDowngradeBypass(t *testing.T) {
	staged := agentScript("v2026.05.01", 0)
	h := newUpdateHarness(t, "v2026.06.02", staged, nil)
	p := h.params(sha256hex(staged))
	p.AllowDowngrade = true

	_, changed, err := h.e.executeAgentUpdate(context.Background(), p)
	if err != nil {
		t.Fatalf("allow_downgrade should permit an older version: %v", err)
	}
	if !changed {
		t.Error("changed must be true when allow_downgrade permits the swap")
	}
	if got := h.currentBinary(t); string(got) != string(staged) {
		t.Error("binary must be swapped to the (older) staged bytes under allow_downgrade")
	}
}
