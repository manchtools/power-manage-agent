package executor

import (
	"bytes"
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// TestRunShellScript_RunAsRootFalseNoSessions pins the empty-set
// policy for #79's shell fan-out: when RunAsRoot=false and nobody
// is signed in, the action returns success no-op + a Warn rather
// than the pre-fix "silently runs as the agent's UID (root)"
// behavior. Without this guard an admin who turned off RunAsRoot
// would still see effectively-root behavior with no diagnostic.
func TestRunShellScript_RunAsRootFalseNoSessions(t *testing.T) {
	sessions, err := desktopMgr.ActiveSessions(context.Background())
	if err != nil {
		t.Skipf("loginctl probe failed (%v) — skipping rather than asserting against an unknown session state", err)
	}
	if len(sessions) > 0 {
		t.Skipf("host has %d active desktop session(s) — empty-set branch not reachable here", len(sessions))
	}

	var buf bytes.Buffer
	e := NewExecutor(nil, nil)
	e.logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	out, err := e.runShellScript(context.Background(), &pb.ShellParams{
		Script:    "echo hello",
		RunAsRoot: false,
	}, "echo hello", nil)

	if err != nil {
		t.Fatalf("expected no error on empty-session per-user shell (no-op success), got: %v", err)
	}
	if out == nil || !strings.Contains(out.Stdout, "no signed-in desktop users") {
		t.Errorf("expected stdout to explain the empty-set deferral, got: %#v", out)
	}
	if !strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("expected WARN log on per-user shell with no signed-in users, got:\n%s", buf.String())
	}
}

// TestRunShellScript_RunAsRootFalseDispatchesToLoop is the
// complement when sessions ARE present: verify the script actually
// runs per-user and the streamed output is tagged with a
// `[user=<name>] ` prefix so downstream log consumers can attribute
// lines back to the right account. We don't pin the script's
// stdout content — the goal is to pin the prefix shape and confirm
// the dispatch reached the per-user runner at all.
func TestRunShellScript_RunAsRootFalseDispatchesToLoop(t *testing.T) {
	if os.Geteuid() != 0 {
		// runuser requires root to switch users — without it the
		// per-user fan-out fails before any script output reaches
		// us. The agent runs as root in production so this test
		// exercises real behavior in privileged CI; locally a
		// developer sees a skip rather than a meaningless failure.
		t.Skip("runuser requires root to switch users; run this test under privileged CI")
	}
	sessions, err := desktopMgr.ActiveSessions(context.Background())
	if err != nil {
		t.Skipf("loginctl probe failed (%v)", err)
	}
	if len(sessions) == 0 {
		t.Skip("no active desktop sessions — TestRunShellScript_RunAsRootFalseNoSessions covers the empty-set path here")
	}

	e := NewExecutor(nil, nil)
	out, err := e.runShellScript(context.Background(), &pb.ShellParams{
		// `id -un` prints the username; if the per-user fan-out
		// works, the merged stdout will contain the desktop user's
		// name, NOT root. That difference is the load-bearing
		// behavioral pin for #79 — exactly the bug the fix
		// addresses.
		Script:    "id -un",
		RunAsRoot: false,
	}, "id -un", nil)

	if err != nil {
		// Per-user execution can fail if runuser isn't available
		// (extremely unusual) or if PAM rejects the impersonation —
		// but the dispatch path is what we're pinning here, not the
		// happy-path end-to-end execution. Surface the failure but
		// don't abort the assertion below.
		t.Logf("per-user shell execution returned error (still asserting dispatch shape): %v", err)
	}
	if out == nil {
		t.Fatal("expected non-nil output from per-user dispatch")
	}
	if !strings.Contains(out.Stdout, "[user=") {
		t.Errorf("expected per-user prefix `[user=<name>] ` in merged stdout, got: %q", out.Stdout)
	}
	if strings.Contains(out.Stdout, "[user=root]") {
		t.Errorf("RunAsRoot=false must NOT impersonate root via the per-user fan-out path; output was: %q", out.Stdout)
	}
}

// TestStripHomeAndUser pins the env-cleanup helper that runs before
// per-user fan-out: HOME/USER from the agent's env baseline are
// dropped because runAsUserStreaming sets per-user values via
// desktop.EnvFor. Pin the absence so a future refactor doesn't
// regress and start sending mismatched HOME/USER pairs (the
// per-user one wins via Go's last-write-wins, but the duplicate is
// noise in audit logs and confuses reviewers).
func TestStripHomeAndUser(t *testing.T) {
	in := []string{
		"PATH=/usr/bin:/bin",
		"HOME=/root",
		"LANG=en_US.UTF-8",
		"USER=root",
		"FLATPAK_USER_DIR=/foo",
	}
	got := stripHomeAndUser(in)
	for _, e := range got {
		if strings.HasPrefix(e, "HOME=") {
			t.Errorf("HOME entry survived strip: %q (full: %v)", e, got)
		}
		if strings.HasPrefix(e, "USER=") {
			t.Errorf("USER entry survived strip: %q (full: %v)", e, got)
		}
	}
	want := []string{"PATH=/usr/bin:/bin", "LANG=en_US.UTF-8", "FLATPAK_USER_DIR=/foo"}
	if len(got) != len(want) {
		t.Fatalf("got %d entries after strip, want %d (got=%v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d: got %q, want %q", i, got[i], want[i])
		}
	}
}
