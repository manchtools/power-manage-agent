package executor

import (
	"bytes"
	"context"
	"log/slog"
	"os/exec"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// TestExecuteFlatpak_PerUserPresentNoSessions guards the empty-set
// policy for #79's per-user install path: when SystemWide=false and
// no graphical session is signed in, the action returns success
// no-op + a Warn naming the app, NOT a silent install into
// /root/.local/share/flatpak (which is what the pre-fix path did).
//
// Skipped on hosts without flatpak (the lookup short-circuit fires
// before the per-user branch) and on hosts that DO have an active
// graphical session — in that case the action correctly enters the
// per-user fan-out loop and the empty-set branch isn't exercised.
// The fan-out loop itself is exercised by the SDK-level tests
// (sdk/go/sys/desktop) and a future end-to-end integration test;
// what matters here is the dispatch + empty-set policy.
func TestExecuteFlatpak_PerUserPresentNoSessions(t *testing.T) {
	if _, err := exec.LookPath("flatpak"); err != nil {
		t.Skip("flatpak is not available on this system; the per-user empty-set branch fires after the lookup")
	}
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

	out, changed, err := e.executeFlatpak(context.Background(), &pb.FlatpakParams{
		AppId:      "org.nonexistent.surely_does_not_exist_pmtest",
		SystemWide: false,
	}, pb.DesiredState_DESIRED_STATE_PRESENT)

	if err != nil {
		t.Fatalf("expected no error on empty-session per-user install (no-op success), got: %v", err)
	}
	if changed {
		t.Errorf("expected changed=false on empty-session no-op, got changed=true")
	}
	if out == nil || !strings.Contains(out.Stdout, "no signed-in desktop users") {
		t.Errorf("expected stdout to explain the empty-set deferral, got: %#v", out)
	}
	if !strings.Contains(buf.String(), "level=WARN") {
		t.Errorf("expected WARN log on per-user install with no signed-in users, got:\n%s", buf.String())
	}
	if !strings.Contains(buf.String(), "deferred until a user signs in") {
		t.Errorf("expected the warn body to explain the action will retry, got:\n%s", buf.String())
	}
}

// TestExecuteFlatpak_PerUserPresentDispatchesToLoop is the
// complement to TestExecuteFlatpak_PerUserPresentNoSessions: when
// graphical sessions are present, verify that the dispatch enters
// the per-user fan-out path (rather than silently no-op'ing or
// falling through to the system-wide branch). We don't assert on
// the install succeeding — flatpak with a nonexistent app will
// always fail, but the failure is per-user-shaped, which is what
// pins the dispatch.
func TestExecuteFlatpak_PerUserPresentDispatchesToLoop(t *testing.T) {
	if _, err := exec.LookPath("flatpak"); err != nil {
		t.Skip("flatpak is not available on this system")
	}
	sessions, err := desktopMgr.ActiveSessions(context.Background())
	if err != nil {
		t.Skipf("loginctl probe failed (%v) — skipping rather than asserting against an unknown session state", err)
	}
	if len(sessions) == 0 {
		t.Skip("no active desktop sessions — TestExecuteFlatpak_PerUserPresentNoSessions covers the empty-set path here")
	}

	e := NewExecutor(nil, nil)
	out, _, _ := e.executeFlatpak(context.Background(), &pb.FlatpakParams{
		AppId:      "org.nonexistent.surely_does_not_exist_pmtest",
		SystemWide: false,
	}, pb.DesiredState_DESIRED_STATE_PRESENT)

	// The per-user loop tags every line with `user=<name>: ...`. If
	// we instead see the system-wide "is already installed" /
	// "is already not installed" wording, the dispatch broke and
	// SystemWide=false silently routed system-wide.
	if out == nil || !strings.Contains(out.Stdout, "user=") {
		t.Errorf("expected per-user fan-out output (lines tagged with user=<name>), got: %#v", out)
	}
}

// TestExecuteFlatpak_PerUserAbsentNoUsers verifies the symmetric
// empty-set path for ABSENT: if no /home/<user> on the box has the
// app installed, the uninstall action is a success no-op (the
// policy is already converged).
func TestExecuteFlatpak_PerUserAbsentNoUsers(t *testing.T) {
	if _, err := exec.LookPath("flatpak"); err != nil {
		t.Skip("flatpak is not available on this system")
	}

	e := NewExecutor(nil, nil)
	out, changed, err := e.executeFlatpak(context.Background(), &pb.FlatpakParams{
		AppId:      "org.nonexistent.surely_does_not_exist_pmtest",
		SystemWide: false,
	}, pb.DesiredState_DESIRED_STATE_ABSENT)

	if err != nil {
		t.Fatalf("expected no error on already-absent per-user uninstall, got: %v", err)
	}
	if changed {
		t.Errorf("expected changed=false when nobody has the app installed, got changed=true")
	}
	if out == nil || !strings.Contains(out.Stdout, "already not installed") {
		t.Errorf("expected stdout to confirm policy is already converged, got: %#v", out)
	}
}

// TestExecuteFlatpak_SystemWideRoutesUnchanged sanity-checks that
// SystemWide=true still flows through the original system path and
// reports a real install error rather than no-op success — the
// dispatch split (#79) must not silently swallow the system-wide
// codepath.
func TestExecuteFlatpak_SystemWideRoutesUnchanged(t *testing.T) {
	if _, err := exec.LookPath("flatpak"); err != nil {
		t.Skip("flatpak is not available on this system")
	}

	e := NewExecutor(nil, nil)
	out, _, err := e.executeFlatpak(context.Background(), &pb.FlatpakParams{
		AppId:      "org.nonexistent.surely_does_not_exist_pmtest",
		SystemWide: true,
	}, pb.DesiredState_DESIRED_STATE_PRESENT)

	if out != nil && strings.Contains(out.Stdout, "no signed-in") {
		t.Errorf("SystemWide=true must not enter the per-user empty-session branch; got %q", out.Stdout)
	}
	if err == nil {
		t.Error("expected real install error for nonexistent app on SystemWide=true path, got nil")
	}
}
