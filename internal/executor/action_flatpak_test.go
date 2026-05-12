package executor

import (
	"bytes"
	"context"
	"log/slog"
	"os/exec"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// TestExecuteFlatpak_SystemWideFalseLogsCoercion guards the #79 fix:
// SystemWide=false used to route through `flatpak --user` under sudo,
// landing apps in /root/.local/share/flatpak where no desktop user
// could see them. The fix coerces SystemWide=false to a system-wide
// install + a Warn line so operators see their assignment got
// silently corrected instead of running in a broken-but-quiet state.
//
// Skipped on hosts without flatpak — the executor short-circuits to
// "skipped: flatpak not available" before reaching the coercion log.
func TestExecuteFlatpak_SystemWideFalseLogsCoercion(t *testing.T) {
	if _, err := exec.LookPath("flatpak"); err != nil {
		t.Skip("flatpak is not available on this system — coercion warn fires after the lookup, so skip")
	}

	var buf bytes.Buffer
	e := NewExecutor(nil)
	e.logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, _, _ = e.executeFlatpak(context.Background(), &pb.FlatpakParams{
		AppId:      "org.nonexistent.surely_does_not_exist_12345",
		SystemWide: false,
	}, pb.DesiredState_DESIRED_STATE_PRESENT)

	got := buf.String()
	if !strings.Contains(got, "level=WARN") {
		t.Errorf("expected WARN-level coercion log when SystemWide=false, got:\n%s", got)
	}
	if !strings.Contains(got, "SystemWide=false coerced") {
		t.Errorf("expected coercion warn body, got:\n%s", got)
	}
	if !strings.Contains(got, "org.nonexistent.surely_does_not_exist_12345") {
		t.Errorf("expected app_id in the coercion warn so operators can locate the assignment, got:\n%s", got)
	}
}

// TestExecuteFlatpak_SystemWideTrueDoesNotCoerce verifies the
// happy-path stays silent — SystemWide=true is the supported config
// and must not trigger the warn intended for the broken case.
func TestExecuteFlatpak_SystemWideTrueDoesNotCoerce(t *testing.T) {
	if _, err := exec.LookPath("flatpak"); err != nil {
		t.Skip("flatpak is not available on this system")
	}

	var buf bytes.Buffer
	e := NewExecutor(nil)
	e.logger = slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	_, _, _ = e.executeFlatpak(context.Background(), &pb.FlatpakParams{
		AppId:      "org.nonexistent.surely_does_not_exist_12345",
		SystemWide: true,
	}, pb.DesiredState_DESIRED_STATE_PRESENT)

	if strings.Contains(buf.String(), "SystemWide=false coerced") {
		t.Errorf("SystemWide=true must not trigger the coercion warn, got:\n%s", buf.String())
	}
}
