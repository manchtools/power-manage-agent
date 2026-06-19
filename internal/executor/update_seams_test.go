package executor

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// interpretUpdateCheck is the pure exit-code/stdout → "updates available?"
// mapping extracted from hasUpdatesAvailable. Driving it with fixtures gives
// every manager — including zypper, which previously only had a logged smoke
// value — a real assertion in both directions. The "wrong" rows (e.g. dnf exit
// 0, apt with no Inst line) are the rejection cases that matter.
func TestInterpretUpdateCheck(t *testing.T) {
	cases := []struct {
		manager  string
		stdout   string
		exitCode int
		want     bool
	}{
		{"dnf", "", 100, true},
		{"dnf", "", 0, false},
		{"apt", "Inst libfoo [1.0] (1.1 stable)\n", 0, true},
		{"apt", "Reading package lists...\nBuilding dependency tree...\n", 0, false},
		{"pacman", "", 0, true},
		{"pacman", "", 1, false},
		{"zypper", "", 100, true},
		{"zypper", "", 0, false},
		{"", "", 0, true},        // unknown manager → assume updates (fail safe)
		{"weirdpm", "", 0, true}, // unknown manager → assume updates (fail safe)
	}
	for _, tc := range cases {
		t.Run(fmt.Sprintf("%s/exit=%d", tc.manager, tc.exitCode), func(t *testing.T) {
			got := interpretUpdateCheck(tc.manager, tc.stdout, tc.exitCode)
			if got != tc.want {
				t.Errorf("interpretUpdateCheck(%q, %q, %d) = %v, want %v",
					tc.manager, tc.stdout, tc.exitCode, got, tc.want)
			}
		})
	}
}

// executeAptUpgrade must fail CLOSED when a security-only update is requested
// but no security-only path exists on the host: the operator asked for
// security-only because their compliance posture forbids the broader upgrade,
// so silently delivering a full apt.Upgrade() is a compliance violation.
func TestExecuteAptUpgrade_SecurityOnly_FailsClosedWhenUnattendedAbsent(t *testing.T) {
	origLook := execLookPath
	origSudo := runSudoCmd
	t.Cleanup(func() { execLookPath = origLook; runSudoCmd = origSudo })

	e := NewExecutor(nil)

	t.Run("absent unattended-upgrade fails closed, no broad upgrade", func(t *testing.T) {
		execLookPath = func(name string) (string, error) {
			return "", fmt.Errorf("exec: %q: executable file not found in $PATH", name)
		}
		var out strings.Builder
		err := e.executeAptUpgrade(context.Background(), &pb.UpdateParams{SecurityOnly: true}, &out)
		if err == nil {
			t.Fatal("security-only upgrade must fail closed when unattended-upgrade is absent")
		}
		if !strings.Contains(err.Error(), "unattended-upgrade") {
			t.Errorf("error = %q, want it to name the missing unattended-upgrade", err)
		}
		if !strings.Contains(out.String(), "ERROR: security-only") {
			t.Errorf("output = %q, want the security-only ERROR line", out.String())
		}
		// The broad upgrade path writes a "Dist-Upgrade" banner — it must NOT
		// have been reached (the function returns at the fail-closed branch).
		if strings.Contains(out.String(), "Dist-Upgrade") {
			t.Error("broad upgrade path was taken; security-only must not fall through to a full upgrade")
		}
	})

	t.Run("present unattended-upgrade runs the security path", func(t *testing.T) {
		execLookPath = func(name string) (string, error) { return "/usr/bin/unattended-upgrade", nil }
		ran := ""
		runSudoCmd = func(ctx context.Context, name string, args ...string) (*pb.CommandOutput, error) {
			ran = name
			return &pb.CommandOutput{Stdout: "0 upgraded, 0 newly installed"}, nil
		}
		var out strings.Builder
		err := e.executeAptUpgrade(context.Background(), &pb.UpdateParams{SecurityOnly: true}, &out)
		if err != nil {
			t.Fatalf("present security path returned error: %v", err)
		}
		if ran != "unattended-upgrade" {
			t.Errorf("expected the security path to run unattended-upgrade, ran %q", ran)
		}
		if strings.Contains(out.String(), "Dist-Upgrade") {
			t.Error("security path must not run the broad dist-upgrade")
		}
	})
}

// scheduleRebootAfterUpdate must treat a failed `shutdown` as a real action
// error (the operator asked for the reboot), and must NOT notify users that
// their system will reboot when it won't. On success it notifies exactly once.
func TestScheduleRebootAfterUpdate(t *testing.T) {
	origSudo := runSudoCmd
	origNotify := notifyAll
	t.Cleanup(func() { runSudoCmd = origSudo; notifyAll = origNotify })

	e := NewExecutor(nil)

	t.Run("shutdown failure returns an error and suppresses notify", func(t *testing.T) {
		runSudoCmd = func(ctx context.Context, name string, args ...string) (*pb.CommandOutput, error) {
			return &pb.CommandOutput{Stderr: "Failed to set wall message"}, fmt.Errorf("exit status 1")
		}
		notified := 0
		notifyAll = func(ctx context.Context, title, body string) { notified++ }

		var out strings.Builder
		err := e.scheduleRebootAfterUpdate(context.Background(), &out)
		if err == nil {
			t.Fatal("a failed reboot schedule must return an error, not a clean success")
		}
		if !strings.Contains(err.Error(), "schedule reboot") {
			t.Errorf("error = %q, want it to name the reboot scheduling failure", err)
		}
		if !strings.Contains(out.String(), "FAILED to schedule reboot") {
			t.Errorf("output = %q, want the FAILED line", out.String())
		}
		if notified != 0 {
			t.Errorf("users must NOT be notified when the reboot did not go out, got %d notifications", notified)
		}
	})

	t.Run("success notifies exactly once", func(t *testing.T) {
		runSudoCmd = func(ctx context.Context, name string, args ...string) (*pb.CommandOutput, error) {
			return &pb.CommandOutput{Stdout: "Shutdown scheduled"}, nil
		}
		notified := 0
		notifyAll = func(ctx context.Context, title, body string) { notified++ }

		var out strings.Builder
		if err := e.scheduleRebootAfterUpdate(context.Background(), &out); err != nil {
			t.Fatalf("successful reboot scheduling returned error: %v", err)
		}
		if notified != 1 {
			t.Errorf("want exactly one notification on success, got %d", notified)
		}
		if !strings.Contains(out.String(), "Scheduled reboot") {
			t.Errorf("output = %q, want the scheduled-reboot line", out.String())
		}
	})

	t.Run("reboot failure joins with a prior error rather than demoting it", func(t *testing.T) {
		runSudoCmd = func(ctx context.Context, name string, args ...string) (*pb.CommandOutput, error) {
			return nil, fmt.Errorf("exit status 1")
		}
		notifyAll = func(ctx context.Context, title, body string) {}

		var out strings.Builder
		// Mirror executeUpdate's call site: lastErr = errors.Join(lastErr, ...).
		prior := errors.New("apt upgrade failed")
		joined := errors.Join(prior, e.scheduleRebootAfterUpdate(context.Background(), &out))
		if !errors.Is(joined, prior) {
			t.Error("a prior upgrade error must stay visible alongside the reboot failure")
		}
		if !strings.Contains(joined.Error(), "schedule reboot") {
			t.Error("the reboot failure must not be demoted by a first-error-wins guard")
		}
	})
}
