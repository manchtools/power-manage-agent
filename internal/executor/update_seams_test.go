package executor

import (
	"context"
	"errors"
	"strings"
	"testing"

	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

// scheduleRebootAfterUpdate schedules the reboot through the SDK reboot Manager
// (over the executor's runner). It must treat a failed schedule as a real action
// error (the operator asked for the reboot) and must NOT notify users that their
// system will reboot when it won't; on success it notifies exactly once.
//
// The interpret-update-check and apt security-only fail-closed logic that used
// to live here moved into the SDK (pkg.HasUpdates and apt securityUpgrade) and
// is tested there — the agent now delegates rather than reimplementing them.
func TestScheduleRebootAfterUpdate(t *testing.T) {
	origNotify := notifyAll
	t.Cleanup(func() { notifyAll = origNotify })

	t.Run("schedule failure returns an error and suppresses notify", func(t *testing.T) {
		fake := exectest.New(sysexec.Sudo)
		fake.Push(sysexec.Result{ExitCode: 1, Stderr: "Failed to set wall message"}, nil)
		e := &Executor{runner: fake}
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
		fake := exectest.New(sysexec.Sudo) // empty queue → clean success
		e := &Executor{runner: fake}
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
		fake := exectest.New(sysexec.Sudo)
		fake.Push(sysexec.Result{}, errors.New("escalation unavailable"))
		e := &Executor{runner: fake}
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
