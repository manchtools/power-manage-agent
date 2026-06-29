//go:build integration

package executor

import (
	"context"
	"errors"
	"strings"
	"testing"

	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// TestScheduleRebootAfterUpdate exercises scheduleRebootAfterUpdate with a real
// Direct runner. The reboot Manager will fail (no real shutdown available in a
// test environment), which is exactly the failure path we need to exercise:
// it must return an error, suppress the notification, and report the failure.
func TestScheduleRebootAfterUpdate(t *testing.T) {
	origNotify := notifyAll
	t.Cleanup(func() { notifyAll = origNotify })

	t.Run("schedule failure returns an error and suppresses notify", func(t *testing.T) {
		r, err := sysexec.NewRunner(sysexec.Direct)
		if err != nil {
			t.Fatalf("build direct runner: %v", err)
		}
		e := &Executor{runner: r}
		notified := 0
		notifyAll = func(ctx context.Context, title, body string) { notified++ }

		var out strings.Builder
		err = e.scheduleRebootAfterUpdate(context.Background(), &out)
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

	t.Run("reboot failure joins with a prior error rather than demoting it", func(t *testing.T) {
		r, err := sysexec.NewRunner(sysexec.Direct)
		if err != nil {
			t.Fatalf("build direct runner: %v", err)
		}
		e := &Executor{runner: r}
		notifyAll = func(ctx context.Context, title, body string) {}

		var out strings.Builder
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
