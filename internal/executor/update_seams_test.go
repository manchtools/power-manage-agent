package executor

import (
	"context"
	"errors"
	"strings"
	"testing"

	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

// TestScheduleRebootAfterUpdate exercises scheduleRebootAfterUpdate's failure
// path: a reboot that could not be scheduled must return an error, suppress the
// "your system will reboot" notification, and stay visible when joined with a
// prior upgrade error.
//
// It MUST use a FakeRunner, never a real one. An earlier version of this test
// built a real Direct runner and let sysreboot.Schedule run; systemd-logind
// grants an active desktop session the right to reboot via polkit with no sudo,
// so `shutdown -r +1` fired for real and rebooted a developer's workstation.
// The SDK draws the same line: its live `shutdown` round-trip is gated behind
// //go:build container (sys/reboot/reboot_container_test.go); the scheduling
// LOGIC is unit-tested with a FakeRunner. We test logic here too — the failure
// path needs Schedule to fail, which the FakeRunner scripts deterministically on
// any host. See also action_reboot_test.go for the original incident.
func TestScheduleRebootAfterUpdate(t *testing.T) {
	origNotify := notifyAll
	t.Cleanup(func() { notifyAll = origNotify })

	// newFailingExecutor returns an Executor whose reboot scheduling fails
	// without touching the host: the FakeRunner returns an exec error for the
	// shutdown command, so sysreboot.Schedule reports failure.
	newFailingExecutor := func() *Executor {
		r := exectest.New(sysexec.Direct)
		r.Push(sysexec.Result{}, errors.New("shutdown unavailable"))
		return &Executor{runner: r}
	}

	t.Run("schedule failure returns an error and suppresses notify", func(t *testing.T) {
		notified := 0
		notifyAll = func(ctx context.Context, title, body string) { notified++ }

		var out strings.Builder
		err := newFailingExecutor().scheduleRebootAfterUpdate(context.Background(), &out)
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

	t.Run("fails closed without a privilege runner", func(t *testing.T) {
		notified := 0
		notifyAll = func(ctx context.Context, title, body string) { notified++ }

		var out strings.Builder
		e := &Executor{} // runner is nil — the NewExecutor(_, nil) unit-test convention
		err := e.scheduleRebootAfterUpdate(context.Background(), &out)
		if err == nil {
			t.Fatal("a reboot with no privilege runner must fail closed, not fall through to the global Direct runner")
		}
		if notified != 0 {
			t.Errorf("users must NOT be notified when no reboot can be scheduled, got %d notifications", notified)
		}
	})

	t.Run("reboot failure joins with a prior error rather than demoting it", func(t *testing.T) {
		notifyAll = func(ctx context.Context, title, body string) {}

		var out strings.Builder
		prior := errors.New("apt upgrade failed")
		joined := errors.Join(prior, newFailingExecutor().scheduleRebootAfterUpdate(context.Background(), &out))
		if !errors.Is(joined, prior) {
			t.Error("a prior upgrade error must stay visible alongside the reboot failure")
		}
		if !strings.Contains(joined.Error(), "schedule reboot") {
			t.Error("the reboot failure must not be demoted by a first-error-wins guard")
		}
	})
}
