package executor

import (
	"context"
	"testing"
)

// TestExecuteReboot_FailsClosedWithoutRunner pins the guard for a real incident:
// an executor built without a privilege runner (NewExecutor(_, nil), the
// unit-test convention) must REFUSE to schedule a reboot rather than fall back
// to the process-global Direct runner and issue a real `shutdown -r +5`. A
// handler test that dispatched a signed REBOOT envelope through such an executor
// once rebooted a developer's workstation (systemd-logind grants reboot to an
// active desktop session via polkit, no sudo needed).
//
// Running this test must NEVER reboot the host: the guard returns before any
// reboot command is built. Removing the guard would make executeReboot shell out
// for real here, so this test cannot be red-checked by reverting the fix without
// risking a real reboot — the assertion below is the safe pin.
func TestExecuteReboot_FailsClosedWithoutRunner(t *testing.T) {
	e := NewExecutor(nil, nil)
	if e.runner != nil {
		t.Fatal("NewExecutor(_, nil) must leave the executor runner nil so reboot fails closed")
	}
	out, err := e.executeReboot(context.Background())
	if err == nil {
		t.Fatal("executeReboot with no privilege runner must fail closed, not schedule a real reboot")
	}
	if out != nil {
		t.Errorf("a refused reboot must not return command output, got %v", out)
	}
}
