package main

import (
	"context"
	"os"
	"testing"

	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/exec/exectest"
)

// TestReconcileUnitAtStartup_NonRootIsCompleteNoop pins spec 27 AC 7's
// guard rail at the seam: without root, the startup reconcile must not
// run a single command — no probe, no read, no write, no reload. (CI
// and dev runs are non-root, so this exercises the real first guard.)
func TestReconcileUnitAtStartup_NonRootIsCompleteNoop(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test requires a non-root euid to exercise the root guard")
	}
	fake := exectest.New(sysexec.Direct)
	reconcileUnitAtStartup(context.Background(), fake, discardLogger(), "/var/lib/power-manage")
	if calls := fake.Calls(); len(calls) != 0 {
		t.Fatalf("non-root reconcile must be a complete no-op, ran %d commands: %+v", len(calls), calls)
	}
}

// TestRunInstallUnit_NonRootRefused pins the install path's inverse
// contract: where the startup reconcile silently no-ops, install-unit
// must FAIL loudly without root — install.sh needs the non-zero exit.
func TestRunInstallUnit_NonRootRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("test requires a non-root euid to exercise the root guard")
	}
	if code := runInstallUnit([]string{}); code != 1 {
		t.Fatalf("runInstallUnit as non-root = exit %d, want 1", code)
	}
}
