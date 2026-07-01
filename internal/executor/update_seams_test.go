package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	osexec "os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// installShutdownStub makes `shutdown` resolve to a HARMLESS stub on a fully
// isolated PATH, so scheduleRebootAfterUpdate can be driven through a REAL
// runner without any risk of rebooting the host. The stub records its argv to a
// file and exits with exitCode; the real /sbin/shutdown is unreachable because
// PATH is replaced (not appended) with only the stub dir.
//
// The hard guard is load-bearing: it FATALs unless `shutdown` resolves inside
// the stub dir, so a PATH mistake can never reach the real binary. This is why a
// real reboot is impossible here even though a real runner runs a real exec —
// the earlier version of this test used a real runner against the REAL shutdown
// and rebooted a developer's workstation (see action_reboot_test.go).
//
// Returns the argv-log path so a test can assert the exact command the SDK
// reboot Manager built (`shutdown -r +1 <message>`).
func installShutdownStub(t *testing.T, exitCode int) (argvLog string) {
	t.Helper()
	stubDir := t.TempDir()
	argvLog = filepath.Join(stubDir, "argv")
	// POSIX single-quote the redirect target (%q is Go, not shell, quoting).
	quotedArgvLog := "'" + strings.ReplaceAll(argvLog, "'", `'\''`) + "'"
	stub := fmt.Sprintf("#!/bin/sh\nprintf '%%s\\n' \"$@\" > %s\nexit %d\n", quotedArgvLog, exitCode)
	if err := os.WriteFile(filepath.Join(stubDir, "shutdown"), []byte(stub), 0o755); err != nil {
		t.Fatalf("write shutdown stub: %v", err)
	}
	t.Setenv("PATH", stubDir) // full replacement: only the stub is reachable

	// Refuse to run unless `shutdown` resolves INSIDE the stub dir. This is the
	// safety net that makes a real reboot impossible.
	p, err := osexec.LookPath("shutdown")
	if err != nil || filepath.Dir(p) != stubDir {
		t.Fatalf("refusing to run: `shutdown` must resolve inside the stub dir, got %q (%v)", p, err)
	}
	return argvLog
}

// newRebootExecutor builds an Executor over a REAL Direct runner. Paired with
// installShutdownStub, the runner exercises the real exec path (LookPath, forced
// LC_ALL=C env, escalation wrapping, streaming, exit-code handling) against the
// harmless stub.
func newRebootExecutor(t *testing.T) *Executor {
	t.Helper()
	r, err := sysexec.NewRunner(sysexec.Direct)
	if err != nil {
		t.Fatalf("build direct runner: %v", err)
	}
	return &Executor{runner: r}
}

// TestScheduleRebootAfterUpdate drives scheduleRebootAfterUpdate through a real
// runner against a stubbed `shutdown` (installShutdownStub), covering both the
// success and failure paths without touching a real reboot.
func TestScheduleRebootAfterUpdate(t *testing.T) {
	origNotify := notifyAll
	t.Cleanup(func() { notifyAll = origNotify })

	t.Run("schedules the reboot and notifies on success", func(t *testing.T) {
		argvLog := installShutdownStub(t, 0) // real runner reaches a stub that exits 0
		notified := 0
		notifyAll = func(ctx context.Context, title, body string) { notified++ }

		var out strings.Builder
		if err := newRebootExecutor(t).scheduleRebootAfterUpdate(context.Background(), &out); err != nil {
			t.Fatalf("scheduleRebootAfterUpdate = %v, want a scheduled reboot", err)
		}
		if notified != 1 {
			t.Errorf("users must be notified once when the reboot is scheduled, got %d", notified)
		}
		if !strings.Contains(out.String(), "Scheduled reboot") {
			t.Errorf("output = %q, want the scheduled-reboot line", out.String())
		}
		// The REAL runner built and ran the command — assert the argv the SDK
		// reboot Manager constructed reached `shutdown` as `-r +1 <message>`.
		argv, err := os.ReadFile(argvLog)
		if err != nil {
			t.Fatalf("read stub argv: %v", err)
		}
		// The stub logged one arg per line; assert the first two positionally
		// (-r then +1) rather than by substring, so a message containing "-r"
		// can't satisfy the check.
		args := strings.Split(strings.TrimSuffix(string(argv), "\n"), "\n")
		wantArgs := []string{"-r", "+1", "System update requires reboot"}
		if !reflect.DeepEqual(args, wantArgs) {
			t.Errorf("shutdown argv = %q, want exactly %q", args, wantArgs)
		}
	})

	t.Run("schedule failure returns an error and suppresses notify", func(t *testing.T) {
		installShutdownStub(t, 1) // stub `shutdown` exits nonzero → Schedule fails
		notified := 0
		notifyAll = func(ctx context.Context, title, body string) { notified++ }

		var out strings.Builder
		err := newRebootExecutor(t).scheduleRebootAfterUpdate(context.Background(), &out)
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
		installShutdownStub(t, 1)
		notifyAll = func(ctx context.Context, title, body string) {}

		var out strings.Builder
		prior := errors.New("apt upgrade failed")
		joined := errors.Join(prior, newRebootExecutor(t).scheduleRebootAfterUpdate(context.Background(), &out))
		if !errors.Is(joined, prior) {
			t.Error("a prior upgrade error must stay visible alongside the reboot failure")
		}
		if !strings.Contains(joined.Error(), "schedule reboot") {
			t.Error("the reboot failure must not be demoted by a first-error-wins guard")
		}
	})

	t.Run("fails closed without a privilege runner", func(t *testing.T) {
		// No runner at all → scheduleRebootAfterUpdate returns before any exec,
		// so no stub is needed (and nothing can run).
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
}
