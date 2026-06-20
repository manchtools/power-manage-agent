package executor

import (
	"context"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// runShellScript builds the child environment from a curated baseline plus
// only the caller-supplied entries that pass the SDK hijack allow-list. A
// blocklisted variable (LD_PRELOAD, PATH, LD_LIBRARY_PATH, …) must be refused
// BEFORE the interpreter is ever launched, so a compromised gateway cannot
// inject an ambient-library hijack through a SHELL action.
//
// The wrong inputs are sourced from intent (the classic LD_* / PATH hijack
// names), not from the allow-list's own table. A deliberately non-existent
// interpreter is used so that if the guard ever regressed to run *after*
// exec, the failure would surface as an interpreter error rather than the
// allow-list message — and this test would catch it.
func TestRunShellScript_RejectsBlocklistedEnvVar(t *testing.T) {
	e := NewExecutor(nil, nil)
	ctx := context.Background()

	const bogusInterp = "/nonexistent/pm-ws17a-interp"

	for _, name := range []string{"LD_PRELOAD", "PATH", "LD_LIBRARY_PATH"} {
		t.Run("rejects "+name, func(t *testing.T) {
			params := &pb.ShellParams{
				Interpreter: bogusInterp,
				RunAsRoot:   true,
				Environment: map[string]string{name: "/tmp/evil"},
			}
			out, err := e.runShellScript(ctx, params, "echo hi", nil)
			if err == nil {
				t.Fatalf("runShellScript with %s = nil error, want rejection before exec", name)
			}
			if !strings.Contains(err.Error(), "is not allowed") {
				t.Errorf("error = %q, want the env allow-list rejection (%q) — a different error means exec ran first", err, name)
			}
			if out != nil {
				t.Errorf("output must be nil on a rejected env var, got %v", out)
			}
		})
	}

	// correct: an allow-listed application variable passes the gate and the
	// function proceeds to launch the interpreter. With a non-existent
	// interpreter the launch fails, but the error is NOT the allow-list
	// rejection — proving MYAPP_FLAG was accepted into the child env.
	t.Run("allows MYAPP_FLAG past the gate", func(t *testing.T) {
		params := &pb.ShellParams{
			Interpreter: bogusInterp,
			RunAsRoot:   true,
			Environment: map[string]string{"MYAPP_FLAG": "1"},
		}
		_, err := e.runShellScript(ctx, params, "echo hi", nil)
		if err != nil && strings.Contains(err.Error(), "is not allowed") {
			t.Errorf("MYAPP_FLAG was rejected by the env gate (%v); an application variable must pass", err)
		}
	})
}

// TestRunShellScript_DoesNotInjectReservedLocaleVar pins that the shell executor
// does NOT place a reserved locale variable (LANG/LC_*/LANGUAGE/NO_COLOR) in the
// child env. The reworked SDK Runner forces LC_ALL=C/LANG=C/NO_COLOR=1 on every
// command and REJECTS any attempt to set them via Command.Env. The executor used
// to inject `LANG=<host LANG>`, which made EVERY shell action fail with
// ErrReservedEnvVar once the agent moved onto the reworked Runner — the
// integration suite caught it. Running a no-op `true` through a real Direct
// runner makes a regression resurface as that reserved-env-var error here, with
// no container needed.
func TestRunShellScript_DoesNotInjectReservedLocaleVar(t *testing.T) {
	r, err := sysexec.NewRunner(sysexec.Direct)
	if err != nil {
		t.Fatalf("build direct runner: %v", err)
	}
	orig := executorRunner
	executorRunner = r
	t.Cleanup(func() { executorRunner = orig })

	e := &Executor{}
	out, err := e.runShellScript(context.Background(), &pb.ShellParams{RunAsRoot: true}, "true", nil)
	if err != nil {
		t.Fatalf("shell action failed — reserved-env-var regression? %v", err)
	}
	if out == nil || out.ExitCode != 0 {
		t.Fatalf("expected a clean exit, got %+v", out)
	}
}
