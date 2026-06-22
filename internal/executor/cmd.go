// Package executor provides thin wrappers around the SDK sys/exec Runner,
// converting between SDK types and protobuf CommandOutput.
package executor

import (
	"context"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// executorRunner is the privilege-backend runner the command helpers below
// dispatch through. It defaults to a Direct runner — correct for the
// unprivileged query helpers and for a root daemon — and is overridden by
// NewExecutor with the backend the operator configured, so escalating helpers
// (runSudoCmd) use sudo/doas when the agent is not already root. It is
// process-wide because the agent is a single daemon with one privilege
// configuration; tests that need to observe the privileged shell-out stub
// runSudoCmd directly.
var executorRunner = mustDirectRunner()

func mustDirectRunner() sysexec.Runner {
	r, err := sysexec.NewRunner(sysexec.Direct)
	if err != nil {
		panic("executor: Direct runner must construct: " + err.Error())
	}
	return r
}

// OutputCallback is a type alias for the SDK OutputCallback.
type OutputCallback = sysexec.OutputCallback

// toOutput converts an SDK Result to a protobuf CommandOutput.
func toOutput(r *sysexec.Result) *pb.CommandOutput {
	if r == nil {
		return nil
	}
	return &pb.CommandOutput{
		ExitCode: int32(r.ExitCode),
		Stdout:   r.Stdout,
		Stderr:   r.Stderr,
	}
}

// asCmdError preserves the pre-rework contract that a non-zero exit is an error.
// The reworked Runner reports a non-zero exit in Result.ExitCode (not as err),
// but every caller of the non-streaming command helpers treats `err != nil` as
// "the command failed" (e.g. `if err != nil { return ..., err }`). Without this
// mapping a failed sudo command would look like success. (Streaming callers, by
// contrast, want the exit code in the output to report a script's status, so
// runCmdStreaming/runAsUserStreaming deliberately do NOT use this.)
func asCmdError(name string, r sysexec.Result, err error) error {
	if err != nil {
		return err
	}
	if r.ExitCode != 0 {
		return &sysexec.CommandError{Name: name, ExitCode: r.ExitCode, Stderr: r.Stderr}
	}
	return nil
}

// runSudoCmd runs a command through the privilege backend. It is a package var
// (not a plain func) so update/reboot tests can stub the privileged shell-out
// without a live host; production dispatches through the configured runner.
var runSudoCmd = func(ctx context.Context, name string, args ...string) (*pb.CommandOutput, error) {
	r, err := executorRunner.Run(ctx, sysexec.Command{Name: name, Args: args, Escalate: true})
	return toOutput(&r), asCmdError(name, r, err)
}
