// Package executor provides thin wrappers around the SDK sys/exec package,
// converting between SDK types and protobuf CommandOutput.
package executor

import (
	"context"
	"fmt"
	"io"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

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

// runCmd executes a command and returns its output.
func runCmd(ctx context.Context, name string, args ...string) (*pb.CommandOutput, error) {
	r, err := sysexec.Run(ctx, name, args...)
	return toOutput(r), err
}

// runCmdInDir executes a command in a specific directory.
func runCmdInDir(ctx context.Context, dir, name string, args ...string) (*pb.CommandOutput, error) {
	r, err := sysexec.RunInDir(ctx, dir, name, args...)
	return toOutput(r), err
}

// runCmdWithStdin executes a command with stdin input.
func runCmdWithStdin(ctx context.Context, stdin io.Reader, name string, args ...string) (*pb.CommandOutput, error) {
	r, err := sysexec.RunWithStdin(ctx, stdin, name, args...)
	return toOutput(r), err
}

// runSudoCmd wraps a command with sudo for privileged operations.
func runSudoCmd(ctx context.Context, name string, args ...string) (*pb.CommandOutput, error) {
	r, err := sysexec.Sudo(ctx, name, args...)
	return toOutput(r), err
}

// runSudoCmdWithStdin wraps a command with sudo and provides stdin input.
func runSudoCmdWithStdin(ctx context.Context, stdin io.Reader, name string, args ...string) (*pb.CommandOutput, error) {
	r, err := sysexec.SudoWithStdin(ctx, stdin, name, args...)
	return toOutput(r), err
}

// runCmdStreaming executes a command with real-time output streaming.
func runCmdStreaming(ctx context.Context, name string, args []string, envVars []string, dir string, callback OutputCallback) (*pb.CommandOutput, error) {
	r, err := sysexec.RunStreaming(ctx, name, args, envVars, dir, callback)
	return toOutput(r), err
}

// queryCmd runs a simple command and returns stdout.
func queryCmd(name string, args ...string) (string, error) {
	return sysexec.Query(name, args...)
}

// queryCmdOutput runs a command and returns stdout, exit code, and any error.
func queryCmdOutput(name string, args ...string) (stdout string, exitCode int, err error) {
	return sysexec.QueryOutput(name, args...)
}

// checkCmdSuccess runs a command and returns true if it succeeds (exit 0).
func checkCmdSuccess(name string, args ...string) bool {
	return sysexec.Check(name, args...)
}

// formatCmdError formats a command error with stderr output for better diagnostics.
func formatCmdError(err error, output *pb.CommandOutput) string {
	if output != nil && output.Stderr != "" {
		return fmt.Sprintf("%v: %s", err, strings.TrimSpace(output.Stderr))
	}
	return err.Error()
}
