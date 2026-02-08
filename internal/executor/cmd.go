// Package executor provides command execution utilities using go-cmd.
package executor

import (
	"context"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync/atomic"

	"github.com/go-cmd/cmd"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// maxOutputBytes is the maximum number of bytes captured per command output stream.
const maxOutputBytes = 1 << 20 // 1 MiB

// OutputCallback is called for each line of output during streaming execution.
// streamType: 1 = stdout, 2 = stderr
// line: the output line (with newline)
// seq: sequence number for ordering
type OutputCallback func(streamType int, line string, seq int64)

// =============================================================================
// Basic Command Execution (Buffered)
// =============================================================================

// runCmd executes a command and returns its output.
// This uses go-cmd in buffered mode for simple command execution.
func runCmd(ctx context.Context, name string, args ...string) (*pb.CommandOutput, error) {
	return runCmdWithOptions(ctx, name, args, nil, "")
}

// runCmdInDir executes a command in a specific directory.
func runCmdInDir(ctx context.Context, dir, name string, args ...string) (*pb.CommandOutput, error) {
	return runCmdWithOptions(ctx, name, args, nil, dir)
}

// runCmdWithStdin executes a command with stdin input.
func runCmdWithStdin(ctx context.Context, stdin io.Reader, name string, args ...string) (*pb.CommandOutput, error) {
	return runCmdWithOptions(ctx, name, args, stdin, "")
}

// runCmdWithOptions executes a command with all available options.
func runCmdWithOptions(ctx context.Context, name string, args []string, stdin io.Reader, dir string) (*pb.CommandOutput, error) {
	c := cmd.NewCmd(name, args...)
	if dir != "" {
		c.Dir = dir
	}

	// Start command (with or without stdin)
	var statusChan <-chan cmd.Status
	if stdin != nil {
		statusChan = c.StartWithStdin(stdin)
	} else {
		statusChan = c.Start()
	}

	// Wait for completion or context cancellation
	select {
	case status := <-statusChan:
		output := statusToOutput(status)
		if status.Error != nil {
			return output, status.Error
		}
		if status.Exit != 0 {
			return output, fmt.Errorf("exit code %d", status.Exit)
		}
		return output, nil
	case <-ctx.Done():
		c.Stop()
		// Drain the status channel
		status := <-statusChan
		return statusToOutput(status), ctx.Err()
	}
}

// statusToOutput converts a go-cmd Status to our CommandOutput protobuf.
func statusToOutput(status cmd.Status) *pb.CommandOutput {
	stdout := strings.Join(status.Stdout, "\n")
	stderr := strings.Join(status.Stderr, "\n")

	// Truncate if needed
	if len(stdout) > maxOutputBytes {
		stdout = stdout[:maxOutputBytes] + "\n[output truncated]"
	}
	if len(stderr) > maxOutputBytes {
		stderr = stderr[:maxOutputBytes] + "\n[output truncated]"
	}

	return &pb.CommandOutput{
		Stdout:   stdout,
		Stderr:   stderr,
		ExitCode: int32(status.Exit),
	}
}

// =============================================================================
// Sudo Command Execution
// =============================================================================

// runSudoCmd wraps a command with sudo for privileged operations.
// Uses -n (non-interactive) to avoid password prompts that would hang.
func runSudoCmd(ctx context.Context, name string, args ...string) (*pb.CommandOutput, error) {
	// Resolve to absolute path so the command matches sudoers rules,
	// which require full paths (e.g., /usr/bin/cp instead of cp).
	absPath, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("command not found: %s", name)
	}
	sudoArgs := append([]string{"-n", absPath}, args...)
	return runCmd(ctx, "sudo", sudoArgs...)
}

// runSudoCmdWithStdin wraps a command with sudo and provides stdin input.
func runSudoCmdWithStdin(ctx context.Context, stdin io.Reader, name string, args ...string) (*pb.CommandOutput, error) {
	absPath, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("command not found: %s", name)
	}
	sudoArgs := append([]string{"-n", absPath}, args...)
	return runCmdWithStdin(ctx, stdin, "sudo", sudoArgs...)
}

// =============================================================================
// Streaming Command Execution
// =============================================================================

// runCmdStreaming executes a command with real-time output streaming.
// The callback is called for each line of output as it's produced.
func runCmdStreaming(ctx context.Context, name string, args []string, envVars []string, dir string, callback OutputCallback) (*pb.CommandOutput, error) {
	// Create command with streaming enabled
	c := cmd.NewCmdOptions(cmd.Options{
		Buffered:  false, // Don't buffer, stream instead
		Streaming: true,  // Enable streaming
	}, name, args...)

	if dir != "" {
		c.Dir = dir
	}
	if len(envVars) > 0 {
		c.Env = envVars
	}

	// Start the command
	statusChan := c.Start()

	var stdoutSeq, stderrSeq int64
	var stdoutBuf, stderrBuf strings.Builder
	var stdoutBytes, stderrBytes int64

	done := make(chan struct{})

	// Stream output in a goroutine
	go func() {
		defer close(done)
		for {
			select {
			case line, ok := <-c.Stdout:
				if !ok {
					// Channel closed, drain stderr and exit
					for line := range c.Stderr {
						lineBytes := int64(len(line) + 1)
						if atomic.AddInt64(&stderrBytes, lineBytes) <= int64(maxOutputBytes) {
							stderrBuf.WriteString(line + "\n")
						}
						if callback != nil {
							callback(2, line+"\n", atomic.AddInt64(&stderrSeq, 1)-1)
						}
					}
					return
				}
				lineBytes := int64(len(line) + 1)
				if atomic.AddInt64(&stdoutBytes, lineBytes) <= int64(maxOutputBytes) {
					stdoutBuf.WriteString(line + "\n")
				}
				if callback != nil {
					callback(1, line+"\n", atomic.AddInt64(&stdoutSeq, 1)-1)
				}
			case line, ok := <-c.Stderr:
				if !ok {
					// Channel closed, drain stdout and exit
					for line := range c.Stdout {
						lineBytes := int64(len(line) + 1)
						if atomic.AddInt64(&stdoutBytes, lineBytes) <= int64(maxOutputBytes) {
							stdoutBuf.WriteString(line + "\n")
						}
						if callback != nil {
							callback(1, line+"\n", atomic.AddInt64(&stdoutSeq, 1)-1)
						}
					}
					return
				}
				lineBytes := int64(len(line) + 1)
				if atomic.AddInt64(&stderrBytes, lineBytes) <= int64(maxOutputBytes) {
					stderrBuf.WriteString(line + "\n")
				}
				if callback != nil {
					callback(2, line+"\n", atomic.AddInt64(&stderrSeq, 1)-1)
				}
			case <-ctx.Done():
				c.Stop()
				return
			}
		}
	}()

	// Wait for command to complete
	status := <-statusChan

	// Wait for streaming goroutine to finish
	<-done

	stdoutStr := stdoutBuf.String()
	stderrStr := stderrBuf.String()
	if atomic.LoadInt64(&stdoutBytes) > int64(maxOutputBytes) {
		stdoutStr += "\n[output truncated]"
	}
	if atomic.LoadInt64(&stderrBytes) > int64(maxOutputBytes) {
		stderrStr += "\n[output truncated]"
	}

	return &pb.CommandOutput{
		Stdout:   stdoutStr,
		Stderr:   stderrStr,
		ExitCode: int32(status.Exit),
	}, status.Error
}

// =============================================================================
// Simple Query Commands (No Context)
// =============================================================================

// queryCmd runs a simple command and returns stdout.
// This is for quick queries that don't need context or detailed error handling.
func queryCmd(name string, args ...string) (string, error) {
	c := cmd.NewCmd(name, args...)
	status := <-c.Start()
	if status.Error != nil {
		return "", status.Error
	}
	if status.Exit != 0 {
		return "", fmt.Errorf("exit code %d", status.Exit)
	}
	return strings.Join(status.Stdout, "\n"), nil
}

// queryCmdOutput runs a command and returns the full output.
// Returns stdout even on error for commands where exit code matters.
func queryCmdOutput(name string, args ...string) (stdout string, exitCode int, err error) {
	c := cmd.NewCmd(name, args...)
	status := <-c.Start()
	return strings.Join(status.Stdout, "\n"), status.Exit, status.Error
}

// checkCmdSuccess runs a command and returns true if it succeeds (exit 0).
func checkCmdSuccess(name string, args ...string) bool {
	c := cmd.NewCmd(name, args...)
	status := <-c.Start()
	return status.Exit == 0 && status.Error == nil
}

// =============================================================================
// Utility Functions
// =============================================================================

// formatCmdError formats a command error with stderr output for better diagnostics.
func formatCmdError(err error, output *pb.CommandOutput) string {
	if output != nil && output.Stderr != "" {
		return fmt.Sprintf("%v: %s", err, strings.TrimSpace(output.Stderr))
	}
	return err.Error()
}
