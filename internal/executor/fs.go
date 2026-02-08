// Package executor provides filesystem utility functions for action executors.
package executor

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// =============================================================================
// Ownership Utilities
// =============================================================================

// buildOwnership constructs an "owner:group" string for chown commands.
// If only owner is provided, returns "owner". If only group is provided,
// returns ":group". If both are provided, returns "owner:group".
func buildOwnership(owner, group string) string {
	if owner == "" && group == "" {
		return ""
	}
	if group == "" {
		return owner
	}
	if owner == "" {
		return ":" + group
	}
	return owner + ":" + group
}

// getFileOwnership retrieves the current owner:group of a file using stat.
// Returns empty strings if the file doesn't exist or can't be read.
func getFileOwnership(path string) (owner, group string) {
	out, err := queryCmd("stat", "-c", "%U:%G", path)
	if err != nil {
		return "", ""
	}
	parts := strings.Split(strings.TrimSpace(out), ":")
	if len(parts) >= 2 {
		return parts[0], parts[1]
	}
	if len(parts) == 1 {
		return parts[0], ""
	}
	return "", ""
}

// =============================================================================
// File Write Operations
// =============================================================================

// writeFileWithSudo writes content to a file using sudo tee.
// This is the basic building block for privileged file writes.
func writeFileWithSudo(ctx context.Context, path, content string) (*pb.CommandOutput, error) {
	return runSudoCmdWithStdin(ctx, strings.NewReader(content), "tee", path)
}

// setFileMode sets the file mode (permissions) using sudo chmod.
// mode should be an octal string like "0644".
func setFileMode(ctx context.Context, path, mode string) (*pb.CommandOutput, error) {
	if mode == "" {
		return nil, nil
	}
	return runSudoCmd(ctx, "chmod", mode, path)
}

// setFileOwnership sets the file owner and group using sudo chown.
// Either owner or group can be empty, but not both.
func setFileOwnership(ctx context.Context, path, owner, group string) (*pb.CommandOutput, error) {
	ownership := buildOwnership(owner, group)
	if ownership == "" {
		return nil, nil
	}
	return runSudoCmd(ctx, "chown", ownership, path)
}

// setFilePermissions sets both mode and ownership on a file.
// This is a convenience function that calls setFileMode and setFileOwnership.
func setFilePermissions(ctx context.Context, path, mode, owner, group string) error {
	if mode != "" {
		if _, err := setFileMode(ctx, path, mode); err != nil {
			return fmt.Errorf("chmod: %w", err)
		}
	}
	if owner != "" || group != "" {
		if _, err := setFileOwnership(ctx, path, owner, group); err != nil {
			return fmt.Errorf("chown: %w", err)
		}
	}
	return nil
}

// atomicWriteFile writes content to a file atomically with the specified
// permissions. It writes to a temp file first, sets permissions, then moves
// it into place. This prevents TOCTOU race conditions.
func atomicWriteFile(ctx context.Context, path, content, mode, owner, group string) error {
	tmpPath := path + ".pm-tmp"

	// Write content to temp file
	output, err := writeFileWithSudo(ctx, tmpPath, content)
	if err != nil {
		removeFile(ctx, tmpPath) // cleanup
		errMsg := err.Error()
		if output != nil && output.Stderr != "" {
			errMsg = strings.TrimSpace(output.Stderr)
		}
		return fmt.Errorf("write file %s: %s", tmpPath, errMsg)
	}

	// Set permissions on temp file before moving
	if err := setFilePermissions(ctx, tmpPath, mode, owner, group); err != nil {
		removeFile(ctx, tmpPath) // cleanup
		return err
	}

	// Atomic move into place
	if _, err := runSudoCmd(ctx, "mv", "-f", tmpPath, path); err != nil {
		removeFile(ctx, tmpPath) // cleanup
		return fmt.Errorf("move file into place: %w", err)
	}

	return nil
}

// =============================================================================
// File Read Operations
// =============================================================================

// readFileWithSudo reads a file's contents using sudo cat.
// Returns the content and any error. If the file doesn't exist,
// returns an empty string and nil error (not found is indicated by checking stderr).
func readFileWithSudo(ctx context.Context, path string) (string, error) {
	output, err := runSudoCmd(ctx, "cat", path)
	if err != nil {
		if output != nil && strings.Contains(output.Stderr, "No such file") {
			return "", nil
		}
		return "", err
	}
	return output.Stdout, nil
}

// =============================================================================
// File Delete Operations
// =============================================================================

// removeFile removes a file using sudo rm -f.
// This is a best-effort operation that doesn't return errors.
func removeFile(ctx context.Context, path string) {
	runSudoCmd(ctx, "rm", "-f", path)
}

// removeFileStrict removes a file using sudo rm -f and returns any error.
func removeFileStrict(ctx context.Context, path string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "rm", "-f", path)
}

// =============================================================================
// Directory Operations
// =============================================================================

// createDirectory creates a directory using sudo mkdir.
// If recursive is true, parent directories are created as needed (-p flag).
func createDirectory(ctx context.Context, path string, recursive bool) (*pb.CommandOutput, error) {
	args := []string{}
	if recursive {
		args = append(args, "-p")
	}
	args = append(args, path)
	return runSudoCmd(ctx, "mkdir", args...)
}

// createDirectoryWithPermissions creates a directory with the specified
// mode and ownership. If recursive is true, parent directories are created.
func createDirectoryWithPermissions(ctx context.Context, path, mode, owner, group string, recursive bool) error {
	// Create the directory
	if _, err := createDirectory(ctx, path, recursive); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}

	// Set permissions
	if err := setFilePermissions(ctx, path, mode, owner, group); err != nil {
		return err
	}

	return nil
}

// removeDirectory removes a directory and its contents using sudo rm -rf.
func removeDirectory(ctx context.Context, path string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "rm", "-rf", path)
}

// =============================================================================
// User/Group Utilities
// =============================================================================

// userExists checks if a user exists on the system.
func userExists(username string) bool {
	return checkCmdSuccess("id", username)
}

// groupExists checks if a group exists on the system.
func groupExists(groupName string) bool {
	return checkCmdSuccess("getent", "group", groupName)
}

// =============================================================================
// Copy Operations
// =============================================================================

// copyFile copies a file from src to dst using sudo cp.
func copyFile(ctx context.Context, src, dst string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "cp", src, dst)
}

// copyFileWithPermissions copies a file and sets the specified permissions.
func copyFileWithPermissions(ctx context.Context, src, dst, mode, owner, group string) error {
	if _, err := copyFile(ctx, src, dst); err != nil {
		return fmt.Errorf("copy file: %w", err)
	}
	if err := setFilePermissions(ctx, dst, mode, owner, group); err != nil {
		return err
	}
	return nil
}
