// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysfs "github.com/manchtools/power-manage/sdk/go/sys/fs"
)

func (e *Executor) executeFile(ctx context.Context, params *pb.FileParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("file params required")
	}
	if len(params.Content) > maxFileContentSize {
		return nil, false, fmt.Errorf("file content exceeds maximum size (%d bytes)", maxFileContentSize)
	}

	// Resolve symlinks to prevent traversal attacks
	resolvedPath, err := sysfs.ResolveAndValidatePath(params.Path)
	if err != nil {
		return nil, false, fmt.Errorf("invalid path: %w", err)
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Check if file already exists with correct content, mode, and ownership
		if e.fileMatchesDesired(resolvedPath, params) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("file %s is already in desired state", resolvedPath),
			}, false, nil
		}

		// Refuse content overwrite of critical files (/etc/passwd,
		// /etc/shadow, /etc/sudoers, …). Unlike ABSENT, the PRESENT
		// branch is NOT blocked from writing under protected
		// directories — managed config under /etc/foo.d/ is the whole
		// point of the file action; only the named individual files
		// are off-limits. Check both the cleaned input and the
		// resolved-symlink path so /etc/resolv.conf -> /run/... can't
		// slip past via symlink resolution.
		// isCriticalFile already runs filepath.Clean internally, but
		// pass the cleaned path explicitly here for symmetry with the
		// ABSENT branch's `isProtectedPath(filepath.Clean(...))` call
		// — both call sites read the same way.
		if isCriticalFile(resolvedPath) || isCriticalFile(filepath.Clean(params.Path)) {
			return nil, false, fmt.Errorf("refusing to overwrite critical system file: %s (resolved from %s)", resolvedPath, params.Path)
		}

		// Repair filesystem if mounted read-only
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		// Create parent directories using sudo
		parentDir := filepath.Dir(resolvedPath)
		if err := createDirectory(ctx, parentDir, true); err != nil {
			return nil, false, fmt.Errorf("create directory %s: %w", parentDir, err)
		}

		// Determine final content based on managed block mode
		var finalContent string
		actionVerb := "created"
		if params.ManagedBlock {
			// For managed block: read existing content and append block if not present
			// Use sudo cat to read files with restrictive permissions
			var existingContent []byte
			if output, err := runSudoCmd(ctx, "cat", resolvedPath); err == nil {
				existingContent = []byte(output.Stdout)
			} else if output != nil && strings.Contains(output.Stderr, "No such file") {
				// File doesn't exist, that's fine
				existingContent = nil
			} else {
				return nil, false, fmt.Errorf("read existing file: %w", err)
			}
			// Ensure there's a newline before appending block if file exists and doesn't end with newline
			existing := string(existingContent)
			if len(existing) > 0 && !strings.HasSuffix(existing, "\n") {
				existing += "\n"
			}
			finalContent = existing + params.Content
			actionVerb = "added block to"
		} else {
			finalContent = params.Content
		}

		// Atomic write: write to temp file, set permissions, then move into place.
		// This avoids TOCTOU race conditions.
		if err := atomicWriteFile(ctx, resolvedPath, finalContent, params.Mode, params.Owner, params.Group); err != nil {
			return nil, false, err
		}

		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("%s %s", actionVerb, resolvedPath),
		}, true, nil

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		// Check if file already doesn't exist
		if _, err := os.Stat(resolvedPath); os.IsNotExist(err) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("file %s does not exist, nothing to remove", resolvedPath),
			}, false, nil
		}

		// Refuse ABSENT delete on protected system paths. A signed
		// action could otherwise request deletion of /etc/shadow,
		// /etc/sudoers, /etc/passwd, etc. and the agent would oblige.
		// Check BOTH the resolved path and the cleaned original path:
		// e.g. /etc/resolv.conf is a symlink to /run/systemd/resolve/...
		// on systemd-resolved hosts; the resolved path has 3 components
		// and slips past isProtectedPath, but the original is in the
		// criticalFiles denylist. Managed-block mode is gated by the
		// same rule: editing protected files via block-removal is just
		// as dangerous as full deletion.
		if isProtectedPath(resolvedPath) || isProtectedPath(filepath.Clean(params.Path)) {
			return nil, false, fmt.Errorf("refusing to remove protected system path: %s (resolved from %s)", resolvedPath, params.Path)
		}

		// Repair filesystem if mounted read-only
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		// For managed block mode, remove only the specified content block from the file
		if params.ManagedBlock {
			// Read file with restrictive permissions
			existingContent, err := readFileWithSudo(ctx, resolvedPath)
			if err != nil {
				return nil, false, fmt.Errorf("read file: %w", err)
			}

			// Check if content exists in file
			if !strings.Contains(existingContent, params.Content) {
				return &pb.CommandOutput{
					ExitCode: 0,
					Stdout:   fmt.Sprintf("content not found in %s, nothing to remove", resolvedPath),
				}, false, nil
			}

			// Remove the content block from the file
			newContent := strings.Replace(existingContent, params.Content, "", 1)
			// Clean up any resulting double newlines
			for strings.Contains(newContent, "\n\n\n") {
				newContent = strings.ReplaceAll(newContent, "\n\n\n", "\n\n")
			}

			// Write the modified content back using atomic write
			if err := atomicWriteFile(ctx, resolvedPath, newContent, params.Mode, params.Owner, params.Group); err != nil {
				return nil, false, err
			}

			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("removed content block from %s", resolvedPath),
			}, true, nil
		}

		// For regular mode, delete the entire file
		if err := removeFileStrict(ctx, resolvedPath); err != nil {
			return nil, false, fmt.Errorf("remove: %w", err)
		}
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("removed %s", resolvedPath),
		}, true, nil
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// fileMatchesDesired checks if a file already has the desired content, mode, and ownership.
func (e *Executor) fileMatchesDesired(path string, params *pb.FileParams) bool {
	// Check if file exists
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	// Check if it's a regular file
	if !info.Mode().IsRegular() {
		return false
	}

	// Check content
	content, err := os.ReadFile(path)
	if err != nil {
		return false
	}

	if params.ManagedBlock {
		// For managed block mode, check if content block is already present in file
		if !strings.Contains(string(content), params.Content) {
			return false
		}
	} else {
		// For regular mode, check exact content match via hash
		currentHash := sha256.Sum256(content)
		desiredHash := sha256.Sum256([]byte(params.Content))
		if currentHash != desiredHash {
			return false
		}
	}

	// Check mode if specified
	if params.Mode != "" {
		// Parse desired mode
		var desiredMode uint64
		if _, err := fmt.Sscanf(params.Mode, "%o", &desiredMode); err == nil {
			currentMode := info.Mode().Perm()
			if uint32(currentMode) != uint32(desiredMode) {
				return false
			}
		}
	}

	// Check owner/group if specified
	if params.Owner != "" || params.Group != "" {
		currentOwner, currentGroup := getFileOwnership(path)
		if currentOwner == "" && currentGroup == "" {
			return false
		}
		// Handle case where only owner is specified
		if params.Group == "" {
			if currentOwner != params.Owner {
				return false
			}
		} else if currentOwner != params.Owner || currentGroup != params.Group {
			return false
		}
	}

	return true
}

// protectedPaths contains directories that should never be deleted as a whole.
var protectedPaths = []string{
	"/",
	"/bin",
	"/boot",
	"/dev",
	"/etc",
	"/home",
	"/lib",
	"/lib32",
	"/lib64",
	"/libx32",
	"/media",
	"/mnt",
	"/opt",
	"/proc",
	"/root",
	"/run",
	"/sbin",
	"/srv",
	"/sys",
	"/tmp",
	"/usr",
	"/var",
}

// criticalFiles lists individual files whose removal would render the
// system unbootable, lock the operator out, or destroy account/auth
// state. Their parent directories (e.g. /etc) are not blanket-protected
// because legitimate managed-file removal under /etc must keep working;
// these specific files are denylisted instead.
var criticalFiles = []string{
	"/etc/passwd",
	"/etc/shadow",
	"/etc/group",
	"/etc/gshadow",
	"/etc/sudoers",
	"/etc/fstab",
	"/etc/hosts",
	"/etc/hostname",
	"/etc/resolv.conf",
	"/etc/nsswitch.conf",
	"/etc/ssh/sshd_config",
	"/etc/pam.conf",
	"/etc/machine-id",
}

// isProtectedPath checks if a path is a protected system directory or a
// critical file. Returns true if the path should not be deleted.
func isProtectedPath(path string) bool {
	cleanPath := filepath.Clean(path)

	for _, protected := range protectedPaths {
		if cleanPath == protected {
			return true
		}
	}

	if isCriticalFile(cleanPath) {
		return true
	}

	// Also protect immediate children of / that aren't in our list
	// (e.g., /lost+found, or any other top-level directory).
	parts := strings.Split(strings.TrimPrefix(cleanPath, "/"), "/")
	if len(parts) == 1 && parts[0] != "" {
		return true
	}

	return false
}

// isCriticalFile checks if a path matches a critical-file denylist entry.
// Used by both ABSENT and PRESENT branches: deletion AND content overwrite
// of /etc/passwd, /etc/shadow, /etc/sudoers, etc. is catastrophic. The
// PRESENT branch only blocks criticalFiles (not the protectedPaths
// directories) because writing managed config under /etc/foo.d/ is the
// whole point of the file action; only the named individual files are
// off-limits.
func isCriticalFile(path string) bool {
	cleanPath := filepath.Clean(path)
	for _, critical := range criticalFiles {
		if cleanPath == critical {
			return true
		}
	}
	return false
}
