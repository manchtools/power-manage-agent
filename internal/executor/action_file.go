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

// protectedPaths contains paths that should never be deleted.
// These are checked as prefixes after path cleaning.
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

// isProtectedPath checks if a path is a protected system directory.
// Returns true if the path should not be deleted.
func isProtectedPath(path string) bool {
	// Clean and get absolute path
	cleanPath := filepath.Clean(path)

	// Check exact matches against protected paths
	for _, protected := range protectedPaths {
		if cleanPath == protected {
			return true
		}
	}

	// Also protect immediate children of / that aren't in our list
	// (e.g., /lost+found, or any other top-level directory)
	parts := strings.Split(strings.TrimPrefix(cleanPath, "/"), "/")
	if len(parts) == 1 && parts[0] != "" {
		// This is a top-level directory like /something
		return true
	}

	return false
}
