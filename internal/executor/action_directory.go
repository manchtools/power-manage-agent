// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"fmt"
	"os"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysfs "github.com/manchtools/power-manage/sdk/go/sys/fs"
)

func (e *Executor) executeDirectory(ctx context.Context, params *pb.DirectoryParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("directory params required")
	}

	if params.Path == "" {
		return nil, false, fmt.Errorf("directory path is required")
	}

	// Resolve symlinks to prevent traversal attacks
	cleanPath, err := sysfs.ResolveAndValidatePath(params.Path)
	if err != nil {
		return nil, false, fmt.Errorf("invalid path: %w", err)
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Check if directory already exists with correct mode and ownership
		if e.directoryMatchesDesired(cleanPath, params) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("directory %s is already in desired state", cleanPath),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		// Create directory with permissions (handles mkdir, chmod, and chown)
		if err := createDirectoryWithPermissions(ctx, cleanPath, params.Mode, params.Owner, params.Group, params.Recursive); err != nil {
			return nil, false, err
		}

		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("created directory %s", cleanPath),
		}, true, nil

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		// Check if directory already doesn't exist
		if _, err := os.Stat(cleanPath); os.IsNotExist(err) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("directory %s does not exist, nothing to remove", cleanPath),
			}, false, nil
		}

		// Safety check: refuse to delete protected system directories
		if isProtectedPath(cleanPath) {
			return nil, false, fmt.Errorf("refusing to delete protected system path: %s", cleanPath)
		}

		// Repair filesystem if mounted read-only
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		// Remove directory (use -r for recursive removal if it has contents)
		if err := removeDirectory(ctx, cleanPath); err != nil {
			return nil, false, fmt.Errorf("remove directory: %w", err)
		}
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("removed directory %s", cleanPath),
		}, true, nil
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// directoryMatchesDesired checks if a directory already has the desired mode and ownership.
func (e *Executor) directoryMatchesDesired(path string, params *pb.DirectoryParams) bool {
	// Check if directory exists
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	// Check if it's a directory
	if !info.IsDir() {
		return false
	}

	// Check mode if specified
	if params.Mode != "" {
		var desiredMode uint64
		if _, err := fmt.Sscanf(params.Mode, "%o", &desiredMode); err == nil {
			currentMode := info.Mode().Perm()
			if uint32(currentMode) != uint32(desiredMode) {
				return false
			}
		}
	}

	// Check owner/group if specified. See fileMatchesDesired for
	// the full rationale — same group-only mismatch bug lived
	// here too and made directoryMatchesDesired never return true
	// when only the group was requested, so the action rechowned
	// on every run.
	if params.Owner != "" || params.Group != "" {
		currentOwner, currentGroup := getFileOwnership(path)
		if currentOwner == "" && currentGroup == "" {
			return false
		}
		if params.Owner != "" && currentOwner != params.Owner {
			return false
		}
		if params.Group != "" && currentGroup != params.Group {
			return false
		}
	}

	return true
}
