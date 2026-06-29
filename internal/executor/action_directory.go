// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"fmt"
	"path/filepath"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysfs "github.com/manchtools/power-manage-sdk/sys/fs"
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
		// WS6 #6: protected-path guard, symmetric with ABSENT. Without it
		// a PRESENT action could chmod/chown a protected system directory
		// or anything under a protected prefix — e.g. `chmod 0777
		// /etc/sudoers.d` (world-writable sudoers dir → privesc) or relax
		// /var/lib/<service>. Mirror ABSENT exactly: refuse the top-level
		// denylist AND the whole protected subtree, on both the resolved
		// path and the cleaned input (so a symlinked protected dir can't
		// slip past resolution). The FILE action still creates its own
		// parent dirs under /etc/*.d via createDirectory, so managed config
		// files are unaffected.
		if isProtectedPath(cleanPath) || isProtectedPath(filepath.Clean(params.Path)) ||
			sysfs.IsUnderProtectedPrefix(cleanPath) || sysfs.IsUnderProtectedPrefix(filepath.Clean(params.Path)) {
			return nil, false, fmt.Errorf("refusing to manage protected system path: %s (resolved from %s)", cleanPath, params.Path)
		}

		// Check if directory already exists with correct mode and ownership
		if e.directoryMatchesDesired(ctx, cleanPath, params) {
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
		// Safety check FIRST (before the existence probe): refuse to delete
		// a protected system directory or anything UNDER a security-
		// relevant prefix. WS6 #12 widens the old top-level-only denylist
		// (isProtectedPath) to deny-by-default across whole subtrees
		// (sysfs.IsUnderProtectedPrefix), so /etc/sudoers.d, /home/<user>,
		// /var/lib/<x>, /boot/efi, … can no longer slip through to rm -rf.
		// Checking before os.Stat also refuses regardless of existence and
		// avoids leaking whether a protected path is present. Both the
		// resolved path and the cleaned input are checked so a symlinked
		// protected directory can't slip past resolution.
		if isProtectedPath(cleanPath) || isProtectedPath(filepath.Clean(params.Path)) ||
			sysfs.IsUnderProtectedPrefix(cleanPath) || sysfs.IsUnderProtectedPrefix(filepath.Clean(params.Path)) {
			return nil, false, fmt.Errorf("refusing to delete protected system path: %s (resolved from %s)", cleanPath, params.Path)
		}

		// Check if directory already doesn't exist
		if !fileExistsWithSudo(ctx, cleanPath) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("directory %s does not exist, nothing to remove", cleanPath),
			}, false, nil
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
func (e *Executor) directoryMatchesDesired(ctx context.Context, path string, params *pb.DirectoryParams) bool {
	// Check existence + type through the metadata chokepoint; a stat error
	// reads as "does not match" so the caller falls through to the
	// privilege-routed mkdir/perms path.
	mode, err := statFile(ctx, path)
	if err != nil {
		return false
	}

	// Check if it's a directory
	if !mode.IsDir() {
		return false
	}

	// Check mode if specified
	if params.Mode != "" {
		var desiredMode uint64
		if _, err := fmt.Sscanf(params.Mode, "%o", &desiredMode); err == nil {
			currentMode := mode.Perm()
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
