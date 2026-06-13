// Package executor provides thin wrappers around the SDK sys/fs package.
package executor

import (
	"context"
	"fmt"
	"os"
	"strconv"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysfs "github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// getFileOwnership retrieves the current owner:group of a file using stat.
func getFileOwnership(path string) (owner, group string) {
	return sysfs.GetOwnership(path)
}

// writeFileWithSudo writes content to a file using sudo tee.
func writeFileWithSudo(ctx context.Context, path, content string) (*pb.CommandOutput, error) {
	err := sysfs.WriteFile(ctx, path, content)
	if err != nil {
		return &pb.CommandOutput{ExitCode: 1, Stderr: err.Error()}, err
	}
	return &pb.CommandOutput{ExitCode: 0}, nil
}

// atomicWriteFile writes content to a file atomically with the specified permissions.
func atomicWriteFile(ctx context.Context, path, content, mode, owner, group string) error {
	return sysfs.WriteFileAtomic(ctx, path, content, mode, owner, group)
}

// readFileWithSudo reads a file's contents using sudo cat.
func readFileWithSudo(ctx context.Context, path string) (string, error) {
	return sysfs.ReadFile(ctx, path)
}

// fileExistsWithSudo checks whether a path exists using sudo test -e.
func fileExistsWithSudo(ctx context.Context, path string) bool {
	return sysfs.FileExists(ctx, path)
}

// removeFileStrict removes a file and returns any error.
func removeFileStrict(ctx context.Context, path string) error {
	return sysfs.RemoveStrict(ctx, path)
}

// createDirectory creates a directory using sudo mkdir.
func createDirectory(ctx context.Context, path string, recursive bool) error {
	return sysfs.Mkdir(ctx, path, recursive)
}

// createDirectoryWithPermissions creates a directory and applies its mode
// and ownership through the fd-based, no-follow helper (WS6 #5). The old
// path-based chmod/chown (sysfs.MkdirWithPermissions) re-resolved the path
// and would dereference a final-component symlink swapped in after mkdir,
// redirecting a root chmod/chown onto the target. Here the perms are
// applied via an O_NOFOLLOW|O_DIRECTORY fd, so a swapped-in symlink aborts
// the operation (ELOOP) instead.
func createDirectoryWithPermissions(ctx context.Context, path, mode, owner, group string, recursive bool) error {
	if err := sysfs.Mkdir(ctx, path, recursive); err != nil {
		return fmt.Errorf("create directory: %w", err)
	}
	if mode == "" && owner == "" && group == "" {
		return nil
	}
	uid, gid := -1, -1
	if owner != "" || group != "" {
		var err error
		uid, gid, err = sysfs.ResolveOwnership(owner, group)
		if err != nil {
			return err
		}
	}
	perm := os.FileMode(0o755) // deterministic default when mode is unspecified
	if mode != "" {
		v, err := strconv.ParseUint(mode, 8, 32)
		if err != nil {
			return fmt.Errorf("invalid directory mode %q: %w", mode, err)
		}
		perm = os.FileMode(v)
	}
	return sysfs.SetDirPermissionsNoFollow(path, perm, uid, gid)
}

// removeDirectory removes a directory and its contents.
func removeDirectory(ctx context.Context, path string) error {
	return sysfs.RemoveDir(ctx, path)
}

// userExists checks if a user exists on the system.
func userExists(username string) bool {
	return checkCmdSuccess("id", username)
}

// groupExists checks if a group exists on the system.
func groupExists(groupName string) bool {
	return checkCmdSuccess("getent", "group", groupName)
}
