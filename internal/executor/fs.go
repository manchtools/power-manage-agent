// Package executor provides thin wrappers around the SDK sys/fs package.
package executor

import (
	"context"
	"fmt"
	"os"
	"strconv"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysfs "github.com/manchtools/power-manage-sdk/sys/fs"
)

// getFileOwnership retrieves the current owner:group of a file using stat.
func getFileOwnership(path string) (owner, group string) {
	return sysfs.GetOwnership(path)
}

// writeFileWithSudo writes content to a file through the fs Manager (fd-anchored
// on the Direct/root backend; escalated tee otherwise).
func writeFileWithSudo(ctx context.Context, path, content string) (*pb.CommandOutput, error) {
	if err := fsMgr.WriteFile(ctx, path, []byte(content), sysfs.WriteOptions{}); err != nil {
		return &pb.CommandOutput{ExitCode: 1, Stderr: err.Error()}, err
	}
	return &pb.CommandOutput{ExitCode: 0}, nil
}

// atomicWriteFile writes content to a file atomically with the specified
// permissions. The fs Manager's WriteFile is atomic on every backend.
func atomicWriteFile(ctx context.Context, path, content, mode, owner, group string) error {
	opts := sysfs.WriteOptions{Owner: owner, Group: group}
	if mode != "" {
		v, err := strconv.ParseUint(mode, 8, 32)
		if err != nil {
			return fmt.Errorf("invalid file mode %q: %w", mode, err)
		}
		opts.Mode = os.FileMode(v)
	}
	return fsMgr.WriteFile(ctx, path, []byte(content), opts)
}

// readFileWithSudo reads a file's contents through the fs Manager.
func readFileWithSudo(ctx context.Context, path string) (string, error) {
	b, err := fsMgr.ReadFile(ctx, path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// fileExistsWithSudo checks whether a path exists. A probe error is treated as
// "absent" to preserve the boolean contract of the previous helper.
func fileExistsWithSudo(ctx context.Context, path string) bool {
	ok, _ := fsMgr.Exists(ctx, path)
	return ok
}

// removeFileStrict removes a file and returns any error.
func removeFileStrict(ctx context.Context, path string) error {
	return fsMgr.Remove(ctx, path)
}

// createDirectory creates a directory through the fs Manager.
func createDirectory(ctx context.Context, path string, recursive bool) error {
	return fsMgr.Mkdir(ctx, path, sysfs.MkdirOptions{Recursive: recursive})
}

// createDirectoryWithPermissions creates a directory and applies its mode
// and ownership through the fd-based, no-follow helper (WS6 #5). The old
// path-based chmod/chown re-resolved the path and would dereference a final-
// component symlink swapped in after mkdir, redirecting a root chmod/chown onto
// the target. Here the perms are applied via an O_NOFOLLOW|O_DIRECTORY fd, so a
// swapped-in symlink aborts the operation (ELOOP) instead.
func createDirectoryWithPermissions(ctx context.Context, path, mode, owner, group string, recursive bool) error {
	if err := fsMgr.Mkdir(ctx, path, sysfs.MkdirOptions{Recursive: recursive}); err != nil {
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
	return fsMgr.RemoveDir(ctx, path)
}

// userExists checks if a user exists on the system, via the SDK user Manager
// (which runs the `id` lookup) rather than shelling it here.
func userExists(ctx context.Context, username string) bool {
	exists, _ := userMgr.Exists(ctx, username)
	return exists
}

// groupExists checks if a group exists on the system, via the SDK user Manager
// (which runs the `getent group` lookup) rather than shelling it here.
func groupExists(ctx context.Context, groupName string) bool {
	exists, _ := userMgr.GroupExists(ctx, groupName)
	return exists
}
