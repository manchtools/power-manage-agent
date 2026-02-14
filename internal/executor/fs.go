// Package executor provides thin wrappers around the SDK sys/fs package.
package executor

import (
	"context"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysfs "github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// buildOwnership constructs an "owner:group" string for chown commands.
func buildOwnership(owner, group string) string {
	return sysfs.Ownership(owner, group)
}

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

// setFileMode sets the file mode (permissions) using sudo chmod.
func setFileMode(ctx context.Context, path, mode string) error {
	if mode == "" {
		return nil
	}
	return sysfs.SetMode(ctx, path, mode)
}

// setFileOwnership sets the file owner and group using sudo chown.
func setFileOwnership(ctx context.Context, path, owner, group string) error {
	ownership := sysfs.Ownership(owner, group)
	if ownership == "" {
		return nil
	}
	return sysfs.SetOwnership(ctx, path, owner, group)
}

// setFilePermissions sets both mode and ownership on a file.
func setFilePermissions(ctx context.Context, path, mode, owner, group string) error {
	return sysfs.SetPermissions(ctx, path, mode, owner, group)
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

// removeFile removes a file using sudo rm -f (best-effort, no error).
func removeFile(ctx context.Context, path string) {
	sysfs.Remove(ctx, path)
}

// removeFileStrict removes a file and returns any error.
func removeFileStrict(ctx context.Context, path string) error {
	return sysfs.RemoveStrict(ctx, path)
}

// createDirectory creates a directory using sudo mkdir.
func createDirectory(ctx context.Context, path string, recursive bool) error {
	return sysfs.Mkdir(ctx, path, recursive)
}

// createDirectoryWithPermissions creates a directory with the specified mode and ownership.
func createDirectoryWithPermissions(ctx context.Context, path, mode, owner, group string, recursive bool) error {
	return sysfs.MkdirWithPermissions(ctx, path, mode, owner, group, recursive)
}

// removeDirectory removes a directory and its contents.
func removeDirectory(ctx context.Context, path string) error {
	return sysfs.RemoveDir(ctx, path)
}

// copyFile copies a file from src to dst.
func copyFile(ctx context.Context, src, dst string) error {
	return sysfs.CopyFile(ctx, src, dst)
}

// copyFileWithPermissions copies a file and sets the specified permissions.
func copyFileWithPermissions(ctx context.Context, src, dst, mode, owner, group string) error {
	return sysfs.CopyFileWithPermissions(ctx, src, dst, mode, owner, group)
}

// userExists checks if a user exists on the system.
func userExists(username string) bool {
	return checkCmdSuccess("id", username)
}

// groupExists checks if a group exists on the system.
func groupExists(groupName string) bool {
	return checkCmdSuccess("getent", "group", groupName)
}
