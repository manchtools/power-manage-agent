// Package executor provides thin wrappers around the SDK sys/fs package.
package executor

import (
	"context"

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

// createDirectoryWithPermissions creates a directory with the specified mode and ownership.
func createDirectoryWithPermissions(ctx context.Context, path, mode, owner, group string, recursive bool) error {
	return sysfs.MkdirWithPermissions(ctx, path, mode, owner, group, recursive)
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
