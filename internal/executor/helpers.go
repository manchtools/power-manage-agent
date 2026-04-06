package executor

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// errReadOnlyFS is a sentinel error returned when the filesystem is read-only and repair failed.
var errReadOnlyFS = fmt.Errorf("filesystem is read-only")

// readOnlyFSOutput returns a CommandOutput for read-only filesystem failures
// with the full diagnostic message.
func readOnlyFSOutput() *pb.CommandOutput {
	return &pb.CommandOutput{
		ExitCode: 1,
		Stderr:   "filesystem is read-only and could not be remounted - system may need reboot and fsck",
	}
}

// readOnlyFSOutputShort returns a CommandOutput for read-only filesystem failures
// with a shorter message (used by some handlers).
func readOnlyFSOutputShort() *pb.CommandOutput {
	return &pb.CommandOutput{
		ExitCode: 1,
		Stderr:   "filesystem is read-only and could not be remounted",
	}
}

// readOnlyFSOutputMinimal returns a CommandOutput with the minimal read-only message.
func readOnlyFSOutputMinimal() *pb.CommandOutput {
	return &pb.CommandOutput{
		ExitCode: 1,
		Stderr:   "filesystem is read-only",
	}
}

// requireWritableFS checks if the filesystem is writable and attempts repair if not.
// Returns nil, nil if writable. Returns (output, error) if repair failed.
func (e *Executor) requireWritableFS(ctx context.Context) (*pb.CommandOutput, error) {
	if e.repairFilesystem(ctx) {
		return nil, nil
	}
	return readOnlyFSOutput(), errReadOnlyFS
}

// requireWritableFSShort is like requireWritableFS but uses a shorter error message.
func (e *Executor) requireWritableFSShort(ctx context.Context) (*pb.CommandOutput, error) {
	if e.repairFilesystem(ctx) {
		return nil, nil
	}
	return readOnlyFSOutputShort(), errReadOnlyFS
}

// requireWritableFSMinimal is like requireWritableFS but uses a minimal error message.
func (e *Executor) requireWritableFSMinimal(ctx context.Context) (*pb.CommandOutput, error) {
	if e.repairFilesystem(ctx) {
		return nil, nil
	}
	return readOnlyFSOutputMinimal(), errReadOnlyFS
}

// getActionID extracts the action ID string from an action, returning "" if nil.
func getActionID(action *pb.Action) string {
	if action == nil || action.Id == nil {
		return ""
	}
	return action.Id.Value
}

// syncGroupMembers adds missing users and removes users no longer in the desired list
// for the given group. It logs warnings for non-existent users.
// Returns (changed bool, error).
func syncGroupMembers(ctx context.Context, groupName string, desiredUsers []string, output *strings.Builder) (bool, error) {
	changed := false

	// Add missing members
	for _, username := range desiredUsers {
		if !userExists(username) {
			output.WriteString(fmt.Sprintf("warning: user %q does not exist, skipping group membership\n", username))
			continue
		}
		if !userInGroup(username, groupName) {
			if err := addUserToGroup(ctx, username, groupName); err != nil {
				output.WriteString(fmt.Sprintf("warning: failed to add user %s to group: %v\n", username, err))
			} else {
				output.WriteString(fmt.Sprintf("added user %s to group %s\n", username, groupName))
				changed = true
			}
		}
	}

	// Remove members not in desired list
	currentMembers := getGroupMembers(groupName)
	desiredSet := make(map[string]bool, len(desiredUsers))
	for _, u := range desiredUsers {
		desiredSet[u] = true
	}
	for _, member := range currentMembers {
		if !desiredSet[member] {
			if err := removeUserFromGroup(ctx, member, groupName); err == nil {
				output.WriteString(fmt.Sprintf("removed user %s from group %s\n", member, groupName))
				changed = true
			}
		}
	}

	return changed, nil
}

// contentChanged checks if a file's content differs from the desired content.
// Returns true if the file doesn't exist or its content differs.
func contentChanged(ctx context.Context, filePath, desiredContent string) (bool, error) {
	existing, err := readFileWithSudo(ctx, filePath)
	if err != nil {
		return true, nil // file doesn't exist, content is "changed"
	}
	return existing != desiredContent, nil
}
