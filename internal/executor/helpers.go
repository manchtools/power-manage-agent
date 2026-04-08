package executor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysuser "github.com/manchtools/power-manage/sdk/go/sys/user"
)

// errReadOnlyFS is a sentinel error returned when the filesystem is read-only and repair failed.
var errReadOnlyFS = errors.New("filesystem is read-only")

// requireWritableFS checks if the filesystem is writable and attempts repair if not.
// Returns nil, nil if writable. Returns (output, error) if repair failed.
func (e *Executor) requireWritableFS(ctx context.Context) (*pb.CommandOutput, error) {
	if e.repairFilesystem(ctx) {
		return nil, nil
	}
	return &pb.CommandOutput{
		ExitCode: 1,
		Stderr:   "filesystem is read-only and could not be remounted",
	}, errReadOnlyFS
}

// validActionIDRegex matches only safe alphanumeric characters for action IDs.
var validActionIDRegex = regexp.MustCompile(`^[A-Za-z0-9]+$`)

// getActionID extracts the action ID string from an action, returning "" if nil or invalid.

func getActionID(action *pb.Action) string {
	if action == nil || action.Id == nil {
		return ""
	}
	id := action.Id.Value
	if id == "" || len(id) > 64 || !validActionIDRegex.MatchString(id) {
		return ""
	}
	return id
}

// syncGroupMembers adds missing users and removes users no longer in the desired list
// for the given group. It logs warnings for non-existent users.
// Returns (changed bool, error). The error is non-nil if any membership operation
// failed, even if some operations succeeded (changed may still be true).
func syncGroupMembers(ctx context.Context, groupName string, desiredUsers []string, output *strings.Builder) (bool, error) {
	changed := false
	var errs []string

	// Add missing members
	for _, username := range desiredUsers {
		if !userExists(username) {
			output.WriteString(fmt.Sprintf("warning: user %q does not exist, skipping group membership\n", username))
			continue
		}
		if !userInGroup(username, groupName) {
			if err := addUserToGroup(ctx, username, groupName); err != nil {
				msg := fmt.Sprintf("failed to add user %s to group %s: %v", username, groupName, err)
				output.WriteString(fmt.Sprintf("warning: %s\n", msg))
				errs = append(errs, msg)
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
			if err := removeUserFromGroup(ctx, member, groupName); err != nil {
				msg := fmt.Sprintf("failed to remove user %s from group %s: %v", member, groupName, err)
				output.WriteString(fmt.Sprintf("warning: %s\n", msg))
				errs = append(errs, msg)
			} else {
				output.WriteString(fmt.Sprintf("removed user %s from group %s\n", member, groupName))
				changed = true
			}
		}
	}

	if len(errs) > 0 {
		return changed, fmt.Errorf("group membership errors: %s", strings.Join(errs, "; "))
	}
	return changed, nil
}


// writeAndValidateConfig writes a config file atomically and validates it with an external command.
// If validation fails, the file is removed and the validation error is returned.
// On success, returns nil, nil.
func (e *Executor) writeAndValidateConfig(ctx context.Context, path, content, mode, owner, group string, validateCmd string, validateArgs ...string) (*pb.CommandOutput, error) {
	if err := atomicWriteFile(ctx, path, content, mode, owner, group); err != nil {
		return nil, fmt.Errorf("write config file: %w", err)
	}

	validateOut, validateErr := runSudoCmd(ctx, validateCmd, validateArgs...)
	if validateErr != nil {
		// Config is invalid — remove it and report error
		if rmErr := removeFileStrict(ctx, path); rmErr != nil {
			slog.Warn("failed to remove invalid config after validation failure", "path", path, "error", rmErr)
		}
		errMsg := "config validation failed"
		if validateOut != nil && validateOut.Stderr != "" {
			errMsg = strings.TrimSpace(validateOut.Stderr)
		}
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   errMsg,
		}, fmt.Errorf("%s validation failed: %s", validateCmd, errMsg)
	}

	return nil, nil
}

// removeGroupWithConfig removes a managed config file and its associated group.
// Removes all users from the group, deletes the group, and removes the config file.
// If configPath is empty, only the group is removed.
func (e *Executor) removeGroupWithConfig(ctx context.Context, groupName, configPath string, output *strings.Builder) (bool, error) {
	changed := false

	// Remove config file if specified
	if configPath != "" && fileExistsWithSudo(ctx, configPath) {
		if _, err := e.requireWritableFS(ctx); err != nil {
			return false, fmt.Errorf("writable fs: %w", err)
		}
		if err := removeFileStrict(ctx, configPath); err != nil {
			return false, fmt.Errorf("remove config file %s: %w", configPath, err)
		}
		output.WriteString(fmt.Sprintf("removed config file: %s\n", configPath))
		changed = true
	}

	// Remove group and membership
	if groupExists(groupName) {
		if !changed {
			// Need writable FS for group operations (may not have been checked above)
			if _, err := e.requireWritableFS(ctx); err != nil {
				return false, fmt.Errorf("writable fs: %w", err)
			}
		}
		members := getGroupMembers(groupName)
		for _, member := range members {
			if err := removeUserFromGroup(ctx, member, groupName); err != nil {
				output.WriteString(fmt.Sprintf("warning: failed to remove user %s from group %s: %v\n", member, groupName, err))
			} else {
				output.WriteString(fmt.Sprintf("removed user %s from group %s\n", member, groupName))
				changed = true
			}
		}
		if err := sysuser.GroupDelete(ctx, groupName); err != nil {
			return changed, fmt.Errorf("delete group %s: %w", groupName, err)
		}
		output.WriteString(fmt.Sprintf("deleted group: %s\n", groupName))
		changed = true
	}

	return changed, nil
}
