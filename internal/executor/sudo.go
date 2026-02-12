package executor

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// sanitizeSudoGroupName creates a valid Linux group name from the action ID.
// Linux group names: max 32 chars. pm-sudo- (8 chars) + up to 24 chars of action ID.
func sanitizeSudoGroupName(actionID string) string {
	lower := strings.ToLower(actionID)
	if len(lower) > 24 {
		lower = lower[:24]
	}
	return "pm-sudo-" + lower
}

// sudoersFilePath returns the path for a sudoers drop-in file.
func sudoersFilePath(actionID string) string {
	return fmt.Sprintf("/etc/sudoers.d/pm-sudo-%s", strings.ToLower(actionID))
}

// executeSudo manages sudoers policies via /etc/sudoers.d/ drop-in files.
func (e *Executor) executeSudo(ctx context.Context, params *pb.SudoParams, state pb.DesiredState, actionID string) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("sudo params required")
	}
	if actionID == "" {
		return nil, false, fmt.Errorf("action ID required for sudo group/file naming")
	}

	groupName := sanitizeSudoGroupName(actionID)
	filePath := sudoersFilePath(actionID)

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		return e.removeSudoPolicy(ctx, groupName, filePath, params.Users)
	default:
		return e.setupSudoPolicy(ctx, params, groupName, filePath)
	}
}

// setupSudoPolicy creates or updates a sudo policy: group, sudoers file, and user membership.
func (e *Executor) setupSudoPolicy(ctx context.Context, params *pb.SudoParams, groupName, sudoersPath string) (*pb.CommandOutput, bool, error) {
	var output strings.Builder
	changed := false

	// Validate usernames
	for _, u := range params.Users {
		if !isValidUsername(u) {
			return nil, false, fmt.Errorf("invalid username: %q", u)
		}
	}

	// Generate sudoers content
	var content string
	switch params.AccessLevel {
	case pb.SudoAccessLevel_SUDO_ACCESS_LEVEL_FULL:
		content = generateFullSudoConfig(groupName)
	case pb.SudoAccessLevel_SUDO_ACCESS_LEVEL_LIMITED:
		content = generateLimitedSudoConfig(groupName)
	case pb.SudoAccessLevel_SUDO_ACCESS_LEVEL_CUSTOM:
		if params.CustomConfig == "" {
			return nil, false, fmt.Errorf("custom_config is required when access_level is CUSTOM")
		}
		content = generateCustomSudoConfig(groupName, params.CustomConfig)
	default:
		return nil, false, fmt.Errorf("unsupported access level: %v", params.AccessLevel)
	}

	// Check idempotency: file content + group membership
	fileMatches := e.sshConfigMatchesDesired(sudoersPath, content)
	membersMatch := sudoGroupMembersMatch(groupName, params.Users)
	if fileMatches && membersMatch {
		output.WriteString(fmt.Sprintf("sudo policy already up to date: %s\n", sudoersPath))
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   output.String(),
		}, false, nil
	}

	if !e.repairFilesystem(ctx) {
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   "filesystem is read-only and could not be remounted",
		}, false, fmt.Errorf("filesystem is read-only")
	}

	// Ensure group exists
	if !groupExists(groupName) {
		if grpOut, err := groupAdd(ctx, groupName); err != nil {
			errMsg := "failed to create group"
			if grpOut != nil && grpOut.Stderr != "" {
				errMsg = strings.TrimSpace(grpOut.Stderr)
			}
			return nil, false, fmt.Errorf("create group %s: %s", groupName, errMsg)
		}
		output.WriteString(fmt.Sprintf("created group: %s\n", groupName))
		changed = true
	}

	// Write sudoers file
	if !fileMatches {
		if err := atomicWriteFile(ctx, sudoersPath, content, "0440", "root", "root"); err != nil {
			return nil, false, fmt.Errorf("write sudoers file: %w", err)
		}
		output.WriteString(fmt.Sprintf("wrote sudoers file: %s\n", sudoersPath))

		// Validate with visudo
		validateOut, validateErr := runSudoCmd(ctx, "visudo", "-c", "-f", sudoersPath)
		if validateErr != nil {
			// Config is invalid — remove it and report error
			removeFileStrict(ctx, sudoersPath)
			errMsg := "sudoers validation failed"
			if validateOut != nil && validateOut.Stderr != "" {
				errMsg = strings.TrimSpace(validateOut.Stderr)
			}
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   errMsg,
			}, false, fmt.Errorf("visudo validation failed: %s", errMsg)
		}
		changed = true
	}

	// Add users to group
	for _, username := range params.Users {
		if !userExists(username) {
			output.WriteString(fmt.Sprintf("warning: user %q does not exist, skipping group membership\n", username))
			continue
		}
		if !userInGroup(username, groupName) {
			if addOut, err := addUserToGroup(ctx, username, groupName); err != nil {
				errMsg := "failed to add user to group"
				if addOut != nil && addOut.Stderr != "" {
					errMsg = strings.TrimSpace(addOut.Stderr)
				}
				output.WriteString(fmt.Sprintf("warning: %s for user %s: %s\n", errMsg, username, err))
			} else {
				output.WriteString(fmt.Sprintf("added user %s to group %s\n", username, groupName))
				changed = true
			}
		}
	}

	// Remove users that are no longer in the list
	currentMembers := getGroupMembers(groupName)
	desiredSet := make(map[string]bool, len(params.Users))
	for _, u := range params.Users {
		desiredSet[u] = true
	}
	for _, member := range currentMembers {
		if !desiredSet[member] {
			if _, err := removeUserFromGroup(ctx, member, groupName); err == nil {
				output.WriteString(fmt.Sprintf("removed user %s from group %s\n", member, groupName))
				changed = true
			}
		}
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, changed, nil
}

// removeSudoPolicy removes a sudo policy: sudoers file, group membership, and group.
func (e *Executor) removeSudoPolicy(ctx context.Context, groupName, sudoersPath string, users []string) (*pb.CommandOutput, bool, error) {
	var output strings.Builder
	changed := false

	// Remove sudoers file
	if _, err := os.Stat(sudoersPath); err == nil {
		if !e.repairFilesystem(ctx) {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   "filesystem is read-only and could not be remounted",
			}, false, fmt.Errorf("filesystem is read-only")
		}
		if _, err := removeFileStrict(ctx, sudoersPath); err != nil {
			return nil, false, fmt.Errorf("remove sudoers file: %w", err)
		}
		output.WriteString(fmt.Sprintf("removed sudoers file: %s\n", sudoersPath))
		changed = true
	}

	// Remove users from group
	if groupExists(groupName) {
		members := getGroupMembers(groupName)
		for _, member := range members {
			if _, err := removeUserFromGroup(ctx, member, groupName); err == nil {
				output.WriteString(fmt.Sprintf("removed user %s from group %s\n", member, groupName))
				changed = true
			}
		}

		// Delete group
		if delOut, err := groupDel(ctx, groupName); err != nil {
			errMsg := "failed to delete group"
			if delOut != nil && delOut.Stderr != "" {
				errMsg = strings.TrimSpace(delOut.Stderr)
			}
			output.WriteString(fmt.Sprintf("warning: %s %s: %s\n", errMsg, groupName, err))
		} else {
			output.WriteString(fmt.Sprintf("deleted group: %s\n", groupName))
			changed = true
		}
	}

	if !changed {
		output.WriteString("sudo policy does not exist, nothing to remove\n")
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, changed, nil
}

// =============================================================================
// Sudoers config generators
// =============================================================================

func generateFullSudoConfig(groupName string) string {
	lines := []string{
		"# Managed by Power Manage - do not edit manually",
		fmt.Sprintf("# Full sudo access for group %s (password required)", groupName),
		fmt.Sprintf("%%%s ALL=(ALL:ALL) ALL", groupName),
	}
	return strings.Join(lines, "\n") + "\n"
}

func generateLimitedSudoConfig(groupName string) string {
	lines := []string{
		"# Managed by Power Manage - do not edit manually",
		fmt.Sprintf("# Limited sudo access for group %s", groupName),
		"",
		"# Package management",
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get, /usr/bin/apt-cache, /usr/bin/dpkg", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/dnf, /usr/bin/yum, /usr/bin/rpm", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/pacman", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/zypper", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/flatpak, /usr/bin/snap", groupName),
		"",
		"# Service and system management",
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/journalctl", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/sbin/reboot, /usr/sbin/shutdown", groupName),
		"",
		"# Deny modifications to power-manage-agent and sudoers",
		fmt.Sprintf("%%%s ALL=(ALL) !!/usr/bin/systemctl * power-manage-agent*", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) !!/usr/bin/visudo, !!/usr/sbin/visudo", groupName),
	}
	return strings.Join(lines, "\n") + "\n"
}

func generateCustomSudoConfig(groupName, customConfig string) string {
	// Replace {group} placeholder with actual group name
	resolved := strings.ReplaceAll(customConfig, "{group}", groupName)
	lines := []string{
		"# Managed by Power Manage - do not edit manually",
		fmt.Sprintf("# Custom sudo access for group %s", groupName),
		"",
		resolved,
	}
	return strings.Join(lines, "\n") + "\n"
}

// =============================================================================
// Group membership helpers
// =============================================================================

// addUserToGroup adds a user to a supplementary group.
func addUserToGroup(ctx context.Context, username, groupName string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "usermod", "-aG", groupName, username)
}

// removeUserFromGroup removes a user from a supplementary group.
func removeUserFromGroup(ctx context.Context, username, groupName string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "gpasswd", "-d", username, groupName)
}

// groupDel deletes a group.
func groupDel(ctx context.Context, groupName string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "groupdel", groupName)
}

// getGroupMembers returns the members of a group.
func getGroupMembers(groupName string) []string {
	out, err := queryCmd("getent", "group", groupName)
	if err != nil {
		return nil
	}
	fields := strings.Split(strings.TrimSpace(out), ":")
	if len(fields) < 4 || fields[3] == "" {
		return nil
	}
	return strings.Split(fields[3], ",")
}

// userInGroup checks if a user is a member of the specified group.
func userInGroup(username, groupName string) bool {
	members := getGroupMembers(groupName)
	for _, m := range members {
		if m == username {
			return true
		}
	}
	return false
}

// sudoGroupMembersMatch checks if the current group members match the desired list.
func sudoGroupMembersMatch(groupName string, desiredUsers []string) bool {
	if !groupExists(groupName) {
		return len(desiredUsers) == 0
	}
	current := getGroupMembers(groupName)
	if len(current) != len(desiredUsers) {
		return false
	}
	// Sort both and compare
	sortedCurrent := make([]string, len(current))
	copy(sortedCurrent, current)
	sort.Strings(sortedCurrent)

	sortedDesired := make([]string, len(desiredUsers))
	copy(sortedDesired, desiredUsers)
	sort.Strings(sortedDesired)

	for i := range sortedCurrent {
		if sortedCurrent[i] != sortedDesired[i] {
			return false
		}
	}
	return true
}
