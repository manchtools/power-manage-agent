package executor

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysuser "github.com/manchtools/power-manage/sdk/go/sys/user"
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
		if !sysuser.IsValidName(u) {
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
	fileMatches := e.configMatchesDesired(sudoersPath, content)
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
		if err := sysuser.GroupCreate(ctx, groupName); err != nil {
			return nil, false, fmt.Errorf("create group %s: %v", groupName, err)
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
			if err := addUserToGroup(ctx, username, groupName); err != nil {
				output.WriteString(fmt.Sprintf("warning: failed to add user %s to group: %v\n", username, err))
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
			if err := removeUserFromGroup(ctx, member, groupName); err == nil {
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
	if fileExistsWithSudo(ctx, sudoersPath) {
		if !e.repairFilesystem(ctx) {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   "filesystem is read-only and could not be remounted",
			}, false, fmt.Errorf("filesystem is read-only")
		}
		if err := removeFileStrict(ctx, sudoersPath); err != nil {
			return nil, false, fmt.Errorf("remove sudoers file: %w", err)
		}
		output.WriteString(fmt.Sprintf("removed sudoers file: %s\n", sudoersPath))
		changed = true
	}

	// Remove users from group
	if groupExists(groupName) {
		members := getGroupMembers(groupName)
		for _, member := range members {
			if err := removeUserFromGroup(ctx, member, groupName); err == nil {
				output.WriteString(fmt.Sprintf("removed user %s from group %s\n", member, groupName))
				changed = true
			}
		}

		// Delete group
		if err := sysuser.GroupDelete(ctx, groupName); err != nil {
			output.WriteString(fmt.Sprintf("warning: failed to delete group %s: %v\n", groupName, err))
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
		fmt.Sprintf("# Limited sudo access for group %s (password required)", groupName),
		"",
		"# Package management",
		fmt.Sprintf("%%%s ALL=(ALL) /usr/bin/apt, /usr/bin/apt-get, /usr/bin/apt-cache, /usr/bin/dpkg", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) /usr/bin/dnf, /usr/bin/yum, /usr/bin/rpm", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) /usr/bin/pacman", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) /usr/bin/zypper", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) /usr/bin/flatpak, /usr/bin/snap", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) /usr/bin/nix, /usr/bin/nix-env, /usr/bin/nix-store, /usr/bin/nix-channel", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) /sbin/apk", groupName),
		"",
		"# Service and system management",
		fmt.Sprintf("%%%s ALL=(ALL) /usr/bin/systemctl, /usr/bin/journalctl", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) /usr/sbin/reboot, /usr/sbin/shutdown", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) /usr/bin/timedatectl, /usr/bin/hostnamectl", groupName),
		"",
		"# Network management",
		fmt.Sprintf("%%%s ALL=(ALL) /usr/bin/ip, /usr/bin/nmcli, /usr/bin/networkctl", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) /usr/sbin/ufw, /usr/bin/firewall-cmd", groupName),
		"",
		"# Disk and storage",
		fmt.Sprintf("%%%s ALL=(ALL) /usr/bin/mount, /usr/bin/umount, /usr/sbin/blkid", groupName),
		"",
		"# Containers",
		fmt.Sprintf("%%%s ALL=(ALL) /usr/bin/docker, /usr/bin/podman", groupName),
		"",
		"# Diagnostics",
		fmt.Sprintf("%%%s ALL=(ALL) /usr/bin/dmesg", groupName),
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
func addUserToGroup(ctx context.Context, username, groupName string) error {
	return sysuser.GroupAddUser(ctx, username, groupName)
}

// removeUserFromGroup removes a user from a supplementary group.
func removeUserFromGroup(ctx context.Context, username, groupName string) error {
	return sysuser.GroupRemoveUser(ctx, username, groupName)
}

// getGroupMembers returns the members of a group.
func getGroupMembers(groupName string) []string {
	return sysuser.GroupMembers(groupName)
}

// userInGroup checks if a user is a member of the specified group.
func userInGroup(username, groupName string) bool {
	return sysuser.GroupHasUser(username, groupName)
}

// sudoGroupMembersMatch checks if the current group members match the desired list.
func sudoGroupMembersMatch(groupName string, desiredUsers []string) bool {
	return sysuser.GroupMembersMatch(groupName, desiredUsers)
}
