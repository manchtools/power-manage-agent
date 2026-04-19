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
func (e *Executor) executeSudo(ctx context.Context, params *pb.AdminPolicyParams, state pb.DesiredState, actionID string) (*pb.CommandOutput, bool, error) {
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
func (e *Executor) setupSudoPolicy(ctx context.Context, params *pb.AdminPolicyParams, groupName, sudoersPath string) (*pb.CommandOutput, bool, error) {
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
	case pb.AdminAccessLevel_ADMIN_ACCESS_LEVEL_FULL:
		content = generateFullSudoConfig(groupName)
	case pb.AdminAccessLevel_ADMIN_ACCESS_LEVEL_LIMITED:
		content = generateLimitedSudoConfig(groupName)
	case pb.AdminAccessLevel_ADMIN_ACCESS_LEVEL_CUSTOM:
		if params.CustomConfig == "" {
			return nil, false, fmt.Errorf("custom_config is required when access_level is CUSTOM")
		}
		content = generateCustomSudoConfig(groupName, params.CustomConfig)
	default:
		return nil, false, fmt.Errorf("unsupported access level: %v", params.AccessLevel)
	}

	// Check idempotency: file content + group membership
	fileMatches := e.configMatchesDesired(ctx, sudoersPath, content)
	membersMatch := sudoGroupMembersMatch(groupName, params.Users)
	if fileMatches && membersMatch {
		output.WriteString(fmt.Sprintf("sudo policy already up to date: %s\n", sudoersPath))
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   output.String(),
		}, false, nil
	}

	if out, err := e.requireWritableFS(ctx); err != nil {
		return out, false, err
	}

	// Ensure group exists
	if !groupExists(groupName) {
		if err := sysuser.GroupCreate(ctx, groupName); err != nil {
			return nil, false, fmt.Errorf("create group %s: %v", groupName, err)
		}
		output.WriteString(fmt.Sprintf("created group: %s\n", groupName))
		changed = true
	}

	// Write and validate sudoers file
	if !fileMatches {
		if out, err := e.writeAndValidateConfig(ctx, sudoersPath, content, "0440", "root", "root", "visudo", "-c", "-f", sudoersPath); err != nil {
			return out, false, err
		}
		output.WriteString(fmt.Sprintf("wrote sudoers file: %s\n", sudoersPath))
		changed = true
	}

	// Sync group membership
	if memberChanged, err := syncGroupMembers(ctx, groupName, params.Users, &output); err != nil {
		return &pb.CommandOutput{ExitCode: 1, Stdout: output.String(), Stderr: err.Error()}, memberChanged, err
	} else if memberChanged {
		changed = true
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, changed, nil
}

// removeSudoPolicy removes a sudo policy: sudoers file, group membership, and group.
func (e *Executor) removeSudoPolicy(ctx context.Context, groupName, sudoersPath string, _ []string) (*pb.CommandOutput, bool, error) {
	var output strings.Builder

	changed, err := e.removeGroupWithConfig(ctx, groupName, sudoersPath, &output)
	if err != nil {
		if !changed {
			// Config file removal failed — fatal
			return nil, false, err
		}
		// Config removed but group deletion failed — non-fatal warning
		output.WriteString(fmt.Sprintf("warning: %v\n", err))
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
