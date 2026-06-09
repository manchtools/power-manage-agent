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
// For longer action IDs, falls back to a hash-suffix scheme to keep
// the mapping unique — see shortGroupName.
func sanitizeSudoGroupName(actionID string) string {
	return shortGroupName("pm-sudo-", actionID)
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
	if err := validateActionIDForFilesystem(actionID); err != nil {
		return nil, false, err
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

	// Generate sudoers content. The switch is extracted into
	// sudoConfigForParams so unit tests can pin the enum → template
	// mapping without touching the filesystem / group-membership
	// work this function does next.
	content, err := sudoConfigForParams(params, groupName)
	if err != nil {
		return nil, false, err
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
		if _, err := sysuser.GroupCreate(ctx, groupName); err != nil {
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

// sudoConfigForParams maps an AdminPolicyParams to the sudoers content
// that setupSudoPolicy will write to disk. Extracted from
// setupSudoPolicy so unit tests can pin the enum → template mapping
// without standing up the surrounding filesystem / group-membership
// work.
//
// The two TERMINAL_ADMIN_* arms route to passwordless templates
// designed for pm-tty-* accounts (see manchtools/power-manage-server#70).
// The pre-existing FULL/LIMITED/CUSTOM arms are unchanged — operator-
// authored AdminPolicy actions continue to behave exactly as they did
// before this PR.
func sudoConfigForParams(params *pb.AdminPolicyParams, groupName string) (string, error) {
	switch params.AccessLevel {
	case pb.AdminAccessLevel_ADMIN_ACCESS_LEVEL_FULL:
		return generateFullSudoConfig(groupName), nil
	case pb.AdminAccessLevel_ADMIN_ACCESS_LEVEL_LIMITED:
		return generateLimitedSudoConfig(groupName), nil
	case pb.AdminAccessLevel_ADMIN_ACCESS_LEVEL_CUSTOM:
		if params.CustomConfig == "" {
			return "", fmt.Errorf("custom_config is required when access_level is CUSTOM")
		}
		return generateCustomSudoConfig(groupName, params.CustomConfig), nil
	case pb.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_LIMITED:
		return generateTerminalAdminLimitedSudoConfig(groupName), nil
	case pb.AdminAccessLevel_ADMIN_ACCESS_LEVEL_TERMINAL_ADMIN_FULL:
		return generateTerminalAdminFullSudoConfig(groupName), nil
	default:
		return "", fmt.Errorf("unsupported access level: %v", params.AccessLevel)
	}
}

// terminalAdminDefaultsBlock is the Defaults block both TERMINAL_ADMIN
// templates emit at the top of their sudoers fragment. Per the ADR's
// T4: requiretty pins TTY-stream input audit; env_reset stops
// LD_PRELOAD / BASH_ENV / PATH propagation; !lecture skips the
// operator-confusing first-time prompt; timestamp_timeout=0 forces
// sudoers re-evaluation on every sudo call so a fresh revocation lands
// immediately under NOPASSWD.
//
// The Defaults are scoped to the group (`Defaults:%group`), NOT bare.
// A bare `Defaults` line in an /etc/sudoers.d drop-in applies host-
// globally to every sudo invocation on the box — so a bare requiretty
// would break root's non-TTY sudo (cron, systemd units, ansible) and a
// bare timestamp_timeout=0 would strip credential caching for every
// other admin. The ADR's threat model only concerns the TerminalAdmin
// group, so the per-group binding is the correct scope.
func terminalAdminDefaultsBlock(groupName string) string {
	g := "%" + groupName
	return strings.Join([]string{
		"Defaults:" + g + " requiretty",
		"Defaults:" + g + " env_reset",
		"Defaults:" + g + " !lecture",
		"Defaults:" + g + " timestamp_timeout=0",
	}, "\n")
}

// terminalAdminLimitedDenyBlocks are the !-deny rules the LIMITED
// template emits to close ADR T2 (editor escapes), T3 (shell spawns),
// and T5 (persistence vectors). Under NOPASSWD an escape vector in
// the allowlist is unprompted root, so the deny rules are mandatory,
// not advisory.
func terminalAdminLimitedDenyBlocks(groupName string) []string {
	return []string{
		"",
		"# Deny editor escapes (vim :!bash, less !sh, etc.) — ADR T2",
		fmt.Sprintf("%%%s ALL=(ALL) !/usr/bin/vim, !/usr/bin/vi, !/usr/bin/vimdiff, !/usr/bin/view, !/usr/bin/nvim", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) !/usr/bin/emacs, !/usr/bin/emacsclient", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) !/usr/bin/nano, !/bin/nano", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) !/usr/bin/less, !/usr/bin/more, !/usr/bin/most", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) !/usr/bin/ed, !/usr/bin/ex", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) !/usr/bin/mc, !/usr/bin/joe, !/usr/bin/jed", groupName),
		"",
		"# Deny shell spawns — ADR T3",
		fmt.Sprintf("%%%s ALL=(ALL) !/bin/sh, !/bin/bash, !/bin/dash, !/bin/zsh, !/bin/ksh, !/bin/csh, !/bin/tcsh, !/bin/fish", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) !/usr/bin/sh, !/usr/bin/bash, !/usr/bin/dash, !/usr/bin/zsh, !/usr/bin/ksh, !/usr/bin/csh, !/usr/bin/tcsh, !/usr/bin/fish", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) !/usr/bin/env", groupName),
		"",
		"# Deny persistence vectors — ADR T5",
		fmt.Sprintf("%%%s ALL=(ALL) !/usr/bin/at, !/usr/bin/atq, !/usr/bin/atrm, !/usr/bin/batch", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) !/usr/bin/crontab", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) !/usr/sbin/dpkg-divert, !/usr/bin/dpkg-divert", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) !/usr/bin/update-alternatives, !/usr/sbin/update-alternatives", groupName),
	}
}

// generateTerminalAdminLimitedSudoConfig is the LIMITED template for
// the server's TerminalAdmin reconciler (#70). The allowlist mirrors
// the existing generateLimitedSudoConfig content (package management,
// systemd, network, disk, containers, diagnostics, agent-protection
// denies) but every rule carries NOPASSWD: and the editor/shell/
// persistence deny blocks land on top.
func generateTerminalAdminLimitedSudoConfig(groupName string) string {
	lines := []string{
		"# Managed by Power Manage — do not edit manually",
		fmt.Sprintf("# Passwordless LIMITED sudo for group %s (TerminalAdmin, server #70)", groupName),
		"",
		terminalAdminDefaultsBlock(groupName),
		"",
		"# Package management",
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/apt, /usr/bin/apt-get, /usr/bin/apt-cache, /usr/bin/dpkg", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/dnf, /usr/bin/yum, /usr/bin/rpm", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/pacman", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/zypper", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/flatpak, /usr/bin/snap", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/nix, /usr/bin/nix-env, /usr/bin/nix-store, /usr/bin/nix-channel", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /sbin/apk", groupName),
		"",
		"# Service and system management",
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/systemctl, /usr/bin/journalctl", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/sbin/reboot, /usr/sbin/shutdown", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/timedatectl, /usr/bin/hostnamectl", groupName),
		"",
		"# Network management",
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/ip, /usr/bin/nmcli, /usr/bin/networkctl", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/sbin/ufw, /usr/bin/firewall-cmd", groupName),
		"",
		"# Disk and storage",
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/mount, /usr/bin/umount, /usr/sbin/blkid", groupName),
		"",
		"# Containers",
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/docker, /usr/bin/podman", groupName),
		"",
		"# Diagnostics",
		fmt.Sprintf("%%%s ALL=(ALL) NOPASSWD: /usr/bin/dmesg", groupName),
		"",
		"# Deny modifications to power-manage-agent and sudoers",
		fmt.Sprintf("%%%s ALL=(ALL) !/usr/bin/systemctl * power-manage-agent*", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) !/usr/bin/visudo, !/usr/sbin/visudo", groupName),
	}
	lines = append(lines, terminalAdminLimitedDenyBlocks(groupName)...)
	return strings.Join(lines, "\n") + "\n"
}

// generateTerminalAdminFullSudoConfig is the FULL template for
// TerminalAdmin (#70). Single ALL=(ALL:ALL) NOPASSWD: ALL grant
// preceded by the same Defaults block as the Limited template — the
// Defaults block applies regardless of access level.
func generateTerminalAdminFullSudoConfig(groupName string) string {
	lines := []string{
		"# Managed by Power Manage — do not edit manually",
		fmt.Sprintf("# Passwordless FULL sudo for group %s (TerminalAdmin, server #70)", groupName),
		"",
		terminalAdminDefaultsBlock(groupName),
		"",
		fmt.Sprintf("%%%s ALL=(ALL:ALL) NOPASSWD: ALL", groupName),
	}
	return strings.Join(lines, "\n") + "\n"
}

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
		fmt.Sprintf("%%%s ALL=(ALL) !/usr/bin/systemctl * power-manage-agent*", groupName),
		fmt.Sprintf("%%%s ALL=(ALL) !/usr/bin/visudo, !/usr/sbin/visudo", groupName),
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
	_, err := sysuser.GroupAddUser(ctx, username, groupName)
	return err
}

// removeUserFromGroup removes a user from a supplementary group.
func removeUserFromGroup(ctx context.Context, username, groupName string) error {
	_, err := sysuser.GroupRemoveUser(ctx, username, groupName)
	return err
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
