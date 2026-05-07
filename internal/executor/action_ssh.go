// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"fmt"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysuser "github.com/manchtools/power-manage/sdk/go/sys/user"
)

// validateActionIDForFilesystem rejects an actionID that contains
// any character outside the alphanumeric-safe set. Action IDs flow
// into filesystem paths (/etc/sudoers.d/<id>,
// /etc/ssh/sshd_config.d/<id>.conf, …) and into Linux group names
// (pm-ssh-<id>, pm-sudo-<id>). The entry-point getActionID enforces
// the same rule, but defense-in-depth at the splice point matters
// because each action_*.go file accepts actionID as a parameter:
// any future caller that bypasses getActionID would otherwise smuggle
// path-meaningful characters straight into a system path.
func validateActionIDForFilesystem(actionID string) error {
	if actionID == "" {
		return fmt.Errorf("action ID required for group/file naming")
	}
	if len(actionID) > 64 || !validActionIDRegex.MatchString(actionID) {
		return fmt.Errorf("action ID %q contains characters that are unsafe for filesystem paths", actionID)
	}
	return nil
}

// sshGroupName creates a valid Linux group name from the action ID for SSH access.
// Linux group names: max 32 chars. pm-ssh- (7 chars) + up to 25 chars of action ID.
func sshGroupName(actionID string) string {
	lower := strings.ToLower(actionID)
	if len(lower) > 25 {
		lower = lower[:25]
	}
	return "pm-ssh-" + lower
}

// sshConfigPath returns the path for an SSH config drop-in file.
func sshConfigPath(actionID string) string {
	return fmt.Sprintf("/etc/ssh/sshd_config.d/pm-ssh-%s.conf", strings.ToLower(actionID))
}

// sshEffectiveUsers returns the user list from params.
func sshEffectiveUsers(params *pb.SshParams) []string {
	return params.Users
}

// executeSsh configures SSH access via an sshd_config.d drop-in file with a Match Group directive.
// Each action creates a Linux group pm-ssh-{actionId} and users are added to the group.
func (e *Executor) executeSsh(ctx context.Context, params *pb.SshParams, state pb.DesiredState, actionID string) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("ssh params required")
	}
	if err := validateActionIDForFilesystem(actionID); err != nil {
		return nil, false, err
	}

	users := sshEffectiveUsers(params)
	if len(users) == 0 {
		return nil, false, fmt.Errorf("at least one user is required")
	}
	for _, u := range users {
		if !sysuser.IsValidName(u) {
			return nil, false, fmt.Errorf("invalid username: %s", u)
		}
	}

	groupName := sshGroupName(actionID)
	configPath := sshConfigPath(actionID)

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		return e.removeSshAccess(ctx, groupName, configPath)
	default:
		return e.setupSshAccess(ctx, params, users, groupName, configPath)
	}
}

// generateSshGroupConfig generates sshd_config content using Match Group.
func generateSshGroupConfig(groupName string, params *pb.SshParams) string {
	lines := []string{
		"# Managed by Power Manage - do not edit manually",
		fmt.Sprintf("Match Group %s", groupName),
	}
	if params.AllowPubkey {
		lines = append(lines, "    PubkeyAuthentication yes")
		lines = append(lines, "    AuthorizedKeysFile .ssh/authorized_keys")
	} else {
		lines = append(lines, "    PubkeyAuthentication no")
	}
	if params.AllowPassword {
		lines = append(lines, "    PasswordAuthentication yes")
	} else {
		lines = append(lines, "    PasswordAuthentication no")
	}
	return strings.Join(lines, "\n") + "\n"
}

// setupSshAccess creates or updates the SSH access group and sshd_config.d file.
func (e *Executor) setupSshAccess(ctx context.Context, params *pb.SshParams, users []string, groupName, configPath string) (*pb.CommandOutput, bool, error) {
	var output strings.Builder
	changed := false

	// Generate sshd config content
	content := generateSshGroupConfig(groupName, params)

	// Check idempotency: file content + group membership
	fileMatches := e.configMatchesDesired(ctx, configPath, content)
	membersMatch := sudoGroupMembersMatch(groupName, users)
	if fileMatches && membersMatch {
		output.WriteString(fmt.Sprintf("SSH config already up to date: %s\n", configPath))
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

	// Write sshd config file with validation
	if !fileMatches {
		// Ensure /etc/ssh/sshd_config.d exists
		if err := createDirectory(ctx, "/etc/ssh/sshd_config.d", true); err != nil {
			return nil, false, fmt.Errorf("create sshd_config.d: %w", err)
		}
		if out, err := e.writeAndValidateConfig(ctx, configPath, content, "0644", "root", "root", "sshd", "-t"); err != nil {
			return out, false, err
		}
		output.WriteString(fmt.Sprintf("wrote SSH config: %s\n", configPath))
		changed = true
		reloadSshd(ctx, &output)
	}

	// Sync group membership
	if memberChanged, err := syncGroupMembers(ctx, groupName, users, &output); err != nil {
		return &pb.CommandOutput{ExitCode: 1, Stdout: output.String(), Stderr: err.Error()}, changed, err
	} else if memberChanged {
		changed = true
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, changed, nil
}

// removeSshAccess removes the sshd_config.d file, group membership, and group.
func (e *Executor) removeSshAccess(ctx context.Context, groupName, configPath string) (*pb.CommandOutput, bool, error) {
	var output strings.Builder

	changed, err := e.removeGroupWithConfig(ctx, groupName, configPath, &output)
	if err != nil {
		if !changed {
			return nil, false, err
		}
		output.WriteString(fmt.Sprintf("warning: %v\n", err))
	}

	// Reload sshd after removing the config drop-in
	if changed {
		reloadSshd(ctx, &output)
	}

	if !changed {
		output.WriteString("SSH access does not exist, nothing to remove\n")
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, changed, nil
}

// configMatchesDesired checks if a config file already has the desired content.
func (e *Executor) configMatchesDesired(ctx context.Context, path, desiredContent string) bool {
	if !fileExistsWithSudo(ctx, path) {
		return false
	}
	existing, err := readFileWithSudo(ctx, path)
	if err != nil {
		return false
	}
	return existing == desiredContent
}

// executeSshd configures the SSH daemon via sshd_config.d drop-in files.
func (e *Executor) executeSshd(ctx context.Context, params *pb.SshdParams, state pb.DesiredState, actionID string) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("sshd params required")
	}
	if len(params.Directives) == 0 && state != pb.DesiredState_DESIRED_STATE_ABSENT {
		return nil, false, fmt.Errorf("at least one directive is required")
	}
	if err := validateActionIDForFilesystem(actionID); err != nil {
		return nil, false, err
	}

	configPath := fmt.Sprintf("/etc/ssh/sshd_config.d/%04d-pm-%s.conf", params.Priority, actionID)

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		return e.removeSshdConfig(ctx, configPath)
	default:
		return e.setupSshdConfig(ctx, params, configPath)
	}
}

// generateSshdGlobalConfig generates sshd_config content from directives.
// Returns an error if any directive's key or value contains a newline,
// carriage return, or NUL — these characters would split one directive
// into multiple lines (or terminate the file early via NUL) and let a
// crafted action smuggle arbitrary additional sshd directives past the
// caller's intent. sshd_config has no escape syntax; fail loudly at
// generation time.
func generateSshdGlobalConfig(params *pb.SshdParams) (string, error) {
	var lines []string
	lines = append(lines, "# Managed by Power Manage - do not edit manually")
	for _, d := range params.Directives {
		if strings.ContainsAny(d.Key, "\n\r\x00") {
			return "", fmt.Errorf("sshd directive key contains forbidden control character (CR, LF, or NUL)")
		}
		if strings.ContainsAny(d.Value, "\n\r\x00") {
			return "", fmt.Errorf("sshd directive %q value contains forbidden control character (CR, LF, or NUL)", d.Key)
		}
		lines = append(lines, fmt.Sprintf("%s %s", d.Key, d.Value))
	}
	return strings.Join(lines, "\n") + "\n", nil
}

// setupSshdConfig creates or updates an sshd_config.d drop-in file and reloads sshd if changed.
func (e *Executor) setupSshdConfig(ctx context.Context, params *pb.SshdParams, configPath string) (*pb.CommandOutput, bool, error) {
	var output strings.Builder

	content, err := generateSshdGlobalConfig(params)
	if err != nil {
		return nil, false, err
	}

	// Check idempotency
	if e.configMatchesDesired(ctx, configPath, content) {
		output.WriteString(fmt.Sprintf("SSHD config already up to date: %s\n", configPath))
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   output.String(),
		}, false, nil
	}

	if out, err := e.requireWritableFS(ctx); err != nil {
		return out, false, err
	}

	// Ensure /etc/ssh/sshd_config.d exists
	if err := createDirectory(ctx, "/etc/ssh/sshd_config.d", true); err != nil {
		return nil, false, fmt.Errorf("create sshd_config.d: %w", err)
	}

	if out, err := e.writeAndValidateConfig(ctx, configPath, content, "0644", "root", "root", "sshd", "-t"); err != nil {
		return out, false, err
	}
	output.WriteString(fmt.Sprintf("created SSHD config: %s\n", configPath))

	reloadSshd(ctx, &output)

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, true, nil
}

// removeSshdConfig removes an sshd_config.d drop-in file and reloads sshd.
func (e *Executor) removeSshdConfig(ctx context.Context, configPath string) (*pb.CommandOutput, bool, error) {
	var output strings.Builder

	if !fileExistsWithSudo(ctx, configPath) {
		output.WriteString(fmt.Sprintf("SSHD config does not exist: %s\n", configPath))
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   output.String(),
		}, false, nil
	}

	if out, err := e.requireWritableFS(ctx); err != nil {
		return out, false, err
	}

	if err := removeFileStrict(ctx, configPath); err != nil {
		return nil, false, fmt.Errorf("remove sshd config: %w", err)
	}
	output.WriteString(fmt.Sprintf("removed SSHD config: %s\n", configPath))
	reloadSshd(ctx, &output)

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   output.String(),
	}, true, nil
}
