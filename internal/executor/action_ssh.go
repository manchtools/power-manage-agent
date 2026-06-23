// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysuser "github.com/manchtools/power-manage-sdk/sys/user"
)

// shortGroupName builds a Linux-group-safe name from a prefix and an
// actionID, enforcing the 32-character group-name limit. If
// prefix+actionID fits, the actionID is used verbatim (preserving
// human-readable naming for typical ULID-length inputs). If it would
// overflow, the actionID is replaced with a short stable hash so two
// IDs sharing a long common prefix can't collide on the same group.
// The hash carries 32 bits of collision space — adequate per host
// because the namespace is per-action and the group is unlinked when
// the action is removed.
func shortGroupName(prefix, actionID string) string {
	const linuxGroupMax = 32
	lower := strings.ToLower(actionID)
	full := prefix + lower
	if len(full) <= linuxGroupMax {
		return full
	}
	sum := sha256.Sum256([]byte(lower))
	hashHex := hex.EncodeToString(sum[:])
	// Reserve 1 char for separator, 8 chars for hash; the rest is
	// readable prefix from the actionID itself.
	const hashLen = 8
	const sepLen = 1
	keep := linuxGroupMax - len(prefix) - sepLen - hashLen
	if keep < 1 {
		// Pathological: prefix alone leaves no room for any hash.
		// Caller should keep prefixes short; truncate the prefix in
		// that case so the hash fits — name is no longer
		// human-readable but stays collision-resistant.
		return prefix[:linuxGroupMax-sepLen-hashLen] + "-" + hashHex[:hashLen]
	}
	return prefix + lower[:keep] + "-" + hashHex[:hashLen]
}

// maxActionIDForFilesystem caps the length of an actionID before it is
// spliced into a filesystem path or Linux group name. getActionID
// already enforces the same ceiling at the entry point, but the
// per-action functions accept actionID as a parameter, so we re-check
// here as defense in depth. Set the same as getActionID's limit to
// avoid divergence: any ID accepted upstream is accepted here.
const maxActionIDForFilesystem = 64

// validateActionIDForFilesystem rejects an actionID that is empty,
// too long, or contains any character outside the alphanumeric-safe
// set. Action IDs flow into filesystem paths
// (/etc/sudoers.d/<id>, /etc/ssh/sshd_config.d/<id>.conf, …) and into
// Linux group names (pm-ssh-<id>, pm-sudo-<id>). The entry-point
// getActionID enforces the same rule, but each action_*.go file
// accepts actionID as a parameter and any future caller that bypasses
// getActionID would otherwise smuggle path-meaningful characters
// straight into a system path. Errors are split per failure mode so
// callers can distinguish length issues from character issues.
func validateActionIDForFilesystem(actionID string) error {
	if actionID == "" {
		return fmt.Errorf("action ID required for group/file naming")
	}
	if len(actionID) > maxActionIDForFilesystem {
		return fmt.Errorf("action ID %q exceeds %d-character limit for filesystem use", actionID, maxActionIDForFilesystem)
	}
	if !validActionIDRegex.MatchString(actionID) {
		return fmt.Errorf("action ID %q contains characters that are unsafe for filesystem paths", actionID)
	}
	return nil
}

// sshGroupName creates a valid Linux group name from the action ID for SSH access.
// Linux group names: max 32 chars. pm-ssh- (7 chars) + up to 25 chars of action ID.
// For longer action IDs, falls back to a hash-suffix scheme to keep
// the mapping unique — naïve truncation could otherwise let two
// distinct IDs sharing a 25-char prefix collide on the same group.
func sshGroupName(actionID string) string {
	return shortGroupName("pm-ssh-", actionID)
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
	membersMatch := sudoGroupMembersMatch(ctx, groupName, users)
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
	gExists, err := groupExists(ctx, groupName)
	if err != nil {
		return nil, false, fmt.Errorf("check group %s: %w", groupName, err)
	}
	if !gExists {
		if err := userMgr.GroupCreate(ctx, groupName, sysuser.GroupCreateOptions{}); err != nil {
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

	configPath := fmt.Sprintf("/etc/ssh/sshd_config.d/%04d-pm-%s.conf", params.Priority, strings.ToLower(actionID))

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
