// Package executor provides user management utility functions for action executors.
package executor

import (
	"context"
	"crypto/rand"
	"fmt"
	"strconv"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// =============================================================================
// User Info Types
// =============================================================================

// UserInfo holds the current state of a user account.
type UserInfo struct {
	UID     int
	GID     int
	Comment string
	HomeDir string
	Shell   string
	Groups  []string // supplementary groups (excluding primary)
	Locked  bool
}

// =============================================================================
// User Query Functions
// =============================================================================

// getUserInfo retrieves the current state of a user from the system.
func getUserInfo(username string) (*UserInfo, error) {
	// Get passwd entry: username:x:uid:gid:comment:home:shell
	out, err := queryCmd("getent", "passwd", username)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	fields := strings.Split(strings.TrimSpace(out), ":")
	if len(fields) < 7 {
		return nil, fmt.Errorf("invalid passwd entry")
	}

	uid, _ := strconv.Atoi(fields[2])
	gid, _ := strconv.Atoi(fields[3])

	info := &UserInfo{
		UID:     uid,
		GID:     gid,
		Comment: fields[4],
		HomeDir: fields[5],
		Shell:   fields[6],
	}

	// Get supplementary groups
	if allGroups, err := queryCmd("id", "-Gn", username); err == nil {
		groups := strings.Fields(strings.TrimSpace(allGroups))
		// Filter out the primary group
		if primaryGroup, err := queryCmd("id", "-gn", username); err == nil {
			primary := strings.TrimSpace(primaryGroup)
			for _, g := range groups {
				if g != primary {
					info.Groups = append(info.Groups, g)
				}
			}
		}
	}

	// Check if account is locked (password field starts with ! or *)
	// Use sudo to read shadow file
	if shadowOut, _, _ := queryCmdOutput("sudo", "-n", "getent", "shadow", username); shadowOut != "" {
		shadowFields := strings.Split(shadowOut, ":")
		if len(shadowFields) >= 2 {
			passField := shadowFields[1]
			info.Locked = strings.HasPrefix(passField, "!") || strings.HasPrefix(passField, "*")
		}
	}

	return info, nil
}

// getPrimaryGroup returns the primary group name for a user.
func getPrimaryGroup(username string) (string, error) {
	out, err := queryCmd("id", "-gn", username)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(out), nil
}

// getSupplementaryGroups returns the supplementary groups for a user.
func getSupplementaryGroups(username string) ([]string, error) {
	out, err := queryCmd("id", "-Gn", username)
	if err != nil {
		return nil, err
	}
	groups := strings.Fields(strings.TrimSpace(out))

	// Filter out primary group
	primaryGroup, err := getPrimaryGroup(username)
	if err != nil {
		return groups, nil
	}

	var supplementary []string
	for _, g := range groups {
		if g != primaryGroup {
			supplementary = append(supplementary, g)
		}
	}
	return supplementary, nil
}

// =============================================================================
// User Validation Functions
// =============================================================================

// isValidUsername checks if a username is valid and safe.
// Valid usernames: start with lowercase letter, contain only [a-z0-9_-], max 32 chars.
func isValidUsername(username string) bool {
	if len(username) == 0 || len(username) > 32 {
		return false
	}
	// Must start with a lowercase letter
	if username[0] < 'a' || username[0] > 'z' {
		return false
	}
	// Rest can be lowercase letters, digits, underscores, or hyphens
	for _, c := range username[1:] {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// =============================================================================
// User Management Operations
// =============================================================================

// userAdd creates a new user account with the given options.
func userAdd(ctx context.Context, username string, args ...string) (*pb.CommandOutput, error) {
	fullArgs := append(args, username)
	return runSudoCmd(ctx, "useradd", fullArgs...)
}

// userMod modifies an existing user account.
func userMod(ctx context.Context, username string, args ...string) (*pb.CommandOutput, error) {
	fullArgs := append(args, username)
	return runSudoCmd(ctx, "usermod", fullArgs...)
}

// userDel removes a user account. If removeHome is true, also removes the home directory.
func userDel(ctx context.Context, username string, removeHome bool) (*pb.CommandOutput, error) {
	if removeHome {
		return runSudoCmd(ctx, "userdel", "-r", username)
	}
	return runSudoCmd(ctx, "userdel", username)
}

// userLock locks a user account (usermod -L).
func userLock(ctx context.Context, username string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "usermod", "-L", username)
}

// userUnlock unlocks a user account (usermod -U).
func userUnlock(ctx context.Context, username string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "usermod", "-U", username)
}

// =============================================================================
// Group Management Operations
// =============================================================================

// groupAdd creates a new group. Optional args are passed before the group name
// (e.g., "-g", "1001", "-r" for GID and system group).
func groupAdd(ctx context.Context, groupName string, extraArgs ...string) (*pb.CommandOutput, error) {
	args := append(extraArgs, groupName)
	return runSudoCmd(ctx, "groupadd", args...)
}

// ensureGroupExists creates a group if it doesn't exist.
func ensureGroupExists(ctx context.Context, groupName string) {
	if !groupExists(groupName) {
		groupAdd(ctx, groupName)
	}
}

// =============================================================================
// Password Management Operations
// =============================================================================

// generateTempPassword creates a cryptographically secure temporary password.
// Returns a 16-character password using alphanumeric characters.
func generateTempPassword() (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const length = 16

	password := make([]byte, length)
	randomBytes := make([]byte, length)

	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	for i := 0; i < length; i++ {
		password[i] = charset[randomBytes[i]%byte(len(charset))]
	}

	return string(password), nil
}

// setUserPassword sets a user's password using chpasswd.
func setUserPassword(ctx context.Context, username, password string) error {
	_, err := runSudoCmdWithStdin(ctx, strings.NewReader(fmt.Sprintf("%s:%s", username, password)), "chpasswd")
	return err
}

// expirePassword forces a user to change their password on next login.
func expirePassword(ctx context.Context, username string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "chage", "-d", "0", username)
}

// =============================================================================
// User Permission Operations
// =============================================================================

// chownRecursive changes ownership of a path and all its contents.
func chownRecursive(ctx context.Context, path, owner, group string) (*pb.CommandOutput, error) {
	ownership := buildOwnership(owner, group)
	if ownership == "" {
		return nil, nil
	}
	return runSudoCmd(ctx, "chown", "-R", ownership, path)
}
