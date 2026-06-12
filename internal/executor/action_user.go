// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysfs "github.com/manchtools/power-manage/sdk/go/sys/fs"
	sysuser "github.com/manchtools/power-manage/sdk/go/sys/user"
)

// executeUser manages user accounts (create, update, disable, remove).
func (e *Executor) executeUser(ctx context.Context, params *pb.UserParams, state pb.DesiredState) (*pb.CommandOutput, bool, map[string]string, error) {
	if params == nil {
		return nil, false, nil, fmt.Errorf("user params required")
	}

	if params.Username == "" {
		return nil, false, nil, fmt.Errorf("username is required")
	}

	// Validate username format (prevent injection)
	if !sysuser.IsValidName(params.Username) {
		return nil, false, nil, fmt.Errorf("invalid username: must be 1-32 alphanumeric characters, starting with a letter")
	}

	// Validate home directory if specified
	if params.HomeDir != "" {
		if !filepath.IsAbs(params.HomeDir) {
			return nil, false, nil, fmt.Errorf("home directory must be an absolute path")
		}
		if isProtectedPath(params.HomeDir) {
			return nil, false, nil, fmt.Errorf("home directory %q is a protected system path", params.HomeDir)
		}
	}

	// Repair filesystem if mounted read-only
	if out, err := e.requireWritableFS(ctx); err != nil {
		return out, false, nil, err
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		return e.createOrUpdateUser(ctx, params)
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		output, changed, err := e.removeUser(ctx, params.Username)
		return output, changed, nil, err
	default:
		return nil, false, nil, fmt.Errorf("unknown desired state: %v", state)
	}
}

// createOrUpdateUser creates a new user or updates an existing one.
// Returns the command output, whether changes were made, metadata, and any error.
// homeGroupFor returns the group name/id to use when repairing home
// directory ownership for a user. Preference order mirrors the group
// selection used at user creation time: explicit numeric GID (accepted
// by `chown` as a number), named primary group, else fall back to the
// username (matches the default "useradd creates matching group" case).
func homeGroupFor(params *pb.UserParams) string {
	if params.Gid > 0 {
		return fmt.Sprintf("%d", params.Gid)
	}
	if params.PrimaryGroup != "" {
		return params.PrimaryGroup
	}
	return params.Username
}

// resolveOwnership turns the action's user/group into the numeric
// uid/gid an fd-based fchown needs (sysfs.OpenRealDir / FchownNoFollow
// operate on a descriptor, not a name). It is the numeric counterpart of
// the "username:homeGroupFor()" string the path-based chown previously
// took, and mirrors homeGroupFor's preference order exactly so .ssh
// ownership stays identical to the home-directory chown:
//   - numeric GID (or numeric PrimaryGroup) is used as a literal GID,
//     matching how chown treats an all-numeric group token (no name
//     lookup, so it works even if no group with that name exists);
//   - otherwise the group name is resolved via the group database;
//   - the default (no Gid, no PrimaryGroup) resolves the matching group
//     named after the user, exactly as homeGroupFor returns.
func resolveOwnership(params *pb.UserParams) (uid, gid int, err error) {
	u, err := user.Lookup(params.Username)
	if err != nil {
		return 0, 0, fmt.Errorf("look up user %s: %w", params.Username, err)
	}
	uid, err = strconv.Atoi(u.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse uid %q for %s: %w", u.Uid, params.Username, err)
	}

	group := homeGroupFor(params)
	if n, convErr := strconv.Atoi(group); convErr == nil {
		return uid, n, nil
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		return 0, 0, fmt.Errorf("look up group %s: %w", group, err)
	}
	gid, err = strconv.Atoi(g.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("parse gid %q for group %s: %w", g.Gid, group, err)
	}
	return uid, gid, nil
}

func (e *Executor) createOrUpdateUser(ctx context.Context, params *pb.UserParams) (*pb.CommandOutput, bool, map[string]string, error) {
	var output strings.Builder
	exists := userExists(params.Username)

	if exists {
		// Update existing user
		cmdOutput, changed, err := e.updateUser(ctx, params, &output)
		return cmdOutput, changed, nil, err
	}

	// Create new user - always a change
	cmdOutput, metadata, err := e.createUser(ctx, params, &output)
	return cmdOutput, true, metadata, err
}

// createUser creates a new user account.
func (e *Executor) createUser(ctx context.Context, params *pb.UserParams, output *strings.Builder) (*pb.CommandOutput, map[string]string, error) {
	args := []string{}

	// UID
	if params.Uid > 0 {
		args = append(args, "-u", fmt.Sprintf("%d", params.Uid))
	}

	// GID or primary group
	if params.Gid > 0 {
		args = append(args, "-g", fmt.Sprintf("%d", params.Gid))
	} else if params.PrimaryGroup != "" {
		// Ensure group exists
		if _, err := sysuser.GroupEnsureExists(ctx, params.PrimaryGroup); err != nil {
			e.logger.Warn("failed to ensure primary group exists", "group", params.PrimaryGroup, "error", err)
		}
		args = append(args, "-g", params.PrimaryGroup)
	}

	// Home directory
	if params.HomeDir != "" {
		args = append(args, "-d", params.HomeDir)
	}

	// Shell (default to /bin/bash for normal users, /usr/sbin/nologin for disabled/system)
	shell := params.Shell
	if shell == "" {
		if params.Disabled {
			shell = "/usr/sbin/nologin"
		} else if params.SystemUser {
			shell = "/usr/sbin/nologin"
		} else {
			shell = "/bin/bash"
		}
	}
	args = append(args, "-s", shell)

	// System user
	if params.SystemUser {
		args = append(args, "-r") // Create system account
	}

	// Respect the explicit create_home value from the proto. A prior
	// revision inverted false → true for non-system users on the
	// assumption that proto3 scalar false meant "unset, use default."
	// That broke the UserParams contract — the server could not
	// express "no home directory" for a non-system user even when it
	// explicitly set create_home: false, because the agent would
	// silently override. The control server's system-managed pm-tty
	// action and the web UI's "Create home" checkbox both rely on
	// explicit-false being honoured.
	createHome := params.CreateHome

	// Determine home directory path to check if it exists
	homeDir := params.HomeDir
	if homeDir == "" {
		homeDir = "/home/" + params.Username
	}

	// Check if home directory already exists - useradd -m fails if it does
	homeExists := false
	if _, err := os.Stat(homeDir); err == nil {
		homeExists = true
	}

	if createHome && !homeExists {
		args = append(args, "-m")
	} else {
		args = append(args, "-M")
	}

	// Comment/GECOS
	if params.Comment != "" {
		args = append(args, "-c", params.Comment)
	}

	// Create the user via SDK
	result, err := sysuser.Create(ctx, params.Username, args...)
	if err != nil {
		if result != nil {
			output.WriteString(result.Stderr)
		}
		return &pb.CommandOutput{ExitCode: 1, Stderr: output.String()}, nil, fmt.Errorf("failed to create user: %w", err)
	}
	output.WriteString(fmt.Sprintf("created user: %s\n", params.Username))

	// If home directory already existed, fix ownership
	if homeExists && createHome {
		if chownResult, chownErr := sysuser.ChownRecursive(ctx, homeDir, params.Username, homeGroupFor(params)); chownErr != nil {
			output.WriteString(fmt.Sprintf("warning: failed to fix home directory ownership: %v\n", chownErr))
			if chownResult != nil {
				output.WriteString(chownResult.Stderr)
			}
		} else {
			output.WriteString(fmt.Sprintf("fixed ownership of existing home directory: %s\n", homeDir))
		}
	}

	// Generate and set temporary password for non-system users.
	//
	// NoPassword opts out of this block entirely — used for
	// system-managed nologin accounts (pm-tty-*) that are only ever
	// reached via setuid and would otherwise create an LPS table row
	// that no PAM path will ever consume. The flag is deliberately
	// explicit, not derived from Shell == /usr/sbin/nologin: passwords
	// are good to have for any account that might ever need a
	// PAM-protected login path. See sdk proto comment on no_password.
	var metadata map[string]string
	if !params.NoPassword && !params.SystemUser && !params.Disabled {
		tempPassword, err := sysuser.GeneratePassword(16, false)
		if err != nil {
			output.WriteString(fmt.Sprintf("warning: failed to generate temporary password: %v\n", err))
		} else {
			// Set password
			if chpasswdResult, chpasswdErr := sysuser.SetPassword(ctx, params.Username, tempPassword); chpasswdErr != nil {
				output.WriteString(fmt.Sprintf("warning: failed to set temporary password: %v\n", chpasswdErr))
				if chpasswdResult != nil {
					output.WriteString(chpasswdResult.Stderr)
				}
			} else {
				// Force password change on first login
				if _, chageErr := sysuser.ExpirePassword(ctx, params.Username); chageErr != nil {
					output.WriteString(fmt.Sprintf("warning: failed to expire password: %v\n", chageErr))
				}
				output.WriteString(fmt.Sprintf("temporary password set for %s (must be changed on first login)\n", params.Username))

				// Report password via lps.rotations metadata so it's stored in the LPS table
				rotations := []lpsRotationEntry{{
					Username:  params.Username,
					Password:  tempPassword,
					RotatedAt: e.now().UTC().Format(time.RFC3339),
					Reason:    "user_created",
				}}
				rotationsJSON, err := json.Marshal(rotations)
				if err != nil {
					slog.Warn("failed to marshal user creation rotations", "error", err)
				} else {
					metadata = map[string]string{"lps.rotations": string(rotationsJSON)}
				}
			}
		}
	}

	// Setup SSH authorized keys. Newline / control-character rejection
	// from setupSSHKeys is fatal by design (the function comment is
	// explicit). Surface as a real error so the action result reports
	// FAILED — the previous "warning" path silently degraded a
	// rejected-input failure into apparent success.
	if len(params.SshAuthorizedKeys) > 0 {
		if _, err := e.setupSSHKeys(ctx, params, output); err != nil {
			return nil, nil, fmt.Errorf("setup SSH keys: %w", err)
		}
	}

	// Handle disabled state (lock the account)
	if params.Disabled {
		if lockResult, lockErr := sysuser.Lock(ctx, params.Username); lockErr != nil {
			output.WriteString(fmt.Sprintf("warning: failed to lock user account: %v\n", lockErr))
			if lockResult != nil {
				output.WriteString(lockResult.Stderr)
			}
		} else {
			output.WriteString("account locked (disabled)\n")
		}
	}

	// Hide from login screen if requested
	if params.Hidden {
		setUserHidden(ctx, params.Username, true, output)
	}

	return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, metadata, nil
}

// desiredAccountLocked reports whether the account described by params
// must remain shadow-locked (no PAM login path). It is the single
// source of truth shared between createUser and updateUser, and MUST
// mirror createUser's password-skip condition: createUser sets a temp
// password only when none of no_password / system_user / disabled is
// set, leaving the account at the useradd '!' default otherwise. An
// account with no password must never be unlocked — unlocking a
// hash-less account yields a passwordless login path.
func desiredAccountLocked(params *pb.UserParams) bool {
	return params.Disabled || params.NoPassword || params.SystemUser
}

// updateUser modifies an existing user account.
func (e *Executor) updateUser(ctx context.Context, params *pb.UserParams, output *strings.Builder) (*pb.CommandOutput, bool, error) {
	// Get current user state
	currentInfo, err := sysuser.Get(params.Username)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get current user info: %w", err)
	}

	changed := false
	args := []string{}

	// Determine desired shell
	desiredShell := params.Shell
	if desiredShell == "" {
		if params.Disabled {
			desiredShell = "/usr/sbin/nologin"
		}
		// If not disabled and no shell specified, don't change the existing shell
	}

	// Shell - only change if explicitly set and different
	if desiredShell != "" && currentInfo.Shell != desiredShell {
		args = append(args, "-s", desiredShell)
		output.WriteString(fmt.Sprintf("shell: %s -> %s\n", currentInfo.Shell, desiredShell))
	}

	// Home directory - only if explicitly set and different
	if params.HomeDir != "" && currentInfo.HomeDir != params.HomeDir {
		args = append(args, "-d", params.HomeDir)
		output.WriteString(fmt.Sprintf("home: %s -> %s\n", currentInfo.HomeDir, params.HomeDir))
	}

	// Comment - only if explicitly set and different
	if params.Comment != "" && currentInfo.Comment != params.Comment {
		args = append(args, "-c", params.Comment)
		output.WriteString(fmt.Sprintf("comment: %s -> %s\n", currentInfo.Comment, params.Comment))
	}

	// Primary group - only if explicitly set and different
	if params.Gid > 0 && currentInfo.GID != int(params.Gid) {
		args = append(args, "-g", fmt.Sprintf("%d", params.Gid))
		output.WriteString(fmt.Sprintf("gid: %d -> %d\n", currentInfo.GID, params.Gid))
	} else if params.PrimaryGroup != "" {
		// Check if primary group needs to change (would need to resolve group name to GID)
		if _, err := sysuser.GroupEnsureExists(ctx, params.PrimaryGroup); err != nil {
			e.logger.Warn("failed to ensure primary group exists for usermod", "group", params.PrimaryGroup, "error", err)
		}
		// For simplicity, always set if specified by name (could be optimized)
		args = append(args, "-g", params.PrimaryGroup)
	}

	// Apply usermod if we have changes
	if len(args) > 0 {
		result, err := sysuser.Modify(ctx, params.Username, args...)
		if err != nil {
			if result != nil {
				output.WriteString(result.Stderr)
			}
			return &pb.CommandOutput{ExitCode: 1, Stderr: output.String()}, false, fmt.Errorf("failed to update user: %w", err)
		}
		changed = true
	}

	// Ensure home directory exists (may be missing if a prior run
	// failed). Same change as in createUser — honour the explicit
	// create_home value from the proto rather than inverting false
	// to true for non-system users.
	createHome := params.CreateHome
	if createHome {
		homeDir := params.HomeDir
		if homeDir == "" {
			homeDir = currentInfo.HomeDir
		}
		if homeDir == "" {
			homeDir = "/home/" + params.Username
		}
		if _, err := os.Stat(homeDir); os.IsNotExist(err) {
			if _, mkErr := runSudoCmd(ctx, "mkdir", "-p", "--", homeDir); mkErr != nil {
				output.WriteString(fmt.Sprintf("warning: failed to create home directory: %v\n", mkErr))
			} else {
				runSudoCmd(ctx, "cp", "-a", "--", "/etc/skel/.", homeDir)
				if chownResult, chownErr := sysuser.ChownRecursive(ctx, homeDir, params.Username, homeGroupFor(params)); chownErr != nil {
					output.WriteString(fmt.Sprintf("warning: failed to chown home directory: %v\n", chownErr))
					if chownResult != nil {
						output.WriteString(chownResult.Stderr)
					}
				}
				runSudoCmd(ctx, "chmod", "0700", "--", homeDir)
				output.WriteString(fmt.Sprintf("created missing home directory: %s\n", homeDir))
				changed = true
			}
		}
	}

	// Handle disabled/locked state - only change if different.
	//
	// desiredAccountLocked (not raw params.Disabled) is the source of
	// truth: a no_password or system_user account got NO password at
	// create time and sits at the shadow-locked default ('!'). Driving
	// the decision off Disabled alone would compute desiredLocked=false
	// for such an account, see currentInfo.Locked=true, and run
	// `usermod -U` — stripping the '!' and producing a PASSWORDLESS
	// login path (the no_password / pm-tty-* regression). Unlock is only
	// correct for an account that actually has a password hash to
	// restore.
	desiredLocked := desiredAccountLocked(params)
	if desiredLocked != currentInfo.Locked {
		if desiredLocked {
			if lockResult, err := sysuser.Lock(ctx, params.Username); err != nil {
				output.WriteString(fmt.Sprintf("warning: failed to lock user: %v\n", err))
				if lockResult != nil {
					output.WriteString(lockResult.Stderr)
				}
			} else {
				output.WriteString("account locked (disabled)\n")
				changed = true
			}
		} else {
			if unlockResult, err := sysuser.Unlock(ctx, params.Username); err != nil {
				output.WriteString(fmt.Sprintf("warning: failed to unlock user: %v\n", err))
				if unlockResult != nil {
					output.WriteString(unlockResult.Stderr)
				}
			} else {
				output.WriteString("account unlocked\n")
				changed = true
			}
		}
	}

	// Setup SSH authorized keys. Same fatal-on-rejection contract as
	// in createUser — see the comment there. Newline / CR in a key
	// must fail the action, not degrade to a warning.
	if len(params.SshAuthorizedKeys) > 0 {
		if keysChanged, err := e.setupSSHKeys(ctx, params, output); err != nil {
			return nil, changed, fmt.Errorf("setup SSH keys: %w", err)
		} else if keysChanged {
			changed = true
		}
	}

	// Hide/show on login screen
	if setUserHidden(ctx, params.Username, params.Hidden, output) {
		changed = true
	}

	if !changed {
		output.WriteString(fmt.Sprintf("user %s is already in desired state\n", params.Username))
	}

	return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, changed, nil
}

// removeUser removes a user account from the system.
// Returns the command output, whether changes were made, and any error.
func (e *Executor) removeUser(ctx context.Context, username string) (*pb.CommandOutput, bool, error) {
	// Never allow removal of the agent's own service user
	if username == "power-manage" {
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   "refusing to remove the power-manage service user\n",
		}, false, fmt.Errorf("cannot remove protected user: power-manage")
	}

	if !userExists(username) {
		// User doesn't exist, no change needed
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("user %s does not exist, nothing to remove\n", username),
		}, false, nil
	}

	// Kill all processes and sessions for this user before removal
	killUserSessions(ctx, username)

	// Clean up AccountsService override if present
	removeAccountsServiceFile(ctx, username)

	// Remove user and their home directory
	result, err := sysuser.Delete(ctx, username, true)
	if err != nil {
		// If home directory doesn't exist, userdel -r may still succeed
		// but report an error. Check if user is actually removed.
		if !sysuser.Exists(username) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("removed user: %s (home directory may not have existed)\n", username),
			}, true, nil
		}
		if result != nil {
			return &pb.CommandOutput{ExitCode: 1, Stderr: result.Stderr}, false, fmt.Errorf("failed to remove user: %w", err)
		}
		return nil, false, fmt.Errorf("failed to remove user: %w", err)
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   fmt.Sprintf("removed user: %s\n", username),
	}, true, nil
}

// accountsServicePath returns the AccountsService override file path for a user.
const accountsServiceDir = "/var/lib/AccountsService/users"

// setUserHidden writes or removes the AccountsService override to hide/show a user
// on graphical login screens. Returns whether a change was made. Skips silently if
// AccountsService is not installed (headless systems).
func setUserHidden(ctx context.Context, username string, hidden bool, output *strings.Builder) bool {
	filePath := accountsServiceDir + "/" + username

	if _, err := os.Stat(accountsServiceDir); os.IsNotExist(err) {
		return false // AccountsService not installed, skip
	}

	desiredContent := "[User]\nSystemAccount=true\n"

	if hidden {
		// Check idempotency
		existing, _ := readFileWithSudo(ctx, filePath)
		if existing == desiredContent {
			return false
		}
		if err := atomicWriteFile(ctx, filePath, desiredContent, "0644", "root", "root"); err != nil {
			output.WriteString(fmt.Sprintf("warning: failed to hide user from login screen: %v\n", err))
			return false
		}
		output.WriteString("hidden from login screen (AccountsService)\n")
		return true
	}

	// hidden=false: remove the file if it exists and was set by us
	existing, err := readFileWithSudo(ctx, filePath)
	if err != nil || existing != desiredContent {
		return false // File doesn't exist or wasn't ours
	}
	if err := removeFileStrict(ctx, filePath); err != nil {
		output.WriteString(fmt.Sprintf("warning: failed to unhide user from login screen: %v\n", err))
		return false
	}
	output.WriteString("visible on login screen (AccountsService removed)\n")
	return true
}

// removeAccountsServiceFile removes the AccountsService override for a user during user deletion.
func removeAccountsServiceFile(ctx context.Context, username string) {
	filePath := accountsServiceDir + "/" + username
	if fileExistsWithSudo(ctx, filePath) {
		removeFileStrict(ctx, filePath)
	}
}

// setupSSHKeys configures SSH authorized keys for a user.
func (e *Executor) setupSSHKeys(ctx context.Context, params *pb.UserParams, output *strings.Builder) (bool, error) {
	// Determine home directory
	homeDir := params.HomeDir
	if homeDir == "" {
		if params.SystemUser {
			homeDir = "/"
		} else {
			homeDir = filepath.Join("/home", params.Username)
		}
	}

	sshDir := filepath.Join(homeDir, ".ssh")
	authKeysFile := filepath.Join(sshDir, "authorized_keys")

	// Build desired authorized_keys content
	var keysContent strings.Builder
	validKeyCount := 0
	for i, key := range params.SshAuthorizedKeys {
		trimmedKey := strings.TrimSpace(key)
		if trimmedKey == "" {
			continue
		}
		// Reject keys with embedded newlines BEFORE the prefix check.
		// Without this, a signed action could smuggle additional
		// authorized_keys entries (extra principals, command=
		// overrides, restrict= bypasses) by embedding "\nssh-rsa
		// ATTACKER..." in a single key value. The prefix check on
		// the first line would pass, and the appended lines would
		// land in the file unfiltered. Treat embedded \n or \r as
		// fatal — silent skip is wrong here, the caller needs to
		// know their input was rejected.
		if strings.ContainsAny(trimmedKey, "\n\r") {
			return false, fmt.Errorf("authorized_keys entry contains embedded newline (input index %d for user %s); refusing to splice into file", i, params.Username)
		}
		if !strings.HasPrefix(trimmedKey, "ssh-") && !strings.HasPrefix(trimmedKey, "ecdsa-") {
			output.WriteString(fmt.Sprintf("warning: skipping invalid SSH key (doesn't start with ssh- or ecdsa-): %s...\n", trimmedKey[:min(30, len(trimmedKey))]))
			continue
		}
		keysContent.WriteString(trimmedKey)
		keysContent.WriteString("\n")
		validKeyCount++
	}
	desiredContent := keysContent.String()

	// Check if authorized_keys already has the desired content (idempotency)
	existing, _ := readFileWithSudo(ctx, authKeysFile)
	if existing == desiredContent {
		return false, nil
	}

	// Create .ssh directory
	if _, err := runSudoCmd(ctx, "mkdir", "-p", "--", sshDir); err != nil {
		return false, fmt.Errorf("failed to create .ssh directory: %w", err)
	}

	// Open ~/.ssh through an O_NOFOLLOW directory handle and apply
	// ownership + permissions through the FD (fchown/fchmod), never
	// through the path. The target user owns their home dir, so they can
	// swap ~/.ssh for a symlink to e.g. /etc; a path-based chmod/chown
	// re-resolves the path on every call and would dereference the link,
	// retargeting a root-run chmod onto its target. chmod has no -h, so
	// the prior "AssertRealDir + chown -h" left exactly that hole open
	// (and was itself check-then-use). Operating on the opened inode
	// removes the whole class: OpenRealDir fails outright if ~/.ssh is a
	// symlink or not a directory, and a later swap of the path cannot
	// redirect operations on the FD. Ownership uses the same preference
	// order as the home-directory repair (resolveOwnership mirrors
	// homeGroupFor). The agent runs as root, so the FD-based calls need
	// no sudo.
	sshFd, err := sysfs.OpenRealDir(sshDir)
	if err != nil {
		return false, fmt.Errorf("refusing to configure SSH keys: %w", err)
	}
	defer sshFd.Close()

	uid, gid, err := resolveOwnership(params)
	if err != nil {
		return false, fmt.Errorf("resolve .ssh ownership: %w", err)
	}
	if err := sshFd.Chown(uid, gid); err != nil {
		return false, fmt.Errorf("failed to set .ssh ownership: %w", err)
	}
	if err := sshFd.Chmod(0o700); err != nil {
		return false, fmt.Errorf("failed to set .ssh permissions: %w", err)
	}

	// Write authorized_keys file via the SDK's SafeReplaceFile (F022).
	// The previous shape (`mkdir -p` → `chown` → sudo `tee` → `chown`)
	// followed symlinks at the tee step: a local user able to plant a
	// symlink at ~/.ssh/authorized_keys between the chown and the tee
	// could redirect the write to e.g. /etc/cron.d/root. SafeReplaceFile
	// reopens its temp file with O_NOFOLLOW after CreateTemp and uses
	// renameat2 RENAME_NOREPLACE on Linux, closing both the open-side
	// and the rename-side of the symlink race. The agent runs as root
	// (post root-mode rewire), so it can write to the user's home
	// directly without a sudo'd helper.
	if err := sysfs.SafeReplaceFile(authKeysFile, []byte(desiredContent), 0o600, true); err != nil {
		return false, fmt.Errorf("failed to write authorized_keys: %w", err)
	}

	// Hand authorized_keys back to the target user. SafeReplaceFile left
	// it owned by the agent process (root). Use the FD-based
	// FchownNoFollow rather than a path chown: the user owns the 0700
	// .ssh dir, so they could unlink the freshly-written file and plant a
	// symlink before this runs. An O_NOFOLLOW open refuses the symlink
	// outright (surfacing the tampering) instead of transferring
	// ownership of its target (e.g. /etc/shadow) to the user — stronger
	// than the previous `chown -h`, which would silently chown the
	// planted link itself.
	if err := sysfs.FchownNoFollow(authKeysFile, uid, gid); err != nil {
		return false, fmt.Errorf("failed to set authorized_keys ownership: %w", err)
	}

	output.WriteString(fmt.Sprintf("configured %d SSH authorized key(s)\n", validKeyCount))
	return true, nil
}

// reloadSshd reloads the sshd service, falling back to the "ssh" service name
// for Debian/Ubuntu. Writes the result to output.
func reloadSshd(ctx context.Context, output *strings.Builder) {
	reloadOut, reloadErr := runSudoCmd(ctx, "systemctl", "reload", "sshd")
	if reloadErr != nil {
		reloadOut, reloadErr = runSudoCmd(ctx, "systemctl", "reload", "ssh")
	}
	if reloadErr != nil {
		output.WriteString("warning: failed to reload sshd\n")
		if reloadOut != nil && reloadOut.Stderr != "" {
			output.WriteString(strings.TrimSpace(reloadOut.Stderr) + "\n")
		}
	} else {
		output.WriteString("reloaded sshd\n")
	}
}
