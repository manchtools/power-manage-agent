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

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysfs "github.com/manchtools/power-manage-sdk/sys/fs"
	sysuser "github.com/manchtools/power-manage-sdk/sys/user"
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

// ensureHomeIfMissing repairs a missing home directory for a create_home user
// by delegating the create+seed+own+mode work to the SDK's idempotent
// EnsureHome (mkdir + /etc/skel seed + recursive ownership + 0700) instead of
// orchestrating mkdir / cp -a / chown / chmod by hand. It returns true only
// when a missing home was actually created.
//
// Path safety: params.HomeDir is already validated at the ExecuteUserAction
// entry point (filepath.IsAbs + isProtectedPath, which filepath.Clean's the
// path before rejecting protected/traversal-escaping targets) before this runs.
// EnsureHome resolves the directory to create from the user's passwd entry —
// NOT from this path — so the path here only selects which location the
// read-only Exists probe checks; it is never a write target.
//
// The presence probe fails CLOSED: if fsMgr.Exists cannot determine whether the
// home exists (an I/O / permission error rather than a clean "no such file"),
// the state is indeterminate, so we surface a warning and skip EnsureHome rather
// than treating the error as "missing". Swallowing the probe error would invert
// an unknown into a confident "create it", running EnsureHome on every reconcile
// cycle (and reporting changed=true forever) against a home that may already be
// present.
func (e *Executor) ensureHomeIfMissing(ctx context.Context, params *pb.UserParams, currentHome string, output *strings.Builder) bool {
	if !params.CreateHome {
		return false
	}
	homeDir := params.HomeDir
	if homeDir == "" {
		homeDir = currentHome
	}
	if homeDir == "" {
		homeDir = "/home/" + params.Username
	}
	ok, err := fsMgr.Exists(ctx, homeDir)
	if err != nil {
		output.WriteString(fmt.Sprintf("warning: could not check home directory %s: %v\n", homeDir, err))
		return false
	}
	if ok {
		return false
	}
	// Home is missing (a prior run failed, or the account was created with -M).
	// EnsureHome resolves the home from the user's passwd entry, which any
	// preceding Modify has already set to the desired path.
	if hErr := userMgr.EnsureHome(ctx, params.Username, sysuser.EnsureHomeOptions{Group: homeGroupFor(params), Mode: 0o700}); hErr != nil {
		output.WriteString(fmt.Sprintf("warning: failed to create home directory: %v\n", hErr))
		return false
	}
	output.WriteString(fmt.Sprintf("created missing home directory: %s\n", homeDir))
	return true
}

func (e *Executor) createOrUpdateUser(ctx context.Context, params *pb.UserParams) (*pb.CommandOutput, bool, map[string]string, error) {
	var output strings.Builder
	exists, err := userExists(ctx, params.Username)
	if err != nil {
		return nil, false, nil, fmt.Errorf("check user %s: %w", params.Username, err)
	}

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
	// Shell (default to /bin/bash for normal users, /usr/sbin/nologin for disabled/system)
	shell := params.Shell
	if shell == "" {
		if params.Disabled || params.SystemUser {
			shell = "/usr/sbin/nologin"
		} else {
			shell = "/bin/bash"
		}
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
	opts := sysuser.CreateOptions{
		Shell:      shell,
		HomeDir:    params.HomeDir,
		Comment:    params.Comment,
		System:     params.SystemUser,
		CreateHome: params.CreateHome, // the SDK handles the "home already exists" -M/chown dance
	}
	if params.Uid > 0 {
		opts.UID = int(params.Uid)
	}
	// GID or primary group
	if params.Gid > 0 {
		opts.PrimaryGroup = fmt.Sprintf("%d", params.Gid)
	} else if params.PrimaryGroup != "" {
		if err := userMgr.GroupEnsure(ctx, params.PrimaryGroup); err != nil {
			e.logger.Warn("failed to ensure primary group exists", "group", params.PrimaryGroup, "error", err)
		}
		opts.PrimaryGroup = params.PrimaryGroup
	}

	// Create the user via the SDK user Manager.
	if err := userMgr.Create(ctx, params.Username, opts); err != nil {
		output.WriteString(err.Error())
		return &pb.CommandOutput{ExitCode: 1, Stderr: output.String()}, nil, fmt.Errorf("failed to create user: %w", err)
	}
	output.WriteString(fmt.Sprintf("created user: %s\n", params.Username))

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
	if createUserSetsPassword(params) {
		tempPassword, err := sysuser.GeneratePassword(16, sysuser.ComplexityAlphanumeric)
		if err != nil {
			output.WriteString(fmt.Sprintf("warning: failed to generate temporary password: %v\n", err))
		} else {
			// Set password
			if chpasswdErr := userMgr.SetPassword(ctx, params.Username, tempPassword); chpasswdErr != nil {
				output.WriteString(fmt.Sprintf("warning: failed to set temporary password: %v\n", chpasswdErr))
			} else {
				// Force password change on first login
				if chageErr := userMgr.ExpirePassword(ctx, params.Username); chageErr != nil {
					output.WriteString(fmt.Sprintf("warning: failed to expire password: %v\n", chageErr))
				}
				output.WriteString(fmt.Sprintf("temporary password set for %s (must be changed on first login)\n", params.Username))

				// Report password via lps.rotations metadata so it's stored in the
				// LPS table for operator retrieval — the sanctioned plaintext sink.
				rotations := []lpsRotationEntry{{
					Username:  params.Username,
					Password:  tempPassword.Reveal(),
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

	// Reconcile the shadow lock to the lock=disabled model: "!" (locked) iff the
	// user is disabled, else unlocked. createUser leaves useradd's "!" default and
	// only sets a password for a plain enabled account, so a no_password/system
	// account would otherwise stay locked and the terminal handler would refuse it
	// ("tty user is disabled"). Unlock sets "*" (no password, NOT locked) for a
	// passwordless account and no-ops on an already-unlocked (password-bearing)
	// one — never an empty, login-able password. Mirrors updateUser's reconcile.
	if desiredAccountLocked(params) {
		if lockErr := userMgr.Lock(ctx, params.Username); lockErr != nil {
			output.WriteString(fmt.Sprintf("warning: failed to lock user account: %v\n", lockErr))
		} else {
			output.WriteString("account locked (disabled)\n")
		}
	} else if unlockErr := userMgr.Unlock(ctx, params.Username); unlockErr != nil {
		output.WriteString(fmt.Sprintf("warning: failed to unlock user account: %v\n", unlockErr))
	}

	// Hide from login screen if requested
	if params.Hidden {
		setUserHidden(ctx, params.Username, true, output)
	}

	return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, metadata, nil
}

// createUserSetsPassword reports whether createUser will set a temporary
// password for this account. createUser sets one only when none of
// no_password / system_user / disabled is requested; in every other case the
// account is left at the useradd '!' (locked, hash-less) default. This is the
// single source of truth that createUser and desiredAccountLocked both consult
// so the two can never drift — see desiredAccountLocked.
func createUserSetsPassword(params *pb.UserParams) bool {
	return !params.NoPassword && !params.SystemUser && !params.Disabled
}

// desiredAccountLocked reports whether the account must be shadow-LOCKED ("!")
// at rest. The lock is the agent-side "user is disabled" gate: the terminal
// handler refuses a locked pm-tty-* account, and the control rejects a disabled
// user at StartTerminal — so a disabled user is blocked at BOTH ends, and a
// locked "!" unambiguously means "disabled" (every enabled account is driven to
// an unlocked resting state below).
//
// Driven purely by params.Disabled. This used to ALSO lock every no_password /
// system_user account, because the old Manager.Unlock ran a bare `usermod -U`
// that would strip the "!" off a passwordless account into an EMPTY (login-able)
// password — so leaving such accounts locked was the only safe option, which in
// turn stranded enabled pm-tty-* terminal accounts as "disabled". Manager.Unlock
// now special-cases a passwordless account and sets "*" (no password, NOT
// locked) instead, so an enabled passwordless account is correctly left
// unlocked-but-passwordless and no reconcile path ever yields an empty password.
func desiredAccountLocked(params *pb.UserParams) bool {
	return params.Disabled
}

// updateUser modifies an existing user account.
func (e *Executor) updateUser(ctx context.Context, params *pb.UserParams, output *strings.Builder) (*pb.CommandOutput, bool, error) {
	// Get current user state
	currentInfo, err := userMgr.Get(ctx, params.Username)
	if err != nil {
		return nil, false, fmt.Errorf("failed to get current user info: %w", err)
	}

	changed := false
	var modOpts sysuser.ModifyOptions
	needModify := false

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
		modOpts.Shell = desiredShell
		needModify = true
		output.WriteString(fmt.Sprintf("shell: %s -> %s\n", currentInfo.Shell, desiredShell))
	}

	// Home directory - only if explicitly set and different
	if params.HomeDir != "" && currentInfo.HomeDir != params.HomeDir {
		modOpts.HomeDir = params.HomeDir
		needModify = true
		output.WriteString(fmt.Sprintf("home: %s -> %s\n", currentInfo.HomeDir, params.HomeDir))
	}

	// Comment - only if explicitly set and different
	if params.Comment != "" && currentInfo.Comment != params.Comment {
		modOpts.Comment = params.Comment
		needModify = true
		output.WriteString(fmt.Sprintf("comment: %s -> %s\n", currentInfo.Comment, params.Comment))
	}

	// Primary group - only if explicitly set and different. usermod -g (which the
	// SDK ModifyOptions.PrimaryGroup drives) accepts either a numeric GID or a
	// group name, so both forms map onto the same field.
	if params.Gid > 0 && currentInfo.GID != int(params.Gid) {
		modOpts.PrimaryGroup = fmt.Sprintf("%d", params.Gid)
		needModify = true
		output.WriteString(fmt.Sprintf("gid: %d -> %d\n", currentInfo.GID, params.Gid))
	} else if params.PrimaryGroup != "" {
		if err := userMgr.GroupEnsure(ctx, params.PrimaryGroup); err != nil {
			e.logger.Warn("failed to ensure primary group exists for usermod", "group", params.PrimaryGroup, "error", err)
		}
		// Only modify when the requested primary group differs from the user's
		// current GID, so a re-applied action stays idempotent (changed=false)
		// instead of running usermod every cycle. If the group can't be resolved
		// to a GID, fall back to applying and let usermod reconcile.
		if grp, err := user.LookupGroup(params.PrimaryGroup); err != nil || grp.Gid != strconv.Itoa(currentInfo.GID) {
			modOpts.PrimaryGroup = params.PrimaryGroup
			needModify = true
			output.WriteString(fmt.Sprintf("primary group -> %s\n", params.PrimaryGroup))
		}
	}

	// Apply usermod if we have changes
	if needModify {
		if err := userMgr.Modify(ctx, params.Username, modOpts); err != nil {
			output.WriteString(err.Error())
			return &pb.CommandOutput{ExitCode: 1, Stderr: output.String()}, false, fmt.Errorf("failed to update user: %w", err)
		}
		changed = true
	}

	// Ensure home directory exists (may be missing if a prior run
	// failed). Same change as in createUser — honour the explicit
	// create_home value from the proto rather than inverting false
	// to true for non-system users.
	if e.ensureHomeIfMissing(ctx, params, currentInfo.HomeDir, output) {
		changed = true
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
			if err := userMgr.Lock(ctx, params.Username); err != nil {
				output.WriteString(fmt.Sprintf("warning: failed to lock user: %v\n", err))
			} else {
				output.WriteString("account locked (disabled)\n")
				changed = true
			}
		} else {
			if err := userMgr.Unlock(ctx, params.Username); err != nil {
				output.WriteString(fmt.Sprintf("warning: failed to unlock user: %v\n", err))
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

	uExists, err := userExists(ctx, username)
	if err != nil {
		return nil, false, fmt.Errorf("check user %s: %w", username, err)
	}
	if !uExists {
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
	err = userMgr.Delete(ctx, username, sysuser.DeleteOptions{RemoveHome: true})
	if err != nil {
		// userdel -r can report an error when only the home directory was missing
		// yet the account was removed. Confirm via Exists — but if THAT probe
		// also fails we cannot claim success (the zero value would read
		// exists=false and mask an unknown state), so surface the original error.
		exists, existsErr := userMgr.Exists(ctx, username)
		if existsErr == nil && !exists {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("removed user: %s (home directory may not have existed)\n", username),
			}, true, nil
		}
		return nil, false, fmt.Errorf("failed to remove user: %w", err)
	}

	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   fmt.Sprintf("removed user: %s\n", username),
	}, true, nil
}

// accountsServiceDir is the AccountsService per-user override directory. The
// agent keeps the path + the SystemAccount content string ONLY for the
// idempotency/"was it ours" pre-check below; the actual write/remove is
// delegated to the SDK (user.SetHiddenOnLoginScreen), which owns the file format.
const accountsServiceDir = "/var/lib/AccountsService/users"

// accountsServiceHiddenContent is the SDK-written AccountsService override body;
// the agent compares against it to decide whether a change is needed and whether
// an existing override is one it (the SDK) wrote.
const accountsServiceHiddenContent = "[User]\nSystemAccount=true\n"

// setUserHidden shows or hides a user on graphical login screens, delegating the
// actual AccountsService write/remove to the SDK's user.SetHiddenOnLoginScreen.
// The agent keeps three behaviours on top of the SDK call: skip SILENTLY on a
// headless box (AccountsService not installed) rather than surfacing the SDK's
// "not installed" error; idempotency (no change when already in the desired
// state); and, on unhide, only remove an override that matches what the SDK
// writes (don't delete a foreign override). Returns whether a change was made.
func setUserHidden(ctx context.Context, username string, hidden bool, output *strings.Builder) bool {
	if _, err := os.Stat(accountsServiceDir); os.IsNotExist(err) {
		return false // AccountsService not installed (headless), skip silently
	}

	// Idempotency + was-ours: a file matching accountsServiceHiddenContent means
	// "hidden, written by us". (existing==content)==hidden ⇒ already converged;
	// and on unhide a non-matching/foreign file reads as "not hidden", so we skip
	// rather than remove it.
	existing, _ := readFileWithSudo(ctx, accountsServiceDir+"/"+username)
	if (existing == accountsServiceHiddenContent) == hidden {
		return false
	}

	if err := userMgr.SetHiddenOnLoginScreen(ctx, username, hidden); err != nil {
		verb := "hide"
		if !hidden {
			verb = "unhide"
		}
		output.WriteString(fmt.Sprintf("warning: failed to %s user on login screen: %v\n", verb, err))
		return false
	}
	if hidden {
		output.WriteString("hidden from login screen (AccountsService)\n")
	} else {
		output.WriteString("visible on login screen (AccountsService removed)\n")
	}
	return true
}

// removeAccountsServiceFile removes the AccountsService override for a user during
// user deletion, via the SDK (SetHiddenOnLoginScreen(false) is an rm -f that
// no-ops when the override is absent).
func removeAccountsServiceFile(ctx context.Context, username string) {
	_ = userMgr.SetHiddenOnLoginScreen(ctx, username, false)
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

	// Create .ssh directory via the SDK fs manager (privilege-keyed, like the
	// fsMgr.WriteFile below) instead of a raw `sudo mkdir`. No Mode is set on
	// purpose: MkdirOptions.Mode chmods by PATH, which would follow a
	// user-planted ~/.ssh symlink — the very class the OpenRealDir + fd-chmod
	// below close. The 0700 mode is applied through the O_NOFOLLOW FD.
	if err := fsMgr.Mkdir(ctx, sshDir, sysfs.MkdirOptions{Recursive: true}); err != nil {
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

	uid, gid, err := sysfs.ResolveOwnership(params.Username, homeGroupFor(params))
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
	if err := fsMgr.WriteFile(ctx, authKeysFile, []byte(desiredContent), sysfs.WriteOptions{Mode: 0o600}); err != nil {
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
	// Reload via the SDK service Manager, falling back to the Debian/Ubuntu
	// "ssh" unit name when "sshd" is not the unit on this host.
	err := serviceMgr.Reload(ctx, "sshd")
	if err != nil {
		err = serviceMgr.Reload(ctx, "ssh")
	}
	if err != nil {
		output.WriteString("warning: failed to reload sshd\n")
		output.WriteString(strings.TrimSpace(err.Error()) + "\n")
	} else {
		output.WriteString("reloaded sshd\n")
	}
}
