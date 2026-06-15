package executor

import (
	"os/user"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// The ~/.ssh TOCTOU (audit F022) is closed by FD-based ops: setupSSHKeys
// opens .ssh via sysfs.OpenRealDir (O_NOFOLLOW|O_DIRECTORY) and applies
// ownership/mode through the FD (fchown/fchmod), and hands authorized_keys
// back via sysfs.FchownNoFollow. The symlink/non-dir rejection and the
// fd-acts-on-the-opened-inode property are unit-tested in the SDK
// (sdk/go/sys/fs/safe_fd_unix_test.go). resolveOwnership — the numeric
// uid/gid those FD calls require — is tested below against homeGroupFor.

// resolveOwnership must produce the numeric ids equivalent to the
// "username:homeGroupFor()" string the path-based chown previously used,
// mirroring homeGroupFor's preference order. We anchor on the test
// runner's own account (guaranteed present in the user/group database)
// so the lookups resolve deterministically without root.
func TestResolveOwnership_MirrorsHomeGroupFor(t *testing.T) {
	cur, err := user.Current()
	require.NoError(t, err)
	wantUID, err := strconv.Atoi(cur.Uid)
	require.NoError(t, err)
	wantPrimaryGID, err := strconv.Atoi(cur.Gid)
	require.NoError(t, err)

	t.Run("numeric Gid is used as a literal GID (no name lookup)", func(t *testing.T) {
		// 4242 need not exist as a named group; chown treats a numeric
		// token literally, and so must resolveOwnership.
		uid, gid, err := resolveOwnership(&pb.UserParams{Username: cur.Username, Gid: 4242})
		require.NoError(t, err)
		assert.Equal(t, wantUID, uid)
		assert.Equal(t, 4242, gid)
	})

	t.Run("named PrimaryGroup is resolved via the group database", func(t *testing.T) {
		grp, err := user.LookupGroupId(cur.Gid)
		require.NoError(t, err)
		uid, gid, err := resolveOwnership(&pb.UserParams{Username: cur.Username, PrimaryGroup: grp.Name})
		require.NoError(t, err)
		assert.Equal(t, wantUID, uid)
		assert.Equal(t, wantPrimaryGID, gid)
	})

	t.Run("unknown user is an error, not a silent uid 0", func(t *testing.T) {
		_, _, err := resolveOwnership(&pb.UserParams{Username: "pm-definitely-no-such-user-xyz"})
		assert.Error(t, err, "a failed user lookup must error so .ssh is never chowned to root")
	})
}

// desiredAccountLocked encodes the single source of truth for whether
// an account must stay shadow-locked. It MUST agree with createUser's
// password-skip condition: createUser sets a temp password only when
// !NoPassword && !SystemUser && !Disabled, leaving the account at the
// useradd default '!' (locked, no PAM login) otherwise. updateUser's
// lock reconciliation must therefore treat exactly those three cases as
// "should be locked" — otherwise a reconcile of a passwordless account
// runs `usermod -U`, strips the '!', and produces a PASSWORDLESS
// account (the no_password #94 / pm-tty-* regression).
func TestDesiredAccountLocked(t *testing.T) {
	cases := []struct {
		name string
		p    *pb.UserParams
		want bool
	}{
		// The reported bug: a no_password account that is not disabled
		// must NOT be unlocked — it has no password hash, so unlocking
		// yields a passwordless login path.
		{"no_password, not disabled -> stays locked", &pb.UserParams{NoPassword: true, Disabled: false}, true},
		{"no_password, disabled -> locked", &pb.UserParams{NoPassword: true, Disabled: true}, true},

		// Sibling: system users also get no password in createUser, so
		// the same unlock-to-passwordless trap applies.
		{"system_user, not disabled -> stays locked", &pb.UserParams{SystemUser: true, Disabled: false}, true},

		// A normal, enabled account DID get a temp password at create,
		// so it is legitimately unlockable (restores password login).
		{"normal enabled -> unlocked", &pb.UserParams{}, false},

		// A normal account explicitly disabled must be locked.
		{"normal disabled -> locked", &pb.UserParams{Disabled: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, desiredAccountLocked(tc.p))
		})
	}
}

// Pin the cross-function invariant by binding to the SHARED predicate, not a
// hand-copy of it: for every combination of the three password-skip flags,
// "desiredAccountLocked wants it locked" must equal "createUser did NOT set a
// password". Both callers consult createUserSetsPassword, so this drives the
// real function on both sides — a future edit to one cannot diverge from the
// other without this test (and createUser's call site) catching it. The prior
// version re-derived the rule inline in the test, which only proved
// desiredAccountLocked matched a COPY of the rule, not createUser's actual code.
func TestDesiredAccountLocked_MatchesCreateUserPasswordSkip(t *testing.T) {
	for _, noPass := range []bool{false, true} {
		for _, sysUser := range []bool{false, true} {
			for _, disabled := range []bool{false, true} {
				p := &pb.UserParams{NoPassword: noPass, SystemUser: sysUser, Disabled: disabled}
				assert.Equal(t, !createUserSetsPassword(p), desiredAccountLocked(p),
					"no_password=%v system_user=%v disabled=%v", noPass, sysUser, disabled)
			}
		}
	}

	// Pin the password-skip contract itself so the binding above can't be
	// satisfied by a vacuous "both wrong the same way". createUser sets a
	// temporary password ONLY when none of the three opt-outs is requested.
	assert.True(t, createUserSetsPassword(&pb.UserParams{}),
		"a plain account (no opt-outs) must get a password")
	assert.False(t, createUserSetsPassword(&pb.UserParams{NoPassword: true}), "no_password skips the password")
	assert.False(t, createUserSetsPassword(&pb.UserParams{SystemUser: true}), "system_user skips the password")
	assert.False(t, createUserSetsPassword(&pb.UserParams{Disabled: true}), "disabled skips the password")
}
