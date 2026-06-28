package executor

import (
	"os/user"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysfs "github.com/manchtools/power-manage-sdk/sys/fs"
)

// The ~/.ssh TOCTOU (audit F022) is closed by FD-based ops: setupSSHKeys
// opens .ssh via sysfs.OpenRealDir (O_NOFOLLOW|O_DIRECTORY) and applies
// ownership/mode through the FD (fchown/fchmod), and hands authorized_keys
// back via sysfs.FchownNoFollow. The symlink/non-dir rejection and the
// fd-acts-on-the-opened-inode property are unit-tested in the SDK
// (sdk/go/sys/fs/safe_fd_unix_test.go). The numeric uid/gid those FD calls
// require now come from sdk sysfs.ResolveOwnership fed the agent's homeGroupFor
// group string; this test pins that the agent's homeGroupFor PREFERENCE ORDER
// resolves to the right ids through the SDK (the SDK owns the name/numeric
// resolution; the agent owns homeGroupFor).

// homeGroupFor + sysfs.ResolveOwnership must produce the numeric ids equivalent
// to the "username:homeGroupFor()" string the path-based chown previously used.
// We anchor on the test runner's own account (guaranteed present in the
// user/group database) so the lookups resolve deterministically without root.
func TestHomeGroupForOwnership_ResolvesViaSDK(t *testing.T) {
	cur, err := user.Current()
	require.NoError(t, err)
	wantUID, err := strconv.Atoi(cur.Uid)
	require.NoError(t, err)
	wantPrimaryGID, err := strconv.Atoi(cur.Gid)
	require.NoError(t, err)

	resolve := func(p *pb.UserParams) (int, int, error) {
		return sysfs.ResolveOwnership(p.Username, homeGroupFor(p))
	}

	t.Run("numeric Gid is used as a literal GID (no name lookup)", func(t *testing.T) {
		// 4242 need not exist as a named group; chown treats a numeric
		// token literally, and so must the resolution.
		uid, gid, err := resolve(&pb.UserParams{Username: cur.Username, Gid: 4242})
		require.NoError(t, err)
		assert.Equal(t, wantUID, uid)
		assert.Equal(t, 4242, gid)
	})

	t.Run("named PrimaryGroup is resolved via the group database", func(t *testing.T) {
		grp, err := user.LookupGroupId(cur.Gid)
		require.NoError(t, err)
		uid, gid, err := resolve(&pb.UserParams{Username: cur.Username, PrimaryGroup: grp.Name})
		require.NoError(t, err)
		assert.Equal(t, wantUID, uid)
		assert.Equal(t, wantPrimaryGID, gid)
	})

	t.Run("unknown user is an error, not a silent uid 0", func(t *testing.T) {
		_, _, err := resolve(&pb.UserParams{Username: "pm-definitely-no-such-user-xyz"})
		assert.Error(t, err, "a failed user lookup must error so .ssh is never chowned to root")
	})
}

// desiredAccountLocked is the agent-side "user is disabled" gate: an account is
// shadow-LOCKED ("!") iff the control user is disabled. The terminal handler
// refuses a locked pm-tty-* account, so a "!" unambiguously means disabled —
// every ENABLED account is driven to an unlocked resting state ("*" for a
// passwordless pm-tty-* user, a hash for a normal user), so the agent can tell a
// disabled account apart from a freshly-created passwordless one.
func TestDesiredAccountLocked(t *testing.T) {
	cases := []struct {
		name string
		p    *pb.UserParams
		want bool
	}{
		// The fix: an ENABLED passwordless account (a pm-tty-* terminal user) is
		// NOT locked — Manager.Unlock sets it to "*" (no password, not locked),
		// never an empty/login-able password. Locking it stranded every terminal
		// session as "tty user is disabled".
		{"no_password, not disabled -> unlocked", &pb.UserParams{NoPassword: true, Disabled: false}, false},
		{"no_password, disabled -> locked", &pb.UserParams{NoPassword: true, Disabled: true}, true},

		// System users are likewise unlocked-but-passwordless when enabled.
		{"system_user, not disabled -> unlocked", &pb.UserParams{SystemUser: true, Disabled: false}, false},
		{"system_user, disabled -> locked", &pb.UserParams{SystemUser: true, Disabled: true}, true},

		// A normal enabled account is unlocked; an explicitly disabled one locked.
		{"normal enabled -> unlocked", &pb.UserParams{}, false},
		{"normal disabled -> locked", &pb.UserParams{Disabled: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, desiredAccountLocked(tc.p))
		})
	}
}

// TestDesiredAccountLocked_IsExactlyDisabled pins that the lock tracks ONLY the
// disabled flag, for every combination of the password-skip flags. The old
// "no_password/system_user -> always locked" binding is INTENTIONALLY gone: it
// existed solely because a bare `usermod -U` on a passwordless account stripped
// the "!" into an EMPTY (login-able) password — which Manager.Unlock now prevents
// by setting "*" instead. createUser still skips the temp password for those
// accounts (asserted below), so a no_password account never gains a password; it
// is simply left "*" (not "!") when enabled.
func TestDesiredAccountLocked_IsExactlyDisabled(t *testing.T) {
	for _, noPass := range []bool{false, true} {
		for _, sysUser := range []bool{false, true} {
			for _, disabled := range []bool{false, true} {
				p := &pb.UserParams{NoPassword: noPass, SystemUser: sysUser, Disabled: disabled}
				assert.Equal(t, disabled, desiredAccountLocked(p),
					"lock must track Disabled only: no_password=%v system_user=%v disabled=%v", noPass, sysUser, disabled)
			}
		}
	}

	// The password-skip contract is unchanged and still load-bearing: createUser
	// sets a temp password ONLY for a plain enabled account, so a pm-tty-* account
	// never gains a real password (the lock decision is just no longer bound to it).
	assert.True(t, createUserSetsPassword(&pb.UserParams{}),
		"a plain account (no opt-outs) must get a password")
	assert.False(t, createUserSetsPassword(&pb.UserParams{NoPassword: true}), "no_password skips the password")
	assert.False(t, createUserSetsPassword(&pb.UserParams{SystemUser: true}), "system_user skips the password")
	assert.False(t, createUserSetsPassword(&pb.UserParams{Disabled: true}), "disabled skips the password")
}
