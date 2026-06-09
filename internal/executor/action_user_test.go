package executor

import (
	"testing"

	"github.com/stretchr/testify/assert"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// The symlink-rejection guard for ~/.ssh (audit F022) lives in the SDK
// as sysfs.AssertRealDir and is unit-tested there
// (sdk/go/sys/fs/safe_dir_test.go). setupSSHKeys calls it before the
// privileged chmod/chown and additionally passes chown -h.

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

// Pin the cross-function invariant directly: for every combination of
// the three password-skip flags, "createUser left it passwordless" must
// equal "desiredAccountLocked wants it locked". If they ever diverge,
// updateUser will fight createUser and either churn forever or unlock a
// passwordless account.
func TestDesiredAccountLocked_MatchesCreateUserPasswordSkip(t *testing.T) {
	for _, noPass := range []bool{false, true} {
		for _, sysUser := range []bool{false, true} {
			for _, disabled := range []bool{false, true} {
				p := &pb.UserParams{NoPassword: noPass, SystemUser: sysUser, Disabled: disabled}
				// createUser sets a password (and thus leaves the
				// account unlockable) ONLY in the all-false case.
				createUserSetsPassword := !noPass && !sysUser && !disabled
				wantLocked := !createUserSetsPassword
				assert.Equal(t, wantLocked, desiredAccountLocked(p),
					"no_password=%v system_user=%v disabled=%v", noPass, sysUser, disabled)
			}
		}
	}
}
