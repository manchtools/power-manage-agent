package luksd

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestPeerAuthorized pins the LUKS socket's peer-credential decision. A test
// process cannot connect as a foreign uid without privileges, so the pure
// decision is unit-tested directly and the wired-up listener gets a
// same-uid positive control in peercred_linux_test.go.
//
// The rule differs from enroll.sock's on purpose: this client is the endpoint
// user's UNPRIVILEGED CLI, so same-uid would delete the feature. What must not
// pass is a service account — the identity a remote compromise lands in, and
// the one that would use a token scraped out of /proc.
func TestPeerAuthorized(t *testing.T) {
	cases := []struct {
		name             string
		peerUID, selfUID int
		want             bool
	}{
		{"the agent's own uid (root under the shipped unit)", 0, 0, true},
		{"a regular login user against the root agent", 1000, 0, true},
		{"a second regular login user", 4711, 0, true},
		{"www-data against the root agent", 33, 0, false},
		{"a low system account", 1, 0, false},
		{"nobody", nobodyUID, 0, false},
		{"just below the login floor", firstRegularUID - 1, 0, false},
		{"exactly the login floor", firstRegularUID, 0, true},
		{"a negative uid can never be produced by SO_PEERCRED", -1, 0, false},
		{"root against a non-root agent is not the agent itself", 0, 1000, false},
		{"a non-root agent still accepts login users", 1000, 1000, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, peerAuthorized(tc.peerUID, tc.selfUID),
				"peerAuthorized(peerUID=%d, selfUID=%d)", tc.peerUID, tc.selfUID)
		})
	}
}
