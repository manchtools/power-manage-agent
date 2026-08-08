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
		loginUID         int
		want             bool
	}{
		{"the agent's own uid (root under the shipped unit)", 0, 0, -1, true},
		{"a conventional login user", 1000, 0, 1000, true},
		{"a low uid with an authenticated login session", 500, 0, 500, true},
		{"a directory-backed high uid login", 1000001, 0, 1000001, true},
		{"a high uid service without a login session", 4711, 0, -1, false},
		{"a service running inside another user's session", 33, 0, 1000, false},
		{"a negative uid can never be produced by SO_PEERCRED", -1, 0, -1, false},
		{"root against a non-root agent is not its login identity", 0, 1000, -1, false},
		{"a non-root agent accepts its own maintenance client", 1000, 1000, -1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, peerAuthorized(tc.peerUID, tc.selfUID, tc.loginUID),
				"peerAuthorized(peerUID=%d, selfUID=%d, loginUID=%d)", tc.peerUID, tc.selfUID, tc.loginUID)
		})
	}
}
