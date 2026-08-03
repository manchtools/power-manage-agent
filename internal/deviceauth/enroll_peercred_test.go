package deviceauth

import (
	"context"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/agent/internal/credentials"
)

// TestPeerAuthorized pins the enrollment-socket peer-credential decision:
// only the agent's own uid (root under the shipped unit) may enroll. Every
// other local uid — in particular an unprivileged caller against the root
// agent — is refused. This is the reliable red/green surface for the guard:
// a test process cannot connect as a foreign uid without privileges, so the
// pure decision is unit-tested directly.
func TestPeerAuthorized(t *testing.T) {
	cases := []struct {
		name             string
		peerUID, selfUID int
		want             bool
	}{
		{"same uid root", 0, 0, true},
		{"same uid non-root", 1000, 1000, true},
		{"unprivileged caller against root agent", 1000, 0, false},
		{"root caller against non-root agent", 0, 1000, false},
		{"different non-root uids", 1001, 1000, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, peerAuthorized(tc.peerUID, tc.selfUID),
				"peerAuthorized(peerUID=%d, selfUID=%d)", tc.peerUID, tc.selfUID)
		})
	}
}

// TestEnrollServer_SocketModeIsOwnerOnly pins that the enrollment socket is
// created owner-only (0600). A world-accessible socket lets any local user
// connect and enroll the root agent into an attacker-controlled control
// plane during the installed-but-unenrolled window.
func TestEnrollServer_SocketModeIsOwnerOnly(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "enroll.sock")
	h := NewEnrollHandler("test-host", "dev", credentials.NewStore(t.TempDir()), slog.Default(), nil)
	srv := NewEnrollServer(h, socket, slog.Default())

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() { errCh <- srv.Start(ctx) }()

	// Start chmods the socket to 0600 AFTER net.Listen creates it, so poll
	// for the configured mode rather than stat'ing the pre-chmod file once.
	waitForSocketMode(t, socket, 0o600)

	cancel()
	select {
	case err := <-errCh:
		require.NoError(t, err, "enrollment server returned an error on shutdown")
	case <-time.After(5 * time.Second):
		t.Fatal("enrollment server did not shut down")
	}
}

// waitForSocketMode blocks until the socket at path reaches want, then fails
// at the deadline with the last observed mode for a clear message.
func waitForSocketMode(t *testing.T, path string, want fs.FileMode) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if info, err := os.Stat(path); err == nil && info.Mode().Perm() == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	info, err := os.Stat(path)
	require.NoError(t, err, "socket %s did not appear", path)
	require.Equal(t, want, info.Mode().Perm(),
		"enrollment socket must reach mode %v; a world-accessible socket lets any local user enroll the agent", want)
}
