package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifyRestrictiveDirMode_FailsClosedOnWideDir pins WS14 #6's "couldn't
// tighten → error" contract: the post-chmod re-stat must REJECT a data dir that
// still carries group/world bits (the case where os.Chmod silently no-ops on a
// mount that ignores modes), and accept a 0700 dir.
func TestVerifyRestrictiveDirMode_FailsClosedOnWideDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not meaningful on Windows")
	}
	dir := t.TempDir()

	require.NoError(t, os.Chmod(dir, 0o777)) // simulate a chmod that did not tighten
	require.Error(t, verifyRestrictiveDirMode(dir),
		"a group/world-accessible data dir must be rejected, not accepted")

	require.NoError(t, os.Chmod(dir, 0o750)) // group still has access
	require.Error(t, verifyRestrictiveDirMode(dir),
		"any group/world permission bit must be rejected")

	require.NoError(t, os.Chmod(dir, 0o700))
	require.NoError(t, verifyRestrictiveDirMode(dir), "a 0700 dir must be accepted")
}

// TestStoreNew_TightensDataDirAndDBFileModes pins WS14 #6: store.New re-asserts
// 0700 on the data dir and 0600 on the DB + its WAL/SHM sidecars, even when the
// dir pre-existed with a wider mode (distro package, prior umask) — the DB holds
// action secrets (PSK, WiFi/EAP keys, LUKS passphrase hashes).
func TestStoreNew_TightensDataDirAndDBFileModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file modes are not meaningful on Windows")
	}
	dir := t.TempDir()
	// Simulate a pre-existing, group/other-accessible data dir.
	require.NoError(t, os.Chmod(dir, 0o777))

	st, err := New(dir)
	require.NoError(t, err)
	defer st.Close()

	di, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), di.Mode().Perm(), "store.New must tighten the data dir to 0700")

	dbInfo, err := os.Stat(filepath.Join(dir, "agent.db"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), dbInfo.Mode().Perm(), "agent.db must be 0600 (it holds action secrets)")

	// WAL/SHM sidecars exist under journal_mode=WAL; if present they must be 0600.
	for _, sidecar := range []string{"agent.db-wal", "agent.db-shm"} {
		if info, serr := os.Stat(filepath.Join(dir, sidecar)); serr == nil {
			assert.Equal(t, os.FileMode(0o600), info.Mode().Perm(), "%s must be 0600", sidecar)
		}
	}
}
