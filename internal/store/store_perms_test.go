package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
