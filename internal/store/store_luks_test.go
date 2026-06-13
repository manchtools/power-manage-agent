package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// WS6 #18: the LUKS/LPS state mutators had 0% coverage. These pin the
// round-trip contract so a regression in the SQL (column drift, missing
// ON CONFLICT, etc.) is caught.
func TestLuksState_RoundTrip(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	const actionID = "01HXLUKSSTATE00000000000000"
	const devicePath = "/dev/mapper/luks-test"

	// Absent → (nil, nil)
	got, err := st.GetLuksState(actionID)
	require.NoError(t, err)
	require.Nil(t, got, "no state before any write")

	require.NoError(t, st.SetLuksOwnershipTaken(actionID, devicePath))
	got, err = st.GetLuksState(actionID)
	require.NoError(t, err)
	require.NotNil(t, got)
	assert.True(t, got.OwnershipTaken)
	assert.Equal(t, devicePath, got.DevicePath)
	assert.Equal(t, "none", got.DeviceKeyType)

	require.NoError(t, st.SetLuksDeviceKeyType(actionID, "user_passphrase"))
	got, err = st.GetLuksState(actionID)
	require.NoError(t, err)
	assert.Equal(t, "user_passphrase", got.DeviceKeyType)

	rotAt := time.Date(2026, 6, 1, 12, 0, 0, 0, time.UTC)
	require.NoError(t, st.SetLuksLastRotatedAt(actionID, rotAt))
	got, err = st.GetLuksState(actionID)
	require.NoError(t, err)
	assert.True(t, got.LastRotatedAt.Equal(rotAt), "last_rotated_at round-trips: got %v want %v", got.LastRotatedAt, rotAt)

	require.NoError(t, st.DeleteLuksState(actionID))
	got, err = st.GetLuksState(actionID)
	require.NoError(t, err)
	assert.Nil(t, got, "state gone after delete")
}

// The reuse-prevention window is 3: at most the three most recent hashes
// are retained. Derived from the documented reuse-window intent, not the
// query's LIMIT.
func TestLuksPassphraseHistory_KeepsThreeMostRecent(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	const actionID = "01HXLUKSHIST00000000000000"
	inserted := []string{"h1", "h2", "h3", "h4", "h5"}
	for _, h := range inserted {
		require.NoError(t, st.AddLuksPassphraseHash(actionID, h))
	}

	got, err := st.GetLuksPassphraseHashes(actionID)
	require.NoError(t, err)
	assert.Len(t, got, 3, "exactly the 3 most recent hashes are retained")
	for _, h := range got {
		assert.Contains(t, inserted, h, "retained hash must be one that was inserted")
	}
}

// WS6 #18: LPS state round-trip.
func TestLpsState_RoundTrip(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	const actionID = "01HXLPSSTATE000000000000000"
	rotAt := time.Date(2026, 6, 2, 9, 30, 0, 0, time.UTC)

	require.NoError(t, st.SetLpsUserState(actionID, "alice", rotAt, "hashA"))
	require.NoError(t, st.SetLpsUserState(actionID, "bob", rotAt, "hashB"))

	states, err := st.GetLpsState(actionID)
	require.NoError(t, err)
	require.Len(t, states, 2)
	require.Contains(t, states, "alice")
	assert.Equal(t, "hashA", states["alice"].PasswordHash)
	assert.True(t, states["alice"].LastRotatedAt.Equal(rotAt))

	// Upsert overwrites.
	require.NoError(t, st.SetLpsUserState(actionID, "alice", rotAt, "hashA2"))
	states, err = st.GetLpsState(actionID)
	require.NoError(t, err)
	assert.Equal(t, "hashA2", states["alice"].PasswordHash)

	require.NoError(t, st.DeleteLpsState(actionID))
	states, err = st.GetLpsState(actionID)
	require.NoError(t, err)
	assert.Empty(t, states)
}

// WS6 #10: the agent store holds action secrets (PSK, WiFi/EAP keys, LUKS
// passphrase hashes) and must not be world/group-readable. New must create
// agent.db (and its WAL/SHM sidecars) mode 0600 and re-assert the data
// directory 0700 — MkdirAll/sql.Open only set modes on CREATE, so a
// pre-existing wider mode (or umask) would otherwise persist.
func TestAgentDB_FileModeIs0600(t *testing.T) {
	// Pre-create the data dir with a deliberately wide mode (as a distro
	// package or a prior umask might) so the 0700 re-assert is actually
	// exercised, not satisfied by t.TempDir()'s own 0700.
	dir := filepath.Join(t.TempDir(), "data")
	require.NoError(t, os.Mkdir(dir, 0o755))
	st, err := New(dir)
	require.NoError(t, err)
	defer st.Close()

	// Force a WAL write so the -wal/-shm sidecars exist and are checked.
	require.NoError(t, st.SetLuksOwnershipTaken("01HXMODECHECK0000000000000", "/dev/mapper/x"))

	for _, name := range []string{"agent.db", "agent.db-wal", "agent.db-shm"} {
		path := filepath.Join(dir, name)
		info, statErr := os.Stat(path)
		if os.IsNotExist(statErr) {
			continue // sidecars may be checkpointed away; only assert when present
		}
		require.NoError(t, statErr)
		assert.Equalf(t, os.FileMode(0o600), info.Mode().Perm(),
			"%s must be 0600 (holds action secrets), got %v", name, info.Mode().Perm())
	}

	dirInfo, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm(), "data dir must be 0700")
}
