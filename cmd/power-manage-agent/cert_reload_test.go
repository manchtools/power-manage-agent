package main

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/agent/internal/credentials"
)

func testCreds(cert string) *credentials.Credentials {
	return &credentials.Credentials{
		DeviceID:    "dev-1",
		CACert:      []byte("ca"),
		Certificate: []byte(cert),
		PrivateKey:  []byte("key"),
		GatewayAddr: "https://gw:8443",
		ControlAddr: "https://ctl",
	}
}

// reloadCredsForReconnect must return the cert currently ON DISK so a
// reconnect picks up a certificate rotated by startCertRotation, rather
// than the stale in-memory copy that would fail the handshake once
// expired.
func TestReloadCredsForReconnect_PicksUpRotatedCert(t *testing.T) {
	// store.Save derives its at-rest key from the machine ID; on a host without
	// /etc/machine-id (or /var/lib/dbus/machine-id) it cannot save. Skip cleanly
	// rather than hard-fail via require.NoError below — matching the
	// requireMachineID guard the internal/credentials tests use.
	if !credentials.MachineIDAvailable() {
		t.Skip("no machine-id on this host; credential save/load is unavailable")
	}

	dir := t.TempDir()
	store := credentials.NewStore(dir)

	// Initial enrollment cert on disk and in memory.
	inMemory := testCreds("OLD-CERT")
	require.NoError(t, store.Save(inMemory))

	// Rotation persists a new cert to disk (what startCertRotation does).
	require.NoError(t, store.Save(testCreds("NEW-CERT")))

	got := reloadCredsForReconnect(store, inMemory, slog.Default())
	assert.Equal(t, []byte("NEW-CERT"), got.Certificate,
		"reconnect must use the rotated cert from disk, not the stale in-memory one")
}

// A transient reload failure must not drop the working credentials —
// the agent keeps using the in-memory copy and tries again next time.
func TestReloadCredsForReconnect_FallsBackOnError(t *testing.T) {
	dir := t.TempDir()
	store := credentials.NewStore(dir)

	inMemory := testCreds("WORKING-CERT")
	// No creds file on disk (and remove the dir so Load fails hard).
	require.NoError(t, os.RemoveAll(filepath.Join(dir)))

	got := reloadCredsForReconnect(store, inMemory, slog.Default())
	assert.Same(t, inMemory, got, "a failed reload must return the in-memory credentials unchanged")
}
