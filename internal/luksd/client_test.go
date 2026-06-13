package luksd

import (
	"encoding/json"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startRecordingServer stands up a one-shot unix socket that records the
// single request it receives and replies with resp. It returns `done`,
// closed AFTER the server goroutine has finished writing `received`;
// callers MUST wait on `done` before reading `received` (the write and the
// read are in different goroutines with no other happens-before edge).
func startRecordingServer(t *testing.T, resp Response) (socketPath string, received *Request, done <-chan struct{}) {
	t.Helper()
	socketPath = filepath.Join(t.TempDir(), "luks.sock")
	ln, err := net.Listen("unix", socketPath)
	require.NoError(t, err)
	received = &Request{}
	doneCh := make(chan struct{})

	go func() {
		defer close(doneCh) // establishes happens-before for `received`
		conn, aerr := ln.Accept()
		if aerr != nil {
			return
		}
		defer conn.Close()
		_ = json.NewDecoder(conn).Decode(received)
		_ = json.NewEncoder(conn).Encode(resp)
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return socketPath, received, doneCh
}

// awaitServer blocks until the recording server goroutine has finished (so
// `received` is safe to read), failing the test on timeout.
func awaitServer(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("recording server did not complete")
	}
}

// WS6 #19: the unprivileged client transmits EXACTLY {token, passphrase}
// — never a data dir or store path — and surfaces the daemon's verdict.
func TestLuksClient_CollectsPassphraseAndSendsTokenOnly(t *testing.T) {
	sock, received, done := startRecordingServer(t, Response{OK: true, Code: CodeOK})

	c := NewClient(sock)
	err := c.SetPassphrase("my-token", func() (string, error) {
		return "user-chosen-passphrase", nil
	})
	require.NoError(t, err)

	awaitServer(t, done) // safe to read `received` only after this
	assert.Equal(t, "my-token", received.Token)
	assert.Equal(t, "user-chosen-passphrase", received.Passphrase)

	// The wire form carries no other fields (no data dir / store path).
	b, _ := json.Marshal(received)
	assert.NotContains(t, string(b), "data_dir")
	assert.NotContains(t, string(b), "store")
}

// The client surfaces a daemon rejection as an error.
func TestLuksClient_SurfacesDaemonError(t *testing.T) {
	sock, _, done := startRecordingServer(t, Response{OK: false, Code: CodeInvalidToken, Error: "token is invalid or has expired"})

	c := NewClient(sock)
	err := c.SetPassphrase("tok", func() (string, error) { return "user-chosen-passphrase", nil })
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid")
	awaitServer(t, done) // let the server goroutine finish before teardown
}

// An empty passphrase (prompt aborted / mismatch after retries) must be
// refused WITHOUT contacting the daemon.
func TestLuksClient_RefusesEmptyPassphrase(t *testing.T) {
	dialed := false
	c := NewClient(filepath.Join(t.TempDir(), "nope.sock"))
	c.dialer = func() (net.Conn, error) {
		dialed = true
		return nil, assertNoDial(t)
	}
	err := c.SetPassphrase("tok", func() (string, error) { return "", nil })
	require.Error(t, err)
	assert.False(t, dialed, "client must not contact the daemon with an empty passphrase")
}

func assertNoDial(t *testing.T) error {
	t.Helper()
	t.Error("dialer should not have been called")
	return nil
}
