package luksd

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdk "github.com/manchtools/power-manage-sdk"
	"github.com/manchtools/power-manage/agent/internal/store"
)

// startDaemon runs a daemon on a temp socket and returns its path.
func startDaemon(t *testing.T, sess Session) string {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "luks.sock")
	d := NewDaemon(sock, &fakeStore{state: &store.LuksState{DeviceKeyType: "none"}}, &spyEnroller{}, nil)
	if sess != nil {
		d.SetSession(sess)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); _ = d.Start(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("LUKS daemon did not shut down")
		}
	})
	waitFor(t, func() bool {
		info, err := os.Stat(sock)
		return err == nil && info.Mode()&os.ModeSocket != 0
	})
	return sock
}

// submit sends one request over the socket and returns the decoded response.
func submit(t *testing.T, sock string, req Request) (Response, error) {
	t.Helper()
	conn, err := net.DialTimeout("unix", sock, 5*time.Second)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	err = json.NewDecoder(conn).Decode(&resp)
	return resp, err
}

// ctxRecordingSession captures the context the daemon hands to the request
// path, and can hold a request open until released.
type ctxRecordingSession struct {
	mu      sync.Mutex
	ctx     context.Context
	inFlnow int
	peak    int
	gate    chan struct{}
}

func (s *ctxRecordingSession) ValidateLuksToken(ctx context.Context, _ string) (*sdk.ValidateLuksTokenResult, error) {
	s.mu.Lock()
	s.ctx = ctx
	s.inFlnow++
	if s.inFlnow > s.peak {
		s.peak = s.inFlnow
	}
	s.mu.Unlock()
	if s.gate != nil {
		select {
		case <-s.gate:
		case <-ctx.Done():
		}
	}
	s.mu.Lock()
	s.inFlnow--
	s.mu.Unlock()
	return validResult(), nil
}

func (s *ctxRecordingSession) GetLuksKey(context.Context, string) (string, error) {
	return "managed-key", nil
}

func (s *ctxRecordingSession) capturedContext() context.Context {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ctx
}

func (s *ctxRecordingSession) peakInFlight() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.peak
}

// TestLuksDaemon_RequestContextHasADeadline is F21. The handler inherits the
// process-root context, so a control call that never returns — a stalled
// stream, a wedged cryptsetup — pins a root goroutine on a socket any local
// user can connect to, for the lifetime of the agent.
func TestLuksDaemon_RequestContextHasADeadline(t *testing.T) {
	sess := &ctxRecordingSession{}
	sock := startDaemon(t, sess)

	resp, err := submit(t, sock, Request{Token: "tok", Passphrase: goodPassphrase})
	require.NoError(t, err)
	require.True(t, resp.OK, "%+v", resp)

	ctx := sess.capturedContext()
	require.NotNil(t, ctx, "the daemon never reached the request path")
	deadline, ok := ctx.Deadline()
	assert.True(t, ok,
		"the LUKS request context carries no deadline; an unbounded handler on a world-connectable root socket never returns")
	if ok {
		assert.True(t, deadline.After(time.Now()), "deadline %v is already past", deadline)
	}
}

// TestLuksDaemon_BoundsConcurrentHandlers is the other half of F21: nothing
// limits how many pre-authorization handlers a local caller may have running
// at once against the root daemon.
func TestLuksDaemon_BoundsConcurrentHandlers(t *testing.T) {
	const attempts = 16
	gate := make(chan struct{})
	sess := &ctxRecordingSession{gate: gate}
	sock := startDaemon(t, sess)

	var wg sync.WaitGroup
	for i := 0; i < attempts; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = submit(t, sock, Request{Token: "tok", Passphrase: goodPassphrase})
		}()
	}

	// Give every attempt a chance to reach the request path; stop early once
	// they all have, so an unbounded daemon fails fast rather than at timeout.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && sess.peakInFlight() < attempts {
		time.Sleep(5 * time.Millisecond)
	}
	peak := sess.peakInFlight()
	close(gate)
	wg.Wait()

	assert.Less(t, peak, attempts,
		"the daemon ran %d handlers at once; a world-connectable root socket must bound in-flight requests", peak)
}
