package luksd

import (
	"context"
	"encoding/json"
	"errors"
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
func submit(sock string, req Request) (Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", sock)
	if err != nil {
		return Response{}, err
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	// A saturated daemon may send CodeBusy and close before this client finishes
	// writing. Preserve that valid response instead of turning the race into a
	// broken-pipe test failure.
	writeErr := json.NewEncoder(conn).Encode(req)
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		if writeErr != nil {
			return Response{}, writeErr
		}
		return Response{}, err
	}
	return resp, nil
}

// ctxRecordingSession captures the context the daemon hands to the request
// path, and can hold a request open until released.
type ctxRecordingSession struct {
	mu      sync.Mutex
	ctx     context.Context
	inFlnow int
	peak    int
	gate    chan struct{}
	err     error
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
	if s.err != nil {
		return nil, s.err
	}
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

	resp, err := submit(sock, Request{Token: "tok", Passphrase: goodPassphrase})
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
	sess := &ctxRecordingSession{gate: gate, err: errors.New("stop after concurrency measurement")}
	sock := startDaemon(t, sess)

	type outcome struct {
		response Response
		err      error
	}
	results := make(chan outcome, attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			response, err := submit(sock, Request{Token: "tok", Passphrase: goodPassphrase})
			results <- outcome{response: response, err: err}
		}()
	}

	released := false
	defer func() {
		if !released {
			close(gate)
		}
	}()
	require.Eventually(t, func() bool {
		return sess.peakInFlight() == maxConcurrentRequests
	}, 3*time.Second, 5*time.Millisecond)
	assert.Equal(t, maxConcurrentRequests, sess.peakInFlight())

	for i := 0; i < attempts-maxConcurrentRequests; i++ {
		select {
		case result := <-results:
			require.NoError(t, result.err)
			assert.Equal(t, CodeBusy, result.response.Code)
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for an excess request to be refused")
		}
	}
	close(gate)
	released = true

	for i := 0; i < maxConcurrentRequests; i++ {
		result := <-results
		require.NoError(t, result.err)
		assert.Equal(t, CodeInvalidToken, result.response.Code)
	}
}
