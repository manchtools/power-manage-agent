package deviceauth

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"

	"github.com/manchtools/power-manage/agent/internal/credentials"
)

// failingStore wraps a real store but fails Save — for the
// save-fail-closed test (#14).
type failingStore struct {
	credentialStore
	saveErr error
}

func (f *failingStore) Save(*credentials.Credentials) error { return f.saveErr }

// TestEnroll_RateLimitRejectsSixthInWindow pins the brute-force guard
// (#6): five attempts in the window reach the network; the sixth is
// rejected BEFORE any registration call (guard-before-work). Registration
// is made to fail so each of the first five is a genuine attempt rather
// than enrolling and short-circuiting the rest.
func TestEnroll_RateLimitRejectsSixthInWindow(t *testing.T) {
	var registerCalls int32
	mock := &mockRegisterService{
		registerFunc: func(_ context.Context, _ *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
			atomic.AddInt32(&registerCalls, 1)
			return nil, connect.NewError(connect.CodePermissionDenied, nil)
		},
	}
	srv := startMockControlServer(t, mock)

	credStore := credentials.NewStore(t.TempDir())
	h := NewEnrollHandler("test-host", "dev", credStore, slog.Default(), nil)
	h.registerOpts = trustServer(srv)
	fixed := time.Now()
	h.now = func() time.Time { return fixed } // all attempts land in one window

	for i := 0; i < 5; i++ {
		resp, err := h.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{
			ServerUrl: srv.URL, Token: "tok",
		}))
		require.NoError(t, err)
		assert.Contains(t, resp.Msg.Error, "registration failed", "attempt %d should reach (and fail) registration", i+1)
	}

	resp, err := h.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{
		ServerUrl: srv.URL, Token: "tok",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.Contains(t, resp.Msg.Error, "rate limit")
	assert.EqualValues(t, 5, atomic.LoadInt32(&registerCalls), "the 6th attempt must not reach the network")
}

// TestEnroll_RateLimitSlidingWindowEviction pins WS9 #6: the limiter is a
// SLIDING window, not a permanent lockout — attempts older than the window are
// evicted, so once the window passes enrollment is allowed again. (The
// within-window rejection is covered by TestEnroll_RateLimitRejectsSixthInWindow;
// this covers the eviction side, and also that FAILED attempts consume budget,
// since all six here fail registration yet still trip the limit.)
func TestEnroll_RateLimitSlidingWindowEviction(t *testing.T) {
	var registerCalls int32
	mock := &mockRegisterService{
		registerFunc: func(_ context.Context, _ *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
			atomic.AddInt32(&registerCalls, 1)
			return nil, connect.NewError(connect.CodePermissionDenied, nil)
		},
	}
	srv := startMockControlServer(t, mock)
	credStore := credentials.NewStore(t.TempDir())
	h := NewEnrollHandler("test-host", "dev", credStore, slog.Default(), nil)
	h.registerOpts = trustServer(srv)
	now := time.Now()
	h.now = func() time.Time { return now }

	// Exhaust the window: 5 reach (and fail) registration, the 6th is rate-limited.
	for i := 0; i < 6; i++ {
		_, err := h.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{ServerUrl: srv.URL, Token: "tok"}))
		require.NoError(t, err)
	}
	require.EqualValues(t, 5, atomic.LoadInt32(&registerCalls), "only 5 attempts may reach the network within one window")

	// Advance past the 1-minute window: the prior attempts are evicted, so a
	// fresh attempt is allowed through to registration again.
	now = now.Add(61 * time.Second)
	resp, err := h.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{ServerUrl: srv.URL, Token: "tok"}))
	require.NoError(t, err)
	assert.Contains(t, resp.Msg.Error, "registration failed", "after the window resets, enrollment is allowed through again")
	assert.EqualValues(t, 6, atomic.LoadInt32(&registerCalls), "a fresh attempt after the window must reach registration")
}

// TestEnroll_ConcurrentSerializesToOneRegistration pins WS9 #12: enrollMu
// serializes the enrollment body, so concurrent Enroll calls (all within the
// rate-limit budget) cannot each pass the Exists() check and register duplicate
// devices — the first registers and saves, and the rest short-circuit. Without
// the lock this would race to N registrations / a corrupt Save.
func TestEnroll_ConcurrentSerializesToOneRegistration(t *testing.T) {
	var registerCalls int32
	mock := &mockRegisterService{
		registerFunc: func(_ context.Context, _ *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
			atomic.AddInt32(&registerCalls, 1)
			return connect.NewResponse(&pm.RegisterResponse{
				DeviceId:    &pm.DeviceId{Value: "dev-123"},
				CaCert:      []byte("-----BEGIN CERTIFICATE-----\nfake-ca\n-----END CERTIFICATE-----\n"),
				Certificate: []byte("-----BEGIN CERTIFICATE-----\nfake-cert\n-----END CERTIFICATE-----\n"),
				GatewayUrl:  "https://gw.example.com:8443",
			}), nil
		},
	}
	srv := startMockControlServer(t, mock)
	credStore := credentials.NewStore(t.TempDir())
	h := NewEnrollHandler("test-host", "dev", credStore, slog.Default(), nil)
	h.registerOpts = trustServer(srv)

	const n = 5 // within the 5/min budget, so all reach the serialized body
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = h.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{ServerUrl: srv.URL, Token: "tok"}))
		}()
	}
	wg.Wait()

	assert.EqualValues(t, 1, atomic.LoadInt32(&registerCalls),
		"enrollMu must serialize concurrent enrollments so exactly one device registers; the rest short-circuit on Exists()")
	assert.True(t, credStore.Exists(), "the single enrollment must have saved credentials")
}

// TestEnroll_RejectsMissingMTLSCerts pins fail-closed when the server
// omits a cert (#13): no creds saved, status not primed.
func TestEnroll_RejectsMissingMTLSCerts(t *testing.T) {
	cases := []struct {
		name     string
		ca, cert []byte
	}{
		{"ca only", []byte("ca"), nil},
		{"cert only", nil, []byte("cert")},
		{"both empty", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mock := &mockRegisterService{
				registerFunc: func(_ context.Context, _ *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
					return connect.NewResponse(&pm.RegisterResponse{
						DeviceId:    &pm.DeviceId{Value: "01HZZZZZZZZZZZZZZZZZZZZZZZZ"},
						CaCert:      tc.ca,
						Certificate: tc.cert,
						GatewayUrl:  "https://gw.example.com",
					}), nil
				},
			}
			srv := startMockControlServer(t, mock)
			credStore := credentials.NewStore(t.TempDir())
			h := NewEnrollHandler("test-host", "dev", credStore, slog.Default(), nil)
			h.registerOpts = trustServer(srv)

			resp, err := h.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{
				ServerUrl: srv.URL, Token: "tok",
			}))
			require.NoError(t, err)
			assert.False(t, resp.Msg.Success)
			assert.Contains(t, resp.Msg.Error, "mTLS certificates")
			assert.False(t, credStore.Exists())
		})
	}
}

// TestEnroll_BindsOutboundRegisterRequest pins that the agent sends its
// token, hostname, and version, and a valid self-signed CSR whose key it
// keeps (#8) — the "private key never leaves the agent" contract.
func TestEnroll_BindsOutboundRegisterRequest(t *testing.T) {
	var captured *pm.RegisterRequest
	mock := &mockRegisterService{
		registerFunc: func(_ context.Context, req *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
			captured = req.Msg
			return connect.NewResponse(&pm.RegisterResponse{
				DeviceId:    &pm.DeviceId{Value: "01HZZZZZZZZZZZZZZZZZZZZZZZZ"},
				CaCert:      []byte(fakeLeafPEM),
				Certificate: []byte(fakeLeafPEM),
				GatewayUrl:  "https://gw.example.com",
			}), nil
		},
	}
	srv := startMockControlServer(t, mock)
	credStore := credentials.NewStore(t.TempDir())
	h := NewEnrollHandler("test-host", "dev", credStore, slog.Default(), nil)
	h.registerOpts = trustServer(srv)

	resp, err := h.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{
		ServerUrl: srv.URL, Token: "test-token",
	}))
	require.NoError(t, err)
	require.True(t, resp.Msg.Success, "%s", resp.Msg.Error)

	require.NotNil(t, captured)
	assert.Equal(t, "test-token", captured.Token)
	assert.Equal(t, "test-host", captured.Hostname)
	assert.Equal(t, "dev", captured.AgentVersion)

	block, _ := pem.Decode(captured.Csr)
	require.NotNil(t, block, "CSR must be PEM")
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature(), "CSR signature must verify")
}

// TestEnroll_SaveFailureFailsClosed pins #14: a Save error fails the
// enrollment closed — no callback, status not primed.
func TestEnroll_SaveFailureFailsClosed(t *testing.T) {
	srv := startMockControlServer(t, caReturningMock([]byte(fakeLeafPEM)))
	called := false
	h := NewEnrollHandler("test-host", "dev", credentials.NewStore(t.TempDir()), slog.Default(), func(*credentials.Credentials) { called = true })
	h.registerOpts = trustServer(srv)
	h.credStore = &failingStore{credentialStore: h.credStore, saveErr: errors.New("disk full")}

	resp, err := h.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{
		ServerUrl: srv.URL, Token: "tok",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.Contains(t, resp.Msg.Error, "save credentials")
	assert.False(t, called, "onEnrolled must not fire when Save fails")

	st, err := h.GetEnrollmentStatus(context.Background(), connect.NewRequest(&pm.GetEnrollmentStatusRequest{}))
	require.NoError(t, err)
	assert.False(t, st.Msg.Enrolled, "status cache must not be primed on Save failure")
}
