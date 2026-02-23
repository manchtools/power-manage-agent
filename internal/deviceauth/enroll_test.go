package deviceauth

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"

	"github.com/manchtools/power-manage/agent/internal/credentials"
)

// mockRegisterService implements the Register RPC of ControlServiceHandler.
type mockRegisterService struct {
	pmv1connect.UnimplementedControlServiceHandler

	registerFunc func(context.Context, *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error)
}

func (m *mockRegisterService) Register(ctx context.Context, req *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
	if m.registerFunc != nil {
		return m.registerFunc(ctx, req)
	}
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func startMockControlServer(t *testing.T, mock *mockRegisterService) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := pmv1connect.NewControlServiceHandler(mock)
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func TestEnroll_Success(t *testing.T) {
	mock := &mockRegisterService{
		registerFunc: func(_ context.Context, req *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
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
	logger := slog.Default()

	var enrolledCreds *credentials.Credentials
	handler := NewEnrollHandler("test-host", "dev", credStore, logger, func(creds *credentials.Credentials) {
		enrolledCreds = creds
	})

	resp, err := handler.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{
		ServerUrl: srv.URL,
		Token:     "test-token",
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Success)
	assert.Equal(t, "dev-123", resp.Msg.DeviceId)
	assert.Empty(t, resp.Msg.Error)

	// Callback was called
	require.NotNil(t, enrolledCreds)
	assert.Equal(t, "dev-123", enrolledCreds.DeviceID)
	assert.Equal(t, "https://gw.example.com:8443", enrolledCreds.GatewayAddr)
	assert.Equal(t, srv.URL, enrolledCreds.ControlAddr)

	// Credentials saved to store
	assert.True(t, credStore.Exists())
	loaded, err := credStore.Load()
	require.NoError(t, err)
	assert.Equal(t, "dev-123", loaded.DeviceID)
}

func TestEnroll_MissingFields(t *testing.T) {
	credStore := credentials.NewStore(t.TempDir())
	logger := slog.Default()
	handler := NewEnrollHandler("test-host", "dev", credStore, logger, nil)

	resp, err := handler.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{
		ServerUrl: "",
		Token:     "",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.Contains(t, resp.Msg.Error, "required")
}

func TestEnroll_AlreadyEnrolled(t *testing.T) {
	// Pre-populate credentials
	credStore := credentials.NewStore(t.TempDir())
	credStore.Save(&credentials.Credentials{
		DeviceID:    "existing-device",
		CACert:      []byte("ca"),
		Certificate: []byte("cert"),
		PrivateKey:  []byte("key"),
		GatewayAddr: "https://gw.example.com",
	})

	logger := slog.Default()
	handler := NewEnrollHandler("test-host", "dev", credStore, logger, nil)

	resp, err := handler.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{
		ServerUrl: "https://example.com",
		Token:     "token",
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Success) // Returns success with existing device ID
	assert.Equal(t, "existing-device", resp.Msg.DeviceId)
	assert.Contains(t, resp.Msg.Error, "already enrolled")
}

func TestEnroll_RegistrationFails(t *testing.T) {
	mock := &mockRegisterService{
		registerFunc: func(_ context.Context, _ *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
			return nil, connect.NewError(connect.CodePermissionDenied, nil)
		},
	}
	srv := startMockControlServer(t, mock)

	credStore := credentials.NewStore(t.TempDir())
	logger := slog.Default()
	handler := NewEnrollHandler("test-host", "dev", credStore, logger, nil)

	resp, err := handler.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{
		ServerUrl: srv.URL,
		Token:     "bad-token",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.Contains(t, resp.Msg.Error, "registration failed")
}

func TestGetEnrollmentStatus_NotEnrolled(t *testing.T) {
	credStore := credentials.NewStore(t.TempDir())
	logger := slog.Default()
	handler := NewEnrollHandler("test-host", "dev", credStore, logger, nil)

	resp, err := handler.GetEnrollmentStatus(context.Background(), connect.NewRequest(&pm.GetEnrollmentStatusRequest{}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Enrolled)
	assert.Empty(t, resp.Msg.DeviceId)
}

func TestGetEnrollmentStatus_Enrolled(t *testing.T) {
	credStore := credentials.NewStore(t.TempDir())
	credStore.Save(&credentials.Credentials{
		DeviceID:    "dev-abc",
		CACert:      []byte("ca"),
		Certificate: []byte("cert"),
		PrivateKey:  []byte("key"),
		GatewayAddr: "https://gw.example.com",
	})

	logger := slog.Default()
	handler := NewEnrollHandler("test-host", "dev", credStore, logger, nil)

	resp, err := handler.GetEnrollmentStatus(context.Background(), connect.NewRequest(&pm.GetEnrollmentStatusRequest{}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Enrolled)
	assert.Equal(t, "dev-abc", resp.Msg.DeviceId)
}

func TestEnrollServer_EndToEnd(t *testing.T) {
	mock := &mockRegisterService{
		registerFunc: func(_ context.Context, _ *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
			return connect.NewResponse(&pm.RegisterResponse{
				DeviceId:    &pm.DeviceId{Value: "dev-e2e"},
				CaCert:      []byte("-----BEGIN CERTIFICATE-----\nca\n-----END CERTIFICATE-----\n"),
				Certificate: []byte("-----BEGIN CERTIFICATE-----\ncert\n-----END CERTIFICATE-----\n"),
				GatewayUrl:  "https://gw.example.com",
			}), nil
		},
	}
	controlSrv := startMockControlServer(t, mock)

	credStore := credentials.NewStore(t.TempDir())
	logger := slog.Default()

	enrollCh := make(chan *credentials.Credentials, 1)
	enrollHandler := NewEnrollHandler("test-host", "dev", credStore, logger, func(creds *credentials.Credentials) {
		enrollCh <- creds
	})

	socketPath := filepath.Join(t.TempDir(), "enroll.sock")
	enrollServer := NewEnrollServer(enrollHandler, socketPath, logger)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go enrollServer.Start(ctx)

	// Wait for socket to be ready
	require.Eventually(t, func() bool {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, 2*time.Second, 10*time.Millisecond)

	// Create client over unix socket
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}
	client := pmv1connect.NewDeviceAuthServiceClient(httpClient, "http://localhost")

	// Check status: not enrolled
	status, err := client.GetEnrollmentStatus(context.Background(), connect.NewRequest(&pm.GetEnrollmentStatusRequest{}))
	require.NoError(t, err)
	assert.False(t, status.Msg.Enrolled)

	// Enroll
	resp, err := client.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{
		ServerUrl: controlSrv.URL,
		Token:     "test-token",
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Success)
	assert.Equal(t, "dev-e2e", resp.Msg.DeviceId)

	// Callback received
	select {
	case creds := <-enrollCh:
		assert.Equal(t, "dev-e2e", creds.DeviceID)
	case <-time.After(2 * time.Second):
		t.Fatal("enrollment callback not received")
	}

	// Check status again: enrolled
	status, err = client.GetEnrollmentStatus(context.Background(), connect.NewRequest(&pm.GetEnrollmentStatusRequest{}))
	require.NoError(t, err)
	assert.True(t, status.Msg.Enrolled)
	assert.Equal(t, "dev-e2e", status.Msg.DeviceId)
}
