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
)

func TestSocketServer_StartsAndAcceptsConnections(t *testing.T) {
	// Create mock control server
	mock := &mockControlService{
		authenticateFunc: func(_ context.Context, _ *connect.Request[pm.AuthenticateDeviceUserRequest]) (*connect.Response[pm.AuthenticateDeviceUserResponse], error) {
			return connect.NewResponse(&pm.AuthenticateDeviceUserResponse{
				Success: true,
				User:    &pm.DeviceUserInfo{Username: "testuser", Uid: 60001},
			}), nil
		},
	}

	mux := http.NewServeMux()
	path, handler := pmv1connect.NewControlServiceHandler(mock)
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	// Create handler and socket server
	logger := slog.Default()
	h := NewHandler("test-device", srv.URL, srv.Client(), logger)
	socketPath := filepath.Join(t.TempDir(), "auth.sock")
	s := NewServer(h, socketPath, logger)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	// Start server in background
	serverDone := make(chan error, 1)
	go func() {
		serverDone <- s.Start(ctx)
	}()

	// Wait for socket to be ready
	require.Eventually(t, func() bool {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, 2*time.Second, 10*time.Millisecond)

	// Create a Connect-RPC client over the unix socket
	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}
	client := pmv1connect.NewDeviceAuthServiceClient(httpClient, "http://localhost")

	// Call Authenticate via the socket
	resp, err := client.Authenticate(context.Background(), connect.NewRequest(&pm.DeviceAuthRequest{
		Username: "user@test.com",
		Password: "pass",
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Success)
	assert.Equal(t, "testuser", resp.Msg.User.Username)

	// Shutdown
	cancel()
	select {
	case err := <-serverDone:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not shut down in time")
	}
}

func TestSocketServer_ConcurrentRequests(t *testing.T) {
	mock := &mockControlService{
		authenticateFunc: func(_ context.Context, req *connect.Request[pm.AuthenticateDeviceUserRequest]) (*connect.Response[pm.AuthenticateDeviceUserResponse], error) {
			return connect.NewResponse(&pm.AuthenticateDeviceUserResponse{
				Success: true,
				User:    &pm.DeviceUserInfo{Username: req.Msg.Username},
			}), nil
		},
	}

	mux := http.NewServeMux()
	path, handler := pmv1connect.NewControlServiceHandler(mock)
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	logger := slog.Default()
	h := NewHandler("test-device", srv.URL, srv.Client(), logger)
	socketPath := filepath.Join(t.TempDir(), "auth.sock")
	s := NewServer(h, socketPath, logger)

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	go s.Start(ctx)

	require.Eventually(t, func() bool {
		conn, err := net.Dial("unix", socketPath)
		if err != nil {
			return false
		}
		conn.Close()
		return true
	}, 2*time.Second, 10*time.Millisecond)

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socketPath)
			},
		},
	}
	client := pmv1connect.NewDeviceAuthServiceClient(httpClient, "http://localhost")

	// Send 10 concurrent requests
	const n = 10
	errs := make(chan error, n)
	for i := 0; i < n; i++ {
		go func() {
			_, err := client.Authenticate(context.Background(), connect.NewRequest(&pm.DeviceAuthRequest{
				Username: "user@test.com",
				Password: "pass",
			}))
			errs <- err
		}()
	}

	for i := 0; i < n; i++ {
		err := <-errs
		assert.NoError(t, err)
	}
}
