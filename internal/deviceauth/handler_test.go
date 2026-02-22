package deviceauth

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
)

// mockControlService implements the device auth subset of ControlServiceHandler.
type mockControlService struct {
	pmv1connect.UnimplementedControlServiceHandler

	authenticateFunc     func(context.Context, *connect.Request[pm.AuthenticateDeviceUserRequest]) (*connect.Response[pm.AuthenticateDeviceUserResponse], error)
	listDeviceUsersFunc  func(context.Context, *connect.Request[pm.ListDeviceUsersRequest]) (*connect.Response[pm.ListDeviceUsersResponse], error)
	getDeviceLoginURLFunc func(context.Context, *connect.Request[pm.GetDeviceLoginURLRequest]) (*connect.Response[pm.GetDeviceLoginURLResponse], error)
	deviceLoginCallbackFunc func(context.Context, *connect.Request[pm.DeviceLoginCallbackRequest]) (*connect.Response[pm.DeviceLoginCallbackResponse], error)
}

func (m *mockControlService) AuthenticateDeviceUser(ctx context.Context, req *connect.Request[pm.AuthenticateDeviceUserRequest]) (*connect.Response[pm.AuthenticateDeviceUserResponse], error) {
	if m.authenticateFunc != nil {
		return m.authenticateFunc(ctx, req)
	}
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (m *mockControlService) ListDeviceUsers(ctx context.Context, req *connect.Request[pm.ListDeviceUsersRequest]) (*connect.Response[pm.ListDeviceUsersResponse], error) {
	if m.listDeviceUsersFunc != nil {
		return m.listDeviceUsersFunc(ctx, req)
	}
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (m *mockControlService) GetDeviceLoginURL(ctx context.Context, req *connect.Request[pm.GetDeviceLoginURLRequest]) (*connect.Response[pm.GetDeviceLoginURLResponse], error) {
	if m.getDeviceLoginURLFunc != nil {
		return m.getDeviceLoginURLFunc(ctx, req)
	}
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func (m *mockControlService) DeviceLoginCallback(ctx context.Context, req *connect.Request[pm.DeviceLoginCallbackRequest]) (*connect.Response[pm.DeviceLoginCallbackResponse], error) {
	if m.deviceLoginCallbackFunc != nil {
		return m.deviceLoginCallbackFunc(ctx, req)
	}
	return nil, connect.NewError(connect.CodeUnimplemented, nil)
}

func startMockServer(t *testing.T, mock *mockControlService) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	path, handler := pmv1connect.NewControlServiceHandler(mock)
	mux.Handle(path, handler)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func newTestHandler(t *testing.T, mock *mockControlService) (*Handler, *httptest.Server) {
	t.Helper()
	srv := startMockServer(t, mock)
	logger := slog.Default()
	h := NewHandler("test-device-id", srv.URL, srv.Client(), logger)
	return h, srv
}

func TestAuthenticate_ForwardsToServer(t *testing.T) {
	var receivedReq *pm.AuthenticateDeviceUserRequest

	mock := &mockControlService{
		authenticateFunc: func(_ context.Context, req *connect.Request[pm.AuthenticateDeviceUserRequest]) (*connect.Response[pm.AuthenticateDeviceUserResponse], error) {
			receivedReq = req.Msg
			return connect.NewResponse(&pm.AuthenticateDeviceUserResponse{
				Success:           true,
				SessionToken:      "session-tok",
				SessionTtlSeconds: 28800,
				User: &pm.DeviceUserInfo{
					Username: "testuser",
					Uid:      60001,
					Gid:      60001,
					HomeDir:  "/home/testuser",
					Shell:    "/bin/bash",
				},
			}), nil
		},
	}

	h, _ := newTestHandler(t, mock)

	resp, err := h.Authenticate(context.Background(), connect.NewRequest(&pm.DeviceAuthRequest{
		Username: "testuser@example.com",
		Password: "correct-pass",
		TotpCode: "123456",
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Success)
	assert.Equal(t, "session-tok", resp.Msg.SessionToken)
	assert.Equal(t, int64(28800), resp.Msg.SessionTtlSeconds)
	assert.Equal(t, "testuser", resp.Msg.User.Username)

	// Verify the handler injected the device ID
	require.NotNil(t, receivedReq)
	assert.Equal(t, "test-device-id", receivedReq.DeviceId)
	assert.Equal(t, "testuser@example.com", receivedReq.Username)
	assert.Equal(t, "correct-pass", receivedReq.Password)
	assert.Equal(t, "123456", receivedReq.TotpCode)
}

func TestAuthenticate_ServerReturnsFailure(t *testing.T) {
	mock := &mockControlService{
		authenticateFunc: func(_ context.Context, _ *connect.Request[pm.AuthenticateDeviceUserRequest]) (*connect.Response[pm.AuthenticateDeviceUserResponse], error) {
			return connect.NewResponse(&pm.AuthenticateDeviceUserResponse{
				Success: false,
				Error:   "invalid credentials",
			}), nil
		},
	}

	h, _ := newTestHandler(t, mock)

	resp, err := h.Authenticate(context.Background(), connect.NewRequest(&pm.DeviceAuthRequest{
		Username: "user@test.com",
		Password: "wrong",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.Equal(t, "invalid credentials", resp.Msg.Error)
}

func TestAuthenticate_TOTPRequired(t *testing.T) {
	mock := &mockControlService{
		authenticateFunc: func(_ context.Context, _ *connect.Request[pm.AuthenticateDeviceUserRequest]) (*connect.Response[pm.AuthenticateDeviceUserResponse], error) {
			return connect.NewResponse(&pm.AuthenticateDeviceUserResponse{
				Success:      false,
				TotpRequired: true,
			}), nil
		},
	}

	h, _ := newTestHandler(t, mock)

	resp, err := h.Authenticate(context.Background(), connect.NewRequest(&pm.DeviceAuthRequest{
		Username: "user@test.com",
		Password: "pass",
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.True(t, resp.Msg.TotpRequired)
}

func TestAuthenticate_PasswordProbe(t *testing.T) {
	mock := &mockControlService{
		authenticateFunc: func(_ context.Context, _ *connect.Request[pm.AuthenticateDeviceUserRequest]) (*connect.Response[pm.AuthenticateDeviceUserResponse], error) {
			return connect.NewResponse(&pm.AuthenticateDeviceUserResponse{
				Success:          false,
				PasswordRequired: true,
			}), nil
		},
	}

	h, _ := newTestHandler(t, mock)

	resp, err := h.Authenticate(context.Background(), connect.NewRequest(&pm.DeviceAuthRequest{
		Username: "user@test.com",
		Password: "", // empty password = probe
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.True(t, resp.Msg.PasswordRequired)
}

func TestListUsers_CachesResult(t *testing.T) {
	callCount := 0
	mock := &mockControlService{
		listDeviceUsersFunc: func(_ context.Context, _ *connect.Request[pm.ListDeviceUsersRequest]) (*connect.Response[pm.ListDeviceUsersResponse], error) {
			callCount++
			return connect.NewResponse(&pm.ListDeviceUsersResponse{
				Users: []*pm.DeviceUserInfo{
					{Username: "alice", Uid: 60001},
					{Username: "bob", Uid: 60002},
				},
			}), nil
		},
	}

	h, _ := newTestHandler(t, mock)

	// First call fetches from server
	resp, err := h.ListUsers(context.Background(), connect.NewRequest(&pm.ListDeviceUsersLocalRequest{}))
	require.NoError(t, err)
	assert.Len(t, resp.Msg.Users, 2)
	assert.Equal(t, 1, callCount)

	// Second call uses cache
	resp, err = h.ListUsers(context.Background(), connect.NewRequest(&pm.ListDeviceUsersLocalRequest{}))
	require.NoError(t, err)
	assert.Len(t, resp.Msg.Users, 2)
	assert.Equal(t, 1, callCount) // Still 1 — cached
}

func TestListUsers_CacheRefresh(t *testing.T) {
	callCount := 0
	mock := &mockControlService{
		listDeviceUsersFunc: func(_ context.Context, _ *connect.Request[pm.ListDeviceUsersRequest]) (*connect.Response[pm.ListDeviceUsersResponse], error) {
			callCount++
			return connect.NewResponse(&pm.ListDeviceUsersResponse{
				Users: []*pm.DeviceUserInfo{
					{Username: "alice", Uid: 60001},
				},
			}), nil
		},
	}

	h, _ := newTestHandler(t, mock)
	h.cacheTTL = 10 * time.Millisecond // Very short TTL

	// First call
	_, err := h.ListUsers(context.Background(), connect.NewRequest(&pm.ListDeviceUsersLocalRequest{}))
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Wait for cache to expire
	time.Sleep(20 * time.Millisecond)

	// Second call should refresh
	_, err = h.ListUsers(context.Background(), connect.NewRequest(&pm.ListDeviceUsersLocalRequest{}))
	require.NoError(t, err)
	assert.Equal(t, 2, callCount)
}

func TestGetUser_ByUsername(t *testing.T) {
	mock := &mockControlService{
		listDeviceUsersFunc: func(_ context.Context, _ *connect.Request[pm.ListDeviceUsersRequest]) (*connect.Response[pm.ListDeviceUsersResponse], error) {
			return connect.NewResponse(&pm.ListDeviceUsersResponse{
				Users: []*pm.DeviceUserInfo{
					{Username: "alice", Uid: 60001, HomeDir: "/home/alice"},
					{Username: "bob", Uid: 60002, HomeDir: "/home/bob"},
				},
			}), nil
		},
	}

	h, _ := newTestHandler(t, mock)

	resp, err := h.GetUser(context.Background(), connect.NewRequest(&pm.GetDeviceUserRequest{
		Username: "bob",
	}))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg.User)
	assert.Equal(t, "bob", resp.Msg.User.Username)
	assert.Equal(t, uint32(60002), resp.Msg.User.Uid)
}

func TestGetUser_ByUID(t *testing.T) {
	mock := &mockControlService{
		listDeviceUsersFunc: func(_ context.Context, _ *connect.Request[pm.ListDeviceUsersRequest]) (*connect.Response[pm.ListDeviceUsersResponse], error) {
			return connect.NewResponse(&pm.ListDeviceUsersResponse{
				Users: []*pm.DeviceUserInfo{
					{Username: "alice", Uid: 60001},
				},
			}), nil
		},
	}

	h, _ := newTestHandler(t, mock)

	resp, err := h.GetUser(context.Background(), connect.NewRequest(&pm.GetDeviceUserRequest{
		Uid: 60001,
	}))
	require.NoError(t, err)
	require.NotNil(t, resp.Msg.User)
	assert.Equal(t, "alice", resp.Msg.User.Username)
}

func TestGetUser_NotFound(t *testing.T) {
	mock := &mockControlService{
		listDeviceUsersFunc: func(_ context.Context, _ *connect.Request[pm.ListDeviceUsersRequest]) (*connect.Response[pm.ListDeviceUsersResponse], error) {
			return connect.NewResponse(&pm.ListDeviceUsersResponse{
				Users: []*pm.DeviceUserInfo{
					{Username: "alice", Uid: 60001},
				},
			}), nil
		},
	}

	h, _ := newTestHandler(t, mock)

	resp, err := h.GetUser(context.Background(), connect.NewRequest(&pm.GetDeviceUserRequest{
		Username: "nonexistent",
	}))
	require.NoError(t, err)
	assert.Nil(t, resp.Msg.User)
}

func TestGetLoginURL_ProxiesToServer(t *testing.T) {
	var receivedReq *pm.GetDeviceLoginURLRequest

	mock := &mockControlService{
		getDeviceLoginURLFunc: func(_ context.Context, req *connect.Request[pm.GetDeviceLoginURLRequest]) (*connect.Response[pm.GetDeviceLoginURLResponse], error) {
			receivedReq = req.Msg
			return connect.NewResponse(&pm.GetDeviceLoginURLResponse{
				LoginUrl: "https://pm.example.com/app/device-login?state=abc&device_id=test-device-id&callback_port=12345",
			}), nil
		},
	}

	h, _ := newTestHandler(t, mock)

	resp, err := h.GetLoginURL(context.Background(), connect.NewRequest(&pm.GetLoginURLRequest{
		CallbackPort: 12345,
		Username:     "user@example.com",
	}))
	require.NoError(t, err)
	assert.Contains(t, resp.Msg.LoginUrl, "device-login")

	// Verify the handler injected the device ID
	require.NotNil(t, receivedReq)
	assert.Equal(t, "test-device-id", receivedReq.DeviceId)
	assert.Equal(t, int32(12345), receivedReq.CallbackPort)
	assert.Equal(t, "user@example.com", receivedReq.Username)
}

func TestAuthenticate_InvalidatesCacheOnSuccess(t *testing.T) {
	callCount := 0
	mock := &mockControlService{
		authenticateFunc: func(_ context.Context, _ *connect.Request[pm.AuthenticateDeviceUserRequest]) (*connect.Response[pm.AuthenticateDeviceUserResponse], error) {
			return connect.NewResponse(&pm.AuthenticateDeviceUserResponse{
				Success: true,
				User:    &pm.DeviceUserInfo{Username: "testuser"},
			}), nil
		},
		listDeviceUsersFunc: func(_ context.Context, _ *connect.Request[pm.ListDeviceUsersRequest]) (*connect.Response[pm.ListDeviceUsersResponse], error) {
			callCount++
			return connect.NewResponse(&pm.ListDeviceUsersResponse{
				Users: []*pm.DeviceUserInfo{{Username: "testuser"}},
			}), nil
		},
	}

	h, _ := newTestHandler(t, mock)

	// Populate cache
	_, err := h.ListUsers(context.Background(), connect.NewRequest(&pm.ListDeviceUsersLocalRequest{}))
	require.NoError(t, err)
	assert.Equal(t, 1, callCount)

	// Successful auth invalidates cache
	_, err = h.Authenticate(context.Background(), connect.NewRequest(&pm.DeviceAuthRequest{
		Username: "testuser@example.com",
		Password: "pass",
	}))
	require.NoError(t, err)

	// Next ListUsers should refetch
	_, err = h.ListUsers(context.Background(), connect.NewRequest(&pm.ListDeviceUsersLocalRequest{}))
	require.NoError(t, err)
	assert.Equal(t, 2, callCount)
}
