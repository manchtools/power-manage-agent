// Package deviceauth implements the local DeviceAuthService for PAM/NSS.
// It exposes a Connect-RPC server on a unix socket that proxies
// authentication requests to the PM Control Server.
package deviceauth

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"time"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"
)

// Handler implements DeviceAuthServiceHandler by proxying requests
// to the PM Control Server.
type Handler struct {
	pmv1connect.UnimplementedDeviceAuthServiceHandler

	deviceID     string
	controlAddr  string
	controlHTTP  connect.HTTPClient
	logger       *slog.Logger

	mu          sync.RWMutex
	userCache   []*pm.DeviceUserInfo
	cacheTime   time.Time
	cacheTTL    time.Duration
}

// NewHandler creates a new device auth handler.
func NewHandler(deviceID, controlAddr string, httpClient connect.HTTPClient, logger *slog.Logger) *Handler {
	return &Handler{
		deviceID:    deviceID,
		controlAddr: controlAddr,
		controlHTTP: httpClient,
		logger:      logger,
		cacheTTL:    5 * time.Minute,
	}
}

func (h *Handler) controlClient() pmv1connect.ControlServiceClient {
	return pmv1connect.NewControlServiceClient(h.controlHTTP, h.controlAddr)
}

// Authenticate proxies a PAM authentication request to the Control Server.
func (h *Handler) Authenticate(ctx context.Context, req *connect.Request[pm.DeviceAuthRequest]) (*connect.Response[pm.DeviceAuthResponse], error) {
	h.logger.Info("device auth request", "username", req.Msg.Username)

	resp, err := h.controlClient().AuthenticateDeviceUser(ctx, connect.NewRequest(&pm.AuthenticateDeviceUserRequest{
		DeviceId: h.deviceID,
		Username: req.Msg.Username,
		Password: req.Msg.Password,
		TotpCode: req.Msg.TotpCode,
	}))
	if err != nil {
		h.logger.Error("control server auth failed", "error", err)
		return nil, err
	}

	result := &pm.DeviceAuthResponse{
		Success:          resp.Msg.Success,
		PasswordRequired: resp.Msg.PasswordRequired,
		OidcRequired:     resp.Msg.OidcRequired,
		TotpRequired:     resp.Msg.TotpRequired,
		Error:            resp.Msg.Error,
	}

	if resp.Msg.User != nil {
		result.User = resp.Msg.User
	}
	if resp.Msg.SessionToken != "" {
		result.SessionToken = resp.Msg.SessionToken
		result.SessionTtlSeconds = resp.Msg.SessionTtlSeconds
	}

	if resp.Msg.Success {
		h.logger.Info("device auth succeeded", "username", req.Msg.Username)
		// Invalidate user cache on successful auth (user list may have changed due to auto-assign)
		h.mu.Lock()
		h.cacheTime = time.Time{}
		h.mu.Unlock()
	}

	return connect.NewResponse(result), nil
}

// ValidateSession validates a cached session token for sudo re-auth.
func (h *Handler) ValidateSession(ctx context.Context, req *connect.Request[pm.ValidateSessionRequest]) (*connect.Response[pm.ValidateSessionResponse], error) {
	// TODO: Implement local session token validation (post-PoC)
	return nil, connect.NewError(connect.CodeUnimplemented, errors.New("session validation not yet implemented"))
}

// GetUser looks up a single user by username or UID for NSS.
func (h *Handler) GetUser(ctx context.Context, req *connect.Request[pm.GetDeviceUserRequest]) (*connect.Response[pm.GetDeviceUserResponse], error) {
	users, err := h.getCachedUsers(ctx)
	if err != nil {
		return nil, err
	}

	for _, u := range users {
		if (req.Msg.Username != "" && u.Username == req.Msg.Username) ||
			(req.Msg.Uid != 0 && u.Uid == req.Msg.Uid) {
			return connect.NewResponse(&pm.GetDeviceUserResponse{
				User: u,
			}), nil
		}
	}

	return connect.NewResponse(&pm.GetDeviceUserResponse{}), nil
}

// ListUsers returns all authorized users for NSS enumeration.
func (h *Handler) ListUsers(ctx context.Context, req *connect.Request[pm.ListDeviceUsersLocalRequest]) (*connect.Response[pm.ListDeviceUsersLocalResponse], error) {
	users, err := h.getCachedUsers(ctx)
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pm.ListDeviceUsersLocalResponse{Users: users}), nil
}

// GetLoginURL returns the browser URL for OIDC-only device login.
func (h *Handler) GetLoginURL(ctx context.Context, req *connect.Request[pm.GetLoginURLRequest]) (*connect.Response[pm.GetLoginURLResponse], error) {
	resp, err := h.controlClient().GetDeviceLoginURL(ctx, connect.NewRequest(&pm.GetDeviceLoginURLRequest{
		DeviceId:     h.deviceID,
		CallbackPort: req.Msg.CallbackPort,
		Username:     req.Msg.Username,
	}))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pm.GetLoginURLResponse{
		LoginUrl: resp.Msg.LoginUrl,
	}), nil
}

// CompleteLogin completes a browser-based login.
func (h *Handler) CompleteLogin(ctx context.Context, req *connect.Request[pm.CompleteLoginRequest]) (*connect.Response[pm.CompleteLoginResponse], error) {
	resp, err := h.controlClient().DeviceLoginCallback(ctx, connect.NewRequest(&pm.DeviceLoginCallbackRequest{
		CallbackToken: req.Msg.CallbackToken,
		DeviceId:      h.deviceID,
	}))
	if err != nil {
		return nil, err
	}
	return connect.NewResponse(&pm.CompleteLoginResponse{
		Success:          resp.Msg.Success,
		Error:            resp.Msg.Error,
		User:             resp.Msg.User,
		SessionToken:     resp.Msg.SessionToken,
		SessionTtlSeconds: resp.Msg.SessionTtlSeconds,
	}), nil
}

// getCachedUsers returns the user list, refreshing the cache if stale.
func (h *Handler) getCachedUsers(ctx context.Context) ([]*pm.DeviceUserInfo, error) {
	h.mu.RLock()
	if time.Since(h.cacheTime) < h.cacheTTL && h.userCache != nil {
		users := h.userCache
		h.mu.RUnlock()
		return users, nil
	}
	h.mu.RUnlock()

	// Refresh from server
	resp, err := h.controlClient().ListDeviceUsers(ctx, connect.NewRequest(&pm.ListDeviceUsersRequest{
		DeviceId: h.deviceID,
	}))
	if err != nil {
		// If server unreachable, return stale cache if available
		h.mu.RLock()
		if h.userCache != nil {
			users := h.userCache
			h.mu.RUnlock()
			h.logger.Warn("using stale user cache, server unreachable", "error", err)
			return users, nil
		}
		h.mu.RUnlock()
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("server unreachable and no cached users"))
	}

	h.mu.Lock()
	h.userCache = resp.Msg.Users
	h.cacheTime = time.Now()
	h.mu.Unlock()

	return resp.Msg.Users, nil
}
