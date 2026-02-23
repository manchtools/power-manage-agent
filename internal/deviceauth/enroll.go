package deviceauth

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"

	"github.com/manchtools/power-manage/agent/internal/credentials"
	sdk "github.com/manchtools/power-manage/sdk/go"
)

// EnrollHandler implements the Enroll and GetEnrollmentStatus RPCs
// on the local enrollment socket. All other DeviceAuthService RPCs
// return Unimplemented.
type EnrollHandler struct {
	pmv1connect.UnimplementedDeviceAuthServiceHandler

	hostname   string
	version    string
	credStore  *credentials.Store
	logger     *slog.Logger
	onEnrolled func(creds *credentials.Credentials)
}

// NewEnrollHandler creates a handler for enrollment RPCs.
// onEnrolled is called after successful enrollment with the new credentials.
func NewEnrollHandler(hostname, version string, credStore *credentials.Store, logger *slog.Logger, onEnrolled func(*credentials.Credentials)) *EnrollHandler {
	return &EnrollHandler{
		hostname:   hostname,
		version:    version,
		credStore:  credStore,
		logger:     logger,
		onEnrolled: onEnrolled,
	}
}

// Enroll registers the agent with the PM server using the provided token.
func (h *EnrollHandler) Enroll(ctx context.Context, req *connect.Request[pm.EnrollRequest]) (*connect.Response[pm.EnrollResponse], error) {
	h.logger.Info("enrollment request received", "server_url", req.Msg.ServerUrl)

	if req.Msg.ServerUrl == "" || req.Msg.Token == "" {
		return connect.NewResponse(&pm.EnrollResponse{
			Success: false,
			Error:   "server_url and token are required",
		}), nil
	}

	// Check if already enrolled
	if h.credStore.Exists() {
		creds, err := h.credStore.Load()
		if err == nil {
			return connect.NewResponse(&pm.EnrollResponse{
				Success:  true,
				DeviceId: creds.DeviceID,
				Error:    "agent is already enrolled",
			}), nil
		}
	}

	// Generate key pair and CSR locally — private key never leaves the agent
	h.logger.Debug("generating key pair and CSR")
	csrPEM, keyPEM, err := credentials.GenerateCSR(h.hostname)
	if err != nil {
		h.logger.Error("failed to generate CSR", "error", err)
		return connect.NewResponse(&pm.EnrollResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to generate CSR: %v", err),
		}), nil
	}

	// Build client options
	var clientOpts []sdk.ClientOption
	if req.Msg.SkipVerify {
		clientOpts = append(clientOpts, sdk.WithInsecureSkipVerify())
	}

	// Register via control server RPC
	result, err := sdk.RegisterAgent(ctx, req.Msg.ServerUrl, req.Msg.Token, h.hostname, h.version, csrPEM, clientOpts...)
	if err != nil {
		h.logger.Error("registration failed", "error", err)
		return connect.NewResponse(&pm.EnrollResponse{
			Success: false,
			Error:   fmt.Sprintf("registration failed: %v", err),
		}), nil
	}

	// Verify we received CA cert and signed certificate
	if len(result.CACert) == 0 || len(result.Certificate) == 0 {
		return connect.NewResponse(&pm.EnrollResponse{
			Success: false,
			Error:   "server did not provide mTLS certificates",
		}), nil
	}

	creds := &credentials.Credentials{
		DeviceID:    result.DeviceID,
		CACert:      result.CACert,
		Certificate: result.Certificate,
		PrivateKey:  keyPEM,
		GatewayAddr: result.GatewayURL,
		ControlAddr: req.Msg.ServerUrl,
	}

	// Save credentials
	if err := h.credStore.Save(creds); err != nil {
		h.logger.Error("failed to save credentials", "error", err)
		return connect.NewResponse(&pm.EnrollResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to save credentials: %v", err),
		}), nil
	}

	h.logger.Info("enrollment successful", "device_id", result.DeviceID, "gateway", result.GatewayURL)

	// Notify the main goroutine that enrollment is complete
	if h.onEnrolled != nil {
		h.onEnrolled(creds)
	}

	return connect.NewResponse(&pm.EnrollResponse{
		Success:  true,
		DeviceId: result.DeviceID,
	}), nil
}

// GetEnrollmentStatus checks whether the agent is currently enrolled.
func (h *EnrollHandler) GetEnrollmentStatus(_ context.Context, _ *connect.Request[pm.GetEnrollmentStatusRequest]) (*connect.Response[pm.GetEnrollmentStatusResponse], error) {
	if !h.credStore.Exists() {
		return connect.NewResponse(&pm.GetEnrollmentStatusResponse{
			Enrolled: false,
		}), nil
	}

	creds, err := h.credStore.Load()
	if err != nil {
		// Credentials exist but can't be loaded — treat as not enrolled
		return connect.NewResponse(&pm.GetEnrollmentStatusResponse{
			Enrolled: false,
		}), nil
	}

	return connect.NewResponse(&pm.GetEnrollmentStatusResponse{
		Enrolled: true,
		DeviceId: creds.DeviceID,
	}), nil
}

// getHostname returns the system hostname, used as fallback.
func getHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return h
}
