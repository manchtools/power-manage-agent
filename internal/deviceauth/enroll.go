package deviceauth

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"connectrpc.com/connect"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/gen/go/pm/v1/pmv1connect"

	"github.com/manchtools/power-manage/agent/internal/credentials"
	sdk "github.com/manchtools/power-manage/sdk/go"
	pmcrypto "github.com/manchtools/power-manage/sdk/go/crypto"
)

// credentialStore is the slice of *credentials.Store the enrollment
// handler depends on. Declared as an interface so the costly Load()
// (64 MiB Argon2id) can be counted/faked in tests.
type credentialStore interface {
	Exists() bool
	Load() (*credentials.Credentials, error)
	Save(*credentials.Credentials) error
}

// EnrollHandler implements the Enroll and GetEnrollmentStatus RPCs
// on the local enrollment socket. All other DeviceAuthService RPCs
// return Unimplemented.
type EnrollHandler struct {
	pmv1connect.UnimplementedDeviceAuthServiceHandler

	hostname   string
	version    string
	credStore  credentialStore
	logger     *slog.Logger
	onEnrolled func(creds *credentials.Credentials)

	rateMu       sync.Mutex
	lastAttempts []time.Time

	// enrollMu serializes the whole Enroll body so concurrent requests
	// (the rate limiter allows up to 5 in flight) can't each pass the
	// Exists() check, register a duplicate device, race Save (last
	// write wins, key/cert may mismatch the saved creds), and fire
	// onEnrolled more than the single-buffer enrollCh can absorb.
	enrollMu sync.Mutex

	// statusMu guards the cached device id and serializes the one
	// expensive Load() so a flood of GetEnrollmentStatus calls on the
	// 0666 socket can't each trigger a 64 MiB Argon2id derivation.
	statusMu       sync.Mutex
	cachedDeviceID string
	statusCached   bool

	now func() time.Time // clock seam; defaults to time.Now, overridden in tests
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
		now:        time.Now,
	}
}

// Enroll registers the agent with the PM server using the provided token.
func (h *EnrollHandler) Enroll(ctx context.Context, req *connect.Request[pm.EnrollRequest]) (*connect.Response[pm.EnrollResponse], error) {
	// Rate limiting: max 5 attempts per minute
	h.rateMu.Lock()
	now := h.now()
	cutoff := now.Add(-1 * time.Minute)
	var recent []time.Time
	for _, t := range h.lastAttempts {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}
	recent = append(recent, now)
	h.lastAttempts = recent
	count := len(recent)
	h.rateMu.Unlock()

	if count > 5 {
		h.logger.Warn("enrollment rate limit exceeded")
		return connect.NewResponse(&pm.EnrollResponse{
			Success: false,
			Error:   "rate limit exceeded, try again later",
		}), nil
	}

	// Serialize the rest of enrollment. Up to 5 requests can pass the
	// rate limiter concurrently; without this they would each pass the
	// Exists() check below, register a duplicate device, and race Save.
	h.enrollMu.Lock()
	defer h.enrollMu.Unlock()

	h.logger.Info("enrollment request received", "server_url", req.Msg.ServerUrl)

	if req.Msg.ServerUrl == "" || req.Msg.Token == "" {
		return connect.NewResponse(&pm.EnrollResponse{
			Success: false,
			Error:   "server_url and token are required",
		}), nil
	}

	// (The SkipVerify rejection check that lived here was removed
	// once the SDK dropped the proto field — see SDK PR. The wire
	// format now has no path to request a TLS bypass; outdated
	// clients sending the legacy field number are silently
	// dropped by the proto3 unknown-field handler.)

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
	csrPEM, keyPEM, err := pmcrypto.GenerateCSR(h.hostname)
	if err != nil {
		h.logger.Error("failed to generate CSR", "error", err)
		return connect.NewResponse(&pm.EnrollResponse{
			Success: false,
			Error:   fmt.Sprintf("failed to generate CSR: %v", err),
		}), nil
	}

	// Register via control server RPC.
	result, err := sdk.RegisterAgent(ctx, req.Msg.ServerUrl, req.Msg.Token, h.hostname, h.version, csrPEM)
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

	// Prime the status cache so subsequent GetEnrollmentStatus calls
	// don't re-derive the Argon2id key just to learn the device id.
	h.statusMu.Lock()
	h.cachedDeviceID = result.DeviceID
	h.statusCached = true
	h.statusMu.Unlock()

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
//
// The enrollment socket is mode 0666, so any local user can call this.
// credStore.Load() runs a 64 MiB Argon2id derivation, so a naive
// implementation that loads on every call is a trivial local CPU/memory
// DoS against the root agent process. We cache the device id after the
// first successful load and serialize that single load behind statusMu
// (so a concurrent flood collapses to one derivation, not N).
func (h *EnrollHandler) GetEnrollmentStatus(_ context.Context, _ *connect.Request[pm.GetEnrollmentStatusRequest]) (*connect.Response[pm.GetEnrollmentStatusResponse], error) {
	h.statusMu.Lock()
	defer h.statusMu.Unlock()

	if h.statusCached {
		return connect.NewResponse(&pm.GetEnrollmentStatusResponse{
			Enrolled: true,
			DeviceId: h.cachedDeviceID,
		}), nil
	}

	// Cheap stat; never triggers Argon2id. Not cached so a later
	// enrollment is still observed.
	if !h.credStore.Exists() {
		return connect.NewResponse(&pm.GetEnrollmentStatusResponse{
			Enrolled: false,
		}), nil
	}

	creds, err := h.credStore.Load()
	if err != nil {
		// Credentials exist but can't be loaded — treat as not enrolled.
		// Don't cache the failure: a transient decrypt error shouldn't
		// pin "not enrolled" for the process lifetime.
		return connect.NewResponse(&pm.GetEnrollmentStatusResponse{
			Enrolled: false,
		}), nil
	}

	h.cachedDeviceID = creds.DeviceID
	h.statusCached = true
	return connect.NewResponse(&pm.GetEnrollmentStatusResponse{
		Enrolled: true,
		DeviceId: creds.DeviceID,
	}), nil
}
