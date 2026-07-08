package luksd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	sdk "github.com/manchtools/power-manage-sdk"
	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysenc "github.com/manchtools/power-manage-sdk/sys/encryption"
	"github.com/manchtools/power-manage/agent/internal/store"
)

// Session is the agent's authenticated gateway connection, supplying the
// two operations the daemon performs against the server: validating (and
// consuming) the one-time LUKS token, and fetching the managed unlock key
// for the action. It is swapped in on connect and cleared on disconnect,
// so the daemon authorizes against the agent's OWN credentials, not the
// unprivileged socket peer.
type Session interface {
	ValidateLuksToken(ctx context.Context, token string) (*sdk.ValidateLuksTokenResult, error)
	GetLuksKey(ctx context.Context, actionID string) (string, error)
}

// StateStore is the subset of the agent store the daemon needs. Satisfied
// by *store.Store.
type StateStore interface {
	GetLuksState(actionID string) (*store.LuksState, error)
	GetLuksPassphraseHashes(actionID string) ([]string, error)
	SetLuksDeviceKeyType(actionID, keyType string) error
	AddLuksPassphraseHash(actionID, hash string) error
}

// Enroller performs the privileged cryptsetup slot operations with the
// daemon's OWN root credentials. Injectable so the authz/custody tests
// can assert what ran without touching a real device.
type Enroller interface {
	AddKeyToSlot(ctx context.Context, devicePath string, slot int, unlockKey, newKey string) error
	KillSlot(ctx context.Context, devicePath string, slot int, unlockKey string) error
	WipeTPM(ctx context.Context, devicePath, unlockKey string) error
}

// Daemon serves LUKS passphrase requests over a unix socket.
type Daemon struct {
	socketPath string
	logger     *slog.Logger
	store      StateStore
	enroller   Enroller

	mu      sync.RWMutex
	session Session // nil while the agent is not connected to the gateway

	listenerMu sync.Mutex
	listener   net.Listener
	wg         sync.WaitGroup

	now func() time.Time // clock seam; defaults to time.Now
}

// NewDaemon constructs a daemon. socketPath defaults to
// DefaultSocketPath when empty.
func NewDaemon(socketPath string, st StateStore, enroller Enroller, logger *slog.Logger) *Daemon {
	if socketPath == "" {
		socketPath = DefaultSocketPath
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Daemon{socketPath: socketPath, logger: logger, store: st, enroller: enroller, now: time.Now}
}

// SetSession installs the current connected gateway session. Called on
// connect.
func (d *Daemon) SetSession(s Session) {
	d.mu.Lock()
	d.session = s
	d.mu.Unlock()
}

// ClearSession removes the gateway session. Called on disconnect; while
// cleared, requests fail with CodeNotConnected.
func (d *Daemon) ClearSession() {
	d.mu.Lock()
	d.session = nil
	d.mu.Unlock()
}

func (d *Daemon) currentSession() Session {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.session
}

// Start creates the socket and serves until ctx is cancelled. The socket
// is created world-connectable (0666); the token is the authorization.
func (d *Daemon) Start(ctx context.Context) error {
	dir := filepath.Dir(d.socketPath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create socket directory %s: %w", dir, err)
	}
	// Remove a stale socket from a previous run.
	_ = os.Remove(d.socketPath)

	listener, err := net.Listen("unix", d.socketPath)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", d.socketPath, err)
	}
	if err := os.Chmod(d.socketPath, 0o666); err != nil {
		_ = listener.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	d.listenerMu.Lock()
	d.listener = listener
	d.listenerMu.Unlock()

	d.logger.Info("LUKS passphrase daemon listening", "socket", d.socketPath)

	go func() {
		<-ctx.Done()
		d.Shutdown()
	}()

	for {
		conn, err := listener.Accept()
		if err != nil {
			d.wg.Wait()
			// Only a closed listener is the graceful-shutdown path; any
			// other Accept error (EMFILE, ENOTSOCK, …) previously
			// masqueraded as a clean shutdown and the daemon died
			// silently (#173).
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			d.logger.Error("LUKS daemon accept failed; daemon stopping", "error", err)
			return fmt.Errorf("luksd accept: %w", err)
		}
		d.wg.Add(1)
		go func() {
			defer d.wg.Done()
			d.handleConn(ctx, conn)
		}()
	}
}

// Shutdown stops accepting and removes the socket.
func (d *Daemon) Shutdown() {
	d.listenerMu.Lock()
	l := d.listener
	d.listener = nil
	d.listenerMu.Unlock()
	if l != nil {
		_ = l.Close()
	}
	_ = os.Remove(d.socketPath)
}

// handleConn reads one request, processes it, writes one response.
func (d *Daemon) handleConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(d.now().Add(30 * time.Second))

	var req Request
	// Cap the request size (#173): a passphrase request is tiny; without
	// a limit a local user could stream an arbitrarily large payload
	// into the decoder for the full deadline window (local-only DoS
	// hardening on a root daemon).
	dec := json.NewDecoder(io.LimitReader(conn, maxRequestBytes))
	if err := dec.Decode(&req); err != nil {
		d.writeResponse(conn, Response{OK: false, Code: CodeInternal, Error: "malformed request"})
		return
	}
	resp := d.handleRequest(ctx, req)
	// Fresh write window (#173): enrollment (cryptsetup key-slot work)
	// runs before the response, so a single shared deadline could expire
	// exactly when the passphrase was already set and the client most
	// needs to hear about it.
	_ = conn.SetWriteDeadline(d.now().Add(10 * time.Second))
	d.writeResponse(conn, resp)
}

func (d *Daemon) writeResponse(conn net.Conn, resp Response) {
	if err := json.NewEncoder(conn).Encode(resp); err != nil {
		d.logger.Warn("failed to write LUKS daemon response", "error", err)
	}
}

// maxRequestBytes caps a single request read (#173). Requests carry a
// token + passphrase + small metadata; 64 KiB is generous.
const maxRequestBytes = 64 * 1024

// errResponse builds a rejection.
func errResponse(code, msg string) Response {
	return Response{OK: false, Code: code, Error: msg}
}

// handleRequest is the core authorization + enrollment logic, separated
// from the socket plumbing so it is unit-testable with injected deps.
func (d *Daemon) handleRequest(ctx context.Context, req Request) Response {
	if req.Token == "" {
		return errResponse(CodeMissingToken, "token is required")
	}

	// Authorize via the agent's own gateway connection — NOT the socket
	// peer. ValidateLuksToken consumes the single-use, device-bound,
	// short-TTL token server-side and returns the action's policy.
	sess := d.currentSession()
	if sess == nil {
		return errResponse(CodeNotConnected, "agent is not connected to the gateway; retry when online")
	}
	result, err := sess.ValidateLuksToken(ctx, req.Token)
	if err != nil {
		d.logger.Warn("LUKS daemon: token validation failed", "error", err)
		return errResponse(CodeInvalidToken, "token is invalid or has expired")
	}

	// Passphrase policy is enforced HERE (server-authoritative), never
	// trusted from the unprivileged client. WS6 #1.
	complexity := mapComplexity(result.Complexity)
	minLen := int(result.MinLength)
	if minLen < minPassphraseLength {
		minLen = minPassphraseLength
	}
	if vErr := sysenc.ValidatePassphrase(req.Passphrase, minLen, complexity); vErr != "" {
		return errResponse(CodePassphrasePolicy, vErr)
	}

	// Reuse check against the root-owned history (the unprivileged client
	// cannot read it, so this must be daemon-side).
	recent, err := d.store.GetLuksPassphraseHashes(result.ActionID)
	if err != nil {
		d.logger.Warn("LUKS daemon: failed to read passphrase history", "action_id", result.ActionID, "error", err)
		return errResponse(CodeInternal, "failed to check passphrase history")
	}
	if sysenc.IsRecentlyUsed(req.Passphrase, recent) {
		return errResponse(CodePassphraseReuse, "this passphrase was used recently; choose a different one")
	}

	// Fetch the managed unlock key over the agent's stream.
	managedKey, err := sess.GetLuksKey(ctx, result.ActionID)
	if err != nil {
		d.logger.Warn("LUKS daemon: failed to fetch managed key", "action_id", result.ActionID, "error", err)
		return errResponse(CodeKeyUnavailable, "failed to fetch the managed key")
	}

	// Read current device-key state to revoke an existing key before
	// enrolling the user passphrase into slot 7. Fail closed on a read
	// error (mirrors executor.setupLuks WS6 #13).
	localState, err := d.store.GetLuksState(result.ActionID)
	if err != nil {
		d.logger.Error("LUKS daemon: failed to read local state", "action_id", result.ActionID, "error", err)
		return errResponse(CodeInternal, "failed to read local LUKS state")
	}
	// The revoke MUST precede the enroll (the new passphrase re-uses the
	// same slot), and the managed key stays valid throughout — so a
	// failure between the two never locks the volume out, it only leaves
	// the user-passphrase slot empty until a retry.
	revoked := false
	if localState != nil && localState.DeviceKeyType != "none" && localState.DeviceKeyType != "" {
		switch localState.DeviceKeyType {
		case "tpm":
			if err := d.enroller.WipeTPM(ctx, result.DevicePath, managedKey); err != nil {
				d.logger.Error("luksd: remove existing TPM key failed", "device", result.DevicePath, "error", err)
				return errResponse(CodeInternal, "failed to remove existing TPM key")
			}
			revoked = true
		case "user_passphrase":
			if err := d.enroller.KillSlot(ctx, result.DevicePath, userPassphraseSlot, managedKey); err != nil {
				d.logger.Error("luksd: remove existing passphrase failed", "device", result.DevicePath, "error", err)
				return errResponse(CodeInternal, "failed to remove existing passphrase")
			}
			revoked = true
		}
	}

	if err := d.enroller.AddKeyToSlot(ctx, result.DevicePath, userPassphraseSlot, managedKey, req.Passphrase); err != nil {
		// Detail goes to the root-readable journal, not to the local
		// unprivileged client (#173): enroller/cryptsetup internals can
		// name slots, devices, and failure modes an attacker probing the
		// socket has no business learning.
		d.logger.Error("luksd: set passphrase failed", "device", result.DevicePath, "error", err)
		if revoked {
			// The old key is gone but the new one didn't land (#174):
			// without this the store would keep claiming a device key
			// exists, diverging state from the volume. Best-effort — the
			// managed key still unlocks either way.
			if serr := d.store.SetLuksDeviceKeyType(result.ActionID, "none"); serr != nil {
				d.logger.Error("luksd: failed to record emptied key slot after failed enroll", "action_id", result.ActionID, "error", serr)
			}
		}
		return errResponse(CodeInternal, "failed to set passphrase")
	}

	// Persist state + history. Surface persistence errors: a missed
	// device-key-type leaves reconcile diverged; a missed history append
	// defeats the reuse check.
	if err := d.store.SetLuksDeviceKeyType(result.ActionID, "user_passphrase"); err != nil {
		d.logger.Error("LUKS daemon: failed to persist device key type", "action_id", result.ActionID, "error", err)
		return errResponse(CodeInternal, "passphrase was set but local state update failed; rerun to recover")
	}
	if err := d.store.AddLuksPassphraseHash(result.ActionID, sysenc.HashPassphrase(req.Passphrase)); err != nil {
		d.logger.Error("LUKS daemon: failed to persist passphrase history", "action_id", result.ActionID, "error", err)
		return errResponse(CodeInternal, "passphrase was set but history update failed")
	}

	return Response{OK: true, Code: CodeOK}
}

// mapComplexity converts the proto complexity enum to the sysenc one.
func mapComplexity(c pm.LpsPasswordComplexity) sysenc.Complexity {
	switch c {
	case pm.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_ALPHANUMERIC:
		return sysenc.ComplexityAlphanumeric
	case pm.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_COMPLEX:
		return sysenc.ComplexityComplex
	default:
		return sysenc.ComplexityNone
	}
}
