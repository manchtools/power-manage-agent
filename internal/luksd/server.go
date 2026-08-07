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
	pm "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	sysenc "github.com/manchtools/power-manage-sdk/sys/encryption"
	"github.com/manchtools/power-manage/agent/internal/store"
)

// Session is the agent's authenticated control connection, supplying the
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
	session Session // nil while the agent is not connected to the control

	listenerMu sync.Mutex
	listener   net.Listener
	wg         sync.WaitGroup

	// inFlight bounds concurrent handlers (F21). A token slot is taken before
	// the goroutine starts and released when it ends.
	inFlight chan struct{}

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
	return &Daemon{
		socketPath: socketPath,
		logger:     logger,
		store:      st,
		enroller:   enroller,
		inFlight:   make(chan struct{}, maxConcurrentRequests),
		now:        time.Now,
	}
}

// SetSession installs the current connected control session. Called on
// connect.
func (d *Daemon) SetSession(s Session) {
	d.mu.Lock()
	d.session = s
	d.mu.Unlock()
}

// ClearSession removes the control session. Called on disconnect; while
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

const (
	// maxConcurrentRequests bounds in-flight handlers (F21). Setting a LUKS
	// passphrase is one person at a keyboard; without a bound, a local caller
	// could hold open as many pre-authorization handlers as the root agent has
	// descriptors. Excess connections are refused immediately rather than
	// queued, so the refusal is visible instead of looking like a hang.
	maxConcurrentRequests = 4

	// requestTimeout bounds one request end to end (F21). The handler used to
	// inherit the process-root context, so a stalled control call or a wedged
	// cryptsetup pinned a root goroutine for the life of the agent. It is
	// generous: argon2 key derivation in luksAddKey is deliberately slow.
	requestTimeout = 90 * time.Second

	// busyWriteTimeout bounds the refusal write to a connection that never
	// entered a handler, so refusing cannot itself block the accept loop.
	busyWriteTimeout = 2 * time.Second
)

// Start creates the socket and serves until ctx is cancelled. The socket is
// write-only for group and other (0622 — connect(2) needs no read bit) and
// every accepted connection has passed the peer-uid check in peercred.go.
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
	// The unprivileged endpoint client must be able to connect, and connect(2)
	// requires only write permission — the read bit 0666 handed out was never
	// used by anything and made the mode look like the security boundary. It
	// is not: the peer-uid check below is.
	if err := os.Chmod(d.socketPath, 0o622); err != nil {
		_ = listener.Close()
		return fmt.Errorf("chmod socket: %w", err)
	}

	// Authenticate the connecting process by its OS identity before it reaches
	// any handler. This is what makes a token scraped out of /proc useless to a
	// service account, and it fails closed when peer credentials are
	// unreadable. Server-side token validation remains the authorization for
	// the operation itself.
	guarded := newPeerCredListener(listener, d.logger)

	d.listenerMu.Lock()
	d.listener = listener
	d.listenerMu.Unlock()

	d.logger.Info("LUKS passphrase daemon listening", "socket", d.socketPath)

	go func() {
		<-ctx.Done()
		d.Shutdown()
	}()

	for {
		conn, err := guarded.Accept()
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
		select {
		case d.inFlight <- struct{}{}:
		default:
			// Refuse rather than queue: the caller learns to retry instead of
			// holding a descriptor on the root daemon indefinitely.
			d.logger.Warn("LUKS daemon: refusing request; too many in flight", "limit", maxConcurrentRequests)
			_ = conn.SetWriteDeadline(d.now().Add(busyWriteTimeout))
			d.writeResponse(conn, errResponse(CodeBusy, "too many concurrent LUKS requests; retry shortly"))
			_ = conn.Close()
			continue
		}
		d.wg.Add(1)
		go func() {
			defer func() {
				<-d.inFlight
				d.wg.Done()
			}()
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
	// Bound the request itself (F21). Without this the handler runs under the
	// process-root context, so a control call that never returns or a wedged
	// cryptsetup holds one of the daemon's few request slots forever.
	reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	resp := d.handleRequest(reqCtx, req)
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

	// Authorize via the agent's own control connection — NOT the socket
	// peer. ValidateLuksToken consumes the single-use, device-bound,
	// short-TTL token server-side and returns the action's policy.
	sess := d.currentSession()
	if sess == nil {
		return errResponse(CodeNotConnected, "agent is not connected to the control; retry when online")
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
