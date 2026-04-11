package handler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	sdk "github.com/manchtools/power-manage/sdk/go"
	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/sys/terminal"
	sysuser "github.com/manchtools/power-manage/sdk/go/sys/user"
)

// Compile-time assertion that *Handler satisfies sdk.TerminalHandler.
// If the SDK changes the interface and the handler stops matching, this
// fails at build time instead of silently disabling terminal support
// (the SDK Client's type-assert miss is a no-op for the agent).
var _ sdk.TerminalHandler = (*Handler)(nil)

// Default agent-side limits per the issue spec
// (manchtools/power-manage-sdk#16 — Security section).
const (
	defaultTerminalLimit       = 3
	defaultTerminalIdleTimeout = 30 * time.Minute
	terminalSweepInterval      = 30 * time.Second
	terminalReadChunkBytes     = 32 * 1024 // matches the proto's max=65536 with headroom

	// Activated shell to assign to the TTY user during a session. The
	// agent reverts to nologin on disconnect; this is intentionally
	// hard-coded so it cannot be overridden from the gateway side.
	terminalActivatedShell  = "/bin/bash"
	terminalDeactivatedShell = "/usr/sbin/nologin"
)

// TerminalSender is the subset of the SDK Client that the terminal
// handler needs to push messages back to the gateway. The agent's
// main.go injects the *sdk.Client which satisfies this interface
// implicitly so the handler package doesn't depend on the entire
// client.
type TerminalSender interface {
	SendTerminalOutput(ctx context.Context, out *pb.TerminalOutput) error
	SendTerminalStateChange(ctx context.Context, change *pb.TerminalStateChange) error
}

// terminalSession is the agent's per-session bookkeeping. It owns the
// SDK terminal.Session, the activated tty user (so we know what to
// revert on Stop), and the cancel function for its I/O goroutine.
type terminalSession struct {
	id       string
	ttyUser  string
	tempHome string
	session  *terminal.Session
	cancel   context.CancelFunc

	// lastActivity is updated whenever a frame is read or written;
	// the sweeper closes sessions whose lastActivity is older than
	// the configured idle timeout.
	mu           sync.Mutex
	lastActivity time.Time
}

func (ts *terminalSession) touch() {
	ts.mu.Lock()
	ts.lastActivity = time.Now()
	ts.mu.Unlock()
}

func (ts *terminalSession) idleSince() time.Time {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.lastActivity
}

// SetTerminalSender wires the SDK Client (or any compatible sender)
// into the handler. Must be called once after the Client is created
// and before the stream loop dispatches the first TerminalStart
// message. Calling it twice replaces the previous sender.
func (h *Handler) SetTerminalSender(sender TerminalSender) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.terminalSender = sender
	if h.terminals == nil {
		h.terminals = make(map[string]*terminalSession)
	}
	if h.terminalLimit == 0 {
		h.terminalLimit = defaultTerminalLimit
	}
	if h.terminalIdleTimeout == 0 {
		h.terminalIdleTimeout = defaultTerminalIdleTimeout
	}
	if !h.terminalSweeperStarted {
		h.terminalSweeperStarted = true
		go h.terminalSweepLoop()
	}
}

// OnTerminalStart implements sdk.TerminalHandler. It validates the
// dedicated TTY user, activates its shell, allocates the PTY via the
// SDK terminal package, kicks off the read goroutine that pumps PTY
// output back to the gateway, and emits a STARTED state change. Any
// failure surfaces via SendTerminalStateChange with STATE_ERROR
// instead of returning an error from the dispatch loop, so a single
// bad request never tears down the agent connection.
func (h *Handler) OnTerminalStart(ctx context.Context, req *pb.TerminalStart) error {
	logger := h.logger.With("session_id", req.SessionId, "tty_user", req.TtyUser)
	logger.Info("opening terminal session")

	if h.terminalSender == nil {
		// Should not happen — SetTerminalSender is called at startup.
		// Surface the misconfiguration as a state-change error so the
		// gateway/web client sees a clean failure.
		logger.Error("terminal sender not configured; dropping start request")
		return nil
	}

	// Refuse anything that doesn't look like a Power Manage TTY user.
	// The proto layer enforces ulid session IDs, but the username
	// comes from the control server's resolution and we re-validate
	// here as defense in depth.
	if !sysuser.IsValidName(req.TtyUser) {
		h.failTerminalStart(ctx, req.SessionId, "invalid tty username")
		return nil
	}

	// Verify the TTY user actually exists and is not locked. This is
	// the dedicated pm-tty-* account; failure here means the control
	// server's TerminalAccess provisioning hasn't run on this device
	// yet, or the user has been disabled.
	info, err := sysuser.Get(req.TtyUser)
	if err != nil {
		h.failTerminalStart(ctx, req.SessionId, fmt.Sprintf("tty user %q not provisioned: %v", req.TtyUser, err))
		return nil
	}
	if info.Locked {
		h.failTerminalStart(ctx, req.SessionId, fmt.Sprintf("tty user %q is disabled", req.TtyUser))
		return nil
	}

	// Reserve a slot under the lock so concurrent Start requests can't
	// both pass the limit check.
	h.mu.Lock()
	if h.terminals == nil {
		h.terminals = make(map[string]*terminalSession)
	}
	if _, exists := h.terminals[req.SessionId]; exists {
		h.mu.Unlock()
		h.failTerminalStart(ctx, req.SessionId, "session already exists")
		return nil
	}
	limit := h.terminalLimit
	if limit == 0 {
		limit = defaultTerminalLimit
	}
	if len(h.terminals) >= limit {
		h.mu.Unlock()
		h.failTerminalStart(ctx, req.SessionId, fmt.Sprintf("device terminal session limit reached (%d)", limit))
		return nil
	}
	h.terminals[req.SessionId] = nil // reserve
	h.mu.Unlock()

	// Activate the shell. usermod via the SDK helper which already
	// uses sudo -n.
	if err := sysuser.Modify(ctx, req.TtyUser, "-s", terminalActivatedShell); err != nil {
		h.removeTerminal(req.SessionId)
		h.failTerminalStart(ctx, req.SessionId, fmt.Sprintf("activate shell: %v", err))
		return nil
	}

	// Per-session temp home so the activated shell has a writable
	// CWD without polluting any real user's $HOME. Owned by the TTY
	// user (chown via the SDK helper) and removed on session stop.
	//
	// Use os.Mkdir (NOT MkdirAll) so a pre-existing path causes a
	// hard failure instead of being followed: a malicious local user
	// could otherwise plant /tmp/pm-tty-foo.<sessid> as a symlink
	// pointing at /etc and trick the subsequent chown into rewriting
	// system file ownership. ULID session ids make accidental
	// collisions statistically impossible, so EEXIST really does
	// mean "something is wrong".
	tempHome := filepath.Join("/tmp", req.TtyUser+"."+req.SessionId)
	if err := os.Mkdir(tempHome, 0o700); err != nil {
		h.deactivateShell(ctx, req.TtyUser)
		h.removeTerminal(req.SessionId)
		h.failTerminalStart(ctx, req.SessionId, fmt.Sprintf("create temp home: %v", err))
		return nil
	}
	// Belt and braces: confirm the freshly-created path is actually
	// a directory and not a symlink before chowning anything.
	if info, err := os.Lstat(tempHome); err != nil || !info.Mode().IsDir() {
		_ = os.RemoveAll(tempHome)
		h.deactivateShell(ctx, req.TtyUser)
		h.removeTerminal(req.SessionId)
		h.failTerminalStart(ctx, req.SessionId, "temp home is not a regular directory")
		return nil
	}
	if err := sysuser.ChownRecursive(ctx, tempHome, req.TtyUser, req.TtyUser); err != nil {
		_ = os.RemoveAll(tempHome)
		h.deactivateShell(ctx, req.TtyUser)
		h.removeTerminal(req.SessionId)
		h.failTerminalStart(ctx, req.SessionId, fmt.Sprintf("chown temp home: %v", err))
		return nil
	}

	cols := uint16(req.Cols)
	rows := uint16(req.Rows)
	cfg := terminal.SessionConfig{
		User:    req.TtyUser,
		Shell:   terminalActivatedShell,
		Cols:    cols,
		Rows:    rows,
		WorkDir: tempHome,
		Env:     []string{"HOME=" + tempHome, "USER=" + req.TtyUser, "LOGNAME=" + req.TtyUser},
	}

	sess, err := terminal.Start(cfg)
	if err != nil {
		_ = os.RemoveAll(tempHome)
		h.deactivateShell(ctx, req.TtyUser)
		h.removeTerminal(req.SessionId)
		h.failTerminalStart(ctx, req.SessionId, fmt.Sprintf("allocate pty: %v", err))
		return nil
	}

	// Per-session context for the I/O goroutine. Cancelled by Stop or
	// by the natural exit reaper.
	sessionCtx, cancel := context.WithCancel(context.Background())
	ts := &terminalSession{
		id:       req.SessionId,
		ttyUser:  req.TtyUser,
		tempHome: tempHome,
		session:  sess,
		cancel:   cancel,
	}
	ts.touch()

	h.mu.Lock()
	h.terminals[req.SessionId] = ts
	h.mu.Unlock()

	// Tell the gateway/web client we're live BEFORE starting the
	// reader, so the first byte of output cannot race ahead of the
	// STARTED state change.
	if err := h.terminalSender.SendTerminalStateChange(ctx, &pb.TerminalStateChange{
		SessionId: req.SessionId,
		State:     pb.TerminalSessionState_TERMINAL_SESSION_STATE_STARTED,
	}); err != nil {
		logger.Warn("failed to send STARTED state change", "error", err)
	}

	go h.pumpTerminalOutput(sessionCtx, ts)
	return nil
}

// OnTerminalInput writes the bytes to the named session's PTY. Unknown
// sessions are ignored at debug level — the gateway may have already
// torn down the session and a few in-flight frames are normal.
func (h *Handler) OnTerminalInput(ctx context.Context, req *pb.TerminalInput) error {
	ts := h.lookupTerminal(req.SessionId)
	if ts == nil {
		h.logger.Debug("terminal input for unknown session", "session_id", req.SessionId)
		return nil
	}
	if _, err := ts.session.Write(req.Data); err != nil {
		h.logger.Warn("terminal input write failed", "session_id", req.SessionId, "error", err)
		// Don't tear down the session — the read pump will detect the
		// PTY going away and emit EXITED.
		return nil
	}
	ts.touch()
	return nil
}

// OnTerminalResize forwards a TIOCSWINSZ to the session's PTY.
func (h *Handler) OnTerminalResize(ctx context.Context, req *pb.TerminalResize) error {
	ts := h.lookupTerminal(req.SessionId)
	if ts == nil {
		h.logger.Debug("terminal resize for unknown session", "session_id", req.SessionId)
		return nil
	}
	if err := ts.session.Resize(uint16(req.Cols), uint16(req.Rows)); err != nil {
		h.logger.Warn("terminal resize failed", "session_id", req.SessionId, "error", err)
	}
	return nil
}

// OnTerminalStop terminates the named session and reverts side
// effects: closes the PTY, removes the temp home, and reverts the
// TTY user's shell to nologin if it was the last active session for
// that user. Idempotent: unknown sessions are no-ops so the gateway
// can fire and forget.
func (h *Handler) OnTerminalStop(ctx context.Context, req *pb.TerminalStop) error {
	if req.Reason != "" {
		h.logger.Info("stopping terminal session", "session_id", req.SessionId, "reason", req.Reason)
	} else {
		h.logger.Info("stopping terminal session", "session_id", req.SessionId)
	}
	h.closeTerminal(ctx, req.SessionId, req.Reason)
	return nil
}

// pumpTerminalOutput is the per-session goroutine that copies PTY
// output to TerminalOutput frames. Exits when the session ends
// (PTY closed by Stop or natural shell exit) or when sessionCtx is
// cancelled. Always emits a final state change before returning so
// the web client knows whether the shell exited cleanly or errored.
func (h *Handler) pumpTerminalOutput(sessionCtx context.Context, ts *terminalSession) {
	defer func() {
		// Wait for the shell to actually exit so we can report the
		// real exit code; if Wait races with Close the SDK Session
		// already handles the EIO/EOF in Read.
		exitCode, _ := ts.session.Wait()
		state := &pb.TerminalStateChange{
			SessionId: ts.id,
			State:     pb.TerminalSessionState_TERMINAL_SESSION_STATE_EXITED,
			ExitCode:  int32(exitCode),
		}
		if err := h.terminalSender.SendTerminalStateChange(context.Background(), state); err != nil {
			h.logger.Warn("failed to send EXITED state change",
				"session_id", ts.id, "error", err)
		}
		// Make sure all the side effects are gone even if Stop never came.
		h.closeTerminal(context.Background(), ts.id, "")
	}()

	buf := make([]byte, terminalReadChunkBytes)
	for {
		select {
		case <-sessionCtx.Done():
			return
		default:
		}

		n, err := ts.session.Read(buf)
		if n > 0 {
			ts.touch()
			out := &pb.TerminalOutput{
				SessionId: ts.id,
				Data:      append([]byte(nil), buf[:n]...),
			}
			if sendErr := h.terminalSender.SendTerminalOutput(context.Background(), out); sendErr != nil {
				h.logger.Warn("failed to send terminal output",
					"session_id", ts.id, "error", sendErr)
				return
			}
		}
		if err != nil {
			// io.EOF / os.ErrClosed are expected on shell exit;
			// anything else still ends the session.
			return
		}
	}
}

// failTerminalStart sends a STATE_ERROR back to the gateway and gives
// up on the session. Used during the validation/preparation phase
// before the I/O goroutine has been started; once the goroutine is
// running, errors flow through pumpTerminalOutput's deferred
// EXITED/closeTerminal path.
func (h *Handler) failTerminalStart(ctx context.Context, sessionID, msg string) {
	h.logger.Warn("terminal session start failed", "session_id", sessionID, "error", msg)
	if h.terminalSender == nil {
		return
	}
	change := &pb.TerminalStateChange{
		SessionId: sessionID,
		State:     pb.TerminalSessionState_TERMINAL_SESSION_STATE_ERROR,
		Error:     msg,
	}
	if err := h.terminalSender.SendTerminalStateChange(ctx, change); err != nil {
		h.logger.Warn("failed to send ERROR state change",
			"session_id", sessionID, "error", err)
	}
}

// closeTerminal closes one session and reverts its side effects.
// Idempotent: a second call for the same id is a no-op.
func (h *Handler) closeTerminal(ctx context.Context, sessionID, reason string) {
	h.mu.Lock()
	ts, ok := h.terminals[sessionID]
	if !ok || ts == nil {
		h.mu.Unlock()
		return
	}
	delete(h.terminals, sessionID)
	// Snapshot ttyUser before unlocking to compute the "last session
	// for this user?" check below.
	ttyUser := ts.ttyUser
	stillActiveForUser := false
	for _, other := range h.terminals {
		if other != nil && other.ttyUser == ttyUser {
			stillActiveForUser = true
			break
		}
	}
	h.mu.Unlock()

	if ts.cancel != nil {
		ts.cancel()
	}
	if ts.session != nil {
		if err := ts.session.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			h.logger.Warn("terminal session close error", "session_id", sessionID, "error", err)
		}
	}

	// Revert the TTY user shell only when no other session for the
	// same user is still running. This handles the (rare but possible)
	// case where the same TTY user has multiple concurrent sessions.
	if !stillActiveForUser {
		h.deactivateShell(ctx, ttyUser)
	}

	if ts.tempHome != "" {
		if err := os.RemoveAll(ts.tempHome); err != nil {
			h.logger.Warn("failed to remove terminal temp home",
				"session_id", sessionID, "path", ts.tempHome, "error", err)
		}
	}
	_ = reason
}

// deactivateShell reverts the TTY user's login shell back to nologin.
// Best-effort: a failure here is logged but does not block the rest
// of the cleanup.
func (h *Handler) deactivateShell(ctx context.Context, ttyUser string) {
	if err := sysuser.Modify(ctx, ttyUser, "-s", terminalDeactivatedShell); err != nil {
		h.logger.Warn("failed to revert tty user shell",
			"tty_user", ttyUser, "error", err)
	}
}

func (h *Handler) lookupTerminal(sessionID string) *terminalSession {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.terminals[sessionID]
}

func (h *Handler) removeTerminal(sessionID string) {
	h.mu.Lock()
	delete(h.terminals, sessionID)
	h.mu.Unlock()
}

// terminalSweepLoop runs forever, closing any session that has been
// idle longer than the configured timeout. Started lazily on the
// first SetTerminalSender call.
func (h *Handler) terminalSweepLoop() {
	t := time.NewTicker(terminalSweepInterval)
	defer t.Stop()
	for range t.C {
		h.sweepIdleTerminals()
	}
}

func (h *Handler) sweepIdleTerminals() {
	h.mu.Lock()
	timeout := h.terminalIdleTimeout
	if timeout == 0 {
		timeout = defaultTerminalIdleTimeout
	}
	cutoff := time.Now().Add(-timeout)
	var idle []string
	for id, ts := range h.terminals {
		if ts == nil {
			continue
		}
		if ts.idleSince().Before(cutoff) {
			idle = append(idle, id)
		}
	}
	h.mu.Unlock()

	for _, id := range idle {
		h.logger.Info("closing idle terminal session", "session_id", id, "timeout", timeout)
		h.closeTerminal(context.Background(), id, "idle timeout")
	}
}
