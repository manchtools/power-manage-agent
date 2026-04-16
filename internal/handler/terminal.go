package handler

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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
	terminalActivatedShell   = "/bin/bash"
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

// sessionState tracks the lifecycle of a terminal session.
type sessionState int

const (
	// sessionStateStarting is the brief window between reservation
	// (when the slot is reserved under h.mu) and activation (when the
	// PTY has been allocated and OnTerminalStart is about to send
	// STARTED). closeTerminal during this window marks the session
	// stopping and cancels the start context; OnTerminalStart sees the
	// state transition between sudo calls and tears down its own
	// partial state instead of finishing.
	sessionStateStarting sessionState = iota
	// sessionStateActive is the steady-state: PTY allocated, pump
	// goroutine running, normal I/O flowing.
	sessionStateActive
	// sessionStateStopping signals the session has been ordered to
	// terminate, either by an external Stop or by an internal
	// teardown (idle sweeper, send failure, natural exit). Any
	// subsequent operation on the session is a no-op.
	sessionStateStopping
)

// terminalSession is the agent's per-session bookkeeping. It owns the
// SDK terminal.Session, the activated tty user (so we know what to
// revert on Stop), the cancel function for its I/O goroutine, and a
// snapshot of the TerminalSender captured at creation time so the
// pump goroutine never has to touch h.mu to read the sender.
type terminalSession struct {
	id      string
	ttyUser string
	// sender is captured once at creation and is immutable for the
	// session's lifetime. The pump goroutine uses this field directly
	// rather than h.terminalSender so SetTerminalSender races on the
	// handler are impossible.
	sender TerminalSender

	// mu protects state, session, tempHome, cancel, and lastActivity.
	mu           sync.Mutex
	state        sessionState
	session      *terminal.Session  // nil during sessionStateStarting
	tempHome     string             // "" during sessionStateStarting
	cancel       context.CancelFunc // bound to a sessionCtx that gates both start prep and the I/O loop
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

func (ts *terminalSession) isStopping() bool {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return ts.state == sessionStateStopping
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

// snapshotTerminalSender returns the currently-installed sender under
// h.mu so callers don't race with SetTerminalSender. Returns nil if no
// sender has been wired (the agent dropped the start request before it
// could spawn anything).
func (h *Handler) snapshotTerminalSender() TerminalSender {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.terminalSender
}

// OnTerminalStart implements sdk.TerminalHandler. It validates the
// dedicated TTY user, activates its shell, allocates the PTY via the
// SDK terminal package, kicks off the read goroutine that pumps PTY
// output back to the gateway, and emits a STARTED state change. Any
// failure surfaces via SendTerminalStateChange with STATE_ERROR
// instead of returning an error from the dispatch loop, so a single
// bad request never tears down the agent connection.
//
// The slow setup path (sudo Modify, mkdir, chown, terminal.Start)
// runs after the slot is reserved but before the session is marked
// active. A concurrent OnTerminalStop during that window marks the
// session stopping and cancels the start context; this method checks
// for that state between every step and reverts whichever side
// effects already landed.
func (h *Handler) OnTerminalStart(ctx context.Context, req *pb.TerminalStart) error {
	logger := h.logger.With("session_id", req.SessionId, "tty_user", req.TtyUser)
	logger.Info("opening terminal session")

	// Snapshot the sender once under the lock so we never read
	// h.terminalSender concurrently with SetTerminalSender. The
	// captured value is what the pump goroutine uses too — see
	// terminalSession.sender.
	sender := h.snapshotTerminalSender()
	if sender == nil {
		// Should not happen — SetTerminalSender is called at startup.
		// Surface the misconfiguration as a log line; we have no way
		// to send a state-change error without a sender.
		logger.Error("terminal sender not configured; dropping start request")
		return nil
	}

	// Refuse anything that doesn't look like a Power Manage TTY user.
	// IsValidName covers the syntactic constraints (lowercase, length,
	// charset). The HasPrefix check enforces the dedicated pm-tty-*
	// namespace so the agent can never operate on an arbitrary system
	// account, even if the control server's resolution is buggy or
	// compromised. The constant comes from the SDK so the prefix is
	// the single source of truth.
	if !sysuser.IsValidName(req.TtyUser) || !strings.HasPrefix(req.TtyUser, terminal.TTYUsernamePrefix) {
		h.failTerminalStart(ctx, sender, req.SessionId, "invalid tty username")
		return nil
	}

	// Device-authoritative TTY gate. The toggle lives in the agent's
	// SQLite database and defaults to off. Only the power-manage user
	// (via the CLI) or root can flip it — the server cannot bypass
	// this by pushing an action because the action still runs on the
	// device and goes through the same CLI surface.
	//
	// Fail-closed: a nil store or any read error means the gate is
	// closed, never the other way around. This runs before the user
	// lookup so a disabled device does zero syscalls on each rejected
	// request and the error message doesn't leak whether the pm-tty-*
	// user happens to exist.
	if h.store == nil {
		logger.Warn("terminal start rejected: no store wired for tty gate")
		h.failTerminalStart(ctx, sender, req.SessionId, "terminal sessions are disabled on this device")
		return nil
	}
	enabled, err := h.store.IsTTYEnabled()
	if err != nil {
		logger.Warn("failed to read tty toggle state; refusing session", "error", err)
		h.failTerminalStart(ctx, sender, req.SessionId, "terminal sessions are disabled on this device")
		return nil
	}
	if !enabled {
		logger.Info("terminal start rejected: tty disabled on device")
		h.failTerminalStart(ctx, sender, req.SessionId, "terminal sessions are disabled on this device")
		return nil
	}

	// Verify the TTY user actually exists and is not locked. This is
	// the dedicated pm-tty-* account; failure here means the control
	// server's TerminalAccess provisioning hasn't run on this device
	// yet, or the user has been disabled.
	info, err := sysuser.Get(req.TtyUser)
	if err != nil {
		h.failTerminalStart(ctx, sender, req.SessionId, fmt.Sprintf("tty user %q not provisioned: %v", req.TtyUser, err))
		return nil
	}
	if info.Locked {
		h.failTerminalStart(ctx, sender, req.SessionId, fmt.Sprintf("tty user %q is disabled", req.TtyUser))
		return nil
	}

	// Build the session record up front so closeTerminal can find it
	// during the slow start path and signal cancellation.
	sessionCtx, cancel := context.WithCancel(context.Background())
	ts := &terminalSession{
		id:      req.SessionId,
		ttyUser: req.TtyUser,
		sender:  sender,
		state:   sessionStateStarting,
		cancel:  cancel,
	}
	ts.touch()

	// Reserve the slot under h.mu so concurrent Start requests can't
	// both pass the limit check.
	h.mu.Lock()
	if h.terminals == nil {
		h.terminals = make(map[string]*terminalSession)
	}
	if _, exists := h.terminals[req.SessionId]; exists {
		h.mu.Unlock()
		cancel()
		h.failTerminalStart(ctx, sender, req.SessionId, "session already exists")
		return nil
	}
	limit := h.terminalLimit
	if limit == 0 {
		limit = defaultTerminalLimit
	}
	if len(h.terminals) >= limit {
		h.mu.Unlock()
		cancel()
		h.failTerminalStart(ctx, sender, req.SessionId, fmt.Sprintf("device terminal session limit reached (%d)", limit))
		return nil
	}
	h.terminals[req.SessionId] = ts
	h.mu.Unlock()

	// Track which side effects have landed so the abort path can
	// unwind exactly what was applied. Captured by the closures below.
	var (
		shellActivated bool
		tempHomeDir    string
	)

	cleanup := func() {
		if tempHomeDir != "" {
			if err := os.RemoveAll(tempHomeDir); err != nil {
				logger.Warn("failed to remove terminal temp home", "path", tempHomeDir, "error", err)
			}
		}
		if shellActivated {
			// Only revert if no other session for this user is still
			// active — matches the live-session cleanup path.
			if !h.anySessionForUserExcept(req.TtyUser, req.SessionId) {
				h.deactivateShell(ctx, req.TtyUser)
			}
		}
		h.removeTerminal(req.SessionId)
	}

	// abortFail tears down whatever was built and emits STATE_ERROR.
	// Used for failures during start prep that the gateway hasn't
	// asked for.
	abortFail := func(reason string) {
		cleanup()
		h.failTerminalStart(ctx, sender, req.SessionId, reason)
	}

	// abortStopped tears down whatever was built but does NOT emit a
	// STATE_ERROR — Stop arrived externally and the gateway already
	// knows the session is being killed.
	abortStopped := func() {
		logger.Info("terminal start aborted by concurrent stop")
		cleanup()
	}

	// Activate the shell. usermod via the SDK helper which already
	// uses sudo -n. Note: sysuser.Modify ignores the context for
	// cancellation today (it shells out via sudo), so we still gate
	// on isStopping() between steps as a fallback.
	if ts.isStopping() {
		abortStopped()
		return nil
	}
	if err := sysuser.Modify(sessionCtx, req.TtyUser, "-s", terminalActivatedShell); err != nil {
		abortFail(fmt.Sprintf("activate shell: %v", err))
		return nil
	}
	shellActivated = true

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
	if ts.isStopping() {
		abortStopped()
		return nil
	}
	tempHome := filepath.Join("/tmp", req.TtyUser+"."+req.SessionId)
	if err := os.Mkdir(tempHome, 0o700); err != nil {
		abortFail(fmt.Sprintf("create temp home: %v", err))
		return nil
	}
	tempHomeDir = tempHome
	// Belt and braces: confirm the freshly-created path is actually
	// a directory and not a symlink before chowning anything.
	if info, err := os.Lstat(tempHome); err != nil || !info.Mode().IsDir() {
		abortFail("temp home is not a regular directory")
		return nil
	}
	if err := sysuser.ChownRecursive(sessionCtx, tempHome, req.TtyUser, req.TtyUser); err != nil {
		abortFail(fmt.Sprintf("chown temp home: %v", err))
		return nil
	}

	if ts.isStopping() {
		abortStopped()
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
		abortFail(fmt.Sprintf("allocate pty: %v", err))
		return nil
	}

	// Promote to active under the session lock. If we were marked
	// stopping in the gap between the last isStopping() check and
	// here, tear down the freshly-allocated PTY before returning.
	ts.mu.Lock()
	if ts.state == sessionStateStopping {
		ts.mu.Unlock()
		_ = sess.Close()
		abortStopped()
		return nil
	}
	ts.session = sess
	ts.tempHome = tempHomeDir
	ts.state = sessionStateActive
	ts.touchLocked()
	ts.mu.Unlock()

	// Tell the gateway/web client we're live BEFORE starting the
	// reader, so the first byte of output cannot race ahead of the
	// STARTED state change. If this fails, the gateway never
	// learned we're alive — there's no point keeping the PTY open
	// and burning a slot, so tear the session down.
	if err := sender.SendTerminalStateChange(ctx, &pb.TerminalStateChange{
		SessionId: req.SessionId,
		State:     pb.TerminalSessionState_TERMINAL_SESSION_STATE_STARTED,
	}); err != nil {
		logger.Warn("failed to send STARTED state change; aborting session", "error", err)
		h.closeTerminal(context.Background(), req.SessionId, "send started failed")
		return nil
	}

	go h.pumpTerminalOutput(sessionCtx, ts)
	return nil
}

// touchLocked is the lock-free variant of touch, used when the caller
// already holds ts.mu (e.g. inside the activation transition).
func (ts *terminalSession) touchLocked() {
	ts.lastActivity = time.Now()
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
	// Sessions in the starting state have no PTY yet; ignore until
	// they activate.
	ts.mu.Lock()
	sess := ts.session
	ts.mu.Unlock()
	if sess == nil {
		h.logger.Debug("terminal input for not-yet-active session", "session_id", req.SessionId)
		return nil
	}
	if _, err := sess.Write(req.Data); err != nil {
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
	ts.mu.Lock()
	sess := ts.session
	ts.mu.Unlock()
	if sess == nil {
		h.logger.Debug("terminal resize for not-yet-active session", "session_id", req.SessionId)
		return nil
	}
	if err := sess.Resize(uint16(req.Cols), uint16(req.Rows)); err != nil {
		h.logger.Warn("terminal resize failed", "session_id", req.SessionId, "error", err)
	}
	return nil
}

// OnTerminalStop terminates the named session and reverts side
// effects: closes the PTY, removes the temp home, and reverts the
// TTY user's shell to nologin if it was the last active session for
// that user. Idempotent: unknown sessions are no-ops so the gateway
// can fire and forget. Sessions still in the starting state are
// marked stopping and cleaned up by OnTerminalStart on its next
// state check.
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
//
// All sender access goes through the per-session ts.sender snapshot,
// not h.terminalSender, so this goroutine never has to touch h.mu.
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
		if err := ts.sender.SendTerminalStateChange(context.Background(), state); err != nil {
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
			if sendErr := ts.sender.SendTerminalOutput(context.Background(), out); sendErr != nil {
				h.logger.Warn("failed to send terminal output; tearing down session",
					"session_id", ts.id, "error", sendErr)
				// Returning here triggers the deferred Wait + EXITED
				// + closeTerminal path, so the PTY is torn down and
				// the slot is freed. Without this teardown, a
				// disconnected gateway would leak the PTY indefinitely.
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
//
// Takes an explicit sender so the caller — which has already
// snapshotted h.terminalSender once under h.mu — does not have to
// re-acquire the lock.
func (h *Handler) failTerminalStart(ctx context.Context, sender TerminalSender, sessionID, msg string) {
	h.logger.Warn("terminal session start failed", "session_id", sessionID, "error", msg)
	if sender == nil {
		return
	}
	change := &pb.TerminalStateChange{
		SessionId: sessionID,
		State:     pb.TerminalSessionState_TERMINAL_SESSION_STATE_ERROR,
		Error:     msg,
	}
	if err := sender.SendTerminalStateChange(ctx, change); err != nil {
		h.logger.Warn("failed to send ERROR state change",
			"session_id", sessionID, "error", err)
	}
}

// closeTerminal closes one session and reverts its side effects.
// Idempotent: a second call for the same id is a no-op.
//
// For sessions still in sessionStateStarting, this method only
// transitions the state to stopping and cancels the start context;
// the cleanup of partial side effects (shell, temp home) is done by
// OnTerminalStart on its next state check, because Start owns the
// list of "what has been applied so far".
func (h *Handler) closeTerminal(ctx context.Context, sessionID, reason string) {
	h.mu.Lock()
	ts, ok := h.terminals[sessionID]
	h.mu.Unlock()
	if !ok || ts == nil {
		return
	}

	ts.mu.Lock()
	if ts.state == sessionStateStopping {
		// Already being torn down — nothing to do.
		ts.mu.Unlock()
		return
	}
	wasStarting := ts.state == sessionStateStarting
	ts.state = sessionStateStopping
	if ts.cancel != nil {
		ts.cancel()
	}
	sess := ts.session
	tempHome := ts.tempHome
	ttyUser := ts.ttyUser
	ts.mu.Unlock()

	if wasStarting {
		// OnTerminalStart will see the stopping state on its next
		// isStopping() check (or the cancelled context will pop a
		// sudo call out), and it will clean up its own partial state
		// and remove the entry from the registry. We deliberately
		// don't touch the registry here.
		return
	}

	// Active session: pull from the registry, then revert side effects.
	h.mu.Lock()
	delete(h.terminals, sessionID)
	stillActiveForUser := false
	for _, other := range h.terminals {
		if other != nil && other.ttyUser == ttyUser {
			stillActiveForUser = true
			break
		}
	}
	h.mu.Unlock()

	if sess != nil {
		if err := sess.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			h.logger.Warn("terminal session close error", "session_id", sessionID, "error", err)
		}
	}

	// Revert the TTY user shell only when no other session for the
	// same user is still running. This handles the (rare but possible)
	// case where the same TTY user has multiple concurrent sessions.
	if !stillActiveForUser {
		h.deactivateShell(ctx, ttyUser)
	}

	if tempHome != "" {
		if err := os.RemoveAll(tempHome); err != nil {
			h.logger.Warn("failed to remove terminal temp home",
				"session_id", sessionID, "path", tempHome, "error", err)
		}
	}
	_ = reason
}

// anySessionForUserExcept reports whether any active session in the
// registry has the given tty user, ignoring the supplied session id.
// Used by OnTerminalStart's cleanup path to decide whether reverting
// the shell would yank it out from under a concurrent session.
func (h *Handler) anySessionForUserExcept(ttyUser, exceptSessionID string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	for id, other := range h.terminals {
		if id == exceptSessionID || other == nil {
			continue
		}
		if other.ttyUser == ttyUser {
			return true
		}
	}
	return false
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
		// Skip sessions that aren't fully active yet — they're either
		// still in setup (no PTY to close) or already stopping.
		ts.mu.Lock()
		state := ts.state
		ts.mu.Unlock()
		if state != sessionStateActive {
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
