// Package main is the entry point for the power-manage agent.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	sdk "github.com/manchtools/power-manage-sdk"
	pm "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/agent/internal/credentials"
	"github.com/manchtools/power-manage/agent/internal/crl"
	"github.com/manchtools/power-manage/agent/internal/handler"
	"github.com/manchtools/power-manage/agent/internal/luksd"
	"github.com/manchtools/power-manage/agent/internal/scheduler"
)

// runAgent connects to the gateway and processes messages.
// The agent continues to run scheduled actions even when disconnected.
// If securityAlert is non-nil, it will be sent to the server after connection.
// reloadCredsForReconnect returns the latest credentials from disk,
// falling back to `current` if the reload fails. startCertRotation
// renews the mTLS certificate and persists it to disk, but runAgent
// holds an in-memory copy loaded once at startup; without reloading it
// before each reconnect, a reconnect that happens after the old cert
// expired would keep presenting the stale (expired) cert and fail the
// mTLS handshake forever, even though a valid renewed cert already sits
// on disk. A transient reload error must NOT drop the working creds.
func reloadCredsForReconnect(credStore *credentials.Store, current *credentials.Credentials, logger *slog.Logger) *credentials.Credentials {
	reloaded, err := credStore.Load()
	if err != nil {
		logger.Warn("cert reload: failed to reload credentials before reconnect; using in-memory copy", "error", err)
		return current
	}
	return reloaded
}

func runAgent(ctx context.Context, credStore *credentials.Store, creds *credentials.Credentials, hostname string, h *handler.Handler, sched *scheduler.Scheduler, syncTrigger <-chan struct{}, securityAlert *pendingSecurityAlert, luksDaemon *luksd.Daemon, logger *slog.Logger, now func() time.Time) {
	// Current sync interval (can be updated by server). Owned by
	// runAgent — periodicSync receives its initial value as a
	// stack-local copy and any subsequent updates over a channel.
	// The previous shape (`*time.Duration` shared between this loop
	// and periodicSync) was a write-from-two-goroutines race that
	// `go test -race` did not catch because no test exercises this
	// loop. Audit F002.
	syncInterval := defaultSyncInterval

	// Track if this is the first successful sync (execute all actions)
	firstSync := true

	// Exponential backoff for reconnection
	currentBackoff := randomBackoff()

	// First connection uses the creds passed in (freshly loaded in
	// main); every reconnect reloads from disk to pick up a rotated
	// certificate before building the mTLS client.
	firstConnect := true

	// Gateway CRL (spec 31 Part D): the revocation list is fetched from control
	// and every gateway's server-cert fingerprint is checked against it during
	// the mTLS handshake (WithMTLSFromPEMAndRevocationCheck below). The fetch
	// reloads creds each time so it always presents the freshest (rotated)
	// device cert, and reaches control directly — no gateway relay (AC 13), so
	// a revoked gateway can be learned about even while still connected to it.
	// Best-effort initial load so the first connect can pass the gate; until a
	// list loads, Check fails closed and the connection loop retries (AC 12).
	crlCache := crl.New(func(fctx context.Context) (*sdk.GatewayCRL, error) {
		// Load straight from the store each fetch. This presents the current
		// (rotated) device cert to control AND avoids capturing runAgent's
		// `creds` variable, which the reconnect loop reassigns concurrently —
		// reading it from this refresh goroutine would be a data race. A load
		// failure returns an error; the cache keeps its last-good snapshot
		// until not_after, then Check fails closed.
		cur, err := credStore.Load()
		if err != nil {
			return nil, fmt.Errorf("load credentials for CRL fetch: %w", err)
		}
		if strings.TrimSpace(cur.ControlAddr) == "" {
			return nil, errors.New("no control address in credentials for CRL fetch")
		}
		mtls, err := sdk.WithMTLSFromPEMAndSystemRoots(cur.Certificate, cur.PrivateKey, cur.CACert)
		if err != nil {
			return nil, fmt.Errorf("configure control mTLS for CRL: %w", err)
		}
		return sdk.FetchGatewayCRL(fctx, cur.ControlAddr, mtls)
	}, logger, crl.WithClock(now))
	if err := crlCache.Refresh(ctx); err != nil {
		logger.Warn("initial gateway CRL fetch failed; gateway connections refused until it loads", "error", err)
	}
	go crlCache.Run(ctx, crlRefreshInterval)

	for {
		if !firstConnect {
			creds = reloadCredsForReconnect(credStore, creds, logger)
		}
		firstConnect = false

		// Reset handler connection state for new connection
		h.ResetConnection()

		// rc10: refuse anything but https://host for the network gateway
		// path. The only h2c use in this binary is the local unix-socket
		// enrollment client, never a remote gateway. A non-https (or
		// malformed) GatewayAddr means either a dev-leftover creds file or a
		// tampered redirect — both are reasons to fail fast rather than
		// silently skip mTLS on the live fleet. Shared predicate with
		// cmd_selftest.go so the guard cannot drift (closes the HasPrefix
		// case/opaque/hostless gaps).
		if err := requireHTTPSGateway(creds.GatewayAddr); err != nil {
			logger.Error("refusing gateway URL — re-enrol against an https:// gateway or delete the cached credentials",
				"gateway", creds.GatewayAddr, "error", err)
			os.Exit(1)
		}
		mtlsOpt, err := sdk.WithMTLSFromPEMAndRevocationCheck(creds.Certificate, creds.PrivateKey, creds.CACert, crlCache.Check)
		if err != nil {
			logger.Error("failed to configure mTLS", "error", err)
			os.Exit(1)
		}
		client := sdk.NewClient(strings.TrimSpace(creds.GatewayAddr),
			mtlsOpt,
			sdk.WithAuth(creds.DeviceID, ""),
		)

		// Create a child context for this connection session
		sessionCtx, cancelSession := context.WithCancel(ctx)

		// Wire LUKS key store to the current client for this connection session
		h.Executor().SetLuksKeyStore(&clientLuksKeyStore{client: client})

		// Wire the LUKS passphrase daemon to this connection so it can
		// validate tokens and fetch managed keys over the agent's own
		// authenticated stream (WS6 #1/#19).
		if luksDaemon != nil {
			luksDaemon.SetSession(client)
		}

		// Wire the terminal sender so the handler's terminal session
		// goroutines can push TerminalOutput / TerminalStateChange
		// frames back via the SDK Client. The first call also starts
		// the idle-session sweeper goroutine.
		h.SetTerminalSender(client)

		// Start stream in background (opens connection, heartbeats, receives)
		streamDone := make(chan error, 1)
		go func() {
			streamDone <- client.Run(sessionCtx, hostname, version, defaultHeartbeatInterval, h)
		}()

		// Send any results stored while offline (before syncing new actions)
		syncPendingResults(sessionCtx, sched, client, logger)

		// Sync actions from server (unary RPC — the stream is connecting in
		// parallel). The FIRST sync of a connection is a full reconcile, and
		// it MUST land: a single transient failure (most commonly the unary
		// sync racing ahead of the stream's device→gateway binding publish, so
		// control returns "device not live on any gateway") would otherwise
		// drop the agent into incremental-only mode, skipping every unchanged
		// action and leaving any drift — e.g. an account locked by an older
		// agent — uncorrected until the next reconnect. Retry until one full
		// reconcile succeeds; the binding appears within the stream handshake,
		// so a retry lands almost immediately.
		newInterval := syncUntilFullReconcile(sessionCtx, logger, func() time.Duration {
			return syncActionsFromServer(sessionCtx, client, sched, firstSync, logger)
		})
		if newInterval > 0 {
			syncInterval = newInterval
			firstSync = false
		}

		if securityAlert != nil {
			go sendSecurityAlert(sessionCtx, client, securityAlert, logger)
			securityAlert = nil
		}

		// Channel for sending interval updates to periodicSync.
		// Buffered so the parent never blocks if periodicSync is mid-tick.
		intervalUpdates := make(chan time.Duration, 1)

		// Start periodic sync goroutine (also listens for instant sync
		// triggers). It reports any server-driven interval changes
		// back over intervalUpdatesOut so the parent loop can carry
		// the latest value forward into the next reconnect.
		intervalUpdatesOut := make(chan time.Duration, 1)
		syncDone := make(chan struct{})
		go func() {
			defer close(syncDone)
			periodicSync(sessionCtx, client, sched, syncInterval, intervalUpdates, intervalUpdatesOut, syncTrigger, logger)
		}()

		// Start result sender goroutine to send scheduled execution results to server
		resultsDone := make(chan struct{})
		go func() {
			defer close(resultsDone)
			sendScheduledResults(sessionCtx, client, sched, logger)
		}()

		// Wait for the stream to end. Drain any interval updates the
		// child reports during the session so the parent's
		// `syncInterval` carries the latest value into the next
		// reconnect attempt.
		connStart := now()
		streamErr := waitForStreamEnd(streamDone, intervalUpdatesOut, &syncInterval)
		err = streamErr

		// Stop the goroutines and clear connection-dependent state
		cancelSession()
		h.Executor().SetLuksKeyStore(nil)
		if luksDaemon != nil {
			luksDaemon.ClearSession()
		}
		<-syncDone
		<-resultsDone

		// Release the prior client's idle keep-alive connections before the next
		// reconnect builds a fresh client (WS13 #8). Without this, each reconnect
		// leaks a transport's idle-connection pool — a slow file-descriptor /
		// socket leak over a long-lived agent's reconnect loop.
		client.CloseIdleConnections()

		// Drain any interval-update the child sent after the stream
		// closed but before sessionCtx propagated. Non-blocking.
		select {
		case updated := <-intervalUpdatesOut:
			syncInterval = updated
		default:
		}

		if ctx.Err() != nil {
			logger.Info("agent stopped")
			return
		}

		// Reset backoff if the connection was stable (lasted longer than the backoff interval)
		if now().Sub(connStart) > currentBackoff {
			currentBackoff = randomBackoff()
		}

		logger.Error("connection lost, continuing with scheduled actions",
			"error", err,
			"backoff", currentBackoff.String(),
		)

		// Wait with exponential backoff before reconnecting
		select {
		case <-ctx.Done():
			logger.Info("agent stopped during backoff")
			return
		case <-time.After(currentBackoff):
		}

		// Increase backoff for next attempt (with cap)
		currentBackoff = time.Duration(float64(currentBackoff) * backoffFactor)
		if currentBackoff > maxBackoff {
			currentBackoff = maxBackoff
		}
	}
}

// waitForStreamEnd blocks until the SDK stream goroutine sends an
// error on streamDone. While waiting it consumes any interval updates
// reported by periodicSync, writing the latest value into *interval so
// runAgent can carry it into the next reconnect attempt. Extracted so
// the wait loop avoids labeled-break and stays a plain `for { select }`.
func waitForStreamEnd(streamDone <-chan error, intervalUpdatesOut <-chan time.Duration, interval *time.Duration) error {
	for {
		select {
		case err := <-streamDone:
			return err
		case updated := <-intervalUpdatesOut:
			*interval = updated
		}
	}
}

// periodicSync runs a loop that periodically syncs actions from the server.
// The interval starts at initialInterval and can be updated by either:
//   - the server (returned by syncActionsFromServer) — the new value is
//     reported back over intervalUpdatesOut so runAgent can carry it into
//     the next reconnect attempt;
//   - the parent over intervalUpdates (currently unused, reserved for
//     future "operator-overridden interval" hooks).
//
// Owning the interval as a stack-local closes the F002 shared-pointer
// race; the previous shape passed `*time.Duration` to this goroutine
// while runAgent kept writing the same address from its own goroutine.
func periodicSync(
	ctx context.Context,
	client *sdk.Client,
	sched *scheduler.Scheduler,
	initialInterval time.Duration,
	intervalUpdates <-chan time.Duration,
	intervalUpdatesOut chan<- time.Duration,
	syncTrigger <-chan struct{},
	logger *slog.Logger,
) {
	syncInterval := initialInterval
	ticker := time.NewTicker(syncInterval)
	defer ticker.Stop()

	logger.Info("periodic sync started", "interval", syncInterval.String())

	// full=true re-runs the FULL desired-state reconcile (every action),
	// not just new/changed ones. An operator-triggered SYNC action means
	// "re-apply desired state now" — the lever for correcting drift such as
	// an account left locked by an older agent — so it must be a full sync,
	// matching what a fresh connection does. The periodic ticker stays
	// incremental so it doesn't re-run every action (including SHELL
	// scripts) every interval.
	doSync := func(reason string, full bool) {
		logger.Info("syncing actions", "reason", reason, "full", full)
		newInterval := syncActionsFromServer(ctx, client, sched, full, logger)
		if newInterval > 0 && newInterval != syncInterval {
			syncInterval = newInterval
			ticker.Reset(syncInterval)
			logger.Info("sync interval updated", "new_interval", syncInterval.String())
			// Best-effort report back to runAgent — drop on full
			// because the channel is buffered with 1 slot and a
			// stale pending update would just be overwritten by
			// the next one anyway.
			select {
			case intervalUpdatesOut <- syncInterval:
			default:
			}
		}
	}

	for {
		select {
		case <-ctx.Done():
			logger.Debug("periodic sync stopped")
			return
		case <-ticker.C:
			doSync("periodic", false)
		case <-syncTrigger:
			// Operator-dispatched SYNC action: full desired-state reconcile.
			doSync("instant action trigger", true)
		case override := <-intervalUpdates:
			if override > 0 && override != syncInterval {
				syncInterval = override
				ticker.Reset(syncInterval)
				logger.Info("sync interval overridden", "new_interval", syncInterval.String())
			}
		}
	}
}

// sendScheduledResults consumes the scheduler's Results channel and sends execution results to the server.
// This ensures that results from scheduled actions (not just server-pushed actions) are reported back.
func sendScheduledResults(ctx context.Context, client *sdk.Client, sched *scheduler.Scheduler, logger *slog.Logger) {
	for {
		select {
		case <-ctx.Done():
			return
		case result, ok := <-sched.Results():
			if !ok {
				return
			}

			// Skip results already sent by syncPendingResults on this
			// same reconnect. An action executed while offline is BOTH
			// persisted (unsynced) AND buffered in this channel;
			// syncPendingResults runs first (synchronously, before this
			// goroutine starts) and sends + marks the stored copy synced.
			// Without this check the buffered copy is sent a second time,
			// and the wire ActionResult carries no result id for the
			// server to dedup on — duplicate result events per offline
			// execution.
			if synced, err := sched.IsResultSynced(result.ResultID); err != nil {
				logger.Warn("failed to check result synced state; sending to be safe",
					"result_id", result.ResultID, "error", err)
			} else if synced {
				logger.Debug("skipping result already synced by syncPendingResults",
					"result_id", result.ResultID, "action_id", result.ActionID)
				continue
			}

			// Skip unchanged results unless this is the first execution of the action
			if !result.HasChanges && sched.HasPriorExecution(result.ActionID) {
				logger.Debug("skipping unchanged result (not first run)",
					"action_id", result.ActionID,
				)
				continue
			}

			logger.Info("sending scheduled execution result",
				"result_id", result.ResultID,
				"action_id", result.ActionID,
				"status", result.Result.Status.String(),
				"duration_ms", result.Result.DurationMs,
			)

			if err := client.SendActionResult(ctx, result.Result); err != nil {
				logger.Warn("failed to send scheduled result",
					"result_id", result.ResultID,
					"action_id", result.ActionID,
					"error", err,
				)
				// Result is already stored locally, will be synced later via syncPendingResults
				continue
			}

			// Mark result as synced in local store using the result ID (not action ID)
			if err := sched.MarkResultSynced(result.ResultID); err != nil {
				logger.Warn("failed to mark result synced",
					"result_id", result.ResultID,
					"error", err,
				)
			}
		}
	}
}

// firstSyncMaxAttempts bounds the initial full-sync retry so a genuinely
// persistent failure doesn't block the connection setup forever; the
// operator's manual SYNC (also a full reconcile) and the next reconnect remain
// the fallbacks.
const firstSyncMaxAttempts = 6

// firstSyncBaseBackoff / firstSyncMaxBackoff bound the exponential backoff
// between initial full-sync attempts. The dominant failure — the sync racing
// the device→gateway binding publish — clears within the stream handshake, so
// the first retry (after ~1s) almost always lands. Package vars, not consts, so
// tests can shrink them (the retry loop is otherwise dominated by real sleeps).
var (
	firstSyncBaseBackoff = 1 * time.Second
	firstSyncMaxBackoff  = 8 * time.Second
)

// syncUntilFullReconcile runs syncOnce (a full first-sync) and retries it on
// failure with bounded exponential backoff until one succeeds, aborting early
// if ctx is cancelled (the stream ended). syncOnce returns the sync interval
// (>0) on success or 0 on failure — the same contract as syncActionsFromServer.
// Returns the interval from the first success, or 0 if every attempt failed or
// the ctx ended. Ensuring one full reconcile lands per connection is what keeps
// a transient first-sync failure from stranding the agent in incremental-only
// mode (see the caller).
func syncUntilFullReconcile(ctx context.Context, logger *slog.Logger, syncOnce func() time.Duration) time.Duration {
	backoff := firstSyncBaseBackoff
	for attempt := 1; attempt <= firstSyncMaxAttempts; attempt++ {
		if iv := syncOnce(); iv > 0 {
			if attempt > 1 {
				logger.Info("initial full sync succeeded after retry", "attempt", attempt)
			}
			return iv
		}
		if attempt == firstSyncMaxAttempts {
			break
		}
		logger.Warn("initial full sync failed; retrying",
			"attempt", attempt, "max_attempts", firstSyncMaxAttempts, "backoff", backoff.String())
		select {
		case <-ctx.Done():
			return 0
		case <-time.After(backoff):
		}
		if backoff < firstSyncMaxBackoff {
			backoff *= 2
		}
	}
	logger.Error("initial full sync did not succeed after retries; continuing with periodic sync",
		"attempts", firstSyncMaxAttempts,
		"note", "a manual Sync action or the next reconnect will retry the full reconcile")
	return 0
}

// syncActionsFromServer fetches all assigned actions from the server and updates local store.
// This replaces the local action store with the server's current assignments.
// Actions that are no longer assigned will be removed locally.
// If firstSync is true, all actions are executed; otherwise only new actions are executed.
// Returns the effective sync interval from the server (0 means use default).
func syncActionsFromServer(ctx context.Context, client *sdk.Client, sched *scheduler.Scheduler, firstSync bool, logger *slog.Logger) time.Duration {
	logger.Info("syncing actions from server", "first_sync", firstSync)

	result, err := client.SyncActions(ctx)
	if err != nil {
		logger.Warn("failed to sync actions from server", "error", err)
		return 0
	}

	if err := sched.SyncActions(ctx, result.StandaloneActions, result.GroupedActions, firstSync); err != nil {
		logger.Error("failed to update local action store", "error", err)
		return 0
	}

	// Apply the resolved maintenance window from the same sync. Done
	// after SyncActions so the scheduler's next tick already gates by
	// the new window — and persisted via the scheduler so an agent
	// restart inside an active freeze keeps deferring instead of
	// blasting through queued work. See manchtools/power-manage-server#58.
	sched.SetMaintenanceWindow(result.MaintenanceWindow)

	// Apply the control server's LPS sealing key from the same sync. Verified
	// (CA signature) and persisted by the executor; a failure keeps the last
	// good key and is non-fatal to the sync — LPS rotation fails closed on its
	// own if no key is ever stored. See spec 18 / manchtools/power-manage-agent#62.
	if err := sched.ApplyLpsPublicKey(result.LpsPublicKey); err != nil {
		logger.Error("failed to apply control LPS public key; keeping previous key", "error", err)
	}

	// Convert sync interval from minutes to duration
	var syncInterval time.Duration
	if result.SyncIntervalMinutes > 0 {
		syncInterval = time.Duration(result.SyncIntervalMinutes) * time.Minute
	} else {
		syncInterval = defaultSyncInterval
	}

	logger.Info("actions synced from server",
		"standalone_total", len(result.StandaloneActions),
		"groups_total", len(result.GroupedActions),
		"first_sync", firstSync,
		"sync_interval", syncInterval.String(),
	)

	return syncInterval
}

// syncPendingResults sends any unsynced execution results to the server.
// This is called on connection to sync results that were stored while offline.
func syncPendingResults(ctx context.Context, sched *scheduler.Scheduler, client *sdk.Client, logger *slog.Logger) {
	results, err := sched.GetUnsyncedResults()
	if err != nil {
		logger.Warn("failed to get unsynced results", "error", err)
		return
	}

	if len(results) == 0 {
		return
	}

	logger.Info("syncing pending results", "count", len(results))

	for _, r := range results {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Skip unchanged successes unless this is the first execution of the action
		if !r.HasChanges && r.Status == pm.ExecutionStatus_EXECUTION_STATUS_SUCCESS && sched.HasPriorExecution(r.ActionID) {
			if err := sched.MarkResultSynced(r.ID); err != nil {
				logger.Warn("failed to mark result synced", "result_id", r.ID, "error", err)
			}
			continue
		}

		logger.Info("sending offline execution result",
			"action_id", r.ActionID,
			"status", r.Status.String(),
			"executed_at", r.ExecutedAt,
			"has_changes", r.HasChanges,
		)

		// Reconstruct ActionResult from StoredResult
		actionResult := &pm.ActionResult{
			ActionId:   &pm.ActionId{Value: r.ActionID},
			Status:     r.Status,
			Error:      r.Error,
			Output:     r.Output,
			DurationMs: r.DurationMs,
		}

		// Send result to server
		if err := client.SendActionResult(ctx, actionResult); err != nil {
			logger.Warn("failed to send offline result",
				"action_id", r.ActionID,
				"error", err,
			)
			// Don't mark as synced, will retry on next connection
			continue
		}

		if err := sched.MarkResultSynced(r.ID); err != nil {
			logger.Warn("failed to mark result synced", "result_id", r.ID, "error", err)
		}
	}
}

// sendSecurityAlert sends a security alert to the server for audit logging.
// This is called in a goroutine after connection is established.
func sendSecurityAlert(ctx context.Context, client *sdk.Client, alert *pendingSecurityAlert, logger *slog.Logger) {
	// Wait a moment to ensure connection is established
	select {
	case <-ctx.Done():
		return
	case <-time.After(2 * time.Second):
	}

	logger.Info("sending security alert to server",
		"type", alert.alertType,
		"message", alert.message,
	)

	// Map alert type string to proto enum
	var alertType pm.SecurityAlertType
	switch alert.alertType {
	case "server_reassignment_attempt":
		alertType = pm.SecurityAlertType_SECURITY_ALERT_TYPE_SERVER_REASSIGNMENT_ATTEMPT
	default:
		alertType = pm.SecurityAlertType_SECURITY_ALERT_TYPE_UNSPECIFIED
	}

	protoAlert := &pm.SecurityAlert{
		Type:    alertType,
		Message: alert.message,
		Details: map[string]string{
			"requested_server":  alert.requestedServer,
			"registered_server": alert.registeredServer,
		},
	}

	if err := client.SendSecurityAlert(ctx, protoAlert); err != nil {
		logger.Warn("failed to send security alert", "error", err)
	} else {
		logger.Debug("security alert sent successfully")
	}
}
