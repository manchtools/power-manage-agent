// Package main is the entry point for the power-manage agent.
package main

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/manchtools/power-manage/agent/internal/credentials"
	"github.com/manchtools/power-manage/agent/internal/handler"
	"github.com/manchtools/power-manage/agent/internal/scheduler"
	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sdk "github.com/manchtools/power-manage/sdk/go"
)

// runAgent connects to the gateway and processes messages.
// The agent continues to run scheduled actions even when disconnected.
// If securityAlert is non-nil, it will be sent to the server after connection.
func runAgent(ctx context.Context, creds *credentials.Credentials, hostname string, h *handler.Handler, sched *scheduler.Scheduler, syncTrigger <-chan struct{}, securityAlert *pendingSecurityAlert, logger *slog.Logger) {
	// Current sync interval (can be updated by server)
	syncInterval := defaultSyncInterval

	// Track if this is the first successful sync (execute all actions)
	firstSync := true

	// Exponential backoff for reconnection
	currentBackoff := randomBackoff()

	for {
		// Reset handler connection state for new connection
		h.ResetConnection()

		// rc10: refuse http:// (h2c) for the network gateway path.
		// The only h2c use in this binary is the local unix-socket
		// enrollment client, never a remote gateway. A stored
		// `http://` GatewayAddr means either a dev-leftover creds
		// file or a tampered redirect — both are reasons to fail
		// fast rather than silently skip mTLS on the live fleet.
		if strings.HasPrefix(creds.GatewayAddr, "http://") {
			logger.Error("refusing h2c gateway URL — agent requires https:// for gateway connections; re-enrol against an https:// gateway or delete the cached credentials",
				"gateway", creds.GatewayAddr)
			os.Exit(1)
		}
		mtlsOpt, err := sdk.WithMTLSFromPEM(creds.Certificate, creds.PrivateKey, creds.CACert)
		if err != nil {
			logger.Error("failed to configure mTLS", "error", err)
			os.Exit(1)
		}
		client := sdk.NewClient(creds.GatewayAddr,
			mtlsOpt,
			sdk.WithAuth(creds.DeviceID, ""),
		)

		// Create a child context for this connection session
		sessionCtx, cancelSession := context.WithCancel(ctx)

		// Wire LUKS key store to the current client for this connection session
		h.Executor().SetLuksKeyStore(&clientLuksKeyStore{client: client})

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

		// Sync actions from server (unary RPC — stream is connecting in parallel)
		newInterval := syncActionsFromServer(sessionCtx, client, sched, firstSync, logger)
		if newInterval > 0 {
			syncInterval = newInterval
			firstSync = false
		}

		if securityAlert != nil {
			go sendSecurityAlert(sessionCtx, client, securityAlert, logger)
			securityAlert = nil
		}

		// Start periodic sync goroutine (also listens for instant sync triggers)
		syncDone := make(chan struct{})
		go func() {
			defer close(syncDone)
			periodicSync(sessionCtx, client, sched, &syncInterval, syncTrigger, logger)
		}()

		// Start result sender goroutine to send scheduled execution results to server
		resultsDone := make(chan struct{})
		go func() {
			defer close(resultsDone)
			sendScheduledResults(sessionCtx, client, sched, logger)
		}()

		// Wait for the stream to end
		connStart := time.Now()
		err = <-streamDone

		// Stop the goroutines and clear connection-dependent state
		cancelSession()
		h.Executor().SetLuksKeyStore(nil)
		<-syncDone
		<-resultsDone

		if ctx.Err() != nil {
			logger.Info("agent stopped")
			return
		}

		// Reset backoff if the connection was stable (lasted longer than the backoff interval)
		if time.Since(connStart) > currentBackoff {
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

// periodicSync runs a loop that periodically syncs actions from the server.
// The interval can be dynamically updated based on server response.
// Also listens on syncTrigger for instant sync requests.
func periodicSync(ctx context.Context, client *sdk.Client, sched *scheduler.Scheduler, syncInterval *time.Duration, syncTrigger <-chan struct{}, logger *slog.Logger) {
	ticker := time.NewTicker(*syncInterval)
	defer ticker.Stop()

	logger.Info("periodic sync started", "interval", syncInterval.String())

	doSync := func(reason string) {
		logger.Info("syncing actions", "reason", reason)
		newInterval := syncActionsFromServer(ctx, client, sched, false, logger)
		if newInterval > 0 && newInterval != *syncInterval {
			*syncInterval = newInterval
			ticker.Reset(*syncInterval)
			logger.Info("sync interval updated", "new_interval", syncInterval.String())
		}
	}

	for {
		select {
		case <-ctx.Done():
			logger.Debug("periodic sync stopped")
			return
		case <-ticker.C:
			doSync("periodic")
		case <-syncTrigger:
			doSync("instant action trigger")
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
