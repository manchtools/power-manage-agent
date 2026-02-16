// Package handler implements the stream handler for the agent.
package handler

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/manchtools/power-manage/agent/internal/executor"
	"github.com/manchtools/power-manage/agent/internal/osquery"
	"github.com/manchtools/power-manage/agent/internal/scheduler"
	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// Handler implements the SDK StreamHandler interface.
type Handler struct {
	logger       *slog.Logger
	executor     *executor.Executor
	osquery      *osquery.Registry // nil if osquery is not installed
	scheduler    *scheduler.Scheduler
	syncTrigger  chan<- struct{} // triggers an immediate action sync (for SYNC instant action)
	connectedCh  chan struct{}   // closed when welcome is received and connection is ready
	connectedSet bool            // tracks if connectedCh has been closed
}

// NewHandler creates a new stream handler.
func NewHandler(logger *slog.Logger, exec *executor.Executor, sched *scheduler.Scheduler, syncTrigger chan<- struct{}) *Handler {
	h := &Handler{
		logger:      logger,
		executor:    exec,
		scheduler:   sched,
		syncTrigger: syncTrigger,
		connectedCh: make(chan struct{}),
	}

	// Initialize osquery if installed (optional)
	registry, err := osquery.NewRegistry()
	if err != nil {
		if err == osquery.ErrNotInstalled {
			logger.Info("osquery not installed, query functionality disabled")
		} else {
			logger.Warn("failed to initialize osquery", "error", err)
		}
	} else {
		h.osquery = registry
		logger.Info("osquery initialized")
	}

	return h
}

// OnWelcome handles the welcome message from the server.
func (h *Handler) OnWelcome(ctx context.Context, welcome *pb.Welcome) error {
	h.logger.Info("received welcome from server", "server_version", welcome.ServerVersion)
	// Signal that connection is ready for sending messages
	if !h.connectedSet {
		close(h.connectedCh)
		h.connectedSet = true
	}
	return nil
}

// WaitConnected waits for the connection to be ready (welcome received).
// Returns immediately if already connected, or blocks until connected or context is cancelled.
func (h *Handler) WaitConnected(ctx context.Context) error {
	select {
	case <-h.connectedCh:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ResetConnection resets the connection state for reconnection.
// Must be called before each new connection attempt.
func (h *Handler) ResetConnection() {
	if h.connectedSet {
		h.connectedCh = make(chan struct{})
		h.connectedSet = false
	}
}

// OnAction handles action dispatch from the server.
// Actions are stored locally and executed on schedule for drift prevention.
func (h *Handler) OnAction(ctx context.Context, action *pb.Action) (*pb.ActionResult, error) {
	return h.OnActionWithStreaming(ctx, action, nil)
}

// OnActionWithStreaming handles action dispatch with optional output streaming.
// The sendChunk callback is called for each line of output during execution.
func (h *Handler) OnActionWithStreaming(ctx context.Context, action *pb.Action, sendChunk func(*pb.OutputChunk) error) (*pb.ActionResult, error) {
	h.logger.Info("received action", "action_id", action.Id.Value, "type", action.Type.String())

	// Handle SYNC instant action directly — trigger sync and return success
	if action.Type == pb.ActionType_ACTION_TYPE_SYNC {
		h.logger.Info("triggering immediate sync via instant action")
		if h.syncTrigger != nil {
			select {
			case h.syncTrigger <- struct{}{}:
				h.logger.Info("sync trigger sent")
			default:
				h.logger.Warn("sync trigger channel full, sync already pending")
			}
		}
		return &pb.ActionResult{
			ActionId:    action.Id,
			Status:      pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
			CompletedAt: timestamppb.Now(),
			Output:      &pb.CommandOutput{Stdout: "Sync triggered"},
		}, nil
	}

	// Store the action for scheduled execution (skip for instant actions — they're one-shot)
	if h.scheduler != nil && !executor.IsInstantAction(action.Type) {
		if err := h.scheduler.AddAction(action); err != nil {
			h.logger.Error("failed to store action", "action_id", action.Id.Value, "error", err)
		} else {
			h.logger.Info("action stored for scheduled execution", "action_id", action.Id.Value)
		}
	}

	// Create output callback if sendChunk is provided
	var outputCallback executor.OutputCallback
	if sendChunk != nil {
		executionID := action.Id.Value
		outputCallback = func(streamType int, line string, seq int64) {
			chunk := &pb.OutputChunk{
				ExecutionId: executionID,
				Stream:      pb.OutputStreamType(streamType),
				Data:        []byte(line),
				Sequence:    seq,
			}
			if err := sendChunk(chunk); err != nil {
				h.logger.Warn("failed to send output chunk", "error", err)
			}
		}
	}

	// Execute with streaming support
	result := h.executor.ExecuteWithStreaming(ctx, action, outputCallback)

	h.logger.Info("action completed",
		"action_id", action.Id.Value,
		"status", result.Status.String(),
		"duration_ms", result.DurationMs,
	)

	if result.Error != "" {
		h.logger.Error("action failed", "action_id", action.Id.Value, "error", result.Error)
	}

	// Log output for debugging
	if result.Output != nil {
		if result.Output.Stdout != "" {
			h.logger.Debug("action stdout", "action_id", action.Id.Value, "stdout", result.Output.Stdout)
		}
		if result.Output.Stderr != "" {
			h.logger.Debug("action stderr", "action_id", action.Id.Value, "stderr", result.Output.Stderr)
		}
	}

	return result, nil
}

// OnActionRemove handles action removal from the server.
func (h *Handler) OnActionRemove(ctx context.Context, actionID string) error {
	h.logger.Info("received action removal", "action_id", actionID)

	if h.scheduler != nil {
		if err := h.scheduler.RemoveAction(ctx, actionID); err != nil {
			h.logger.Error("failed to remove action", "action_id", actionID, "error", err)
			return err
		}
	}

	return nil
}

// OnQuery handles OS queries from the server.
func (h *Handler) OnQuery(ctx context.Context, query *pb.OSQuery) (*pb.OSQueryResult, error) {
	h.logger.Info("received query", "query_id", query.QueryId, "table", query.Table)

	// Check if osquery is available
	if h.osquery == nil {
		h.logger.Warn("osquery not available", "query_id", query.QueryId)
		return &pb.OSQueryResult{
			QueryId: query.QueryId,
			Success: false,
			Error:   "osquery is not installed on this system",
		}, nil
	}

	result, err := h.osquery.Query(query)
	if err != nil {
		h.logger.Error("query execution error", "query_id", query.QueryId, "error", err)
		return &pb.OSQueryResult{
			QueryId: query.QueryId,
			Success: false,
			Error:   err.Error(),
		}, nil
	}

	h.logger.Info("query completed", "query_id", query.QueryId, "success", result.Success, "row_count", len(result.Rows))
	return result, nil
}

// OnError handles error messages from the server.
func (h *Handler) OnError(ctx context.Context, err *pb.Error) error {
	h.logger.Error("received error from server", "code", err.Code, "message", err.Message)
	return nil
}

// BuildHeartbeat creates a heartbeat message with current system metrics.
func (h *Handler) BuildHeartbeat() *pb.Heartbeat {
	hb := &pb.Heartbeat{}

	// Skip metrics collection if osquery is not available
	if h.osquery == nil {
		return hb
	}

	// Get uptime
	if result, _ := h.osquery.Query(&pb.OSQuery{QueryId: "hb", Table: "uptime"}); result != nil && result.Success && len(result.Rows) > 0 {
		if sec, err := strconv.ParseInt(result.Rows[0].Data["total_seconds"], 10, 64); err == nil {
			hb.Uptime = durationpb.New(time.Duration(sec) * time.Second)
		}
	}

	// Get memory usage
	if result, _ := h.osquery.Query(&pb.OSQuery{QueryId: "hb", Table: "memory_info"}); result != nil && result.Success && len(result.Rows) > 0 {
		data := result.Rows[0].Data
		total, _ := strconv.ParseInt(data["memory_total"], 10, 64)
		free, _ := strconv.ParseInt(data["memory_free"], 10, 64)
		if total > 0 {
			hb.MemoryPercent = float32(100 * (total - free) / total)
		}
	}

	return hb
}

// OnRevokeLuksDeviceKey handles a LUKS device-bound key revocation request from the server.
// Implements sdk.LuksHandler.
func (h *Handler) OnRevokeLuksDeviceKey(ctx context.Context, actionID string) (bool, string) {
	h.logger.Info("received LUKS device key revocation", "action_id", actionID)
	success, errMsg := h.executor.RevokeLuksDeviceKey(ctx, actionID)
	if !success {
		h.logger.Error("LUKS device key revocation failed", "action_id", actionID, "error", errMsg)
	} else {
		h.logger.Info("LUKS device key revoked", "action_id", actionID)
	}
	return success, errMsg
}

// CollectInventory queries osquery for hardware/software inventory tables.
// Returns nil if osquery is not installed.
func (h *Handler) CollectInventory(ctx context.Context) *pb.DeviceInventory {
	if h.osquery == nil {
		return nil
	}

	// Core inventory tables (always collected)
	coreTables := []string{
		"system_info",
		"os_version",
		"kernel_info",
		"block_devices",
		"interface_details",
		"usb_devices",
		"pci_devices",
		"memory_info",
	}

	// Package tables (best-effort — skip if unavailable)
	packageTables := []string{
		"deb_packages",
		"rpm_packages",
		"python_packages",
	}

	var tables []*pb.InventoryTable

	for _, tableName := range coreTables {
		rows, err := h.osquery.QueryTable(tableName)
		if err != nil {
			h.logger.Debug("inventory table unavailable", "table", tableName, "error", err)
			continue
		}
		tables = append(tables, &pb.InventoryTable{
			TableName: tableName,
			Rows:      rows,
		})
	}

	for _, tableName := range packageTables {
		rows, err := h.osquery.QueryTable(tableName)
		if err != nil {
			continue // expected to fail on non-matching distros
		}
		tables = append(tables, &pb.InventoryTable{
			TableName: tableName,
			Rows:      rows,
		})
	}

	if len(tables) == 0 {
		return nil
	}

	h.logger.Info("inventory collected", "tables", len(tables))
	return &pb.DeviceInventory{Tables: tables}
}

// Executor returns the executor for direct use.
func (h *Handler) Executor() *executor.Executor {
	return h.executor
}
