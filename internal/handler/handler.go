// Package handler implements the stream handler for the agent.
package handler

import (
	"context"
	"log/slog"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/manchtools/power-manage/agent/internal/executor"
	"github.com/manchtools/power-manage/agent/internal/scheduler"
	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/sys/inventory"
	"github.com/manchtools/power-manage/sdk/go/sys/osquery"
)

// Handler implements the SDK StreamHandler interface.
type Handler struct {
	logger       *slog.Logger
	executor     *executor.Executor
	osquery      *osquery.Registry // nil if osquery is not installed
	scheduler    *scheduler.Scheduler
	syncTrigger  chan<- struct{} // triggers an immediate action sync (for SYNC instant action)
	mu           sync.Mutex     // protects connectedCh and connectedSet
	connectedCh  chan struct{}   // closed when welcome is received and connection is ready
	connectedSet bool           // tracks if connectedCh has been closed
}

// NewHandler creates a new stream handler.
func NewHandler(logger *slog.Logger, exec *executor.Executor, sched *scheduler.Scheduler, syncTrigger chan<- struct{}) *Handler {
	return &Handler{
		logger:      logger,
		executor:    exec,
		scheduler:   sched,
		syncTrigger: syncTrigger,
		connectedCh: make(chan struct{}),
	}
}

// getOsquery returns the osquery registry, initializing it lazily on first use.
// If osquery was not found previously, it re-checks so that osquery installed
// after the agent started is detected without requiring a restart.
func (h *Handler) getOsquery() *osquery.Registry {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.osquery != nil {
		return h.osquery
	}

	registry, err := osquery.NewRegistry()
	if err != nil {
		return nil
	}

	h.osquery = registry
	h.logger.Info("osquery detected and initialized")
	return registry
}

// OnWelcome handles the welcome message from the server.
func (h *Handler) OnWelcome(ctx context.Context, welcome *pb.Welcome) error {
	h.logger.Info("received welcome from server", "server_version", welcome.ServerVersion)

	// Signal that connection is ready for sending messages
	h.mu.Lock()
	if !h.connectedSet {
		close(h.connectedCh)
		h.connectedSet = true
	}
	h.mu.Unlock()

	return nil
}

// WaitConnected waits for the connection to be ready (welcome received).
// Returns immediately if already connected, or blocks until connected or context is cancelled.
func (h *Handler) WaitConnected(ctx context.Context) error {
	h.mu.Lock()
	ch := h.connectedCh
	h.mu.Unlock()
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// ResetConnection resets the connection state for reconnection.
// Must be called before each new connection attempt.
func (h *Handler) ResetConnection() {
	h.mu.Lock()
	if h.connectedSet {
		h.connectedCh = make(chan struct{})
		h.connectedSet = false
	}
	h.mu.Unlock()
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

	// Store the action for scheduled execution (skip for instant and one-off actions)
	if h.scheduler != nil && !executor.IsInstantAction(action.Type) && action.Type != pb.ActionType_ACTION_TYPE_SCRIPT_RUN {
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

	// Check if osquery is available (lazy init — detects installs without restart)
	oq := h.getOsquery()
	if oq == nil {
		h.logger.Warn("osquery not available", "query_id", query.QueryId)
		return &pb.OSQueryResult{
			QueryId: query.QueryId,
			Success: false,
			Error:   "osquery is not installed on this system",
		}, nil
	}

	result, err := oq.Query(query)
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
	oq := h.getOsquery()
	if oq == nil {
		return hb
	}

	// Get uptime
	if result, _ := oq.Query(&pb.OSQuery{QueryId: "hb", Table: "uptime"}); result != nil && result.Success && len(result.Rows) > 0 {
		if sec, err := strconv.ParseInt(result.Rows[0].Data["total_seconds"], 10, 64); err == nil {
			hb.Uptime = durationpb.New(time.Duration(sec) * time.Second)
		}
	}

	// Get memory usage
	if result, _ := oq.Query(&pb.OSQuery{QueryId: "hb", Table: "memory_info"}); result != nil && result.Success && len(result.Rows) > 0 {
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

// OnLogQuery handles a remote journalctl log query from the server.
// Implements sdk.LogQueryHandler.
func (h *Handler) OnLogQuery(ctx context.Context, query *pb.LogQuery) (*pb.LogQueryResult, error) {
	h.logger.Info("received log query", "query_id", query.QueryId, "unit", query.Unit)

	args := []string{"--no-pager"}

	lines := query.Lines
	if lines <= 0 {
		lines = 100
	}
	if lines > 10000 {
		lines = 10000
	}
	args = append(args, "-n", strconv.Itoa(int(lines)))

	if query.Unit != "" {
		args = append(args, "-u", query.Unit)
	}
	if query.Since != "" {
		args = append(args, "--since", query.Since)
	}
	if query.Until != "" {
		args = append(args, "--until", query.Until)
	}
	if query.Priority != "" {
		// Validate priority against known values
		switch strings.ToLower(query.Priority) {
		case "0", "1", "2", "3", "4", "5", "6", "7",
			"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug":
			args = append(args, "-p", query.Priority)
		default:
			return &pb.LogQueryResult{
				QueryId: query.QueryId,
				Success: false,
				Error:   "invalid priority value",
			}, nil
		}
	}
	if query.Grep != "" {
		// Limit grep pattern length to prevent ReDoS via crafted regex
		if len(query.Grep) > 256 {
			return &pb.LogQueryResult{
				QueryId: query.QueryId,
				Success: false,
				Error:   "grep pattern too long (max 256 characters)",
			}, nil
		}
		args = append(args, "--grep", query.Grep)
	}
	if query.Kernel {
		args = append(args, "-k")
	}

	out, err := exec.CommandContext(ctx, "journalctl", args...).CombinedOutput()
	if err != nil {
		errMsg := strings.TrimSpace(string(out))
		if errMsg == "" {
			errMsg = err.Error()
		}
		h.logger.Warn("log query failed", "query_id", query.QueryId, "error", errMsg)
		return &pb.LogQueryResult{
			QueryId: query.QueryId,
			Success: false,
			Error:   errMsg,
		}, nil
	}

	logs := string(out)
	// Truncate to 1MB if needed (keep the tail)
	if len(logs) > 1<<20 {
		logs = logs[len(logs)-(1<<20):]
	}

	h.logger.Info("log query completed", "query_id", query.QueryId, "bytes", len(logs))
	return &pb.LogQueryResult{
		QueryId: query.QueryId,
		Success: true,
		Logs:    logs,
	}, nil
}

// CollectInventory gathers device inventory from two sources:
// 1. SDK inventory package — always available, provides baseline system info
// 2. osquery — optional, provides richer data (packages, USB, PCI, etc.)
//
// When both are available, osquery tables override the SDK baseline for tables
// that exist in both (system_info, os_version, block_devices, interface_details).
func (h *Handler) CollectInventory(ctx context.Context) *pb.DeviceInventory {
	// Phase 1: Collect baseline from SDK (always available, no dependencies)
	tables := h.collectBaselineInventory(ctx)

	// Phase 2: Supplement/override with osquery if available
	oq := h.getOsquery()
	if oq != nil {
		h.supplementWithOsquery(oq, tables)
	}

	if len(tables) == 0 {
		return nil
	}

	// Convert map to slice for proto
	result := make([]*pb.InventoryTable, 0, len(tables))
	for _, t := range tables {
		result = append(result, t)
	}

	h.logger.Info("inventory collected", "tables", len(result), "osquery", oq != nil)
	return &pb.DeviceInventory{Tables: result}
}

// collectBaselineInventory uses the SDK inventory package to gather basic
// system information without osquery. Returns tables in osquery-compatible format.
func (h *Handler) collectBaselineInventory(ctx context.Context) map[string]*pb.InventoryTable {
	tables := make(map[string]*pb.InventoryTable)

	// system_info + kernel_info (single GetSystemInfo call)
	if sysInfo, err := inventory.GetSystemInfo(ctx); err == nil {
		tables["system_info"] = &pb.InventoryTable{
			TableName: "system_info",
			Rows: []*pb.OSQueryRow{{Data: map[string]string{
				"hostname":          sysInfo.Hostname,
				"cpu_brand":         sysInfo.CPUModel,
				"cpu_logical_cores": strconv.Itoa(sysInfo.CPUCores),
				"physical_memory":   strconv.FormatInt(sysInfo.MemoryTotalMB*1024*1024, 10),
			}}},
		}
		if sysInfo.KernelVersion != "" {
			tables["kernel_info"] = &pb.InventoryTable{
				TableName: "kernel_info",
				Rows: []*pb.OSQueryRow{{Data: map[string]string{
					"version": sysInfo.KernelVersion,
				}}},
			}
		}
	} else {
		h.logger.Debug("baseline system_info unavailable", "error", err)
	}

	// os_version
	if osInfo, err := inventory.GetOSInfo(); err == nil {
		tables["os_version"] = &pb.InventoryTable{
			TableName: "os_version",
			Rows: []*pb.OSQueryRow{{Data: map[string]string{
				"name":     osInfo.Name,
				"version":  osInfo.Version,
				"platform": osInfo.ID,
				"arch":     osInfo.Arch,
			}}},
		}
	} else {
		h.logger.Debug("baseline os_version unavailable", "error", err)
	}

	// block_devices
	if disks, err := inventory.GetDisks(ctx); err == nil {
		var rows []*pb.OSQueryRow
		for _, d := range disks {
			rows = append(rows, &pb.OSQueryRow{Data: map[string]string{
				"name":  d.Device,
				"size":  d.Size,
				"type":  d.Type,
				"label": d.Mount,
			}})
		}
		if len(rows) > 0 {
			tables["block_devices"] = &pb.InventoryTable{
				TableName: "block_devices",
				Rows:      rows,
			}
		}
	} else {
		h.logger.Debug("baseline block_devices unavailable", "error", err)
	}

	// interface_details + interface_addresses
	if ifaces, err := inventory.GetNetworkInterfaces(ctx); err == nil {
		var detailRows, addrRows []*pb.OSQueryRow
		for _, iface := range ifaces {
			detailRows = append(detailRows, &pb.OSQueryRow{Data: map[string]string{
				"interface": iface.Name,
				"mac":       iface.MAC,
				"type":      "",
			}})
			for _, addr := range iface.Addresses {
				addrRows = append(addrRows, &pb.OSQueryRow{Data: map[string]string{
					"interface": iface.Name,
					"address":   addr,
				}})
			}
		}
		if len(detailRows) > 0 {
			tables["interface_details"] = &pb.InventoryTable{
				TableName: "interface_details",
				Rows:      detailRows,
			}
		}
		if len(addrRows) > 0 {
			tables["interface_addresses"] = &pb.InventoryTable{
				TableName: "interface_addresses",
				Rows:      addrRows,
			}
		}
	} else {
		h.logger.Debug("baseline network interfaces unavailable", "error", err)
	}

	return tables
}

// supplementWithOsquery queries osquery for richer inventory data and overrides
// baseline tables where osquery provides the same data.
func (h *Handler) supplementWithOsquery(oq *osquery.Registry, baseline map[string]*pb.InventoryTable) {
	// osquery tables that override baseline
	coreTables := []string{
		"system_info",
		"os_version",
		"kernel_info",
		"block_devices",
		"interface_details",
		"interface_addresses",
		"usb_devices",
		"pci_devices",
		"memory_info",
	}

	// Package tables (best-effort)
	packageTables := []string{
		"deb_packages",
		"rpm_packages",
		"python_packages",
	}

	for _, tableName := range coreTables {
		rows, err := oq.QueryTable(tableName)
		if err != nil {
			h.logger.Debug("osquery table unavailable", "table", tableName, "error", err)
			continue
		}
		// Override baseline with richer osquery data
		baseline[tableName] = &pb.InventoryTable{
			TableName: tableName,
			Rows:      rows,
		}
	}

	for _, tableName := range packageTables {
		rows, err := oq.QueryTable(tableName)
		if err != nil {
			continue
		}
		baseline[tableName] = &pb.InventoryTable{
			TableName: tableName,
			Rows:      rows,
		}
	}

}

// Executor returns the executor for direct use.
func (h *Handler) Executor() *executor.Executor {
	return h.executor
}
