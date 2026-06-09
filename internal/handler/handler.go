// Package handler implements the stream handler for the agent.
package handler

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/manchtools/power-manage/agent/internal/executor"
	"github.com/manchtools/power-manage/agent/internal/scheduler"
	"github.com/manchtools/power-manage/agent/internal/store"
	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
	"github.com/manchtools/power-manage/sdk/go/sys/inventory"
	"github.com/manchtools/power-manage/sdk/go/sys/osquery"
)

// Handler implements the SDK StreamHandler interface.
type Handler struct {
	logger       *slog.Logger
	executor     *executor.Executor
	osquery      *osquery.Registry // nil if osquery is not installed
	scheduler    *scheduler.Scheduler
	store        *store.Store
	syncTrigger  chan<- struct{} // triggers an immediate action sync (for SYNC instant action)
	mu           sync.Mutex      // protects connectedCh, connectedSet and the terminal* fields below
	connectedCh  chan struct{}   // closed when welcome is received and connection is ready
	connectedSet bool            // tracks if connectedCh has been closed

	// Remote terminal session state. terminals is the live registry,
	// guarded by mu. terminalSender is the SDK Client (or any
	// TerminalSender) injected at startup via SetTerminalSender; it
	// must be set before the SDK dispatch loop delivers the first
	// TerminalStart message. The sweeper goroutine is started lazily
	// on the first SetTerminalSender call.
	terminalSender         TerminalSender
	terminals              map[string]*terminalSession
	terminalLimit          int
	terminalIdleTimeout    time.Duration
	terminalSweeperStarted bool
	terminalSweeperStop    chan struct{} // closed by StopTerminalSweeper to stop the sweep loop
}

// NewHandler creates a new stream handler.
func NewHandler(logger *slog.Logger, exec *executor.Executor, sched *scheduler.Scheduler, st *store.Store, syncTrigger chan<- struct{}) *Handler {
	return &Handler{
		logger:      logger,
		executor:    exec,
		scheduler:   sched,
		store:       st,
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

	// Handle SYNC instant action directly — trigger sync and return success.
	//
	// The signature MUST be verified here. SYNC returns before
	// ExecuteWithStreaming, so the executor's verification never runs on
	// this path; without this check a compromised gateway/Valkey (the
	// F-31 threat model) could inject an unsigned type=SYNC and force
	// resyncs at will. #90 removed the executor's instant-action skip
	// but missed this fast-path, leaving SYNC forgeable.
	if action.Type == pb.ActionType_ACTION_TYPE_SYNC {
		if verifyErr := h.executor.VerifyAction(action); verifyErr != nil {
			h.logger.Warn("rejecting unsigned/tampered SYNC action", "action_id", action.Id.Value, "error", verifyErr)
			return &pb.ActionResult{
				ActionId:    action.Id,
				Status:      pb.ExecutionStatus_EXECUTION_STATUS_FAILED,
				Error:       fmt.Sprintf("refusing to execute unsigned/tampered action: %v", verifyErr),
				CompletedAt: timestamppb.Now(),
			}, nil
		}
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
		outputCallback = func(streamType sysexec.StreamType, line string, seq int64) {
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

	// Log output for debugging — but truncate + redact (audit F-32).
	// Shell scripts and configuration content may embed secrets
	// (LUKS passphrases, API tokens, the AES-GCM `enc:v1:` prefix
	// the server uses for secrets-at-rest). Truncating to a tail
	// preview keeps debugging useful for short-output checks
	// without dumping multi-KB payloads into journald + downstream
	// log shippers (Loki, journald-to-syslog forwarders, etc.).
	if result.Output != nil {
		if result.Output.Stdout != "" {
			h.logger.Debug("action stdout", "action_id", action.Id.Value, "stdout", sanitizeForLog(result.Output.Stdout))
		}
		if result.Output.Stderr != "" {
			h.logger.Debug("action stderr", "action_id", action.Id.Value, "stderr", sanitizeForLog(result.Output.Stderr))
		}
	}

	return result, nil
}

// maxLogOutputBytes caps each stream-line preview at 256 bytes
// (audit F-32). Sized to fit a typical "command failed" line + a
// short diagnostic header without spilling secret-bearing payloads
// into journald.
const maxLogOutputBytes = 256

// sanitizeForLog returns a log-safe rendering of an action's
// stdout/stderr stream: redacts AES-GCM ciphertext markers
// (`enc:v1:...`) and truncates the result to maxLogOutputBytes.
// The redaction is a static prefix scan — the same prefix the
// control server's internal/crypto.Encrypt produces — so any
// secret-at-rest blob that makes it into agent output never
// transits journald in plaintext.
func sanitizeForLog(s string) string {
	if s == "" {
		return s
	}
	// Redact AES-GCM ciphertext blobs. The encryptor emits the
	// fixed `enc:v1:` prefix followed by base64 — we replace the
	// whole token (prefix + base64 chars) with [REDACTED-ENC]
	// rather than only the prefix, so partial leakage of the
	// base64 body doesn't slip through.
	if strings.Contains(s, "enc:v1:") {
		s = redactEncMarkers(s)
	}
	if len(s) > maxLogOutputBytes {
		s = s[:maxLogOutputBytes] + "... [truncated by agent log filter]"
	}
	return s
}

// redactEncMarkers replaces every `enc:v1:<base64...>` run with
// `[REDACTED-ENC]`. Base64 chars are A-Z / a-z / 0-9 / + / / / =.
// We stop the run at any other character or end of string.
func redactEncMarkers(s string) string {
	const marker = "enc:v1:"
	var out strings.Builder
	out.Grow(len(s))
	for {
		idx := strings.Index(s, marker)
		if idx < 0 {
			out.WriteString(s)
			return out.String()
		}
		out.WriteString(s[:idx])
		out.WriteString("[REDACTED-ENC]")
		// Skip the marker plus the base64 run.
		i := idx + len(marker)
		for i < len(s) && isBase64Char(s[i]) {
			i++
		}
		s = s[i:]
	}
}

func isBase64Char(b byte) bool {
	return (b >= 'A' && b <= 'Z') ||
		(b >= 'a' && b <= 'z') ||
		(b >= '0' && b <= '9') ||
		b == '+' || b == '/' || b == '='
}

// isPathologicalGrepPattern flags regex shapes that are known to
// drive PCRE / RE2 into catastrophic backtracking (audit F-35).
// Returns a non-empty reason string when the pattern is rejected.
//
// The detector is intentionally conservative — it rejects on
// structural heuristics rather than trying to actually evaluate
// catastrophic-backtracking risk (which is undecidable in general).
// False positives are acceptable here: a rejected pattern returns a
// clean error to the caller; the worst-case is the operator has to
// rephrase a query. False negatives are not: a pathological pattern
// that slips through hangs `journalctl --grep` on the agent and
// denies log-query service.
//
// Rules (each independently disqualifying):
//   - nested quantifier on a group: `(...)*`, `(...)+`, `(...){n,}`
//     where the inner group contains its own quantifier (`*`, `+`,
//     `{n,}`). Classic `(a+)+`, `(a*)*`, `(a{1,})+` shapes.
//   - overlapping alternation under a quantifier: `(a|a)+`,
//     `(a|ab)+` — flagged by any `|` inside a quantified group.
//   - more than 5 unbounded quantifiers (`*`, `+`, `{n,}`) total —
//     compounds with the above rules to catch staircase patterns.
func isPathologicalGrepPattern(p string) string {
	// Count unbounded quantifiers — `*`, `+`, `{n,}`. `\` escapes
	// the following metachar so we skip a pair when we see one.
	unbounded := 0
	for i := 0; i < len(p); i++ {
		c := p[i]
		if c == '\\' && i+1 < len(p) {
			i++
			continue
		}
		switch c {
		case '*', '+':
			unbounded++
		case '{':
			if quantifierUnbounded(p[i:]) {
				unbounded++
			}
		}
	}
	if unbounded > 5 {
		return "too many unbounded quantifiers (max 5)"
	}

	// Walk groups and look for nested-quantifier / alternation-
	// under-quantifier shapes.
	depth := 0
	type groupState struct {
		start         int
		hasAlt        bool
		hasInnerQuant bool
	}
	var stack []groupState
	for i := 0; i < len(p); i++ {
		c := p[i]
		// Skip escapes — `\(` and `\|` are literal characters, not
		// regex metas.
		if c == '\\' && i+1 < len(p) {
			i++
			continue
		}
		switch c {
		case '(':
			stack = append(stack, groupState{start: i})
			depth++
		case ')':
			if depth == 0 {
				continue
			}
			top := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			depth--
			// Is the closing paren followed by an unbounded quantifier?
			if i+1 < len(p) {
				next := p[i+1]
				if next == '*' || next == '+' || (next == '{' && quantifierUnbounded(p[i+1:])) {
					if top.hasInnerQuant {
						return "nested unbounded quantifier (catastrophic backtracking shape)"
					}
					if top.hasAlt {
						return "alternation under unbounded quantifier (catastrophic backtracking shape)"
					}
				}
			}
		case '|':
			if depth > 0 {
				stack[len(stack)-1].hasAlt = true
			}
		case '*', '+':
			if depth > 0 {
				stack[len(stack)-1].hasInnerQuant = true
			}
		case '{':
			if j := strings.IndexByte(p[i:], '}'); j > 0 && quantifierUnbounded(p[i:]) {
				if depth > 0 {
					stack[len(stack)-1].hasInnerQuant = true
				}
				i += j
			}
		}
	}
	return ""
}

// quantifierUnbounded reports whether a `{n,m?}` token starting at
// p[0] is unbounded — `{n,}` is unbounded; `{n}` and `{n,m}` are
// bounded.
func quantifierUnbounded(p string) bool {
	if len(p) == 0 || p[0] != '{' {
		return false
	}
	j := strings.IndexByte(p, '}')
	if j <= 0 {
		return false
	}
	body := p[1:j]
	if !strings.Contains(body, ",") {
		return false // `{n}` — bounded
	}
	parts := strings.SplitN(body, ",", 2)
	return len(parts) == 2 && parts[1] == "" // `{n,}` — unbounded
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
		total, totalErr := strconv.ParseInt(data["memory_total"], 10, 64)
		free, freeErr := strconv.ParseInt(data["memory_free"], 10, 64)
		if totalErr != nil || freeErr != nil {
			// Audit F029: previously silent — a malformed osquery
			// row caused MemoryPercent to silently retain the prior
			// value or zero. Debug-only so a steady-state agent
			// doesn't flood logs.
			slog.Debug("heartbeat: memory_info parse failed",
				"memory_total_err", totalErr, "memory_free_err", freeErr)
		} else if total > 0 {
			// Only compute MemoryPercent when BOTH values parsed
			// cleanly — otherwise free defaults to 0 (CR catch on
			// PR #81) and we'd report 100% used on every heartbeat
			// for an agent whose osquery is missing memory_free.
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
		// Length cap + complexity check (audit F-35). The 256-char
		// length bound stops the most obvious DoS, but doesn't catch
		// adversarial ReDoS — `(a+)+b` is only 6 chars yet drives the
		// underlying PCRE engine into exponential backtracking. The
		// complexity guard refuses patterns whose **structure** is a
		// known catastrophic-backtracking shape, regardless of length.
		if len(query.Grep) > 256 {
			return &pb.LogQueryResult{
				QueryId: query.QueryId,
				Success: false,
				Error:   "grep pattern too long (max 256 characters)",
			}, nil
		}
		if reason := isPathologicalGrepPattern(query.Grep); reason != "" {
			return &pb.LogQueryResult{
				QueryId: query.QueryId,
				Success: false,
				Error:   "grep pattern rejected: " + reason,
			}, nil
		}
		args = append(args, "--grep", query.Grep)
	}
	if query.Kernel {
		args = append(args, "-k")
	}

	result, err := sysexec.Run(ctx, "journalctl", args...)
	if err != nil {
		// journalctl's human-readable failure message is on stderr;
		// surface that to the caller rather than the bare Go error.
		errMsg := ""
		if result != nil {
			errMsg = strings.TrimSpace(result.Stderr)
		}
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

	logs := result.Stdout
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
		// Only override baseline if osquery returned data
		if len(rows) > 0 {
			baseline[tableName] = &pb.InventoryTable{
				TableName: tableName,
				Rows:      rows,
			}
		}
	}

	for _, tableName := range packageTables {
		rows, err := oq.QueryTable(tableName)
		if err != nil {
			continue
		}
		if len(rows) > 0 {
			baseline[tableName] = &pb.InventoryTable{
				TableName: tableName,
				Rows:      rows,
			}
		}
	}

}

// Executor returns the executor for direct use.
func (h *Handler) Executor() *executor.Executor {
	return h.executor
}
