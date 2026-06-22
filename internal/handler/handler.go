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

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/inventory"
	syslog "github.com/manchtools/power-manage-sdk/sys/log"
	"github.com/manchtools/power-manage-sdk/sys/osquery"
	"github.com/manchtools/power-manage-sdk/validate"
	"github.com/manchtools/power-manage/agent/internal/executor"
	"github.com/manchtools/power-manage/agent/internal/scheduler"
	"github.com/manchtools/power-manage/agent/internal/store"
)

// streamValidator validates incoming stream-RPC messages at the agent boundary
// (validate → verify-signature → execute). The control server already validates
// before dispatch; this is defense-in-depth so a malformed message is rejected
// before any signature/root work.
var streamValidator = validate.NewValidator()

// handlerRunner is the unprivileged runner OnLogQuery shells out through (the
// agent runs as root; journalctl reads run directly, matching the prior
// unprivileged sysexec.Run behaviour).
var handlerRunner = func() sysexec.Runner {
	r, err := sysexec.NewRunner(sysexec.Direct)
	if err != nil {
		panic("handler: Direct runner must construct: " + err.Error())
	}
	return r
}()

// osqueryRunner is the minimal osquery surface the handler uses. Declared as an
// interface (vs the concrete osquery client) so tests can inject a fake that
// records calls — letting the WS4 charter assert "osquery was NOT invoked" when
// a stream-RPC signature is missing/invalid. The SDK's osquery.Querier satisfies it.
type osqueryRunner interface {
	Query(ctx context.Context, query *pb.OSQuery) (*pb.OSQueryResult, error)
	QueryTable(ctx context.Context, tableName string) ([]*pb.OSQueryRow, error)
}

// Handler implements the SDK StreamHandler interface.
type Handler struct {
	logger       *slog.Logger
	executor     *executor.Executor
	osquery      osqueryRunner // nil if osquery is not installed
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

	now func() time.Time // clock seam; defaults to time.Now, overridden in tests
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
		now:         time.Now,
	}
}

// getOsquery returns the osquery registry, initializing it lazily on first use.
// If osquery was not found previously, it re-checks so that osquery installed
// after the agent started is detected without requiring a restart.
func (h *Handler) getOsquery() osqueryRunner {
	h.mu.Lock()
	defer h.mu.Unlock()

	if h.osquery != nil {
		return h.osquery
	}

	registry, err := osquery.New(handlerRunner)
	if err != nil {
		return nil
	}

	h.osquery = registry
	h.logger.Info("osquery detected and initialized")
	return registry
}

// setOsqueryForTest injects a fake osquery runner so tests can assert whether a
// stream-RPC reached osquery (call-count) under a missing/invalid signature.
func (h *Handler) setOsqueryForTest(r osqueryRunner) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.osquery = r
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
func (h *Handler) OnAction(ctx context.Context, envelope []byte, signature []byte) (*pb.ActionResult, error) {
	return h.OnActionWithStreaming(ctx, envelope, signature, nil)
}

// OnActionWithStreaming handles action dispatch with optional output streaming.
// The sendChunk callback is called for each line of output during execution.
//
// The handler receives the SIGNED envelope bytes and the CA signature. It
// verifies the signature over those bytes and unmarshals THOSE SAME bytes
// into a SignedActionEnvelope (VerifyEnvelope) BEFORE any side effect — no
// storing, no sync trigger, no execution happens on an unverified envelope
// (sdk#82). Verification is fail-closed: any verify/unmarshal error returns a
// FAILED result and nothing runs.
func (h *Handler) OnActionWithStreaming(ctx context.Context, envelope []byte, signature []byte, sendChunk func(*pb.OutputChunk) error) (*pb.ActionResult, error) {
	// Verify FIRST. The verified envelope is the only thing we act on; we read
	// the type/id/params off it, never off any advisory wire field. A failure
	// here is a hard refusal — return FAILED and do not store, sync, or run.
	env, err := h.executor.VerifyEnvelope(envelope, signature)
	if err != nil {
		h.logger.Warn("refusing to execute unsigned/tampered action", "error", err)
		return &pb.ActionResult{
			Status:      pb.ExecutionStatus_EXECUTION_STATUS_FAILED,
			Error:       fmt.Sprintf("refusing to execute unsigned/tampered action: %v", err),
			CompletedAt: timestamppb.Now(),
		}, nil
	}

	actionID := env.GetActionId().GetValue()
	h.logger.Info("received action", "action_id", actionID, "type", env.GetActionType().String())

	// Handle SYNC instant action directly — trigger sync and return success.
	//
	// Safe because the type is bound INSIDE the verified envelope: a signature
	// minted for a non-SYNC action cannot be lifted onto a SYNC envelope, and
	// a non-SYNC envelope delivered here can never reach this branch. SYNC
	// returns before the executor's typed switch, so verifying the envelope
	// up front is the only thing that can enforce the CA signature on this
	// path — which we now always do above.
	if env.GetActionType() == pb.ActionType_ACTION_TYPE_SYNC {
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
			ActionId:    env.GetActionId(),
			Status:      pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
			CompletedAt: timestamppb.Now(),
			Output:      &pb.CommandOutput{Stdout: "Sync triggered"},
		}, nil
	}

	// Store the action for scheduled execution (skip for instant and one-off
	// actions). The stored wire Action carries the verified envelope bytes +
	// signature so the offline scheduler re-verifies and executes the SAME
	// bytes later; the typed oneof on the stored Action is advisory only.
	if h.scheduler != nil && !executor.IsInstantAction(env.GetActionType()) && env.GetActionType() != pb.ActionType_ACTION_TYPE_SCRIPT_RUN {
		stored := &pb.Action{
			Id:             env.GetActionId(),
			Type:           env.GetActionType(),
			DesiredState:   env.GetDesiredState(),
			TimeoutSeconds: env.GetTimeoutSeconds(),
			Schedule:       env.GetSchedule(),
			SignedEnvelope: envelope,
			Signature:      signature,
		}
		if err := h.scheduler.AddAction(stored); err != nil {
			h.logger.Error("failed to store action", "action_id", actionID, "error", err)
		} else {
			h.logger.Info("action stored for scheduled execution", "action_id", actionID)
		}
	}

	// Create output callback if sendChunk is provided
	var outputCallback executor.OutputCallback
	if sendChunk != nil {
		executionID := actionID
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

	// Execute the VERIFIED envelope with streaming support.
	result := h.executor.ExecuteWithStreaming(ctx, env, outputCallback)

	h.logger.Info("action completed",
		"action_id", actionID,
		"status", result.Status.String(),
		"duration_ms", result.DurationMs,
	)

	if result.Error != "" {
		h.logger.Error("action failed", "action_id", actionID, "error", result.Error)
	}

	// Log output for debugging — but truncate + redact (audit F-32).
	// The exact contract (see sanitizeForLog): the AES-GCM `enc:v1:`
	// ciphertext token the server uses for secrets-at-rest is redacted,
	// and the whole preview is length-bounded. A PLAINTEXT secret (a LUKS
	// passphrase or API token printed without the enc:v1: prefix) is NOT
	// redacted — only length-bounded — so this is a payload-size guard plus
	// ciphertext redaction, not a plaintext-secret scrubber. Truncating to a
	// tail preview keeps debugging useful for short-output checks without
	// dumping multi-KB payloads into journald + downstream log shippers
	// (Loki, journald-to-syslog forwarders, etc.).
	if result.Output != nil {
		if result.Output.Stdout != "" {
			h.logger.Debug("action stdout", "action_id", actionID, "stdout", sanitizeForLog(result.Output.Stdout))
		}
		if result.Output.Stderr != "" {
			h.logger.Debug("action stderr", "action_id", actionID, "stderr", sanitizeForLog(result.Output.Stderr))
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

	// Validate at the boundary (validate → verify → execute).
	if msg, ok := validate.Struct(streamValidator, query); !ok {
		h.logger.Warn("rejecting invalid query", "query_id", query.GetQueryId(), "error", msg)
		return &pb.OSQueryResult{QueryId: query.GetQueryId(), Success: false, Error: msg}, nil
	}

	// WS4: verify the CA signature before ANY osquery execution (incl. raw SQL).
	// Fail-closed — a missing/tampered/wrong-domain signature, or no verifier,
	// is refused and osquery is never invoked.
	if err := h.executor.VerifyOSQuery(query); err != nil {
		h.logger.Warn("refusing unsigned/tampered query", "query_id", query.GetQueryId(), "error", err)
		return &pb.OSQueryResult{
			QueryId: query.GetQueryId(),
			Success: false,
			Error:   "refusing to execute unsigned/tampered query: " + err.Error(),
		}, nil
	}

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

	result, err := oq.Query(ctx, query)
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
	if result, _ := oq.Query(context.Background(), &pb.OSQuery{QueryId: "hb", Table: "uptime"}); result != nil && result.Success && len(result.Rows) > 0 {
		if sec, err := strconv.ParseInt(result.Rows[0].Data["total_seconds"], 10, 64); err == nil {
			hb.Uptime = durationpb.New(time.Duration(sec) * time.Second)
		}
	}

	// Get memory usage
	if result, _ := oq.Query(context.Background(), &pb.OSQuery{QueryId: "hb", Table: "memory_info"}); result != nil && result.Success && len(result.Rows) > 0 {
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
func (h *Handler) OnRevokeLuksDeviceKey(ctx context.Context, req *pb.RevokeLuksDeviceKey) (bool, string) {
	actionID := req.GetActionId()
	h.logger.Info("received LUKS device key revocation", "action_id", actionID)

	// WS4: the slot-7 device-key wipe is destructive and irreversible — verify
	// the CA signature binding action_id before touching the executor.
	// Fail-closed (incl. nil verifier).
	if err := h.executor.VerifyRevokeLuksDeviceKey(req); err != nil {
		h.logger.Error("refusing unsigned/tampered LUKS device key revocation", "action_id", actionID, "error", err)
		return false, "refusing to revoke unsigned/tampered LUKS device key: " + err.Error()
	}

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

	// Validate at the boundary (validate → verify → execute).
	if msg, ok := validate.Struct(streamValidator, query); !ok {
		h.logger.Warn("rejecting invalid log query", "query_id", query.GetQueryId(), "error", msg)
		return &pb.LogQueryResult{QueryId: query.GetQueryId(), Success: false, Error: msg}, nil
	}

	// WS4: journalctl runs as root — verify the CA signature before building any
	// journalctl invocation. Fail-closed.
	if err := h.executor.VerifyLogQuery(query); err != nil {
		h.logger.Warn("refusing unsigned/tampered log query", "query_id", query.GetQueryId(), "error", err)
		return &pb.LogQueryResult{
			QueryId: query.GetQueryId(),
			Success: false,
			Error:   "refusing to execute unsigned/tampered log query: " + err.Error(),
		}, nil
	}

	// The journalctl invocation — including the line cap, the priority
	// allow-list, the grep length cap + ReDoS guard, and the -k kernel filter —
	// is owned by the SDK sys/log source (it ported the agent's grep-guard
	// verbatim). Build the query and let it validate + run. handlerRunner is the
	// agent's Direct runner: the SDK marks the journalctl command Escalate:true,
	// which is a no-op on Direct (the agent already runs as root), so behaviour is
	// unchanged.
	src, err := syslog.New(syslog.Journald, handlerRunner)
	if err != nil {
		h.logger.Warn("log query setup failed", "query_id", query.QueryId, "error", err)
		return &pb.LogQueryResult{QueryId: query.QueryId, Success: false, Error: err.Error()}, nil
	}
	lines, err := src.Query(ctx, syslog.Query{
		Unit:     query.Unit,
		Since:    query.Since,
		Until:    query.Until,
		Priority: query.Priority,
		Grep:     query.Grep,
		Kernel:   query.Kernel,
		Lines:    int(query.Lines),
	})
	if err != nil {
		// Surfaces both the SDK's validation rejections (invalid priority,
		// over-cap/pathological grep) and journalctl's own failure (the
		// CommandError carries stderr).
		h.logger.Warn("log query failed", "query_id", query.QueryId, "error", err)
		return &pb.LogQueryResult{QueryId: query.QueryId, Success: false, Error: err.Error()}, nil
	}

	logs := strings.Join(lines, "\n")
	// Truncate to 1MB if needed (keep the tail).
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

// OnRequestInventory handles a SERVER-originated inventory collection request.
// Implements sdk.InventoryHandler. The request is verified fail-closed before
// any osquery runs (WS4) — a compromised gateway cannot forge it. The
// agent-initiated periodic path calls CollectInventory directly and needs no
// signature.
func (h *Handler) OnRequestInventory(ctx context.Context, req *pb.RequestInventory) *pb.DeviceInventory {
	// WS4: a server-originated request runs osquery as root — verify the CA
	// signature before collecting. Fail-closed (incl. nil verifier): a forged
	// request from a compromised gateway returns nil and never runs osquery.
	if err := h.executor.VerifyRequestInventory(req); err != nil {
		h.logger.Warn("refusing unsigned/tampered inventory request", "query_id", req.GetQueryId(), "error", err)
		return nil
	}
	return h.CollectInventory(ctx)
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

	inv, err := inventory.New(handlerRunner)
	if err != nil {
		h.logger.Debug("baseline inventory unavailable", "error", err)
		return tables
	}

	// system_info + kernel_info (single System call)
	if sysInfo, err := inv.System(ctx); err == nil {
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
	if osInfo, err := inv.OS(); err == nil {
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
	if disks, err := inv.Disks(ctx); err == nil {
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
	if ifaces, err := inv.NetworkInterfaces(ctx); err == nil {
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
// inventoryCoreTables and inventoryPackageTables are the FIXED, hardcoded set
// of osquery tables CollectInventory may query. They are never derived from a
// server-supplied request (a RequestInventory carries no table field) — this is
// what bounds the blast radius of an inventory request. Declared at package
// scope so a test can read them and assert that CollectInventory queries
// exactly this union (self-discovering: adding a table here keeps the test
// green; querying a table NOT here fails it).
var (
	inventoryCoreTables = []string{
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
	inventoryPackageTables = []string{
		"deb_packages",
		"rpm_packages",
		"python_packages",
	}
)

func (h *Handler) supplementWithOsquery(oq osqueryRunner, baseline map[string]*pb.InventoryTable) {
	// osquery tables that override baseline
	coreTables := inventoryCoreTables

	// Package tables (best-effort)
	packageTables := inventoryPackageTables

	for _, tableName := range coreTables {
		rows, err := oq.QueryTable(context.Background(), tableName)
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
		rows, err := oq.QueryTable(context.Background(), tableName)
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
