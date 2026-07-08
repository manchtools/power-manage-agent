// Package scheduler manages autonomous action execution on schedule.
// Actions run even when the agent is disconnected from the server.
package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/maintenance"
	"github.com/manchtools/power-manage/agent/internal/store"
)

const (
	// DefaultCheckInterval is how often the scheduler checks for due actions
	DefaultCheckInterval = 1 * time.Minute
	// ResultRetention is how long to keep synced results
	ResultRetention = 7 * 24 * time.Hour
)

// ActionExecutor is the interface for executing actions.
//
// The scheduler decides WHEN to run (per-action / per-group schedule,
// maintenance window) but WHAT runs is always the verified envelope: it
// verifies the stored signed bytes via VerifyEnvelope and executes the
// returned SignedActionEnvelope via ExecuteEnvelope (sdk#82). There is no
// path that executes a wire *pb.Action's advisory typed oneof directly.
type ActionExecutor interface {
	// VerifyEnvelope verifies the CA signature over the exact envelope bytes
	// and unmarshals THOSE SAME bytes into a SignedActionEnvelope. It is
	// fail-closed: any verify/unmarshal error (or a missing verifier) returns
	// an error and the caller must NOT execute.
	VerifyEnvelope(envelopeBytes, signature []byte) (*pb.SignedActionEnvelope, error)
	// ExecuteEnvelope runs a previously-VERIFIED envelope and returns the
	// result. Callers must pass only an envelope returned by VerifyEnvelope.
	ExecuteEnvelope(ctx context.Context, env *pb.SignedActionEnvelope) *pb.ActionResult
	// ResetUpdateCycle clears the per-cycle AGENT_UPDATE dedup
	// flag on the executor instance so a new sync cycle can run an
	// update again (audit F042 + F048).
	ResetUpdateCycle()
	// ApplyLpsPublicKey verifies the control server's CA-signed LPS sealing
	// key against the agent's enrollment CA and, on success, persists it for
	// the LPS seal path. Fail-closed: a bad signature or missing verifier
	// leaves any prior key untouched and returns an error (spec 18).
	ApplyLpsPublicKey(signed *pb.LpsPublicKey) error
}

// maintenanceWindowSettingKey is the agent-store settings key under
// which the most-recently-synced resolved MaintenanceWindow lives.
// Persisting it across restarts means an agent that boots inside a
// freeze window won't blast through queued actions just because it
// hasn't completed its first sync yet.
const maintenanceWindowSettingKey = "maintenance_window"

// Scheduler manages autonomous action execution.
type Scheduler struct {
	store    *store.Store
	executor ActionExecutor
	logger   *slog.Logger

	now func() time.Time // clock seam; defaults to time.Now, overridden in tests

	// mu guards Start/Stop transitions only. resultsCh is set once
	// at construction in New() and is read on the receiver side
	// without the lock — the lock here exists purely to make the
	// running/stopCh state machine race-free, NOT to serialise
	// access to the results channel. Audit F019: previously
	// documented as "protects running, stopCh, resultsCh" which was
	// misleading.
	mu      sync.RWMutex
	running bool
	stopCh  chan struct{}
	// done is closed when the Start loop returns. Stop() blocks on it so a
	// caller can join the scheduler goroutine before closing the store (WS14 #9)
	// — execution is synchronous in the loop, so once Start returns the last
	// runDueActions (and its RecordExecution) has fully committed. Set in Start
	// under mu; nil before the first Start.
	done chan struct{}

	// resultsCh is created once in New and never reassigned, so it
	// is safe to read/write without the lock from any goroutine.
	resultsCh chan *ExecutionResult

	// windowMu guards window and windowDecodeFailed. Separate from mu so a
	// long Sync that also holds mu cannot block runDueActions' window check
	// on a scheduler that's already started.
	windowMu sync.RWMutex
	window   *pb.MaintenanceWindow
	// windowDecodeFailed is the fail-CLOSED sentinel: set when a PERSISTED
	// maintenance window existed at boot but could not be proto-decoded
	// (tampered/corrupt). While set, dispatchAllowed denies every moment —
	// deny-until-next-sync — so a corrupt persisted gate can never silently
	// unconstrain the agent. Cleared by the next SetMaintenanceWindow.
	windowDecodeFailed bool
}

// ExecutionResult contains the result of a scheduled execution.
type ExecutionResult struct {
	ResultID   string // Unique ID for this execution result (for sync tracking)
	ActionID   string
	Result     *pb.ActionResult
	HasChanges bool
	ExecutedAt time.Time
}

// New creates a new scheduler. The persisted maintenance window (if
// any) is restored from the agent store so a restart inside an active
// freeze keeps gating dispatches until the next sync overwrites it.
func New(store *store.Store, executor ActionExecutor, logger *slog.Logger) *Scheduler {
	s := &Scheduler{
		store:    store,
		executor: executor,
		logger:   logger,
		now:      time.Now,
		// resultsCh buffer is sized for typical tick volume (one
		// channel write per scheduled action result). When full,
		// executeAction logs a Warn and continues — the result is
		// still persisted to SQLite, so syncPendingResults will pick
		// it up on the next reconnect. Audit F036: documented so the
		// drop behaviour is visible to readers.
		resultsCh: make(chan *ExecutionResult, 100),
	}
	if w, err := loadMaintenanceWindow(store); err != nil {
		// FAIL CLOSED. A persisted window existed but could not be decoded
		// (corrupt/tampered settings row). Leaving s.window nil would make
		// IsAllowed(nil, t) == true and UNCONSTRAIN dispatch — the opposite
		// of what an unreadable freeze should do. Set the deny-until-sync
		// sentinel instead; the next SetMaintenanceWindow clears it.
		logger.Error("persisted maintenance window could not be decoded; failing CLOSED (denying dispatch until next sync)",
			"error", err)
		s.windowDecodeFailed = true
	} else {
		s.window = w
	}
	return s
}

// SetMaintenanceWindow replaces the active window in memory and on
// disk. A nil or empty window clears the gate; non-empty windows are
// deep-cloned so the caller cannot mutate the cached pointer after
// returning. Persistence errors are logged but non-fatal — the
// in-memory pointer is still updated so the running scheduler
// reflects the latest sync.
func (s *Scheduler) SetMaintenanceWindow(w *pb.MaintenanceWindow) {
	var normalized *pb.MaintenanceWindow
	if w != nil && len(w.GetSchedule()) > 0 {
		normalized = proto.Clone(w).(*pb.MaintenanceWindow)
	}
	s.windowMu.Lock()
	s.window = normalized
	// A successful sync replaces whatever was on disk, so the corrupt-window
	// deny sentinel (if any) no longer applies — clear it. This is what makes
	// the fail-closed posture "until next sync" rather than a permanent brick.
	s.windowDecodeFailed = false
	s.windowMu.Unlock()
	if err := storeMaintenanceWindow(s.store, normalized); err != nil {
		s.logger.Warn("failed to persist maintenance window; in-memory only", "error", err)
	}
}

// ApplyLpsPublicKey delegates to the executor, which owns the LPS verifier
// and the seal path. Mirrors SetMaintenanceWindow's role as the sync-response
// applier; verification + persistence + fail-closed policy live in the
// executor (spec 18).
func (s *Scheduler) ApplyLpsPublicKey(signed *pb.LpsPublicKey) error {
	return s.executor.ApplyLpsPublicKey(signed)
}

// activeWindow returns a snapshot of the current window for read
// without holding the lock during evaluation.
func (s *Scheduler) activeWindow() *pb.MaintenanceWindow {
	s.windowMu.RLock()
	defer s.windowMu.RUnlock()
	return s.window
}

// dispatchAllowed reports whether scheduled dispatch may run at t. It is the
// single gate consulted by runDueActions and the fail-closed sentinel point: a
// corrupt persisted window denies here until the next sync. The flag and the
// window are read under one lock so the deny sentinel and the window snapshot
// cannot race apart.
func (s *Scheduler) dispatchAllowed(t time.Time) bool {
	s.windowMu.RLock()
	failed := s.windowDecodeFailed
	window := s.window
	s.windowMu.RUnlock()
	if failed {
		return false
	}
	return maintenance.IsAllowed(window, t)
}

// loadMaintenanceWindow restores the persisted window from settings.
// An empty / missing entry yields (nil, nil) — the agent boots
// unconstrained, which is the same default a fresh-install device
// gets before its first sync. Encoded with proto wire format so any
// future field added to MaintenanceWindow round-trips automatically;
// a JSON shadow schema would silently drop new fields and let the
// post-restart evaluator diverge from the live one.
func loadMaintenanceWindow(st *store.Store) (*pb.MaintenanceWindow, error) {
	raw, err := st.GetSetting(maintenanceWindowSettingKey)
	if err != nil || raw == "" {
		return nil, err
	}
	out := &pb.MaintenanceWindow{}
	if err := proto.Unmarshal([]byte(raw), out); err != nil {
		return nil, err
	}
	if len(out.GetSchedule()) == 0 {
		return nil, nil
	}
	return out, nil
}

// storeMaintenanceWindow encodes the window for the settings table.
// nil / empty windows clear the row so a subsequent restart sees
// "no constraint" (matches the SetMaintenanceWindow contract: empty
// in = unconstrained out). Uses proto wire format so persistence
// stays bound to the message shape the shared evaluator consumes.
func storeMaintenanceWindow(st *store.Store, w *pb.MaintenanceWindow) error {
	if w == nil || len(w.GetSchedule()) == 0 {
		return st.DeleteSetting(maintenanceWindowSettingKey)
	}
	raw, err := proto.Marshal(w)
	if err != nil {
		return err
	}
	return st.SetSetting(maintenanceWindowSettingKey, string(raw))
}

// HasPriorExecution returns true if the action has been executed before.
// Used to determine if an unchanged result should be reported (first run)
// or skipped (subsequent runs).
func (s *Scheduler) HasPriorExecution(actionID string) bool {
	return s.store.HasPriorExecution(actionID)
}

// Start begins the scheduler loop.
func (s *Scheduler) Start(ctx context.Context) {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return
	}
	// Join a previous loop that Stop() has signalled but which has not
	// exited yet (#173 review finding): Stop flips running=false before
	// <-done, so without this join a Start racing the drain would
	// allocate fresh channels and run a SECOND loop concurrently with
	// the old one — double-executing due actions. Join outside the
	// lock (the same rule Stop follows), then re-check running: another
	// Start may have won the race while we waited.
	if prev := s.done; prev != nil {
		s.mu.Unlock()
		<-prev
		s.mu.Lock()
		if s.running {
			s.mu.Unlock()
			return
		}
	}
	s.running = true
	s.stopCh = make(chan struct{})
	s.done = make(chan struct{})
	// Capture stopCh into a local under the lock. The select below
	// reads this local, never the shared s.stopCh field — so Stop()
	// mutating s.stopCh can't race the reader (audit F020 regression).
	stopCh := s.stopCh
	done := s.done
	s.mu.Unlock()

	// Closed when the loop returns so Stop() can join before the store closes
	// (WS14 #9). Execution is synchronous in this loop, so a closed done means
	// no runDueActions / RecordExecution is in flight.
	defer close(done)

	s.logger.Info("scheduler started")

	ticker := time.NewTicker(DefaultCheckInterval)
	defer ticker.Stop()

	// Run immediately on start to catch any due actions
	s.runDueActions(ctx)

	for {
		select {
		case <-ctx.Done():
			s.logger.Info("scheduler stopped by context")
			return
		case <-stopCh:
			s.logger.Info("scheduler stopped")
			return
		case <-ticker.C:
			s.runDueActions(ctx)
		}
	}
}

// Stop stops the scheduler. Safe to call multiple times and safe to
// call on a never-Start()'d scheduler — both no-op without panicking.
//
// The `running` flag (set true with stopCh under the same lock in
// Start, cleared here) is the guard: a pre-Start or repeat Stop sees
// running=false and returns before touching stopCh, so close() runs at
// most once on a non-nil channel. We deliberately do NOT nil out
// s.stopCh — Start reads a local copy, and a stale closed channel is
// harmless because the next Start() reassigns it (audit F020; the
// earlier nil-assignment raced Start's select reader).
// Stop signals the scheduler loop to halt and BLOCKS until it has returned
// (WS14 #9), so a caller can guarantee any in-flight execution's RecordExecution
// has committed before closing the store. Safe to call when not running.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	if !s.running {
		s.mu.Unlock()
		return
	}
	close(s.stopCh)
	s.running = false
	done := s.done
	s.mu.Unlock()

	// Join the loop OUTSIDE the lock: runDueActions doesn't take s.mu, but
	// waiting under the lock would still deadlock a concurrent Start()/Stop().
	if done != nil {
		<-done
	}
}

// Results returns a channel for receiving execution results.
// These can be used to sync results to the server when connected.
func (s *Scheduler) Results() <-chan *ExecutionResult {
	return s.resultsCh
}

// AddAction adds or updates an action in the store. The dispatch caller
// executes the action inline, so SaveAction advances the stored cursor
// to the next scheduled occurrence (run_on_assign is honored by that
// inline execution, not by the stored next_execute_at).
func (s *Scheduler) AddAction(action *pb.Action) error {
	if err := s.store.SaveAction(action); err != nil {
		// Wrap with the action_id so the caller's "failed to store
		// action" log line points at the specific action that
		// failed instead of just the generic class. Audit F030.
		return fmt.Errorf("save action %s: %w", action.GetId().GetValue(), err)
	}
	return nil
}

// RemoveAction removes an action from the store. Policy-type actions (SSH,
// SSHD, Sudo, LPS) are executed with DESIRED_STATE_ABSENT first to clean up
// their effects on the device.
func (s *Scheduler) RemoveAction(ctx context.Context, actionID string) error {
	stored, err := s.store.GetAction(actionID)
	if err == nil && stored != nil && shouldRevertOnUnassign(stored.Action.Type) {
		s.revertAction(ctx, stored.Action)
	}
	return s.store.RemoveAction(actionID)
}

// GetStoredActions returns all stored actions.
func (s *Scheduler) GetStoredActions() ([]*store.StoredAction, error) {
	return s.store.GetAllActions()
}

// runDueActions executes all actions that are due — both standalone
// actions (per-action schedule) and grouped actions (one schedule per
// container, members run in declared order when the container fires).
//
// Standalone actions run first, then groups. Within a group every
// member executes serially in declared order; the executor is the
// existing single-action path, so the group simply iterates and
// dispatches one at a time. This is what gives manchtools/power-manage-
// agent#45 its ordering guarantee: when a container fires, all of its
// members enter the queue together rather than each firing
// independently and racing.
func (s *Scheduler) runDueActions(ctx context.Context) {
	actions, err := s.store.GetDueActions(ctx)
	if err != nil {
		s.logger.Error("failed to get due actions", "error", err)
		return
	}
	groups, err := s.store.GetDueGroups(ctx)
	if err != nil {
		s.logger.Error("failed to get due groups", "error", err)
		// Continue with standalone-only — group failures shouldn't
		// silently strand standalone work.
	}

	if len(actions) == 0 && len(groups) == 0 {
		return
	}

	// Maintenance-window gate. Evaluated in device-local time so
	// "02:00 local" means 02:00 wherever the device runs (the server
	// can't compute this; only the agent knows its time.Local). When
	// the active window denies the moment, every due item defers to
	// the next tick — runDueActions does NOT advance next_execute_at,
	// so a deferred action stays "due" until the window opens.
	//
	// The window does not gate the stream-dispatched path: instant
	// actions (REBOOT, SYNC) and pushed dispatches arrive through
	// the gateway and bypass this scheduler entirely. That matches
	// the spec — admins hitting "reboot now" expect immediate
	// execution.
	if !s.dispatchAllowed(s.now().Local()) {
		s.logger.Info("maintenance window closed; deferring due dispatches",
			"standalone", len(actions),
			"groups", len(groups),
		)
		return
	}

	if len(actions) > 0 || len(groups) > 0 {
		s.logger.Debug("found due actions", "standalone", len(actions), "groups", len(groups))
	}

	// Reset the per-cycle agent update dedup flag.
	s.executor.ResetUpdateCycle()

	for _, stored := range actions {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.executeAction(ctx, stored)
	}

	for _, g := range groups {
		select {
		case <-ctx.Done():
			return
		default:
		}
		s.executeGroup(ctx, g)
	}

	// Cleanup old results periodically. Bounds the table independently of sync
	// state (WS13 #6): unsynced eviction means undelivered results were dropped
	// to protect local disk — surface it loudly.
	if unsyncedEvicted, err := s.store.CleanupOldResults(ResultRetention); err != nil {
		s.logger.Warn("failed to cleanup old results", "error", err)
	} else if unsyncedEvicted > 0 {
		s.logger.Warn("evicted UNSYNCED results to bound the offline store; undelivered results were dropped",
			"count", unsyncedEvicted)
	}
}

// executeGroup walks a due group's members in declared order, dispatches
// each through the existing per-action executor, and advances the
// group's next_execute_at when all members have been attempted.
//
// A failure on one member does NOT short-circuit the rest — this is a
// deliberate design choice from the #45 design discussion. The original
// issue text proposed cascading SKIPPED_DEPENDENCY_FAILED to siblings,
// but during design we landed on simpler "ordered execution + idempotent
// retries" semantics: members run in declared order on every group fire,
// and a failed member fails again next cycle. Sibling failures don't
// hide root-cause failures — they each surface their own status — but
// we don't fabricate skip records for them either. If an operator wants
// strict skip-on-failure with explicit dependency reporting later,
// that's a follow-up that re-introduces SKIPPED_DEPENDENCY_FAILED.
func (s *Scheduler) executeGroup(ctx context.Context, g store.StoredActionGroup) {
	s.logger.Info("group due",
		"group_id", g.ID,
		"member_count", len(g.MemberActionIDs),
	)

	for _, actionID := range g.MemberActionIDs {
		select {
		case <-ctx.Done():
			return
		default:
		}

		stored, err := s.store.GetAction(actionID)
		if err != nil {
			s.logger.Error("failed to get group member action",
				"group_id", g.ID, "action_id", actionID, "error", err)
			continue
		}
		if stored == nil {
			s.logger.Warn("group member action missing from store",
				"group_id", g.ID, "action_id", actionID)
			continue
		}

		s.executeAction(ctx, stored)
	}

	// Mark the group as fired so its next_execute_at advances.
	if err := s.store.MarkGroupExecuted(g.ID, s.now()); err != nil {
		s.logger.Error("failed to mark group executed",
			"group_id", g.ID, "error", err)
	}
}

// verifyAndExecute is the single verify-then-execute seam the scheduler runs
// for every stored action (sdk#82). It verifies the action's stored signed
// envelope bytes and executes the VERIFIED envelope. On any verify/unmarshal
// failure — tampered store row, missing signature, no verifier — it returns a
// FAILED result and does NOT call the executor. The scheduler reads the wire
// Action only for WHEN/grouping metadata; WHAT runs is the verified envelope.
func (s *Scheduler) verifyAndExecute(ctx context.Context, action *pb.Action) *pb.ActionResult {
	env, err := s.executor.VerifyEnvelope(action.GetSignedEnvelope(), action.GetSignature())
	if err != nil {
		s.logger.Warn("refusing to run unsigned/tampered stored action",
			"action_id", action.GetId().GetValue(),
			"type", action.GetType().String(),
			"error", err,
		)
		return &pb.ActionResult{
			ActionId: action.GetId(),
			Status:   pb.ExecutionStatus_EXECUTION_STATUS_FAILED,
			Error:    fmt.Sprintf("refusing to execute unsigned/tampered action: %v", err),
		}
	}
	return s.executor.ExecuteEnvelope(ctx, env)
}

// executeAction executes a single action and records the result.
func (s *Scheduler) executeAction(ctx context.Context, stored *store.StoredAction) {
	action := stored.Action

	s.logger.Info("executing scheduled action",
		"action_id", action.Id.Value,
		"type", action.Type.String(),
	)

	// Advance the due cursor BEFORE executing. If the agent crashes between
	// here and RecordExecution, the action is no longer due on the next boot,
	// so a non-idempotent action is not silently applied twice. RecordExecution
	// writes the authoritative cursor on success; this is the in-flight guard.
	if err := s.store.MarkActionStarted(action.Id.Value); err != nil {
		s.logger.Warn("failed to mark action started; proceeding without crash-replay guard",
			"action_id", action.Id.Value, "error", err)
	}

	// Verify the stored signed envelope and execute THOSE bytes.
	result := s.verifyAndExecute(ctx, action)

	// If context was cancelled, don't record or send results
	if ctx.Err() != nil {
		s.logger.Info("action interrupted by shutdown",
			"action_id", action.Id.Value,
		)
		return
	}

	// Determine if there were changes by comparing output hash
	hasChanges := s.detectChanges(stored, result)

	// Log based on changes
	if hasChanges {
		s.logger.Info("action completed with changes",
			"action_id", action.Id.Value,
			"status", result.Status.String(),
			"duration_ms", result.DurationMs,
		)
	} else {
		s.logger.Debug("action completed (no changes)",
			"action_id", action.Id.Value,
			"status", result.Status.String(),
			"duration_ms", result.DurationMs,
		)
	}

	if result.Error != "" {
		s.logger.Error("action failed",
			"action_id", action.Id.Value,
			"error", result.Error,
		)
	}

	// Record the execution and get the result ID for sync tracking
	resultID, err := s.store.RecordExecution(action.Id.Value, result, hasChanges)
	if err != nil {
		s.logger.Error("failed to record execution",
			"action_id", action.Id.Value,
			"error", err,
		)
		return
	}

	// Send result to channel for potential sync
	select {
	case s.resultsCh <- &ExecutionResult{
		ResultID:   resultID,
		ActionID:   action.Id.Value,
		Result:     result,
		HasChanges: hasChanges,
		ExecutedAt: s.now(),
	}:
	default:
		s.logger.Warn("result channel full, dropping result",
			"action_id", action.Id.Value,
		)
	}
}

// detectChanges determines whether an execution result should be reported to
// the server. It uses the executor's Changed flag (set accurately by every
// action type) and optionally compares output hashes for SkipIfUnchanged actions.
func (s *Scheduler) detectChanges(stored *store.StoredAction, result *pb.ActionResult) bool {
	// Always consider non-success statuses as changes
	if result.Status != pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS {
		return true
	}

	// Compliance/detection scripts must always be reported so the server
	// can track compliance status, even when the detection result is unchanged.
	if shell := stored.Action.GetShell(); shell != nil {
		if shell.GetIsCompliance() || (shell.GetDetectionScript() != "" && shell.GetScript() == "") {
			return true
		}
	}

	// Use the executor's changed flag — all action types set this accurately.
	// For example, package already installed → false, SSH config matches → false.
	if !result.Changed {
		return false
	}

	// For SkipIfUnchanged actions, also compare output hashes. This catches
	// shell scripts (which always set Changed=true without a detection script)
	// that produce identical output across runs.
	if stored.Action.Schedule != nil && stored.Action.Schedule.SkipIfUnchanged {
		if stored.LastResultHash != "" {
			currentHash := ""
			if result.Output != nil {
				h := sha256.New()
				h.Write([]byte(result.Output.Stdout))
				h.Write([]byte(result.Output.Stderr))
				currentHash = hex.EncodeToString(h.Sum(nil))
			}
			return currentHash != stored.LastResultHash
		}
	}

	return true
}

// GetUnsyncedResults returns results that need to be synced to the server.
func (s *Scheduler) GetUnsyncedResults() ([]*store.StoredResult, error) {
	return s.store.GetUnsyncedResults()
}

// MarkResultSynced marks a result as synced.
func (s *Scheduler) MarkResultSynced(resultID string) error {
	return s.store.MarkResultSynced(resultID)
}

// IsResultSynced reports whether a result has already been sent.
func (s *Scheduler) IsResultSynced(resultID string) (bool, error) {
	return s.store.IsResultSynced(resultID)
}

// ForceExecute immediately executes an action regardless of schedule.
func (s *Scheduler) ForceExecute(ctx context.Context, actionID string) (*pb.ActionResult, error) {
	s.executor.ResetUpdateCycle()
	stored, err := s.store.GetAction(actionID)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, nil
	}

	result := s.verifyAndExecute(ctx, stored.Action)
	hasChanges := s.detectChanges(stored, result)

	if _, err := s.store.RecordExecution(actionID, result, hasChanges); err != nil {
		s.logger.Error("failed to record execution", "error", err)
	}

	return result, nil
}

// SyncActions replaces all stored actions with the provided list from the server.
// This syncs the local action store with the server's assigned actions.
// Removed standalone actions: policy-type actions (SSH, SSHD, Sudo, LPS,
// USER, GROUP) are reverted to ABSENT state before removal. Other types
// are removed without reverting to avoid destructive side effects.
// Changed actions (desired_state flipped, or migrated standalone↔grouped)
// are re-executed.
// New actions are executed immediately on first sync.
//
// Grouped actions are stored with their containers (action_groups +
// group_members) and only fire when their group's schedule is due —
// they are NOT executed individually here. New groups are handled by
// runDueActions on the next tick (their initial next_execute_at honors
// the schedule's run_on_assign / interval). The scheduler's per-tick
// loop fires every due group's members in declared order, which is the
// ordering guarantee introduced for #45.
func (s *Scheduler) SyncActions(ctx context.Context, standalone []*pb.Action, groups []*pb.ActionGroup, firstSync bool) error {
	// Check for shutdown before starting
	if ctx.Err() != nil {
		return ctx.Err()
	}

	// Reset the per-cycle agent update dedup flag for the sync batch.
	s.executor.ResetUpdateCycle()

	s.logger.Info("syncing actions from server",
		"standalone", len(standalone),
		"groups", len(groups),
		"first_sync", firstSync)

	// Sync actions to store and get change info
	syncResult, err := s.store.SyncStandaloneAndGrouped(standalone, groups)
	if err != nil {
		s.logger.Error("failed to sync actions", "error", err)
		return err
	}

	// synced_total counts every action received — standalone PLUS each group's
	// members — so the line doesn't read as "nothing received" when an action set
	// arrived but carried no standalone actions (standalone_total=0).
	syncedTotal := len(standalone)
	for _, g := range groups {
		syncedTotal += len(g.GetActions())
	}
	s.logger.Info("actions synced successfully",
		"synced_total", syncedTotal,
		"standalone_total", len(standalone),
		"groups_total", len(groups),
		"new_standalone", len(syncResult.NewActionIDs),
		"changed_standalone", len(syncResult.ChangedActionIDs),
		"new_groups", len(syncResult.NewGroupIDs),
		"removed_standalone", len(syncResult.RemovedActions),
	)

	// Revert policy-type actions before removal to clean up their effects.
	if len(syncResult.RemovedActions) > 0 {
		for _, removed := range syncResult.RemovedActions {
			if removed.Id != nil {
				if shouldRevertOnUnassign(removed.Type) {
					s.logger.Info("reverting policy action before unassignment",
						"action_id", removed.Id.Value,
						"type", removed.Type.String(),
					)
					s.revertAction(ctx, removed)
				} else {
					s.logger.Info("action unassigned from device",
						"action_id", removed.Id.Value,
						"type", removed.Type.String(),
					)
				}
			}
		}
	}

	// Determine which standalone actions to execute right now.
	var actionsToExecute []string
	if firstSync {
		for _, action := range standalone {
			if action.Id != nil {
				actionsToExecute = append(actionsToExecute, action.Id.Value)
			}
		}
		if len(actionsToExecute) > 0 {
			s.logger.Info("first sync: executing all standalone actions", "count", len(actionsToExecute))
		}
	} else {
		actionsToExecute = append(syncResult.NewActionIDs, syncResult.ChangedActionIDs...)
		if len(actionsToExecute) > 0 {
			s.logger.Info("executing new/changed standalone actions", "count", len(actionsToExecute))
		}
	}

	for _, actionID := range actionsToExecute {
		select {
		case <-ctx.Done():
			s.logger.Info("sync cancelled, skipping remaining actions")
			return ctx.Err()
		default:
		}

		stored, err := s.store.GetAction(actionID)
		if err != nil {
			s.logger.Error("failed to get action for execution", "action_id", actionID, "error", err)
			continue
		}
		if stored == nil {
			s.logger.Warn("action not found in store", "action_id", actionID)
			continue
		}

		s.logger.Info("executing action",
			"action_id", actionID,
			"type", stored.Action.Type.String(),
			"desired_state", stored.Action.DesiredState.String(),
		)

		s.executeAction(ctx, stored)
	}

	return nil
}

// shouldRevertOnUnassign returns true for action types whose effects should
// be cleaned up when the action is unassigned from a device. USER and GROUP
// join the policy-style reverters because a user or group created by an
// assignment should not outlive it — leaving the account on disk after a
// scope change is an access-leak.
func shouldRevertOnUnassign(actionType pb.ActionType) bool {
	switch actionType {
	case pb.ActionType_ACTION_TYPE_SSH,
		pb.ActionType_ACTION_TYPE_SSHD,
		pb.ActionType_ACTION_TYPE_ADMIN_POLICY,
		pb.ActionType_ACTION_TYPE_LPS,
		pb.ActionType_ACTION_TYPE_USER,
		pb.ActionType_ACTION_TYPE_GROUP:
		return true
	default:
		return false
	}
}

// revertAction executes a policy action's cleanup with DESIRED_STATE_ABSENT.
// This is best-effort — failures are logged but do not block removal.
//
// Revert is the one path that does NOT run a server-signed desired_state: the
// server never signs an ABSENT envelope for an action it is unassigning, so
// the agent synthesizes the ABSENT run locally. To stay faithful to sdk#82 we
// still source the params (and id/type/timeout/schedule) from the VERIFIED
// envelope — we verify the stored signed bytes, take the authenticated params
// from them, and only locally override desired_state to ABSENT. We never lift
// the unverified wire Action's typed oneof. If the stored envelope fails to
// verify (tampered/unsigned store row) we refuse to run the revert rather
// than execute attacker-controlled params under a privileged cleanup.
func (s *Scheduler) revertAction(ctx context.Context, action *pb.Action) {
	env, err := s.executor.VerifyEnvelope(action.GetSignedEnvelope(), action.GetSignature())
	if err != nil {
		s.logger.Warn("refusing to revert unsigned/tampered action",
			"action_id", action.GetId().GetValue(),
			"type", action.GetType().String(),
			"error", err,
		)
		return
	}

	reverted := proto.Clone(env).(*pb.SignedActionEnvelope)
	reverted.DesiredState = pb.DesiredState_DESIRED_STATE_ABSENT

	result := s.executor.ExecuteEnvelope(ctx, reverted)
	if result.Status == pb.ExecutionStatus_EXECUTION_STATUS_FAILED {
		s.logger.Warn("failed to revert action",
			"action_id", action.Id.Value,
			"type", action.Type.String(),
			"error", result.Error,
		)
	} else {
		s.logger.Info("action reverted successfully",
			"action_id", action.Id.Value,
			"type", action.Type.String(),
		)
	}
}
