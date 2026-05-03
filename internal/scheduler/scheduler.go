// Package scheduler manages autonomous action execution on schedule.
// Actions run even when the agent is disconnected from the server.
package scheduler

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"sync"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/manchtools/power-manage/agent/internal/executor"
	"github.com/manchtools/power-manage/agent/internal/store"
	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

const (
	// DefaultCheckInterval is how often the scheduler checks for due actions
	DefaultCheckInterval = 1 * time.Minute
	// ResultRetention is how long to keep synced results
	ResultRetention = 7 * 24 * time.Hour
)

// ActionExecutor is the interface for executing actions.
type ActionExecutor interface {
	Execute(ctx context.Context, action *pb.Action) *pb.ActionResult
}

// Scheduler manages autonomous action execution.
type Scheduler struct {
	store    *store.Store
	executor ActionExecutor
	logger   *slog.Logger

	mu        sync.RWMutex
	running   bool
	stopCh    chan struct{}
	resultsCh chan *ExecutionResult
}

// ExecutionResult contains the result of a scheduled execution.
type ExecutionResult struct {
	ResultID   string // Unique ID for this execution result (for sync tracking)
	ActionID   string
	Result     *pb.ActionResult
	HasChanges bool
	ExecutedAt time.Time
}

// New creates a new scheduler.
func New(store *store.Store, executor ActionExecutor, logger *slog.Logger) *Scheduler {
	return &Scheduler{
		store:     store,
		executor:  executor,
		logger:    logger,
		resultsCh: make(chan *ExecutionResult, 100),
	}
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
	s.running = true
	s.stopCh = make(chan struct{})
	s.mu.Unlock()

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
		case <-s.stopCh:
			s.logger.Info("scheduler stopped")
			return
		case <-ticker.C:
			s.runDueActions(ctx)
		}
	}
}

// Stop stops the scheduler.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return
	}

	close(s.stopCh)
	s.running = false
}

// Results returns a channel for receiving execution results.
// These can be used to sync results to the server when connected.
func (s *Scheduler) Results() <-chan *ExecutionResult {
	return s.resultsCh
}

// AddAction adds or updates an action in the store.
func (s *Scheduler) AddAction(action *pb.Action) error {
	runOnAssign := false
	if action.Schedule != nil {
		runOnAssign = action.Schedule.RunOnAssign
	}
	return s.store.SaveAction(action, runOnAssign)
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
	actions, err := s.store.GetDueActions()
	if err != nil {
		s.logger.Error("failed to get due actions", "error", err)
		return
	}
	groups, err := s.store.GetDueGroups()
	if err != nil {
		s.logger.Error("failed to get due groups", "error", err)
		// Continue with standalone-only — group failures shouldn't
		// silently strand standalone work.
	}

	if len(actions) == 0 && len(groups) == 0 {
		return
	}

	if len(actions) > 0 || len(groups) > 0 {
		s.logger.Debug("found due actions", "standalone", len(actions), "groups", len(groups))
	}

	// Reset the per-cycle agent update dedup flag.
	executor.ResetAgentUpdateCycle()

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

	// Cleanup old results periodically.
	if err := s.store.CleanupOldResults(ResultRetention); err != nil {
		s.logger.Warn("failed to cleanup old results", "error", err)
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
	if err := s.store.MarkGroupExecuted(g.ID, time.Now()); err != nil {
		s.logger.Error("failed to mark group executed",
			"group_id", g.ID, "error", err)
	}
}

// executeAction executes a single action and records the result.
func (s *Scheduler) executeAction(ctx context.Context, stored *store.StoredAction) {
	action := stored.Action

	s.logger.Info("executing scheduled action",
		"action_id", action.Id.Value,
		"type", action.Type.String(),
	)

	// Execute the action
	result := s.executor.Execute(ctx, action)

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
		ExecutedAt: time.Now(),
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

// ForceExecute immediately executes an action regardless of schedule.
func (s *Scheduler) ForceExecute(ctx context.Context, actionID string) (*pb.ActionResult, error) {
	executor.ResetAgentUpdateCycle()
	stored, err := s.store.GetAction(actionID)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return nil, nil
	}

	result := s.executor.Execute(ctx, stored.Action)
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
	executor.ResetAgentUpdateCycle()

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

	s.logger.Info("actions synced successfully",
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

// revertAction executes an action with DESIRED_STATE_ABSENT to clean up its
// effects. This is best-effort — failures are logged but do not block removal.
func (s *Scheduler) revertAction(ctx context.Context, action *pb.Action) {
	reverted := proto.Clone(action).(*pb.Action)
	reverted.DesiredState = pb.DesiredState_DESIRED_STATE_ABSENT

	result := s.executor.Execute(ctx, reverted)
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
