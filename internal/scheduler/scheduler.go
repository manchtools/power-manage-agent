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

// runDueActions executes all actions that are due.
func (s *Scheduler) runDueActions(ctx context.Context) {
	actions, err := s.store.GetDueActions()
	if err != nil {
		s.logger.Error("failed to get due actions", "error", err)
		return
	}

	if len(actions) == 0 {
		return
	}

	s.logger.Debug("found due actions", "count", len(actions))

	for _, stored := range actions {
		select {
		case <-ctx.Done():
			return
		default:
		}

		s.executeAction(ctx, stored)
	}

	// Cleanup old results periodically
	if err := s.store.CleanupOldResults(ResultRetention); err != nil {
		s.logger.Warn("failed to cleanup old results", "error", err)
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

// detectChanges compares the current output with the previous output.
func (s *Scheduler) detectChanges(stored *store.StoredAction, result *pb.ActionResult) bool {
	// Always consider failures as changes
	if result.Status != pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS {
		return true
	}

	// If skip_if_unchanged is not set, always report as changed
	if stored.Action.Schedule == nil || !stored.Action.Schedule.SkipIfUnchanged {
		return true
	}

	// No previous hash means first execution
	if stored.LastResultHash == "" {
		return true
	}

	// Compare output hash
	currentHash := ""
	if result.Output != nil {
		h := sha256.New()
		h.Write([]byte(result.Output.Stdout))
		h.Write([]byte(result.Output.Stderr))
		currentHash = hex.EncodeToString(h.Sum(nil))
	}

	return currentHash != stored.LastResultHash
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
// Removed actions: policy-type actions (SSH, SSHD, Sudo, LPS) are reverted
// to ABSENT state before removal. Other action types are removed without
// reverting to avoid destructive side effects.
// Changed actions (desired_state flipped) are re-executed.
// New actions are executed immediately.
// If firstSync is true, all actions are executed (used on agent startup).
func (s *Scheduler) SyncActions(ctx context.Context, actions []*pb.Action, firstSync bool) error {
	// Check for shutdown before starting
	if ctx.Err() != nil {
		return ctx.Err()
	}

	s.logger.Info("syncing actions from server", "count", len(actions), "first_sync", firstSync)

	// Sync actions to store and get change info
	syncResult, err := s.store.SyncActions(actions)
	if err != nil {
		s.logger.Error("failed to sync actions", "error", err)
		return err
	}

	s.logger.Info("actions synced successfully",
		"total", len(actions),
		"new", len(syncResult.NewActionIDs),
		"changed", len(syncResult.ChangedActionIDs),
		"removed", len(syncResult.RemovedActions),
	)

	// Revert policy-type actions before removal to clean up their effects.
	// Non-policy actions (Package, User, File, etc.) are just removed without
	// reverting to avoid destructive side effects.
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

	// Determine which stored actions to execute
	var actionsToExecute []string
	if firstSync {
		// On first sync, execute ALL actions
		for _, action := range actions {
			if action.Id != nil {
				actionsToExecute = append(actionsToExecute, action.Id.Value)
			}
		}
		if len(actionsToExecute) > 0 {
			s.logger.Info("first sync: executing all assigned actions", "count", len(actionsToExecute))
		}
	} else {
		// On subsequent syncs, execute new and changed actions
		actionsToExecute = append(syncResult.NewActionIDs, syncResult.ChangedActionIDs...)
		if len(actionsToExecute) > 0 {
			s.logger.Info("executing new/changed actions", "count", len(actionsToExecute))
		}
	}

	// Execute the actions
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
// be cleaned up when the action is unassigned from a device.
func shouldRevertOnUnassign(actionType pb.ActionType) bool {
	switch actionType {
	case pb.ActionType_ACTION_TYPE_SSH,
		pb.ActionType_ACTION_TYPE_SSHD,
		pb.ActionType_ACTION_TYPE_SUDO,
		pb.ActionType_ACTION_TYPE_LPS:
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
