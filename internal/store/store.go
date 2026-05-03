// Package store provides persistent storage for agent actions and execution results.
// This enables offline operation and configuration drift prevention.
package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/pressly/goose/v3"
	"github.com/robfig/cron/v3"
	_ "modernc.org/sqlite"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/agent/internal/store/migrations"
)

// Store manages persistent storage for actions and execution results.
type Store struct {
	db *sql.DB
	mu sync.RWMutex
}

// StoredAction represents an action stored locally on the agent.
type StoredAction struct {
	ID             string
	Action         *pb.Action
	AssignedAt     time.Time
	LastExecutedAt *time.Time
	NextExecuteAt  time.Time
	LastResultHash string // Hash of last execution output to detect changes
}

// SyncResult contains information about what changed during a SyncActions call.
type SyncResult struct {
	NewActionIDs     []string     // Actions that were not previously stored
	ChangedActionIDs []string     // Actions whose desired_state changed
	RemovedActions   []*pb.Action // Full action data for removed actions (for undo)
	NewGroupIDs      []string     // Groups that were not previously stored (run-on-first-sync)
}

// StoredActionGroup represents one container's worth of actions sharing
// a schedule. The group's schedule fires every member action when due,
// in declared order — see manchtools/power-manage-agent#45.
type StoredActionGroup struct {
	ID              string // server-emitted source_label, e.g. "definition:<ulid>"
	SourceLabel     string
	Schedule        *pb.ActionSchedule
	LastExecutedAt  *time.Time
	NextExecuteAt   time.Time
	MemberActionIDs []string // in declared sort_order; duplicates allowed
}

// StoredResult represents an execution result stored locally (for sync when online).
type StoredResult struct {
	ID            string
	ActionID      string
	ExecutedAt    time.Time
	Status        pb.ExecutionStatus
	Error         string
	Output        *pb.CommandOutput
	DurationMs    int64
	HasChanges    bool // Whether this execution made changes
	Synced        bool // Whether this result has been sent to the server
}

// New creates a new store with the given data directory.
func New(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data directory: %w", err)
	}

	dbPath := filepath.Join(dataDir, "agent.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}

	// Enable WAL mode for better concurrent access
	if _, err := db.Exec("PRAGMA journal_mode=WAL"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable WAL mode: %w", err)
	}
	// Enable foreign key enforcement (OFF by default in SQLite)
	if _, err := db.Exec("PRAGMA foreign_keys=ON"); err != nil {
		db.Close()
		return nil, fmt.Errorf("enable foreign keys: %w", err)
	}

	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("sqlite3"); err != nil {
		db.Close()
		return nil, fmt.Errorf("set goose dialect: %w", err)
	}
	if err := goose.Up(db, "."); err != nil {
		db.Close()
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	return &Store{db: db}, nil
}

// Close closes the database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// SaveAction stores or updates an action.
func (s *Store) SaveAction(action *pb.Action, runOnAssign bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	actionJSON, err := protojson.Marshal(action)
	if err != nil {
		return fmt.Errorf("marshal action: %w", err)
	}

	// Calculate next execution time
	nextExecute := s.calculateNextExecute(action, nil, runOnAssign)

	_, err = s.db.Exec(`
		INSERT INTO actions (id, action_json, assigned_at, next_execute_at)
		VALUES (?, ?, CURRENT_TIMESTAMP, ?)
		ON CONFLICT(id) DO UPDATE SET
			action_json = excluded.action_json,
			next_execute_at = CASE
				WHEN actions.last_executed_at IS NULL THEN excluded.next_execute_at
				ELSE actions.next_execute_at
			END
	`, action.Id.Value, string(actionJSON), nextExecute)

	return err
}

// RemoveAction removes an action from the store.
func (s *Store) RemoveAction(actionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM actions WHERE id = ?", actionID)
	return err
}

// GetAction retrieves an action by ID.
func (s *Store) GetAction(actionID string) (*StoredAction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var stored StoredAction
	var actionJSON string
	var lastExecutedAt sql.NullTime

	err := s.db.QueryRow(`
		SELECT id, action_json, assigned_at, last_executed_at, next_execute_at, last_result_hash
		FROM actions WHERE id = ?
	`, actionID).Scan(
		&stored.ID,
		&actionJSON,
		&stored.AssignedAt,
		&lastExecutedAt,
		&stored.NextExecuteAt,
		&stored.LastResultHash,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}

	if lastExecutedAt.Valid {
		stored.LastExecutedAt = &lastExecutedAt.Time
	}

	stored.Action = &pb.Action{}
	if err := protojson.Unmarshal([]byte(actionJSON), stored.Action); err != nil {
		return nil, fmt.Errorf("unmarshal action: %w", err)
	}

	return &stored, nil
}

// GetDueActions returns all standalone actions that are due for
// execution. Grouped action members are skipped (is_grouped = 1) — they
// only fire when their owning group fires, via GetDueGroups +
// executeGroup. This is the load-bearing invariant for #45's ordering
// guarantee: members must not race each other on independent per-action
// schedules. Note that RecordExecution updates next_execute_at on every
// run including for grouped members, so without this filter a grouped
// member would silently leak back into standalone scheduling after its
// first execution.
//
// Takes a context so the scheduler can cancel a blocking SQLite query
// when shutdown fires; without this the poll loop would stall on the
// query rather than honoring ctx.Done().
func (s *Store) GetDueActions(ctx context.Context) ([]*StoredAction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, action_json, assigned_at, last_executed_at, next_execute_at, last_result_hash
		FROM actions
		WHERE next_execute_at <= ? AND is_grouped = 0
		ORDER BY next_execute_at ASC
	`, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var actions []*StoredAction
	for rows.Next() {
		var stored StoredAction
		var actionJSON string
		var lastExecutedAt sql.NullTime

		if err := rows.Scan(
			&stored.ID,
			&actionJSON,
			&stored.AssignedAt,
			&lastExecutedAt,
			&stored.NextExecuteAt,
			&stored.LastResultHash,
		); err != nil {
			return nil, err
		}

		if lastExecutedAt.Valid {
			stored.LastExecutedAt = &lastExecutedAt.Time
		}

		stored.Action = &pb.Action{}
		if err := protojson.Unmarshal([]byte(actionJSON), stored.Action); err != nil {
			return nil, fmt.Errorf("unmarshal action: %w", err)
		}

		actions = append(actions, &stored)
	}

	return actions, rows.Err()
}

// GetAllActions returns all stored actions.
func (s *Store) GetAllActions() ([]*StoredAction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, action_json, assigned_at, last_executed_at, next_execute_at, last_result_hash
		FROM actions
		ORDER BY next_execute_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var actions []*StoredAction
	for rows.Next() {
		var stored StoredAction
		var actionJSON string
		var lastExecutedAt sql.NullTime

		if err := rows.Scan(
			&stored.ID,
			&actionJSON,
			&stored.AssignedAt,
			&lastExecutedAt,
			&stored.NextExecuteAt,
			&stored.LastResultHash,
		); err != nil {
			return nil, err
		}

		if lastExecutedAt.Valid {
			stored.LastExecutedAt = &lastExecutedAt.Time
		}

		stored.Action = &pb.Action{}
		if err := protojson.Unmarshal([]byte(actionJSON), stored.Action); err != nil {
			return nil, fmt.Errorf("unmarshal action: %w", err)
		}

		actions = append(actions, &stored)
	}

	return actions, rows.Err()
}

// RecordExecution records an execution result and updates the action's next execution time.
// Returns the result ID for tracking sync status.
func (s *Store) RecordExecution(actionID string, result *pb.ActionResult, hasChanges bool) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Get the action to calculate next execution time
	var actionJSON string
	err := s.db.QueryRow("SELECT action_json FROM actions WHERE id = ?", actionID).Scan(&actionJSON)
	if err != nil {
		return "", fmt.Errorf("get action: %w", err)
	}

	action := &pb.Action{}
	if err := protojson.Unmarshal([]byte(actionJSON), action); err != nil {
		return "", fmt.Errorf("unmarshal action: %w", err)
	}

	now := time.Now()
	nextExecute := s.calculateNextExecute(action, &now, false)

	// Calculate result hash for change detection (must match scheduler.detectChanges format)
	resultHash := ""
	if result.Output != nil {
		h := sha256.New()
		h.Write([]byte(result.Output.Stdout))
		h.Write([]byte(result.Output.Stderr))
		resultHash = hex.EncodeToString(h.Sum(nil))
	}

	// Store the result
	var outputJSON []byte
	if result.Output != nil {
		var err error
		outputJSON, err = json.Marshal(result.Output)
		if err != nil {
			slog.Warn("failed to marshal execution output", "error", err)
		}
	}

	resultID := fmt.Sprintf("%s-%d", actionID, now.UnixNano())

	tx, err := s.db.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()

	// Insert result
	_, err = tx.Exec(`
		INSERT INTO results (id, action_id, executed_at, status, error, output_json, duration_ms, has_changes, synced)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)
	`, resultID, actionID, now, int32(result.Status), result.Error, string(outputJSON), result.DurationMs, hasChanges)
	if err != nil {
		return "", err
	}

	// Update action
	_, err = tx.Exec(`
		UPDATE actions SET
			last_executed_at = ?,
			next_execute_at = ?,
			last_result_hash = ?
		WHERE id = ?
	`, now, nextExecute, resultHash, actionID)
	if err != nil {
		return "", err
	}

	return resultID, tx.Commit()
}

// GetUnsyncedResults returns all results that haven't been sent to the server.
func (s *Store) GetUnsyncedResults() ([]*StoredResult, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, action_id, executed_at, status, error, output_json, duration_ms, has_changes
		FROM results
		WHERE synced = 0
		ORDER BY executed_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []*StoredResult
	for rows.Next() {
		var r StoredResult
		var outputJSON sql.NullString

		if err := rows.Scan(
			&r.ID,
			&r.ActionID,
			&r.ExecutedAt,
			&r.Status,
			&r.Error,
			&outputJSON,
			&r.DurationMs,
			&r.HasChanges,
		); err != nil {
			return nil, err
		}

		if outputJSON.Valid && outputJSON.String != "" {
			r.Output = &pb.CommandOutput{}
			if err := json.Unmarshal([]byte(outputJSON.String), r.Output); err != nil {
				slog.Warn("failed to unmarshal stored command output", "result_id", r.ID, "error", err)
			}
		}

		results = append(results, &r)
	}

	return results, rows.Err()
}

// MarkResultSynced marks a result as synced with the server.
func (s *Store) MarkResultSynced(resultID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("UPDATE results SET synced = 1 WHERE id = ?", resultID)
	return err
}

// HasPriorExecution returns true if the action has more than one recorded execution.
// This is used to distinguish first-run results (which should always be reported)
// from subsequent unchanged results (which can be skipped).
func (s *Store) HasPriorExecution(actionID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var count int
	err := s.db.QueryRow("SELECT COUNT(*) FROM results WHERE action_id = ?", actionID).Scan(&count)
	return err == nil && count > 1
}

// CleanupOldResults removes synced results older than the retention period.
func (s *Store) CleanupOldResults(retention time.Duration) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := time.Now().Add(-retention)
	_, err := s.db.Exec("DELETE FROM results WHERE synced = 1 AND executed_at < ?", cutoff)
	return err
}

// SyncActions replaces all stored actions with the provided list from the server.
// Actions that are no longer in the server list are removed.
// Actions that exist are updated. New actions are added.
// Returns a SyncResult describing what changed.
func (s *Store) SyncActions(actions []*pb.Action) (*SyncResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := &SyncResult{}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	// Build a map of server actions for quick lookup
	serverActions := make(map[string]*pb.Action)
	for _, action := range actions {
		if action.Id != nil {
			serverActions[action.Id.Value] = action
		}
	}

	// Get all current local actions with their desired_state
	rows, err := tx.Query("SELECT id, action_json, desired_state FROM actions")
	if err != nil {
		return nil, fmt.Errorf("query actions: %w", err)
	}

	type localAction struct {
		id           string
		actionJSON   string
		desiredState int32
	}
	localActions := make(map[string]*localAction)
	for rows.Next() {
		var la localAction
		if err := rows.Scan(&la.id, &la.actionJSON, &la.desiredState); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan action: %w", err)
		}
		localActions[la.id] = &la
	}
	rows.Close()

	// Identify and load removed actions (for undo), then delete them
	for localID, la := range localActions {
		if _, exists := serverActions[localID]; !exists {
			// Load the full action for undo
			action := &pb.Action{}
			if err := protojson.Unmarshal([]byte(la.actionJSON), action); err != nil {
				slog.Warn("failed to unmarshal removed action for undo", "action_id", localID, "error", err)
			} else {
				result.RemovedActions = append(result.RemovedActions, action)
			}
			if _, err := tx.Exec("DELETE FROM actions WHERE id = ?", localID); err != nil {
				return nil, fmt.Errorf("delete action %s: %w", localID, err)
			}
		}
	}

	// Upsert all server actions, tracking new and changed
	for _, action := range actions {
		if action.Id == nil {
			continue
		}

		actionID := action.Id.Value
		newDesiredState := int32(action.DesiredState)

		local, exists := localActions[actionID]

		actionJSON, err := protojson.Marshal(action)
		if err != nil {
			return nil, fmt.Errorf("marshal action %s: %w", actionID, err)
		}

		if !exists {
			result.NewActionIDs = append(result.NewActionIDs, actionID)
		} else if local.desiredState != newDesiredState || local.actionJSON != string(actionJSON) {
			result.ChangedActionIDs = append(result.ChangedActionIDs, actionID)
		}

		// Always set next_execute_at to the future. The caller (scheduler.SyncActions)
		// executes new/changed actions immediately via ID lists, not via next_execute_at.
		// Setting next_execute_at to "now" caused the scheduler's runDueActions ticker
		// to double-execute actions while the sync execution was still running.
		now := time.Now()
		nextExecute := s.calculateNextExecute(action, &now, false)

		// Upsert: insert new or update existing (but preserve execution history)
		_, err = tx.Exec(`
			INSERT INTO actions (id, action_json, assigned_at, next_execute_at, desired_state)
			VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?)
			ON CONFLICT(id) DO UPDATE SET
				action_json = excluded.action_json,
				desired_state = excluded.desired_state,
				next_execute_at = CASE
					WHEN excluded.desired_state != actions.desired_state
						OR excluded.action_json != actions.action_json
					THEN excluded.next_execute_at
					ELSE actions.next_execute_at
				END
		`, actionID, string(actionJSON), nextExecute, newDesiredState)
		if err != nil {
			return nil, fmt.Errorf("upsert action %s: %w", actionID, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// SyncStandaloneAndGrouped replaces both the standalone-action store
// and the grouped-action store with the server's latest snapshot.
//
// Standalone actions follow the existing SyncActions semantics: the
// caller's slice is upserted into the actions table with is_grouped=0,
// new/changed/removed are reported in SyncResult, and removed actions
// are returned in full so policy-style executors can revert them.
//
// Grouped action data is upserted with is_grouped=1 so the standalone
// runDueActions query (next_execute_at <= now AND is_grouped = 0)
// silently skips it — these actions only fire when their group fires.
//
// action_groups + group_members are dropped and rebuilt on every call
// per the design (server is authoritative; the agent is a snapshot).
// New groups (not present on the previous sync) are reported in
// SyncResult.NewGroupIDs so the scheduler can fire them once on first
// arrival before their normal cadence kicks in.
func (s *Store) SyncStandaloneAndGrouped(standalone []*pb.Action, groups []*pb.ActionGroup) (*SyncResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	result := &SyncResult{}

	tx, err := s.db.Begin()
	if err != nil {
		return nil, fmt.Errorf("begin transaction: %w", err)
	}
	defer tx.Rollback()

	// ---- standalone actions: existing diff/upsert pattern ----

	serverStandalone := make(map[string]*pb.Action, len(standalone))
	for _, a := range standalone {
		if a.Id != nil {
			serverStandalone[a.Id.Value] = a
		}
	}

	// Collect every action id that should be present on the agent. We
	// keep grouped-member ids in a second set so we can distinguish
	// removed-standalone (returned in RemovedActions for revert) from
	// removed-or-now-grouped (silent — group members never get the
	// revert path because they're driven by the group, not by their own
	// schedule).
	groupedMembers := make(map[string]bool)
	for _, g := range groups {
		for _, ga := range g.Actions {
			if ga.Id != nil {
				groupedMembers[ga.Id.Value] = true
			}
		}
	}

	rows, err := tx.Query("SELECT id, action_json, desired_state, is_grouped FROM actions")
	if err != nil {
		return nil, fmt.Errorf("query actions: %w", err)
	}
	type localAction struct {
		id           string
		actionJSON   string
		desiredState int32
		isGrouped    int
	}
	localActions := make(map[string]*localAction)
	for rows.Next() {
		var la localAction
		if err := rows.Scan(&la.id, &la.actionJSON, &la.desiredState, &la.isGrouped); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan action: %w", err)
		}
		localActions[la.id] = &la
	}
	rows.Close()

	// Removals: action no longer present on standalone OR grouped.
	for localID, la := range localActions {
		if _, isStandalone := serverStandalone[localID]; isStandalone {
			continue
		}
		if groupedMembers[localID] {
			continue
		}
		// Only return previously-standalone actions for revert; grouped
		// members that simply migrated to standalone (or vice versa)
		// were already handled by the upsert below in past syncs.
		if la.isGrouped == 0 {
			action := &pb.Action{}
			if err := protojson.Unmarshal([]byte(la.actionJSON), action); err != nil {
				slog.Warn("failed to unmarshal removed action for undo", "action_id", localID, "error", err)
			} else {
				result.RemovedActions = append(result.RemovedActions, action)
			}
		}
		if _, err := tx.Exec("DELETE FROM actions WHERE id = ?", localID); err != nil {
			return nil, fmt.Errorf("delete action %s: %w", localID, err)
		}
	}

	// Standalone upserts.
	now := time.Now()
	for _, action := range standalone {
		if action.Id == nil {
			continue
		}
		actionID := action.Id.Value
		newDesiredState := int32(action.DesiredState)

		actionJSON, err := protojson.Marshal(action)
		if err != nil {
			return nil, fmt.Errorf("marshal action %s: %w", actionID, err)
		}

		local, exists := localActions[actionID]
		if !exists {
			result.NewActionIDs = append(result.NewActionIDs, actionID)
		} else if local.desiredState != newDesiredState || local.actionJSON != string(actionJSON) || local.isGrouped != 0 {
			result.ChangedActionIDs = append(result.ChangedActionIDs, actionID)
		}

		nextExecute := s.calculateNextExecute(action, &now, false)

		_, err = tx.Exec(`
			INSERT INTO actions (id, action_json, assigned_at, next_execute_at, desired_state, is_grouped)
			VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, 0)
			ON CONFLICT(id) DO UPDATE SET
				action_json = excluded.action_json,
				desired_state = excluded.desired_state,
				is_grouped = 0,
				next_execute_at = CASE
					WHEN excluded.desired_state != actions.desired_state
						OR excluded.action_json != actions.action_json
						OR actions.is_grouped != 0
					THEN excluded.next_execute_at
					ELSE actions.next_execute_at
				END
		`, actionID, string(actionJSON), nextExecute, newDesiredState)
		if err != nil {
			return nil, fmt.Errorf("upsert action %s: %w", actionID, err)
		}
	}

	// Grouped action data upserts. is_grouped=1 keeps the standalone
	// tick from picking them up; next_execute_at is irrelevant for the
	// scheduler but kept non-NULL to satisfy the column constraint.
	farFuture := time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, g := range groups {
		for _, action := range g.Actions {
			if action.Id == nil {
				continue
			}
			actionID := action.Id.Value
			actionJSON, err := protojson.Marshal(action)
			if err != nil {
				return nil, fmt.Errorf("marshal grouped action %s: %w", actionID, err)
			}
			_, err = tx.Exec(`
				INSERT INTO actions (id, action_json, assigned_at, next_execute_at, desired_state, is_grouped)
				VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, 1)
				ON CONFLICT(id) DO UPDATE SET
					action_json = excluded.action_json,
					desired_state = excluded.desired_state,
					is_grouped = 1,
					next_execute_at = excluded.next_execute_at
			`, actionID, string(actionJSON), farFuture, int32(action.DesiredState))
			if err != nil {
				return nil, fmt.Errorf("upsert grouped action %s: %w", actionID, err)
			}
		}
	}

	// ---- groups: drop and recreate in this same TX ----

	// Snapshot existing groups' execution state. The drop+rebuild path
	// would otherwise wipe last_executed_at and next_execute_at every
	// sync, and a group with an interval/run_on_assign schedule would
	// then come back with lastExecuted=nil and re-fire immediately.
	// For groups whose schedule_json is unchanged we preserve the
	// existing cadence; only schedule changes (or a brand-new group)
	// reset to the schedule's first slot.
	type existingGroup struct {
		scheduleJSON   string
		lastExecutedAt sql.NullTime
		nextExecuteAt  time.Time
	}
	existingGroups := make(map[string]existingGroup)
	groupRows, err := tx.Query(`
		SELECT id, schedule_json, last_executed_at, next_execute_at
		FROM action_groups
	`)
	if err != nil {
		return nil, fmt.Errorf("query action_groups: %w", err)
	}
	for groupRows.Next() {
		var id string
		var eg existingGroup
		if err := groupRows.Scan(&id, &eg.scheduleJSON, &eg.lastExecutedAt, &eg.nextExecuteAt); err != nil {
			groupRows.Close()
			return nil, fmt.Errorf("scan action_group: %w", err)
		}
		existingGroups[id] = eg
	}
	groupRows.Close()

	if _, err := tx.Exec("DELETE FROM group_members"); err != nil {
		return nil, fmt.Errorf("clear group_members: %w", err)
	}
	if _, err := tx.Exec("DELETE FROM action_groups"); err != nil {
		return nil, fmt.Errorf("clear action_groups: %w", err)
	}

	for _, g := range groups {
		groupID := g.SourceLabel
		if groupID == "" {
			// Defensive: a group with no source label is unidentifiable
			// across syncs; skip rather than collide on PRIMARY KEY.
			slog.Warn("dropping action group with empty source_label", "actions", len(g.Actions))
			continue
		}

		schedJSON, err := protojson.Marshal(g.Schedule)
		if err != nil {
			return nil, fmt.Errorf("marshal group schedule for %s: %w", groupID, err)
		}

		// Preserve cadence across syncs when nothing about the group's
		// schedule changed; otherwise reset to the new schedule's first
		// slot.
		var nextExecute time.Time
		var lastExecutedAt sql.NullTime
		if prior, ok := existingGroups[groupID]; ok && prior.scheduleJSON == string(schedJSON) {
			nextExecute = prior.nextExecuteAt
			lastExecutedAt = prior.lastExecutedAt
		} else {
			var lastExec *time.Time
			if prior, ok := existingGroups[groupID]; ok && prior.lastExecutedAt.Valid {
				t := prior.lastExecutedAt.Time
				lastExec = &t
				lastExecutedAt = prior.lastExecutedAt
			}
			nextExecute = calculateNextExecuteFromSchedule(g.Schedule, lastExec, false)
		}

		if _, err := tx.Exec(`
			INSERT INTO action_groups (id, source_label, schedule_json, assigned_at, last_executed_at, next_execute_at)
			VALUES (?, ?, ?, CURRENT_TIMESTAMP, ?, ?)
		`, groupID, g.SourceLabel, string(schedJSON), lastExecutedAt, nextExecute); err != nil {
			return nil, fmt.Errorf("insert action_group %s: %w", groupID, err)
		}

		for pos, action := range g.Actions {
			if action.Id == nil {
				continue
			}
			if _, err := tx.Exec(`
				INSERT INTO group_members (group_id, position, action_id)
				VALUES (?, ?, ?)
			`, groupID, pos, action.Id.Value); err != nil {
				return nil, fmt.Errorf("insert group_member %s/%d: %w", groupID, pos, err)
			}
		}

		if _, existed := existingGroups[groupID]; !existed {
			result.NewGroupIDs = append(result.NewGroupIDs, groupID)
		}
	}

	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return result, nil
}

// GetDueGroups returns action groups whose schedule says they're due
// for execution. Caller fetches members via GetGroupMembers and runs
// them in declared order.
//
// Takes a context so the scheduler can cancel a blocking SQLite query
// when shutdown fires, same rationale as GetDueActions.
func (s *Store) GetDueGroups(ctx context.Context) ([]StoredActionGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	now := time.Now().UTC()
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, source_label, schedule_json, last_executed_at, next_execute_at
		FROM action_groups
		WHERE next_execute_at <= ?
		ORDER BY next_execute_at ASC
	`, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var due []StoredActionGroup
	for rows.Next() {
		var g StoredActionGroup
		var schedJSON string
		var lastExec sql.NullTime
		if err := rows.Scan(&g.ID, &g.SourceLabel, &schedJSON, &lastExec, &g.NextExecuteAt); err != nil {
			return nil, err
		}
		var sched pb.ActionSchedule
		if err := protojson.Unmarshal([]byte(schedJSON), &sched); err != nil {
			slog.Warn("failed to unmarshal group schedule", "group_id", g.ID, "error", err)
		} else {
			g.Schedule = &sched
		}
		if lastExec.Valid {
			t := lastExec.Time
			g.LastExecutedAt = &t
		}
		due = append(due, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	// Hydrate member ids in declared order.
	for i := range due {
		members, err := s.getGroupMemberIDs(due[i].ID)
		if err != nil {
			return nil, err
		}
		due[i].MemberActionIDs = members
	}
	return due, nil
}

// GetGroupByID returns a group's metadata + members in declared order.
// Returns nil if the group is not in the store.
func (s *Store) GetGroupByID(groupID string) (*StoredActionGroup, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var g StoredActionGroup
	var schedJSON string
	var lastExec sql.NullTime
	err := s.db.QueryRow(`
		SELECT id, source_label, schedule_json, last_executed_at, next_execute_at
		FROM action_groups WHERE id = ?
	`, groupID).Scan(&g.ID, &g.SourceLabel, &schedJSON, &lastExec, &g.NextExecuteAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var sched pb.ActionSchedule
	if err := protojson.Unmarshal([]byte(schedJSON), &sched); err == nil {
		g.Schedule = &sched
	}
	if lastExec.Valid {
		t := lastExec.Time
		g.LastExecutedAt = &t
	}
	members, err := s.getGroupMemberIDs(groupID)
	if err != nil {
		return nil, err
	}
	g.MemberActionIDs = members
	return &g, nil
}

func (s *Store) getGroupMemberIDs(groupID string) ([]string, error) {
	rows, err := s.db.Query(`
		SELECT action_id FROM group_members
		WHERE group_id = ? ORDER BY position ASC
	`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// MarkGroupExecuted records that a group fired and advances its
// next_execute_at to the next slot of its schedule. Called by the
// scheduler after every member of a due group has run (or attempted).
func (s *Store) MarkGroupExecuted(groupID string, executedAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var schedJSON string
	if err := s.db.QueryRow("SELECT schedule_json FROM action_groups WHERE id = ?", groupID).Scan(&schedJSON); err != nil {
		return err
	}
	var sched pb.ActionSchedule
	if err := protojson.Unmarshal([]byte(schedJSON), &sched); err != nil {
		return fmt.Errorf("unmarshal group schedule: %w", err)
	}
	executedUTC := executedAt.UTC()
	next := calculateNextExecuteFromSchedule(&sched, &executedUTC, false)

	_, err := s.db.Exec(`
		UPDATE action_groups SET last_executed_at = ?, next_execute_at = ?
		WHERE id = ?
	`, executedUTC, next, groupID)
	return err
}

// calculateNextExecuteFromSchedule mirrors calculateNextExecute but
// works directly on an ActionSchedule pointer so groups can use it
// without faking a pb.Action.
func calculateNextExecuteFromSchedule(schedule *pb.ActionSchedule, lastExecuted *time.Time, runImmediately bool) time.Time {
	now := time.Now().UTC()
	if runImmediately && lastExecuted == nil {
		return now
	}
	if schedule == nil {
		if lastExecuted == nil {
			return now
		}
		return lastExecuted.UTC().Add(8 * time.Hour)
	}
	if schedule.RunOnAssign && lastExecuted == nil {
		return now
	}
	if schedule.Cron != "" {
		parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
		sched, err := parser.Parse(schedule.Cron)
		if err == nil {
			return sched.Next(now.Local()).UTC()
		}
		slog.Warn("invalid cron expression on group schedule", "cron", schedule.Cron, "error", err)
	}
	interval := schedule.IntervalHours
	if interval <= 0 {
		interval = 8
	}
	if lastExecuted == nil {
		return now
	}
	return lastExecuted.UTC().Add(time.Duration(interval) * time.Hour)
}

// GetAllActionIDs returns the IDs of all stored actions.
func (s *Store) GetAllActionIDs() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query("SELECT id FROM actions")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}

	return ids, rows.Err()
}

// calculateNextExecute determines when an action should next be executed.
// All returned times are in UTC to ensure correct SQLite comparisons.
func (s *Store) calculateNextExecute(action *pb.Action, lastExecuted *time.Time, runImmediately bool) time.Time {
	now := time.Now().UTC()

	// Run immediately if requested and never executed
	if runImmediately && lastExecuted == nil {
		return now
	}

	// Get schedule from action
	schedule := action.Schedule
	if schedule == nil {
		// Default: run every 8 hours for drift prevention
		if lastExecuted == nil {
			return now
		}
		return lastExecuted.UTC().Add(8 * time.Hour)
	}

	// Check for run_on_assign
	if schedule.RunOnAssign && lastExecuted == nil {
		return now
	}

	// Cron takes precedence over interval.
	// Cron expressions run in the device's local timezone, so we use
	// local time as input and convert the result to UTC for storage.
	if schedule.Cron != "" {
		parser := cron.NewParser(cron.Minute | cron.Hour | cron.Dom | cron.Month | cron.Dow)
		sched, err := parser.Parse(schedule.Cron)
		if err == nil {
			localNow := now.Local()
			return sched.Next(localNow).UTC()
		}
		slog.Warn("invalid cron expression, using interval fallback", "cron", schedule.Cron, "error", err)
	}

	// Use interval
	interval := schedule.IntervalHours
	if interval <= 0 {
		interval = 8 // Default 8 hours
	}
	if lastExecuted == nil {
		return now
	}
	return lastExecuted.UTC().Add(time.Duration(interval) * time.Hour)
}

// =============================================================================
// LUKS State
// =============================================================================

// LuksState represents the local LUKS state for an action.
type LuksState struct {
	ActionID       string
	DevicePath     string
	OwnershipTaken bool
	DeviceKeyType  string // "none", "tpm", "user_passphrase"
	LastRotatedAt  time.Time
}

// GetLuksState returns the LUKS state for an action, or nil if not found.
func (s *Store) GetLuksState(actionID string) (*LuksState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var state LuksState
	var lastRotated string
	err := s.db.QueryRow(
		"SELECT action_id, device_path, ownership_taken, device_key_type, last_rotated_at FROM luks_state WHERE action_id = ?",
		actionID,
	).Scan(&state.ActionID, &state.DevicePath, &state.OwnershipTaken, &state.DeviceKeyType, &lastRotated)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	if lastRotated != "" {
		var parseErr error
		state.LastRotatedAt, parseErr = time.Parse(time.RFC3339, lastRotated)
		if parseErr != nil {
			slog.Warn("failed to parse LUKS last_rotated_at", "action_id", actionID, "value", lastRotated, "error", parseErr)
		}
	}
	return &state, nil
}

// SetLuksOwnershipTaken marks ownership as taken and stores the detected device path.
func (s *Store) SetLuksOwnershipTaken(actionID, devicePath string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC().Format(time.RFC3339)
	_, err := s.db.Exec(`
		INSERT INTO luks_state (action_id, device_path, ownership_taken, device_key_type, last_rotated_at)
		VALUES (?, ?, TRUE, 'none', ?)
		ON CONFLICT(action_id) DO UPDATE SET
			device_path = excluded.device_path,
			ownership_taken = TRUE,
			last_rotated_at = excluded.last_rotated_at
	`, actionID, devicePath, now)
	return err
}

// SetLuksDeviceKeyType updates the device-bound key type.
func (s *Store) SetLuksDeviceKeyType(actionID, keyType string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		"UPDATE luks_state SET device_key_type = ? WHERE action_id = ?",
		keyType, actionID,
	)
	return err
}

// SetLuksLastRotatedAt records the time of the most recent key rotation.
func (s *Store) SetLuksLastRotatedAt(actionID string, t time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		"UPDATE luks_state SET last_rotated_at = ? WHERE action_id = ?",
		t.UTC().Format(time.RFC3339), actionID,
	)
	return err
}

// DeleteLuksState removes the LUKS state for an action.
func (s *Store) DeleteLuksState(actionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM luks_state WHERE action_id = ?", actionID)
	return err
}

// GetLuksPassphraseHashes returns the most recent passphrase hashes for an action (max 3).
func (s *Store) GetLuksPassphraseHashes(actionID string) ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		"SELECT passphrase_hash FROM luks_user_passphrase_history WHERE action_id = ? ORDER BY created_at DESC LIMIT 3",
		actionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hashes []string
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
	return hashes, rows.Err()
}

// AddLuksPassphraseHash stores a passphrase hash and prunes old entries beyond 3.
func (s *Store) AddLuksPassphraseHash(actionID, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.db.Exec(
		"INSERT INTO luks_user_passphrase_history (action_id, passphrase_hash) VALUES (?, ?)",
		actionID, hash,
	); err != nil {
		return err
	}

	// Keep only the 3 most recent entries per action
	_, err := s.db.Exec(`
		DELETE FROM luks_user_passphrase_history
		WHERE action_id = ? AND id NOT IN (
			SELECT id FROM luks_user_passphrase_history
			WHERE action_id = ?
			ORDER BY created_at DESC
			LIMIT 3
		)
	`, actionID, actionID)
	return err
}

// =============================================================================
// LPS State
// =============================================================================

// LpsUserState represents the LPS rotation state for a single user within an action.
type LpsUserState struct {
	ActionID      string
	Username      string
	LastRotatedAt time.Time
	PasswordHash  string
}

// GetLpsState returns all LPS user states for an action.
func (s *Store) GetLpsState(actionID string) (map[string]*LpsUserState, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(
		"SELECT action_id, username, last_rotated_at, password_hash FROM lps_state WHERE action_id = ?",
		actionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make(map[string]*LpsUserState)
	for rows.Next() {
		var state LpsUserState
		var lastRotated string
		if err := rows.Scan(&state.ActionID, &state.Username, &lastRotated, &state.PasswordHash); err != nil {
			return nil, err
		}
		if lastRotated != "" {
			if t, parseErr := time.Parse(time.RFC3339, lastRotated); parseErr == nil {
				state.LastRotatedAt = t
			} else {
				slog.Warn("failed to parse LPS last_rotated_at", "action_id", actionID, "username", state.Username, "error", parseErr)
			}
		}
		users[state.Username] = &state
	}
	return users, rows.Err()
}

// SetLpsUserState upserts the LPS rotation state for a single user.
func (s *Store) SetLpsUserState(actionID, username string, lastRotatedAt time.Time, passwordHash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO lps_state (action_id, username, last_rotated_at, password_hash)
		VALUES (?, ?, ?, ?)
		ON CONFLICT(action_id, username) DO UPDATE SET
			last_rotated_at = excluded.last_rotated_at,
			password_hash = excluded.password_hash
	`, actionID, username, lastRotatedAt.UTC().Format(time.RFC3339), passwordHash)
	return err
}

// DeleteLpsState removes all LPS state for an action.
func (s *Store) DeleteLpsState(actionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM lps_state WHERE action_id = ?", actionID)
	return err
}

// =============================================================================
// Settings
// =============================================================================

// GetSetting returns the value of a setting, or empty string if unset.
func (s *Store) GetSetting(key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var value string
	err := s.db.QueryRow("SELECT value FROM settings WHERE key = ?", key).Scan(&value)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return value, err
}

// SetSetting stores a setting, overwriting any existing value for the key.
func (s *Store) SetSetting(key, value string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`
		INSERT INTO settings (key, value) VALUES (?, ?)
		ON CONFLICT(key) DO UPDATE SET value = excluded.value
	`, key, value)
	return err
}

// DeleteSetting removes a setting.
func (s *Store) DeleteSetting(key string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec("DELETE FROM settings WHERE key = ?", key)
	return err
}
