// Package store provides persistent storage for agent actions and execution results.
// This enables offline operation and configuration drift prevention.
package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "modernc.org/sqlite"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
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

	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate database: %w", err)
	}

	return store, nil
}

// migrate creates or updates the database schema.
func (s *Store) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS actions (
		id TEXT PRIMARY KEY,
		action_json TEXT NOT NULL,
		assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_executed_at DATETIME,
		next_execute_at DATETIME NOT NULL,
		last_result_hash TEXT DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS results (
		id TEXT PRIMARY KEY,
		action_id TEXT NOT NULL,
		executed_at DATETIME NOT NULL,
		status INTEGER NOT NULL,
		error TEXT DEFAULT '',
		output_json TEXT,
		duration_ms INTEGER NOT NULL DEFAULT 0,
		has_changes BOOLEAN NOT NULL DEFAULT 0,
		synced BOOLEAN NOT NULL DEFAULT 0,
		FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE CASCADE
	);

	CREATE INDEX IF NOT EXISTS idx_actions_next_execute ON actions(next_execute_at);
	CREATE INDEX IF NOT EXISTS idx_results_synced ON results(synced) WHERE synced = 0;
	CREATE INDEX IF NOT EXISTS idx_results_action ON results(action_id);
	`

	if _, err := s.db.Exec(schema); err != nil {
		return err
	}

	// Add desired_state column if it doesn't exist (migration)
	s.db.Exec("ALTER TABLE actions ADD COLUMN desired_state INTEGER NOT NULL DEFAULT 0")

	// LUKS state tables
	luksSchema := `
	CREATE TABLE IF NOT EXISTS luks_state (
		action_id TEXT PRIMARY KEY,
		device_path TEXT NOT NULL DEFAULT '',
		ownership_taken BOOLEAN NOT NULL DEFAULT FALSE,
		device_key_type TEXT NOT NULL DEFAULT 'none',
		last_rotated_at TEXT NOT NULL DEFAULT ''
	);

	CREATE TABLE IF NOT EXISTS luks_user_passphrase_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		action_id TEXT NOT NULL,
		passphrase_hash TEXT NOT NULL,
		created_at TEXT NOT NULL DEFAULT (datetime('now'))
	);

	CREATE INDEX IF NOT EXISTS idx_luks_passphrase_history_action ON luks_user_passphrase_history(action_id);
	`
	if _, err := s.db.Exec(luksSchema); err != nil {
		return err
	}

	// Add last_rotated_at column if it doesn't exist (migration for pre-existing tables)
	s.db.Exec("ALTER TABLE luks_state ADD COLUMN last_rotated_at TEXT NOT NULL DEFAULT ''")

	return nil
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

// GetDueActions returns all actions that are due for execution.
func (s *Store) GetDueActions() ([]*StoredAction, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	rows, err := s.db.Query(`
		SELECT id, action_json, assigned_at, last_executed_at, next_execute_at, last_result_hash
		FROM actions
		WHERE next_execute_at <= CURRENT_TIMESTAMP
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

	// Calculate result hash for change detection
	resultHash := ""
	if result.Output != nil {
		resultHash = fmt.Sprintf("%d:%s", result.Output.ExitCode, result.Output.Stdout)
	}

	// Store the result
	var outputJSON []byte
	if result.Output != nil {
		outputJSON, _ = json.Marshal(result.Output)
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
			json.Unmarshal([]byte(outputJSON.String), r.Output)
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
			if err := protojson.Unmarshal([]byte(la.actionJSON), action); err == nil {
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

		isChanged := false
		if !exists {
			result.NewActionIDs = append(result.NewActionIDs, actionID)
		} else if local.desiredState != newDesiredState || local.actionJSON != string(actionJSON) {
			result.ChangedActionIDs = append(result.ChangedActionIDs, actionID)
			isChanged = true
		}

		isNew := !exists

		// Calculate next execution time - run immediately for new or changed actions
		runNow := isNew || isChanged
		nextExecute := s.calculateNextExecute(action, nil, runNow)

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
func (s *Store) calculateNextExecute(action *pb.Action, lastExecuted *time.Time, runImmediately bool) time.Time {
	now := time.Now()

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
		return lastExecuted.Add(8 * time.Hour)
	}

	// Check for run_on_assign
	if schedule.RunOnAssign && lastExecuted == nil {
		return now
	}

	// Use interval if specified (and no cron)
	interval := schedule.IntervalHours
	if interval <= 0 {
		interval = 8 // Default 8 hours
	}

	// TODO: Add cron parsing support
	// For now, just use interval
	if lastExecuted == nil {
		return now
	}
	return lastExecuted.Add(time.Duration(interval) * time.Hour)
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
		state.LastRotatedAt, _ = time.Parse(time.RFC3339, lastRotated)
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
