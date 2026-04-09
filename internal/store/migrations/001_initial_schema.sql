-- +goose Up

CREATE TABLE IF NOT EXISTS actions (
    id TEXT PRIMARY KEY,
    action_json TEXT NOT NULL,
    assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_executed_at DATETIME,
    next_execute_at DATETIME NOT NULL,
    last_result_hash TEXT DEFAULT '',
    desired_state INTEGER NOT NULL DEFAULT 0
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

-- LUKS and LPS state tables intentionally have NO foreign key to actions.
-- State must persist independently: executors write state during execution
-- before the action may be stored, and state must survive action removal
-- (e.g., LUKS key ownership outlives the action assignment).

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

CREATE TABLE IF NOT EXISTS lps_state (
    action_id TEXT NOT NULL,
    username TEXT NOT NULL,
    last_rotated_at TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (action_id, username)
);

-- +goose Down

DROP TABLE IF EXISTS lps_state;
DROP TABLE IF EXISTS luks_user_passphrase_history;
DROP TABLE IF EXISTS luks_state;
DROP TABLE IF EXISTS results;
DROP TABLE IF EXISTS actions;
