-- +goose Up

CREATE TABLE settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE manifest_deliveries (
    delivery_id TEXT PRIMARY KEY,
    manifest_blob BLOB NOT NULL,
    received_at DATETIME NOT NULL,
    last_executed_at DATETIME,
    next_execute_at DATETIME NOT NULL,
    run_started_at DATETIME,
    run_in_progress BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_manifest_deliveries_due
    ON manifest_deliveries(next_execute_at);

CREATE TABLE manifest_occurrences (
    delivery_id TEXT NOT NULL,
    occurrence_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    action_id TEXT NOT NULL,
    state TEXT NOT NULL DEFAULT 'PENDING'
        CHECK (state IN ('PENDING', 'STARTED', 'SUCCESS', 'FAILED', 'INDETERMINATE')),
    started_at DATETIME,
    completed_at DATETIME,
    result_status INTEGER,
    result_error TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (delivery_id, occurrence_id),
    UNIQUE (delivery_id, position),
    FOREIGN KEY (delivery_id) REFERENCES manifest_deliveries(delivery_id) ON DELETE CASCADE
);

CREATE TABLE reboot_markers (
    delivery_id TEXT NOT NULL,
    occurrence_id TEXT NOT NULL,
    boot_id TEXT NOT NULL,
    scheduled_at DATETIME NOT NULL,
    PRIMARY KEY (delivery_id, occurrence_id),
    FOREIGN KEY (delivery_id, occurrence_id)
        REFERENCES manifest_occurrences(delivery_id, occurrence_id)
        ON DELETE CASCADE
);

CREATE TABLE result_outbox (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    id TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK (kind IN ('ACTION', 'MANIFEST')),
    payload BLOB NOT NULL,
    created_at DATETIME NOT NULL,
    synced BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE INDEX idx_result_outbox_pending
    ON result_outbox(sequence) WHERE synced = FALSE;

-- LUKS/LPS state deliberately outlives an individual delivery. The executor
-- needs it to safely reconcile key ownership and password rotation after the
-- manifest that established the policy is superseded.
CREATE TABLE luks_state (
    action_id TEXT PRIMARY KEY,
    device_path TEXT NOT NULL DEFAULT '',
    ownership_taken BOOLEAN NOT NULL DEFAULT FALSE,
    device_key_type TEXT NOT NULL DEFAULT 'none',
    last_rotated_at TEXT NOT NULL DEFAULT ''
);

CREATE TABLE luks_user_passphrase_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action_id TEXT NOT NULL,
    passphrase_hash TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX idx_luks_passphrase_history_action
    ON luks_user_passphrase_history(action_id);

CREATE TABLE lps_state (
    action_id TEXT NOT NULL,
    username TEXT NOT NULL,
    last_rotated_at TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (action_id, username)
);

-- +goose Down

DROP TABLE lps_state;
DROP TABLE luks_user_passphrase_history;
DROP TABLE luks_state;
DROP TABLE result_outbox;
DROP TABLE reboot_markers;
DROP TABLE manifest_occurrences;
DROP TABLE manifest_deliveries;
DROP TABLE settings;
