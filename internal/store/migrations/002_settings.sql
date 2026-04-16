-- +goose Up

-- settings holds device-local configuration toggles that the admin controls
-- via the agent CLI. Key-value schema keeps it trivially extensible.
CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- +goose Down

DROP TABLE IF EXISTS settings;
