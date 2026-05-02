-- Add action_groups + group_members and tag standalone vs grouped
-- actions on the existing actions table.
--
-- A group is one action set or definition that reaches the device,
-- carrying a single schedule and an ordered list of member actions.
-- When the group's schedule fires, every member runs in declared
-- order through the existing executor — that's the ordering guarantee
-- introduced for #45 (manchtools/power-manage-agent#45).
--
-- Per the design, group state is replaced wholesale on every sync.
-- Action *data* still lives on the existing `actions` table (so the
-- executor's per-action lookups and last_executed_at bookkeeping
-- don't need to change), but member actions are tagged is_grouped=1
-- so the standalone-due query (next_execute_at <= now) skips them —
-- they fire only when their owning group fires.
--
-- The action_groups.id is the server-emitted source_label (e.g.
-- "definition:<ulid>" or "action_set:<ulid>"). Stable across syncs
-- only because the source ulid doesn't change.
--
-- See manchtools/power-manage-agent#45.

-- +goose Up

ALTER TABLE actions ADD COLUMN is_grouped INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS action_groups (
    id                TEXT PRIMARY KEY,
    source_label      TEXT NOT NULL,
    schedule_json     TEXT NOT NULL,
    assigned_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_executed_at  DATETIME,
    next_execute_at   DATETIME NOT NULL
);

CREATE TABLE IF NOT EXISTS group_members (
    group_id   TEXT NOT NULL,
    position   INTEGER NOT NULL,
    action_id  TEXT NOT NULL,
    PRIMARY KEY (group_id, position),
    FOREIGN KEY (group_id) REFERENCES action_groups(id) ON DELETE CASCADE,
    FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_action_groups_next_execute ON action_groups(next_execute_at);
CREATE INDEX IF NOT EXISTS idx_group_members_action ON group_members(action_id);

-- +goose Down

DROP INDEX IF EXISTS idx_group_members_action;
DROP INDEX IF EXISTS idx_action_groups_next_execute;
DROP TABLE IF EXISTS group_members;
DROP TABLE IF EXISTS action_groups;

-- SQLite doesn't support DROP COLUMN cleanly across versions; rebuild
-- the actions table without is_grouped.
CREATE TABLE actions_new (
    id TEXT PRIMARY KEY,
    action_json TEXT NOT NULL,
    assigned_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_executed_at DATETIME,
    next_execute_at DATETIME NOT NULL,
    last_result_hash TEXT DEFAULT '',
    desired_state INTEGER NOT NULL DEFAULT 0
);
INSERT INTO actions_new (id, action_json, assigned_at, last_executed_at, next_execute_at, last_result_hash, desired_state)
    SELECT id, action_json, assigned_at, last_executed_at, next_execute_at, last_result_hash, desired_state FROM actions;
DROP TABLE actions;
ALTER TABLE actions_new RENAME TO actions;
CREATE INDEX IF NOT EXISTS idx_actions_next_execute ON actions(next_execute_at);
