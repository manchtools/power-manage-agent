-- +goose Up
-- Binary-protobuf storage cutover. Actions, group schedules and execution outputs
-- are now stored as binary protobuf with NO protojson read-fallback. Rather than
-- carry compatibility code, clear the server-synced cache so no legacy protojson
-- row is ever read: the agent re-syncs actions and group schedules from the server
-- on its next connection (it only reaches this release via a self-update, which
-- requires connectivity). results cascade-delete from actions; LUKS/LPS secret
-- state carries no protojson and is intentionally left untouched.
DELETE FROM actions;
DELETE FROM action_groups;

-- +goose Down
-- No-op: the cache repopulates from the server on the next sync.
SELECT 1;
