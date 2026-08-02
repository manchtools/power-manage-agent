-- +goose Up

-- A one-shot delivery executes exactly once. The timestamp of that single run
-- is the terminal marker that keeps the row out of the due set forever, while
-- the row itself survives so a replayed delivery frame stays absorbed by the
-- existing RecordManifestDelivery dedup. NULL means "not a one-shot run", so
-- assigned manifests keep their ordinary cadence.
ALTER TABLE manifest_deliveries ADD COLUMN one_shot_run_at DATETIME;

-- +goose Down

ALTER TABLE manifest_deliveries DROP COLUMN one_shot_run_at;
