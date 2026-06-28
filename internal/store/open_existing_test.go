package store

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestOpenExisting_RequiresInitialisedDB: the CLI store-open must not silently
// create-and-run on an unmigrated database — it errors when the DB is absent
// (the agent service, store.New, is the only thing that creates + migrates it).
func TestOpenExisting_RequiresInitialisedDB(t *testing.T) {
	dir := t.TempDir()
	_, err := OpenExisting(dir)
	require.Error(t, err, "OpenExisting on a non-existent DB must error, not create an empty one")
	assert.NoFileExists(t, filepath.Join(dir, "agent.db"), "OpenExisting must not create the database")
}

// TestOpenExisting_OpensWithoutMigrating: once the service initialised the store,
// the CLI path opens it and can read/write the tty toggle — no goose involved.
func TestOpenExisting_OpensWithoutMigrating(t *testing.T) {
	dir := t.TempDir()

	svc, err := New(dir) // service creates + migrates
	require.NoError(t, err)
	require.NoError(t, svc.SetTTYEnabled(true))
	require.NoError(t, svc.Close())

	cli, err := OpenExisting(dir) // CLI re-opens, no migration
	require.NoError(t, err)
	defer cli.Close()

	enabled, err := cli.IsTTYEnabled()
	require.NoError(t, err)
	assert.True(t, enabled, "OpenExisting must read the setting the service wrote")
}
