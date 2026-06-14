package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// recordResultAt records one result for a fresh action whose executed_at is
// `age` in the past (via the clock seam), optionally marked synced. Returns the
// result id.
func recordResultAt(t *testing.T, st *Store, clock *time.Time, base time.Time, actionID string, age time.Duration, synced bool) string {
	t.Helper()
	*clock = base.Add(-age) // executed_at = base - age
	a := &pb.Action{
		Id:           &pb.ActionId{Value: actionID},
		Type:         pb.ActionType_ACTION_TYPE_SHELL,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
	}
	require.NoError(t, st.SaveAction(a))
	id, err := st.RecordExecution(actionID, &pb.ActionResult{
		ActionId: a.Id,
		Status:   pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
		Output:   &pb.CommandOutput{Stdout: "x"},
	}, true)
	require.NoError(t, err)
	if synced {
		require.NoError(t, st.MarkResultSynced(id))
	}
	return id
}

func resultExists(t *testing.T, st *Store, id string) bool {
	t.Helper()
	var n int
	require.NoError(t, st.db.QueryRow("SELECT COUNT(*) FROM results WHERE id = ?", id).Scan(&n))
	return n == 1
}

// TestCleanupOldResults_PrunesUnsyncedBeyondCeiling pins WS13 #6: the results
// table is bounded INDEPENDENTLY of sync state. Ceilings are sourced from intent
// (named constants), not from whatever the impl happens to do.
func TestCleanupOldResults_PrunesUnsyncedBeyondCeiling(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	base := time.Now()
	clock := base
	st.now = func() time.Time { return clock }

	// synced + old → deleted (the original behaviour).
	syncedOld := recordResultAt(t, st, &clock, base, "a-synced-old", 8*24*time.Hour, true)
	// unsynced + older than the hard age ceiling → deleted (the gap: NOT kept forever).
	unsyncedOld := recordResultAt(t, st, &clock, base, "a-unsynced-old", unsyncedResultHardAge+24*time.Hour, false)
	// unsynced + fresh + under ceiling → retained.
	unsyncedFresh := recordResultAt(t, st, &clock, base, "a-unsynced-fresh", 24*time.Hour, false)

	clock = base // back to "now" for the cleanup
	evicted, err := st.CleanupOldResults(7 * 24 * time.Hour)
	require.NoError(t, err)

	assert.False(t, resultExists(t, st, syncedOld), "synced+old result must be deleted")
	assert.False(t, resultExists(t, st, unsyncedOld), "unsynced result past the hard age ceiling must be deleted, not kept forever")
	assert.True(t, resultExists(t, st, unsyncedFresh), "fresh unsynced result under the ceiling must be retained")
	assert.GreaterOrEqual(t, evicted, 1, "an evicted UNSYNCED (undelivered) result must be reported so the caller can warn")
}

// TestCleanupOldResults_CapsTotalRowCount pins the hard row-count cap: with the
// cap lowered, the oldest rows beyond it are evicted and the newest retained,
// regardless of sync/age.
func TestCleanupOldResults_CapsTotalRowCount(t *testing.T) {
	prev := maxResultRows
	maxResultRows = 3
	defer func() { maxResultRows = prev }()

	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	base := time.Now()
	clock := base
	st.now = func() time.Time { return clock }

	// 5 fresh unsynced results (all under the hard age ceiling), distinct ages
	// so "oldest" is well-defined. Newest = id4 (age 0), oldest = id0 (age 4h).
	ids := make([]string, 5)
	for i := 0; i < 5; i++ {
		ids[i] = recordResultAt(t, st, &clock, base, "cap-act-"+string(rune('a'+i)), time.Duration(4-i)*time.Hour, false)
	}

	clock = base
	evicted, err := st.CleanupOldResults(7 * 24 * time.Hour)
	require.NoError(t, err)

	var total int
	require.NoError(t, st.db.QueryRow("SELECT COUNT(*) FROM results").Scan(&total))
	assert.Equal(t, 3, total, "total rows must be capped to maxResultRows")
	assert.False(t, resultExists(t, st, ids[0]), "the oldest row beyond the cap must be evicted")
	assert.False(t, resultExists(t, st, ids[1]), "the 2nd-oldest beyond the cap must be evicted")
	assert.True(t, resultExists(t, st, ids[4]), "the newest row must be retained")
	assert.Equal(t, 2, evicted, "both capped rows were unsynced (undelivered) and must be counted")
}
