package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// GetUnsyncedResults must return ONLY unsynced rows, ordered by executed_at
// ascending, with the proto Output round-tripped. The reconnect sender relies
// on this order to deliver results oldest-first and on the synced filter to
// not re-send already-delivered results.
func TestGetUnsyncedResults_FiltersOrdersRoundtrips(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	clock := time.Date(2026, 6, 15, 8, 0, 0, 0, time.UTC)
	st.now = func() time.Time { return clock }

	a := &pb.Action{
		Id:           &pb.ActionId{Value: "act-unsynced"},
		Type:         pb.ActionType_ACTION_TYPE_SHELL,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
	}
	require.NoError(t, st.SaveAction(a))

	rec := func(stdout string) string {
		clock = clock.Add(time.Minute) // distinct executed_at + result id
		id, err := st.RecordExecution(a.Id.Value, &pb.ActionResult{
			ActionId: a.Id,
			Status:   pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
			Output:   &pb.CommandOutput{Stdout: stdout},
		}, true)
		require.NoError(t, err)
		return id
	}
	r1 := rec("first")
	r2 := rec("second")
	r3 := rec("third")

	// Sync the MIDDLE one — it must drop out of the unsynced set.
	require.NoError(t, st.MarkResultSynced(r2))

	got, err := st.GetUnsyncedResults()
	require.NoError(t, err)
	require.Len(t, got, 2, "only the two unsynced results are returned")
	assert.Equal(t, r1, got[0].ID, "ordered by executed_at ASC: oldest first")
	assert.Equal(t, r3, got[1].ID)
	assert.True(t, got[0].ExecutedAt.Before(got[1].ExecutedAt), "executed_at strictly ascending")
	assert.Equal(t, "first", got[0].Output.GetStdout(), "Output round-trips through protojson")
	assert.Equal(t, "third", got[1].Output.GetStdout())
}

// MarkResultSynced on an unknown id is a clean no-op (returns nil, changes
// nothing) — a cleaned-up or never-recorded id must not error nor disturb the
// real unsynced rows.
func TestMarkResultSynced_UnknownId_NoOp(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	clock := time.Date(2026, 6, 15, 8, 0, 0, 0, time.UTC)
	st.now = func() time.Time { return clock }

	a := &pb.Action{
		Id:           &pb.ActionId{Value: "act-noop"},
		Type:         pb.ActionType_ACTION_TYPE_SHELL,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
	}
	require.NoError(t, st.SaveAction(a))
	clock = clock.Add(time.Minute)
	r1, err := st.RecordExecution(a.Id.Value, &pb.ActionResult{
		ActionId: a.Id,
		Status:   pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
		Output:   &pb.CommandOutput{Stdout: "only"},
	}, true)
	require.NoError(t, err)

	require.NoError(t, st.MarkResultSynced("does-not-exist"), "unknown id must be a no-op, not an error")

	got, err := st.GetUnsyncedResults()
	require.NoError(t, err)
	require.Len(t, got, 1, "the real unsynced result is untouched by a no-op mark")
	assert.Equal(t, r1, got[0].ID)
}

// IsResultSynced drives the reconnect dedup that stops sendScheduledResults
// from re-sending a result syncPendingResults already delivered.
func TestIsResultSynced(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	a := &pb.Action{
		Id:           &pb.ActionId{Value: "act-res"},
		Type:         pb.ActionType_ACTION_TYPE_SHELL,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
	}
	require.NoError(t, st.SaveAction(a))

	resultID, err := st.RecordExecution(a.Id.Value, &pb.ActionResult{
		ActionId: a.Id,
		Status:   pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
		Output:   &pb.CommandOutput{Stdout: "ok"},
	}, true)
	require.NoError(t, err)

	synced, err := st.IsResultSynced(resultID)
	require.NoError(t, err)
	assert.False(t, synced, "a freshly recorded result is not yet synced")

	require.NoError(t, st.MarkResultSynced(resultID))
	synced, err = st.IsResultSynced(resultID)
	require.NoError(t, err)
	assert.True(t, synced, "after MarkResultSynced the result is synced")

	// A missing row counts as handled so a cleaned-up result is never re-sent.
	synced, err = st.IsResultSynced("does-not-exist")
	require.NoError(t, err)
	assert.True(t, synced)
}
