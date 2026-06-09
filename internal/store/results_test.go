package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

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
