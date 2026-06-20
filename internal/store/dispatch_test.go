package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// SaveAction is the dispatch path: the handler stores the action AND
// executes it immediately. The stored copy must therefore NOT be
// immediately due — its next_execute_at must be the next scheduled
// occurrence in the future. If it stays "now", the scheduler's ticker
// re-runs the action a second time (double-execution of non-idempotent
// SHELL actions). This mirrors the SyncActions standalone contract:
// "runs new standalone actions inline (advancing their cursor)".
func TestSaveAction_StoredActionIsNotImmediatelyDue(t *testing.T) {
	cases := []struct {
		name  string
		sched *pb.ActionSchedule
	}{
		{"nil schedule (drift default)", nil},
		{"run-on-assign, no interval", &pb.ActionSchedule{RunOnAssign: true}},
		{"interval 8h", &pb.ActionSchedule{IntervalHours: 8}},
		{"run-on-assign + interval", &pb.ActionSchedule{RunOnAssign: true, IntervalHours: 8}},
		{"cron daily 02:00", &pb.ActionSchedule{Cron: "0 2 * * *"}},
		{"invalid cron falls back to interval", &pb.ActionSchedule{Cron: "not-a-cron"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, err := New(t.TempDir())
			require.NoError(t, err)
			defer st.Close()

			id := "dispatch-act"
			a := &pb.Action{
				Id:           &pb.ActionId{Value: id},
				Type:         pb.ActionType_ACTION_TYPE_SHELL,
				DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
				Schedule:     tc.sched,
			}
			require.NoError(t, st.SaveAction(a))

			due, err := st.GetDueActions(context.Background())
			require.NoError(t, err)
			for _, d := range due {
				assert.NotEqual(t, id, d.ID,
					"dispatch-stored action is immediately due; handler already ran it, so the scheduler would double-execute")
			}
		})
	}
}

// TestSaveAction_OnConflictPreservesCursorAfterExecution pins WS14 #8: a
// re-dispatch (SaveAction of an already-executed action) updates action_json but
// PRESERVES next_execute_at — it must not reset the cursor to "now" and cause a
// double-fire. (ON CONFLICT branch: next_execute_at is kept once last_executed_at
// is set.)
func TestSaveAction_OnConflictPreservesCursorAfterExecution(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()
	ctx := context.Background()

	id := "conflict-act"
	a := &pb.Action{
		Id:           &pb.ActionId{Value: id},
		Type:         pb.ActionType_ACTION_TYPE_SHELL,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
		Schedule:     &pb.ActionSchedule{IntervalHours: 8},
	}
	require.NoError(t, st.SaveAction(a))

	// Execute it: RecordExecution sets last_executed_at and advances the cursor.
	_, err = st.RecordExecution(id, &pb.ActionResult{
		ActionId: a.Id, Status: pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
		Output: &pb.CommandOutput{Stdout: "ok"},
	}, true)
	require.NoError(t, err)

	var cursorAfterExec string
	require.NoError(t, st.db.QueryRow("SELECT next_execute_at FROM actions WHERE id = ?", id).Scan(&cursorAfterExec))

	// Re-dispatch with modified action_json (a new param) — the same id.
	a2 := &pb.Action{
		Id:           &pb.ActionId{Value: id},
		Type:         pb.ActionType_ACTION_TYPE_SHELL,
		DesiredState: pb.DesiredState_DESIRED_STATE_ABSENT, // change → action_json differs
		Schedule:     &pb.ActionSchedule{IntervalHours: 8},
	}
	require.NoError(t, st.SaveAction(a2))

	// action_json updated...
	var cursorAfterReSave, actionJSON string
	require.NoError(t, st.db.QueryRow("SELECT next_execute_at, action_json FROM actions WHERE id = ?", id).Scan(&cursorAfterReSave, &actionJSON))
	assert.Contains(t, actionJSON, "DESIRED_STATE_ABSENT", "re-dispatch must update action_json")
	// ...but the cursor is preserved (no reset-to-now double-fire).
	assert.Equal(t, cursorAfterExec, cursorAfterReSave, "re-dispatch must preserve next_execute_at, not reset the cursor")

	// And it is not immediately due.
	due, err := st.GetDueActions(ctx)
	require.NoError(t, err)
	for _, d := range due {
		assert.NotEqual(t, id, d.ID, "a re-dispatched, already-executed action must not be immediately due")
	}
}
