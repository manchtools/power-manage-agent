package store

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
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
