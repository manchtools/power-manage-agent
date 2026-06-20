package scheduler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/agent/internal/store"
)

func shellAction(id string, shell *pb.ShellParams, sched *pb.ActionSchedule) *pb.Action {
	return &pb.Action{
		Id:           &pb.ActionId{Value: id},
		Type:         pb.ActionType_ACTION_TYPE_SHELL,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
		Params:       &pb.Action_Shell{Shell: shell},
		Schedule:     sched,
	}
}

// TestDetectChanges pins WS14 #2 across detectChanges' branches, including the
// compliance/detection always-report carve-out. The SkipIfUnchanged hash cases
// use a REAL store.RecordExecution to compute LastResultHash (never a hand-built
// hash that could pass circularly).
func TestDetectChanges(t *testing.T) {
	sched, _ := newTestScheduler(t)

	t.Run("FAILED status always reports", func(t *testing.T) {
		stored := &store.StoredAction{Action: shellAction("f", &pb.ShellParams{Script: "x"}, nil)}
		got := sched.detectChanges(stored, &pb.ActionResult{
			Status: pb.ExecutionStatus_EXECUTION_STATUS_FAILED, Changed: false,
		})
		assert.True(t, got, "a FAILED result must always be reported regardless of Changed")
	})

	t.Run("compliance shell always reports even when unchanged", func(t *testing.T) {
		stored := &store.StoredAction{Action: shellAction("c", &pb.ShellParams{Script: "check", IsCompliance: true}, nil)}
		got := sched.detectChanges(stored, &pb.ActionResult{
			Status: pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS, Changed: false,
		})
		assert.True(t, got, "compliance results must always be reported (server tracks status)")
	})

	t.Run("detection-only shell always reports even when unchanged", func(t *testing.T) {
		stored := &store.StoredAction{Action: shellAction("d", &pb.ShellParams{DetectionScript: "detect", Script: ""}, nil)}
		got := sched.detectChanges(stored, &pb.ActionResult{
			Status: pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS, Changed: false,
		})
		assert.True(t, got, "detection-only results must always be reported")
	})

	t.Run("non-compliance unchanged does not report", func(t *testing.T) {
		stored := &store.StoredAction{Action: shellAction("n", &pb.ShellParams{Script: "x"}, nil)}
		got := sched.detectChanges(stored, &pb.ActionResult{
			Status: pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS, Changed: false,
		})
		assert.False(t, got, "an ordinary unchanged success must not be reported")
	})

	t.Run("SkipIfUnchanged first run (empty hash) reports", func(t *testing.T) {
		stored := &store.StoredAction{
			Action:         shellAction("s0", &pb.ShellParams{Script: "x"}, &pb.ActionSchedule{SkipIfUnchanged: true}),
			LastResultHash: "",
		}
		got := sched.detectChanges(stored, &pb.ActionResult{
			Status: pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS, Changed: true,
			Output: &pb.CommandOutput{Stdout: "first"},
		})
		assert.True(t, got, "first run (no stored hash) must report")
	})

	t.Run("SkipIfUnchanged identical vs differing output (real recorded hash)", func(t *testing.T) {
		id := "s1"
		a := shellAction(id, &pb.ShellParams{Script: "x"}, &pb.ActionSchedule{SkipIfUnchanged: true})
		require.NoError(t, sched.store.SaveAction(a))
		// Record a run so the store computes + persists LastResultHash from "same".
		_, err := sched.store.RecordExecution(id, &pb.ActionResult{
			ActionId: a.Id, Status: pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS, Changed: true,
			Output: &pb.CommandOutput{Stdout: "same"},
		}, true)
		require.NoError(t, err)

		var stored *store.StoredAction
		all, err := sched.GetStoredActions()
		require.NoError(t, err)
		for _, s := range all {
			if s.ID == id {
				stored = s
			}
		}
		require.NotNil(t, stored)
		require.NotEmpty(t, stored.LastResultHash, "RecordExecution must have stored a result hash")

		// Identical output → not a change.
		assert.False(t, sched.detectChanges(stored, &pb.ActionResult{
			Status: pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS, Changed: true,
			Output: &pb.CommandOutput{Stdout: "same"},
		}), "identical output to the stored hash must not report")

		// Differing output → a change.
		assert.True(t, sched.detectChanges(stored, &pb.ActionResult{
			Status: pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS, Changed: true,
			Output: &pb.CommandOutput{Stdout: "different"},
		}), "differing output must report")
	})
}
