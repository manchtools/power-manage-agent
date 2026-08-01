package scheduler

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	pb "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	"github.com/manchtools/power-manage/agent/internal/store"
)

type recordingExecutor struct {
	executed []string
	status   map[string]pb.ExecutionStatus
}

func (e *recordingExecutor) ExecuteAction(_ context.Context, action *pb.Action) *pb.ActionResult {
	id := action.GetId().GetValue()
	e.executed = append(e.executed, id)
	status := e.status[id]
	if status == pb.ExecutionStatus_EXECUTION_STATUS_UNSPECIFIED {
		status = pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS
	}
	return &pb.ActionResult{ActionId: action.GetId(), Status: status, CompletedAt: timestamppb.Now()}
}

func (*recordingExecutor) ResetUpdateCycle() {}

func scheduledDelivery(onFailure pb.OnFailure) *pb.ManifestDelivery {
	return &pb.ManifestDelivery{
		DeliveryId: "01K00000000000000000000011",
		Manifest: &pb.Manifest{
			ManifestId: "01K00000000000000000000012",
			Schedule:   &pb.ActionSchedule{RunOnAssign: true, IntervalHours: 8},
			Occurrences: []*pb.ManifestOccurrence{
				{OccurrenceId: "01K00000000000000000000013", OnFailure: onFailure, Action: &pb.Action{Id: &pb.ActionId{Value: "01K00000000000000000000014"}, Type: pb.ActionType_ACTION_TYPE_PACKAGE}},
				{OccurrenceId: "01K00000000000000000000015", Action: &pb.Action{Id: &pb.ActionId{Value: "01K00000000000000000000016"}, Type: pb.ActionType_ACTION_TYPE_SERVICE}},
			},
		},
	}
}

func TestManifestRunsInOrderAndReplayDoesNotDoubleExecute(t *testing.T) {
	st, err := store.New(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	st.SetClockForTest(func() time.Time { return now })
	exec := &recordingExecutor{status: map[string]pb.ExecutionStatus{}}
	sched := New(st, exec, slog.New(slog.NewTextHandler(io.Discard, nil)))
	sched.now = func() time.Time { return now }
	delivery := scheduledDelivery(pb.OnFailure_ON_FAILURE_CONTINUE)

	inserted, err := sched.RecordDelivery(context.Background(), delivery)
	require.NoError(t, err)
	require.True(t, inserted)
	inserted, err = sched.RecordDelivery(context.Background(), delivery)
	require.NoError(t, err)
	require.False(t, inserted)

	sched.runDue(context.Background())
	require.Equal(t, []string{
		"01K00000000000000000000014",
		"01K00000000000000000000016",
	}, exec.executed)
	sched.runDue(context.Background())
	require.Len(t, exec.executed, 2, "the transport replay must not create another due run")

	pending, err := st.GetPendingResults()
	require.NoError(t, err)
	require.Len(t, pending, 3)
	require.Equal(t, delivery.GetDeliveryId(), pending[0].ActionResult.GetDeliveryId())
	require.Equal(t, delivery.GetManifest().GetOccurrences()[0].GetOccurrenceId(), pending[0].ActionResult.GetOccurrenceId())
	require.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS, pending[2].ManifestResult.GetStatus())
}

func TestManifestStopPolicyRecordsRemainingOccurrenceAsSkipped(t *testing.T) {
	st, err := store.New(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	delivery := scheduledDelivery(pb.OnFailure_ON_FAILURE_STOP)
	firstID := delivery.GetManifest().GetOccurrences()[0].GetAction().GetId().GetValue()
	exec := &recordingExecutor{status: map[string]pb.ExecutionStatus{firstID: pb.ExecutionStatus_EXECUTION_STATUS_FAILED}}
	sched := New(st, exec, slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, err = sched.RecordDelivery(context.Background(), delivery)
	require.NoError(t, err)
	sched.runDue(context.Background())
	require.Equal(t, []string{firstID}, exec.executed)

	pending, err := st.GetPendingResults()
	require.NoError(t, err)
	require.Len(t, pending, 3)
	require.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_SKIPPED, pending[1].ActionResult.GetStatus())
	require.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_FAILED, pending[2].ManifestResult.GetStatus())
}

func TestSkipIfUnchangedSuppressesRepeatedActionOutputButStillExecutes(t *testing.T) {
	st, err := store.New(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	st.SetClockForTest(func() time.Time { return now })
	delivery := scheduledDelivery(pb.OnFailure_ON_FAILURE_CONTINUE)
	delivery.Manifest.Schedule.SkipIfUnchanged = true
	exec := &recordingExecutor{status: map[string]pb.ExecutionStatus{}}
	sched := New(st, exec, slog.New(slog.NewTextHandler(io.Discard, nil)))
	sched.now = func() time.Time { return now }
	_, err = sched.RecordDelivery(context.Background(), delivery)
	require.NoError(t, err)

	sched.runDue(context.Background())
	now = now.Add(8 * time.Hour)
	sched.runDue(context.Background())
	require.Len(t, exec.executed, 4, "deduplication must not suppress reconciliation")

	pending, err := st.GetPendingResults()
	require.NoError(t, err)
	require.Len(t, pending, 4, "the repeated action outputs are suppressed; each manifest result remains")
	actionResults := 0
	manifestResults := 0
	for _, result := range pending {
		if result.ActionResult != nil {
			actionResults++
		}
		if result.ManifestResult != nil {
			manifestResults++
		}
	}
	require.Equal(t, 2, actionResults)
	require.Equal(t, 2, manifestResults)
}

func TestRebootCompletesOnlyAfterBootIDChangesAndManifestResumes(t *testing.T) {
	st, err := store.New(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	st.SetClockForTest(func() time.Time { return now })
	delivery := scheduledDelivery(pb.OnFailure_ON_FAILURE_CONTINUE)
	delivery.Manifest.Occurrences[0].Action.Type = pb.ActionType_ACTION_TYPE_REBOOT
	exec := &recordingExecutor{status: map[string]pb.ExecutionStatus{}}
	sched := New(st, exec, slog.New(slog.NewTextHandler(io.Discard, nil)))
	sched.now = func() time.Time { return now }
	bootID := "boot-before"
	sched.bootID = func() (string, error) { return bootID, nil }
	_, err = sched.RecordDelivery(context.Background(), delivery)
	require.NoError(t, err)

	sched.runDue(context.Background())
	require.Equal(t, []string{"01K00000000000000000000014"}, exec.executed)
	pending, err := st.GetPendingResults()
	require.NoError(t, err)
	require.Empty(t, pending, "scheduling a reboot is not proof that it completed")

	bootID = "boot-after"
	now = now.Add(time.Minute)
	sched.runDue(context.Background())
	require.Equal(t, []string{
		"01K00000000000000000000014",
		"01K00000000000000000000016",
	}, exec.executed, "the reboot occurrence must not execute twice")
	pending, err = st.GetPendingResults()
	require.NoError(t, err)
	require.Len(t, pending, 3)
	require.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS, pending[0].ActionResult.GetStatus())
	require.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS, pending[2].ManifestResult.GetStatus())
}
