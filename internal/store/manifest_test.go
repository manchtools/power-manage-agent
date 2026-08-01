package store

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
)

func testManifestDelivery() *pb.ManifestDelivery {
	return &pb.ManifestDelivery{
		DeliveryId: "01K00000000000000000000001",
		Manifest: &pb.Manifest{
			ManifestId: "01K00000000000000000000002",
			Schedule:   &pb.ActionSchedule{RunOnAssign: true, IntervalHours: 8},
			Occurrences: []*pb.ManifestOccurrence{{
				OccurrenceId: "01K00000000000000000000003",
				Action: &pb.Action{
					Id:   &pb.ActionId{Value: "01K00000000000000000000004"},
					Type: pb.ActionType_ACTION_TYPE_SYNC,
				},
			}},
		},
	}
}

func TestRecordManifestDeliveryIsDurableAndReplaySafe(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	st.SetClockForTest(func() time.Time { return now })

	delivery := testManifestDelivery()
	inserted, err := st.RecordManifestDelivery(context.Background(), delivery)
	require.NoError(t, err)
	require.True(t, inserted)

	inserted, err = st.RecordManifestDelivery(context.Background(), delivery)
	require.NoError(t, err)
	require.False(t, inserted, "a transport replay must not create a second local execution")

	due, err := st.GetDueManifestDeliveries(context.Background())
	require.NoError(t, err)
	require.Len(t, due, 1)
	require.Equal(t, delivery.GetDeliveryId(), due[0].Delivery.GetDeliveryId())

	mutated := testManifestDelivery()
	mutated.Manifest.Occurrences[0].Action.Type = pb.ActionType_ACTION_TYPE_REBOOT
	_, err = st.RecordManifestDelivery(context.Background(), mutated)
	require.ErrorContains(t, err, "different manifest")
}

func TestRecoverInterruptedOccurrenceQueuesIndeterminate(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	delivery := testManifestDelivery()
	_, err = st.RecordManifestDelivery(context.Background(), delivery)
	require.NoError(t, err)
	_, err = st.BeginManifestRun(delivery, time.Now())
	require.NoError(t, err)
	occurrence := delivery.GetManifest().GetOccurrences()[0]
	require.NoError(t, st.MarkOccurrenceStarted(delivery.GetDeliveryId(), occurrence.GetOccurrenceId(), time.Now()))

	_, err = st.RecoverInterruptedOccurrences("same-boot")
	require.NoError(t, err)
	pending, err := st.GetPendingResults()
	require.NoError(t, err)
	require.Len(t, pending, 1)
	require.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_INDETERMINATE, pending[0].ActionResult.GetStatus())
	require.Equal(t, delivery.GetDeliveryId(), pending[0].ActionResult.GetDeliveryId())
	require.Equal(t, occurrence.GetOccurrenceId(), pending[0].ActionResult.GetOccurrenceId())

	_, err = st.RecoverInterruptedOccurrences("same-boot")
	require.NoError(t, err)
	pending, err = st.GetPendingResults()
	require.NoError(t, err)
	require.Len(t, pending, 1, "recovery must be idempotent")
}

func TestRecoverScheduledRebootUsesBootMarker(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	st.SetClockForTest(func() time.Time { return now })
	delivery := testManifestDelivery()
	delivery.Manifest.Occurrences[0].Action.Type = pb.ActionType_ACTION_TYPE_REBOOT
	_, err = st.RecordManifestDelivery(context.Background(), delivery)
	require.NoError(t, err)
	_, err = st.BeginManifestRun(delivery, now)
	require.NoError(t, err)
	occurrence := delivery.GetManifest().GetOccurrences()[0]
	require.NoError(t, st.MarkRebootStarted(delivery.GetDeliveryId(), occurrence.GetOccurrenceId(), "boot-before", now))

	recovered, err := st.RecoverInterruptedOccurrences("boot-after")
	require.NoError(t, err)
	require.Len(t, recovered, 1)
	require.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS, recovered[0].ActionResult.GetStatus())

	states, err := st.GetManifestOccurrenceStates(delivery.GetDeliveryId())
	require.NoError(t, err)
	require.Equal(t, OccurrenceSuccess, states[occurrence.GetOccurrenceId()].State)
}

func TestRecoverScheduledRebootWaitsOnSameBoot(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })
	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	st.SetClockForTest(func() time.Time { return now })
	delivery := testManifestDelivery()
	_, err = st.RecordManifestDelivery(context.Background(), delivery)
	require.NoError(t, err)
	_, err = st.BeginManifestRun(delivery, now)
	require.NoError(t, err)
	occurrence := delivery.GetManifest().GetOccurrences()[0]
	require.NoError(t, st.MarkRebootStarted(delivery.GetDeliveryId(), occurrence.GetOccurrenceId(), "same-boot", now))

	recovered, err := st.RecoverInterruptedOccurrences("same-boot")
	require.NoError(t, err)
	require.Empty(t, recovered)

	now = now.Add(rebootResolutionGrace)
	recovered, err = st.RecoverInterruptedOccurrences("same-boot")
	require.NoError(t, err)
	require.Len(t, recovered, 1)
	require.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_INDETERMINATE, recovered[0].ActionResult.GetStatus())
}
