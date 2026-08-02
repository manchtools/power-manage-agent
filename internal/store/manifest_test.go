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

// oneShotDelivery mirrors what control's manifest.OneShotAction emits for an
// explicit dispatch: the structural one_shot marker plus a schedule carrying
// no cadence. The empty schedule alone is NOT the marker — assigned manifests
// may carry the same empty schedule for the agent-default drift cadence.
func oneShotDelivery() *pb.ManifestDelivery {
	return &pb.ManifestDelivery{
		DeliveryId: "01K00000000000000000000101",
		Manifest: &pb.Manifest{
			ManifestId: "01K00000000000000000000102",
			OneShot:    true,
			Schedule:   &pb.ActionSchedule{},
			Occurrences: []*pb.ManifestOccurrence{{
				OccurrenceId: "01K00000000000000000000103",
				Action: &pb.Action{
					Id:   &pb.ActionId{Value: "01K00000000000000000000104"},
					Type: pb.ActionType_ACTION_TYPE_REBOOT,
				},
			}},
		},
	}
}

// A dispatched one-shot must execute exactly once. It carries no cron, no
// interval and no run_on_assign, so nothing asks for it to run again — and a
// REBOOT that silently re-arms would reboot the device on every drift tick
// for as long as the delivery is stored.
func TestOneShotDeliveryNeverBecomesDueAgain(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })

	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	st.SetClockForTest(func() time.Time { return now })

	delivery := oneShotDelivery()
	_, err = st.RecordManifestDelivery(context.Background(), delivery)
	require.NoError(t, err)

	// The single receipt-triggered run, then the result that ends it.
	_, err = st.BeginManifestRun(delivery, now)
	require.NoError(t, err)
	_, err = st.RecordManifestResult(&pb.ManifestResult{
		DeliveryId: delivery.GetDeliveryId(),
		ManifestId: delivery.GetManifest().GetManifestId(),
	})
	require.NoError(t, err)

	// Well past any drift interval the agent might default to, the delivery
	// must not be offered for execution again.
	for _, elapsed := range []time.Duration{
		time.Minute,
		8 * time.Hour,
		24 * time.Hour,
		30 * 24 * time.Hour,
	} {
		at := now.Add(elapsed)
		st.SetClockForTest(func() time.Time { return at })
		due, err := st.GetDueManifestDeliveries(context.Background())
		require.NoError(t, err)
		require.Empty(t, due,
			"a one-shot dispatch became due again %s after its single run", elapsed)
	}
}

// Running exactly once must not cost crash recovery. A one-shot whose run
// never reached its manifest result is still an ACTIVE run, so it stays on
// offer for resume however long the agent was down — the terminal marker
// closes the schedule, it does not abandon work in flight.
func TestInterruptedOneShotDeliveryIsStillOfferedForResume(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, st.Close()) })

	now := time.Date(2026, 8, 1, 12, 0, 0, 0, time.UTC)
	st.SetClockForTest(func() time.Time { return now })

	delivery := oneShotDelivery()
	_, err = st.RecordManifestDelivery(context.Background(), delivery)
	require.NoError(t, err)
	_, err = st.BeginManifestRun(delivery, now)
	require.NoError(t, err)
	// The agent crashes here: run_in_progress stays TRUE and no manifest
	// result ever ends the run.

	at := now.Add(30 * 24 * time.Hour)
	st.SetClockForTest(func() time.Time { return at })
	due, err := st.GetDueManifestDeliveries(context.Background())
	require.NoError(t, err)
	require.Len(t, due, 1, "an interrupted one-shot run must still be resumable after a crash")
	require.Equal(t, delivery.GetDeliveryId(), due[0].Delivery.GetDeliveryId())
	require.True(t, due[0].RunInProgress)
}
