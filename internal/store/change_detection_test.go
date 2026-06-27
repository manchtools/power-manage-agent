package store

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// Change detection compares the deterministic BINARY encoding of the stored vs
// incoming action (sameStoredProto). Deterministic marshal removes the per-binary
// whitespace non-determinism protojson had — there is nothing to "drift" — so
// re-syncing an identical action after a self-update must land in NEITHER the
// changed nor the new list, and must NOT reset the action's cadence (which would
// re-execute everything on the next sync).
func TestSyncActions_ReSyncIdenticalPreservesStandaloneCadence(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	now1 := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	st.now = func() time.Time { return now1 }

	a := &pb.Action{
		Id:           &pb.ActionId{Value: "pkg-cadence"},
		Type:         pb.ActionType_ACTION_TYPE_PACKAGE,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
		Schedule:     &pb.ActionSchedule{IntervalHours: 8},
	}
	if _, err := st.SyncActions([]*pb.Action{a}); err != nil {
		t.Fatalf("initial sync: %v", err)
	}

	var before string
	require.NoError(t, st.db.QueryRow("SELECT next_execute_at FROM actions WHERE id = ?", a.Id.Value).Scan(&before))

	// Advance the clock so a spurious reset would move next_execute_at forward, then
	// re-sync the IDENTICAL action.
	st.now = func() time.Time { return now1.Add(time.Hour) }
	res, err := st.SyncActions([]*pb.Action{a})
	require.NoError(t, err)
	assert.NotContains(t, res.ChangedActionIDs, a.Id.Value, "a byte-identical re-sync must not flag the action as changed")

	var after string
	require.NoError(t, st.db.QueryRow("SELECT next_execute_at FROM actions WHERE id = ?", a.Id.Value).Scan(&after))
	assert.Equal(t, before, after, "re-syncing an identical action must PRESERVE its cadence (next_execute_at), not reset it")
}

// The same cadence-preservation guarantee for the group schedule compare: an
// identical group schedule re-synced must keep the group's existing
// next_execute_at.
func TestSyncStandaloneAndGrouped_ReSyncIdenticalSchedulePreservesCadence(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	group := &pb.ActionGroup{
		SourceLabel: "definition:x",
		Schedule:    &pb.ActionSchedule{IntervalHours: 8, RunOnAssign: true},
		Actions: []*pb.Action{{
			Id:           &pb.ActionId{Value: "grp-mem"},
			Type:         pb.ActionType_ACTION_TYPE_PACKAGE,
			DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
		}},
	}
	if _, err := st.SyncStandaloneAndGrouped(nil, []*pb.ActionGroup{group}); err != nil {
		t.Fatalf("initial sync: %v", err)
	}

	var before string
	require.NoError(t, st.db.QueryRow("SELECT next_execute_at FROM action_groups WHERE id = ?", group.SourceLabel).Scan(&before))

	// Re-sync the identical group: its cadence must be preserved.
	if _, err := st.SyncStandaloneAndGrouped(nil, []*pb.ActionGroup{group}); err != nil {
		t.Fatalf("resync: %v", err)
	}

	var after string
	require.NoError(t, st.db.QueryRow("SELECT next_execute_at FROM action_groups WHERE id = ?", group.SourceLabel).Scan(&after))
	assert.Equal(t, before, after, "re-syncing an identical group schedule must preserve the group's cadence, not reset next_execute_at")
}

// Positive direction for change detection: a desired-state flip and a params
// change must both land in ChangedActionIDs, a byte-identical re-sync must land
// in NEITHER list, and nothing is mis-reported as New on a re-sync.
func TestSyncActions_ChangedActionIDs_PositiveDirection(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	flip := &pb.Action{Id: &pb.ActionId{Value: "a-flip"}, Type: pb.ActionType_ACTION_TYPE_PACKAGE, DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT}
	param := &pb.Action{Id: &pb.ActionId{Value: "a-param"}, Type: pb.ActionType_ACTION_TYPE_PACKAGE, DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT, Schedule: &pb.ActionSchedule{IntervalHours: 8}}
	same := &pb.Action{Id: &pb.ActionId{Value: "a-same"}, Type: pb.ActionType_ACTION_TYPE_PACKAGE, DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT}

	if _, err := st.SyncActions([]*pb.Action{flip, param, same}); err != nil {
		t.Fatalf("seed sync: %v", err)
	}

	// (a) desired_state flip; (b) params change (interval); (c) untouched.
	flip.DesiredState = pb.DesiredState_DESIRED_STATE_ABSENT
	param.Schedule = &pb.ActionSchedule{IntervalHours: 12}

	res, err := st.SyncActions([]*pb.Action{flip, param, same})
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"a-flip", "a-param"}, res.ChangedActionIDs,
		"exactly the flipped and re-parameterised actions are changed")
	assert.Empty(t, res.NewActionIDs, "a re-sync of existing actions reports none as new")
	assert.NotContains(t, res.ChangedActionIDs, "a-same", "an unchanged action must not be reported as changed")
}
