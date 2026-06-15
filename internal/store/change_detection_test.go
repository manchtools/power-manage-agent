package store

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// insignificantWhitespaceDrift returns raw with a space injected after a
// colon — a position protojson NEVER emits (its only non-determinism is
// an optional space after the comma separator, seeded per binary). The
// result is therefore guaranteed byte-different from any protojson
// output regardless of seed, yet identical after json.Compact — exactly
// the cross-binary drift the store's change detection must ignore. It
// fails the test if the input has no colon (nothing to drift).
func insignificantWhitespaceDrift(t *testing.T, raw []byte) string {
	t.Helper()
	var compact bytes.Buffer
	require.NoError(t, json.Compact(&compact, raw))
	require.Contains(t, compact.String(), ":", "JSON has no colon to drift")
	drifted := strings.Replace(compact.String(), ":", ": ", 1)
	require.NotEqual(t, string(raw), drifted, "drift must differ from the fresh marshal or the test is vacuous")
	return drifted
}

// protojson injects per-binary random insignificant whitespace; the
// store's change detection byte-compares these blobs. A whitespace-only
// difference (the shape produced when an agent self-updates to a binary
// with a different protojson seed) MUST NOT be treated as a change, or
// every action re-executes and every schedule resets on the next sync.
func TestSyncActions_IgnoresProtojsonWhitespaceDrift(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	a := &pb.Action{
		Id:           &pb.ActionId{Value: "pkg-drift"},
		Type:         pb.ActionType_ACTION_TYPE_PACKAGE,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
	}

	// First sync establishes the row (desired_state + json).
	if _, err := st.SyncActions([]*pb.Action{a}); err != nil {
		t.Fatalf("initial sync: %v", err)
	}

	// Rewrite the stored blob with the identical action re-marshaled but
	// carrying insignificant whitespace a different agent binary's
	// protojson seed could have emitted.
	raw, err := protojson.Marshal(a)
	require.NoError(t, err)
	drifted := insignificantWhitespaceDrift(t, raw)
	_, err = st.db.Exec("UPDATE actions SET action_json = ? WHERE id = ?", drifted, a.Id.Value)
	require.NoError(t, err)

	// Re-sync the identical action.
	res, err := st.SyncActions([]*pb.Action{a})
	require.NoError(t, err)
	assert.NotContains(t, res.ChangedActionIDs, a.Id.Value,
		"whitespace-only protojson drift must not flag the action as changed")
}

// Same guarantee for the group cadence-preservation compare, which
// byte-compares the stored vs fresh schedule JSON to decide whether to
// keep the group's existing next_execute_at.
func TestSyncStandaloneAndGrouped_IgnoresScheduleWhitespaceDrift(t *testing.T) {
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

	// Capture the group's next_execute_at, drift the stored schedule
	// JSON, and re-sync. If the whitespace drift is mistaken for a
	// schedule change, the cadence (next_execute_at) is reset.
	var before string
	require.NoError(t, st.db.QueryRow("SELECT next_execute_at FROM action_groups WHERE id = ?", group.SourceLabel).Scan(&before))

	raw, err := protojson.Marshal(group.Schedule)
	require.NoError(t, err)
	drifted := insignificantWhitespaceDrift(t, raw)
	_, err = st.db.Exec("UPDATE action_groups SET schedule_json = ? WHERE id = ?", drifted, group.SourceLabel)
	require.NoError(t, err)

	if _, err := st.SyncStandaloneAndGrouped(nil, []*pb.ActionGroup{group}); err != nil {
		t.Fatalf("resync: %v", err)
	}

	var after string
	require.NoError(t, st.db.QueryRow("SELECT next_execute_at FROM action_groups WHERE id = ?", group.SourceLabel).Scan(&after))
	assert.Equal(t, before, after,
		"whitespace-only schedule drift must preserve the group's cadence, not reset next_execute_at")
}

// The companion guarantee for STANDALONE actions: the existing drift test only
// proved the action is absent from ChangedActionIDs. The upsert's next_execute_at
// CASE used a raw byte compare of the stored vs incoming action_json — which
// disagreed with the Go compacted compare — so insignificant whitespace drift
// reset the action's cadence even though it was reported unchanged. The clock is
// advanced between syncs so a spurious reset would be observable (the recomputed
// next_execute_at differs); the test pins that it is NOT reset.
func TestSyncActions_WhitespaceDrift_PreservesStandaloneCadence(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	now1 := time.Date(2026, 6, 15, 12, 0, 0, 0, time.UTC)
	st.now = func() time.Time { return now1 }

	a := &pb.Action{
		Id:           &pb.ActionId{Value: "pkg-cadence"},
		Type:         pb.ActionType_ACTION_TYPE_PACKAGE,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
	}
	if _, err := st.SyncActions([]*pb.Action{a}); err != nil {
		t.Fatalf("initial sync: %v", err)
	}

	var before string
	require.NoError(t, st.db.QueryRow("SELECT next_execute_at FROM actions WHERE id = ?", a.Id.Value).Scan(&before))

	// Drift the STORED json with insignificant whitespace and advance the clock
	// so a reset would move next_execute_at forward (now+8h recomputed).
	raw, err := protojson.Marshal(a)
	require.NoError(t, err)
	drifted := insignificantWhitespaceDrift(t, raw)
	_, err = st.db.Exec("UPDATE actions SET action_json = ? WHERE id = ?", drifted, a.Id.Value)
	require.NoError(t, err)
	st.now = func() time.Time { return now1.Add(time.Hour) }

	res, err := st.SyncActions([]*pb.Action{a})
	require.NoError(t, err)
	assert.NotContains(t, res.ChangedActionIDs, a.Id.Value,
		"whitespace-only drift must not flag the standalone action as changed")

	var after string
	require.NoError(t, st.db.QueryRow("SELECT next_execute_at FROM actions WHERE id = ?", a.Id.Value).Scan(&after))
	assert.Equal(t, before, after,
		"whitespace-only drift must PRESERVE the standalone action's cadence (next_execute_at), not reset it")
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
