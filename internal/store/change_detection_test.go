package store

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

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
