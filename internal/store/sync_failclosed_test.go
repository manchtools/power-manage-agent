package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// WS16 #4: a removed policy action whose stored JSON can't unmarshal was
// Warn-and-deleted — the action vanished without ever reverting its side
// effects (SSH/sudo/etc.), drifting store and device apart. The removal path
// must now fail closed: do NOT delete a row it cannot decode for revert.

func actionRowExists(t *testing.T, st *Store, id string) bool {
	t.Helper()
	var n int
	require.NoError(t, st.db.QueryRow("SELECT count(*) FROM actions WHERE id = ?", id).Scan(&n))
	return n > 0
}

func TestSyncActions_RemovedActionUnmarshalFailure_DoesNotDeleteWithoutRevert(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	a := &pb.Action{
		Id:           &pb.ActionId{Value: "corrupt-removed"},
		Type:         pb.ActionType_ACTION_TYPE_PACKAGE,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
	}
	_, err = st.SyncActions([]*pb.Action{a})
	require.NoError(t, err)

	// Corrupt the stored JSON so the removal-undo decode fails.
	_, err = st.db.Exec("UPDATE actions SET action_json = ? WHERE id = ?", "not-valid-protojson", a.Id.Value)
	require.NoError(t, err)

	// Server now reports no actions → the local action is "removed".
	_, err = st.SyncActions(nil)
	require.Error(t, err, "a removed action with undecodable JSON must fail closed, not silently delete")
	assert.True(t, actionRowExists(t, st, a.Id.Value),
		"the undecodable action row must remain (no delete without revert)")
}

func TestSyncStandaloneAndGrouped_RemovedActionUnmarshalFailure_DoesNotDeleteWithoutRevert(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	a := &pb.Action{
		Id:           &pb.ActionId{Value: "corrupt-standalone"},
		Type:         pb.ActionType_ACTION_TYPE_PACKAGE,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
	}
	_, err = st.SyncStandaloneAndGrouped([]*pb.Action{a}, nil)
	require.NoError(t, err)

	_, err = st.db.Exec("UPDATE actions SET action_json = ? WHERE id = ?", "not-valid-protojson", a.Id.Value)
	require.NoError(t, err)

	_, err = st.SyncStandaloneAndGrouped(nil, nil)
	require.Error(t, err, "a removed standalone action with undecodable JSON must fail closed, not silently delete")
	assert.True(t, actionRowExists(t, st, a.Id.Value),
		"the undecodable action row must remain (no delete without revert)")
}
