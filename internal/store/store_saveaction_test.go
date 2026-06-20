package store

import (
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// SaveAction dereferences action.Id.Value to build the upsert key. A nil Id
// from a malformed envelope must be rejected with an error, NOT panic — the
// sibling sync paths (SyncActions, SyncStandaloneAndGrouped) already skip
// nil-Id actions, so SaveAction must be equally defensive rather than crash
// the agent. (If the guard were absent this test would panic, not fail.)
func TestSaveAction_NilId_ReturnsErrorNotPanic(t *testing.T) {
	st, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	err = st.SaveAction(&pb.Action{
		Id:           nil,
		Type:         pb.ActionType_ACTION_TYPE_PACKAGE,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
	})
	if err == nil {
		t.Fatal("SaveAction with a nil Id must return an error, not succeed")
	}
	if !strings.Contains(err.Error(), "nil id") {
		t.Errorf("error = %q, want it to name the nil id", err)
	}
}
