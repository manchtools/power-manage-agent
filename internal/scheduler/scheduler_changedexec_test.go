package scheduler

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// A non-first SyncActions must re-execute exactly the NEW and CHANGED
// standalone actions and leave an UNCHANGED action alone — the positive
// direction of the store's change detection, driven through the real
// Scheduler.SyncActions rather than asserted at the store layer. A regression
// that re-ran unchanged actions (e.g. whitespace drift mistaken for a change)
// would surface here as a spurious execution.
func TestSyncActions_ExecutesNewAndChanged_NotUnchanged(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	// Seed two actions on the first sync (firstSync=true runs them immediately).
	// `unchanged` is reused by-reference below so its stored bytes are identical
	// on the re-sync (no re-signing, which would look like a change).
	unchanged := makeTestAction("a-unchanged", pb.ActionType_ACTION_TYPE_PACKAGE, pb.DesiredState_DESIRED_STATE_PRESENT)
	changedSeed := makeTestAction("a-changed", pb.ActionType_ACTION_TYPE_PACKAGE, pb.DesiredState_DESIRED_STATE_PRESENT)
	require.NoError(t, sched.SyncActions(ctx, []*pb.Action{unchanged, changedSeed}, nil, true))
	mock.reset()

	// Re-sync: flip the changed action's desired state, add a brand-new
	// standalone, and re-send the unchanged action byte-identical.
	changed := makeTestAction("a-changed", pb.ActionType_ACTION_TYPE_PACKAGE, pb.DesiredState_DESIRED_STATE_ABSENT)
	added := makeTestAction("a-new", pb.ActionType_ACTION_TYPE_PACKAGE, pb.DesiredState_DESIRED_STATE_PRESENT)
	require.NoError(t, sched.SyncActions(ctx, []*pb.Action{unchanged, changed, added}, nil, false))

	executed := map[string]int{}
	for _, c := range mock.getCalls() {
		executed[c.GetActionId().GetValue()]++
	}
	assert.Equal(t, 1, executed["a-changed"], "the changed (desired-state-flipped) action re-executes exactly once")
	assert.Equal(t, 1, executed["a-new"], "the new standalone action executes exactly once")
	assert.Equal(t, 0, executed["a-unchanged"], "the byte-identical unchanged action must NOT re-execute")
}
