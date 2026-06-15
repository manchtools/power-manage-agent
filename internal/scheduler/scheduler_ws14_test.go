package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// TestShouldRevertOnUnassign_ExactPartitionOverAllEnumValues pins WS14 #4
// self-discoveringly: every ActionType must be classified into EXACTLY one of
// the two pinned sets, so adding a new account/access-granting type forces an
// explicit revert decision (the test fails until it's classified) rather than
// silently defaulting to "don't revert". The revertible set is sourced from
// intent — a created account/credential must not outlive its assignment — not by
// reading the switch.
func TestShouldRevertOnUnassign_ExactPartitionOverAllEnumValues(t *testing.T) {
	revertible := map[pb.ActionType]bool{
		pb.ActionType_ACTION_TYPE_SSH:          true,
		pb.ActionType_ACTION_TYPE_SSHD:         true,
		pb.ActionType_ACTION_TYPE_ADMIN_POLICY: true,
		pb.ActionType_ACTION_TYPE_LPS:          true,
		pb.ActionType_ACTION_TYPE_USER:         true,
		pb.ActionType_ACTION_TYPE_GROUP:        true,
	}
	nonRevertible := map[pb.ActionType]bool{
		pb.ActionType_ACTION_TYPE_PACKAGE:      true,
		pb.ActionType_ACTION_TYPE_DEB:          true,
		pb.ActionType_ACTION_TYPE_RPM:          true,
		pb.ActionType_ACTION_TYPE_APP_IMAGE:    true,
		pb.ActionType_ACTION_TYPE_FLATPAK:      true,
		pb.ActionType_ACTION_TYPE_REPOSITORY:   true,
		pb.ActionType_ACTION_TYPE_SERVICE:      true,
		pb.ActionType_ACTION_TYPE_FILE:         true,
		pb.ActionType_ACTION_TYPE_DIRECTORY:    true,
		pb.ActionType_ACTION_TYPE_SHELL:        true,
		pb.ActionType_ACTION_TYPE_SCRIPT_RUN:   true,
		pb.ActionType_ACTION_TYPE_REBOOT:       true,
		pb.ActionType_ACTION_TYPE_UPDATE:       true,
		pb.ActionType_ACTION_TYPE_AGENT_UPDATE: true,
		pb.ActionType_ACTION_TYPE_WIFI:         true,
		pb.ActionType_ACTION_TYPE_ENCRYPTION:   true,
		pb.ActionType_ACTION_TYPE_SYNC:         true,
	}

	require.Len(t, revertible, 6, "the revertible set is exactly the six account/access-granting types")

	seen := 0
	for v, name := range pb.ActionType_name {
		at := pb.ActionType(v)
		if at == pb.ActionType_ACTION_TYPE_UNSPECIFIED {
			continue
		}
		seen++
		inRev := revertible[at]
		inNon := nonRevertible[at]
		require.Truef(t, inRev != inNon,
			"ActionType %s (%d) must be in EXACTLY one of {revertible, nonRevertible} — a new account/access type must be explicitly classified", name, v)
		assert.Equalf(t, inRev, shouldRevertOnUnassign(at),
			"ActionType %s: shouldRevertOnUnassign must match the pinned partition", name)
	}
	require.Positive(t, seen, "the ActionType enum must be non-empty")
}

// TestRevertAction_FailureStillRemovesFromStore pins WS14 #3: RemoveAction is
// best-effort — a revertible action is deleted from the offline store even when
// its revert (ABSENT) execution FAILS, and RemoveAction returns nil. Driven
// through the public RemoveAction, not revertAction.
func TestRevertAction_FailureStillRemovesFromStore(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	a := makeTestAction("ssh-001", pb.ActionType_ACTION_TYPE_SSH, pb.DesiredState_DESIRED_STATE_PRESENT)
	require.NoError(t, sched.store.SaveAction(a))

	// The revert run (ABSENT) for ssh-001 fails.
	mock.setScript("ssh-001", &pb.ActionResult{
		ActionId: a.Id, Status: pb.ExecutionStatus_EXECUTION_STATUS_FAILED, Error: "revert boom",
	})

	require.NoError(t, sched.RemoveAction(ctx, "ssh-001"),
		"RemoveAction is best-effort: it must return nil even when the revert fails")

	stored, err := sched.GetStoredActions()
	require.NoError(t, err)
	assert.Empty(t, stored, "the action must be deleted even though its revert failed")
}

// TestScheduler_StopWaitsForInFlightExecution pins WS14 #9: Stop() blocks until
// the loop returns, so an in-flight execution's RecordExecution has committed
// before a caller (main) closes the store. A RunOnAssign group member is due on
// the first tick; its execution blocks until released.
func TestScheduler_StopWaitsForInFlightExecution(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	a := makeTestAction("inflight-1", pb.ActionType_ACTION_TYPE_SHELL, pb.DesiredState_DESIRED_STATE_PRESENT)
	group := &pb.ActionGroup{
		SourceLabel: "action_set:inflight",
		Schedule:    &pb.ActionSchedule{RunOnAssign: true, IntervalHours: 8},
		Actions:     []*pb.Action{a},
	}
	require.NoError(t, sched.SyncActions(ctx, nil, []*pb.ActionGroup{group}, false))

	release := make(chan struct{})
	mock.setBlock("inflight-1", release)

	go sched.Start(ctx)
	require.Eventually(t, func() bool { return len(mock.getCalls()) >= 1 }, 2*time.Second, 5*time.Millisecond,
		"the due group member must start executing on the first tick")

	// Stop() must NOT return while the execution is still in flight.
	stopped := make(chan struct{})
	go func() { sched.Stop(); close(stopped) }()
	select {
	case <-stopped:
		t.Fatal("Stop returned before the in-flight execution finished")
	case <-time.After(150 * time.Millisecond):
	}

	close(release) // let the execution complete

	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return after the execution was released")
	}

	results, err := sched.store.GetUnsyncedResults()
	require.NoError(t, err)
	assert.NotEmpty(t, results, "the in-flight execution's result must be committed before Stop returns (no loss on shutdown)")
}

// TestScheduler_RestartAfterStopRunsAgain pins WS14 #10: a Start after a Stop
// runs again (the next Start reassigns stopCh/done), and the second Stop halts
// it. Proves the stale-closed-channel invariant.
func TestScheduler_RestartAfterStopRunsAgain(t *testing.T) {
	sched, _ := newTestScheduler(t)
	ctx := context.Background()
	running := func() bool {
		sched.mu.RLock()
		defer sched.mu.RUnlock()
		return sched.running
	}

	go sched.Start(ctx)
	require.Eventually(t, running, time.Second, 5*time.Millisecond, "scheduler must be running after first Start")
	sched.Stop()
	require.False(t, running(), "scheduler must be stopped after first Stop")

	go sched.Start(ctx)
	require.Eventually(t, running, time.Second, 5*time.Millisecond, "Start after Stop must run again (fresh stopCh/done)")
	sched.Stop()
	require.False(t, running(), "scheduler must be stopped after second Stop")
}

// TestRunDueActions_StandaloneActionBecomesDueAndFiresOnce pins WS14 #5: the
// standalone-action branch of runDueActions (never previously driven with
// non-empty input). A stored interval action is not due immediately; once the
// clock advances past its interval it fires EXACTLY once, and the advanced
// cursor prevents a double-fire on the next tick.
func TestRunDueActions_StandaloneActionBecomesDueAndFiresOnce(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	a := makeTestAction("standalone-1", pb.ActionType_ACTION_TYPE_SHELL, pb.DesiredState_DESIRED_STATE_PRESENT)
	a.Schedule = &pb.ActionSchedule{IntervalHours: 8}
	require.NoError(t, sched.store.SaveAction(a))

	// Not due yet (next_execute_at is one interval in the future).
	sched.runDueActions(ctx)
	require.Empty(t, mock.getCalls(), "a freshly-stored interval action must not be immediately due")

	// Advance the store clock past the interval → the action becomes due.
	sched.store.SetClockForTest(func() time.Time { return time.Now().Add(9 * time.Hour) })

	sched.runDueActions(ctx)
	require.Len(t, mock.getCalls(), 1, "the now-due standalone action must fire exactly once")

	// The cursor advanced past the (advanced) clock, so the next tick must not re-fire.
	sched.runDueActions(ctx)
	require.Len(t, mock.getCalls(), 1, "no double-fire on the following tick — the cursor advanced")

	results, err := sched.store.GetUnsyncedResults()
	require.NoError(t, err)
	assert.NotEmpty(t, results, "the execution must have produced a stored result")
}

// TestResetUpdateCycle_BumpedOncePerEntryPoint pins WS14 #7: each scheduling
// entry point clears the per-cycle AGENT_UPDATE dedup flag exactly once.
func TestResetUpdateCycle_BumpedOncePerEntryPoint(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	a := makeTestAction("rc-a", pb.ActionType_ACTION_TYPE_SHELL, pb.DesiredState_DESIRED_STATE_PRESENT)
	group := &pb.ActionGroup{
		SourceLabel: "action_set:rc",
		Schedule:    &pb.ActionSchedule{RunOnAssign: true, IntervalHours: 8},
		Actions:     []*pb.Action{a},
	}
	require.NoError(t, sched.SyncActions(ctx, nil, []*pb.ActionGroup{group}, false))

	getResets := func() int {
		mock.mu.Lock()
		defer mock.mu.Unlock()
		return mock.resets
	}
	clear := func() { mock.mu.Lock(); mock.resets = 0; mock.mu.Unlock() }

	clear()
	sched.runDueActions(ctx)
	assert.Equal(t, 1, getResets(), "one runDueActions tick bumps ResetUpdateCycle once")

	clear()
	_, _ = sched.ForceExecute(ctx, "rc-a")
	assert.Equal(t, 1, getResets(), "one ForceExecute bumps ResetUpdateCycle once")

	clear()
	require.NoError(t, sched.SyncActions(ctx, nil, nil, false))
	assert.Equal(t, 1, getResets(), "one SyncActions bumps ResetUpdateCycle once")
}
