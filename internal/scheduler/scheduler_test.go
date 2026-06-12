package scheduler

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/manchtools/power-manage/agent/internal/store"
	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// mockExecutor records all Execute calls for test assertions.
type mockExecutor struct {
	mu     sync.Mutex
	calls  []*pb.Action
	resets int
}

func (m *mockExecutor) Execute(_ context.Context, action *pb.Action) *pb.ActionResult {
	m.mu.Lock()
	m.calls = append(m.calls, action)
	m.mu.Unlock()
	return &pb.ActionResult{
		ActionId: action.Id,
		Status:   pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
	}
}

// ResetUpdateCycle satisfies the ActionExecutor interface. The
// scheduler calls this at each runDueActions / ForceExecute / SyncActions
// to clear the per-cycle AGENT_UPDATE dedup flag (audit F042 + F048).
// The mock just counts calls so tests can assert the contract.
func (m *mockExecutor) ResetUpdateCycle() {
	m.mu.Lock()
	m.resets++
	m.mu.Unlock()
}

func (m *mockExecutor) getCalls() []*pb.Action {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]*pb.Action, len(m.calls))
	copy(cp, m.calls)
	return cp
}

func (m *mockExecutor) reset() {
	m.mu.Lock()
	m.calls = nil
	m.mu.Unlock()
}

// newTestScheduler creates a scheduler with a real SQLite store in a temp dir
// and a mock executor.
func newTestScheduler(t *testing.T) (*Scheduler, *mockExecutor) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })

	mock := &mockExecutor{}
	logger := slog.Default()
	sched := New(s, mock, logger)
	return sched, mock
}

func makeTestAction(id string, actionType pb.ActionType, state pb.DesiredState) *pb.Action {
	return &pb.Action{
		Id:           &pb.ActionId{Value: id},
		Type:         actionType,
		DesiredState: state,
	}
}

// ---------------------------------------------------------------------------
// shouldRevertOnUnassign
// ---------------------------------------------------------------------------

func TestShouldRevertOnUnassign(t *testing.T) {
	revertible := []pb.ActionType{
		pb.ActionType_ACTION_TYPE_SSH,
		pb.ActionType_ACTION_TYPE_SSHD,
		pb.ActionType_ACTION_TYPE_ADMIN_POLICY,
		pb.ActionType_ACTION_TYPE_LPS,
		pb.ActionType_ACTION_TYPE_USER,
		pb.ActionType_ACTION_TYPE_GROUP,
	}
	for _, at := range revertible {
		if !shouldRevertOnUnassign(at) {
			t.Errorf("expected shouldRevertOnUnassign(%s) = true", at)
		}
	}

	nonRevertible := []pb.ActionType{
		pb.ActionType_ACTION_TYPE_PACKAGE,
		pb.ActionType_ACTION_TYPE_SHELL,
		pb.ActionType_ACTION_TYPE_FILE,
		pb.ActionType_ACTION_TYPE_SERVICE,
		pb.ActionType_ACTION_TYPE_APP_IMAGE,
		pb.ActionType_ACTION_TYPE_FLATPAK,
		pb.ActionType_ACTION_TYPE_REPOSITORY,
	}
	for _, at := range nonRevertible {
		if shouldRevertOnUnassign(at) {
			t.Errorf("expected shouldRevertOnUnassign(%s) = false", at)
		}
	}
}

// ---------------------------------------------------------------------------
// RemoveAction — policy actions are reverted before deletion
// ---------------------------------------------------------------------------

func TestRemoveAction_PolicyActionReverted(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	action := makeTestAction("ssh-001", pb.ActionType_ACTION_TYPE_SSH, pb.DesiredState_DESIRED_STATE_PRESENT)
	if err := sched.AddAction(action); err != nil {
		t.Fatal(err)
	}
	mock.reset() // clear the add (no execute on add without RunOnAssign)

	if err := sched.RemoveAction(ctx, "ssh-001"); err != nil {
		t.Fatal(err)
	}

	calls := mock.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected 1 executor call (revert), got %d", len(calls))
	}
	if calls[0].DesiredState != pb.DesiredState_DESIRED_STATE_ABSENT {
		t.Errorf("expected ABSENT desired state, got %s", calls[0].DesiredState)
	}
	if calls[0].Type != pb.ActionType_ACTION_TYPE_SSH {
		t.Errorf("expected SSH type, got %s", calls[0].Type)
	}

	// Verify the action was removed from the store
	stored, err := sched.GetStoredActions()
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 0 {
		t.Errorf("expected 0 stored actions after removal, got %d", len(stored))
	}
}

func TestRemoveAction_NonPolicyActionNotReverted(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	action := makeTestAction("pkg-001", pb.ActionType_ACTION_TYPE_PACKAGE, pb.DesiredState_DESIRED_STATE_PRESENT)
	if err := sched.AddAction(action); err != nil {
		t.Fatal(err)
	}
	mock.reset()

	if err := sched.RemoveAction(ctx, "pkg-001"); err != nil {
		t.Fatal(err)
	}

	calls := mock.getCalls()
	if len(calls) != 0 {
		t.Fatalf("expected 0 executor calls for non-policy removal, got %d", len(calls))
	}

	// Verify the action was still removed from the store
	stored, err := sched.GetStoredActions()
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 0 {
		t.Errorf("expected 0 stored actions after removal, got %d", len(stored))
	}
}

func TestRemoveAction_MissingActionNoError(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	// Removing a non-existent action should not error or call executor
	if err := sched.RemoveAction(ctx, "nonexistent"); err != nil {
		t.Fatal(err)
	}

	calls := mock.getCalls()
	if len(calls) != 0 {
		t.Fatalf("expected 0 executor calls for missing action, got %d", len(calls))
	}
}

// ---------------------------------------------------------------------------
// RemoveAction — all four policy types
// ---------------------------------------------------------------------------

func TestRemoveAction_AllPolicyTypes(t *testing.T) {
	policyTypes := []struct {
		name       string
		actionType pb.ActionType
	}{
		{"SSH", pb.ActionType_ACTION_TYPE_SSH},
		{"SSHD", pb.ActionType_ACTION_TYPE_SSHD},
		{"Sudo", pb.ActionType_ACTION_TYPE_ADMIN_POLICY},
		{"LPS", pb.ActionType_ACTION_TYPE_LPS},
	}

	for _, tt := range policyTypes {
		t.Run(tt.name, func(t *testing.T) {
			sched, mock := newTestScheduler(t)
			ctx := context.Background()

			action := makeTestAction("action-"+tt.name, tt.actionType, pb.DesiredState_DESIRED_STATE_PRESENT)
			if err := sched.AddAction(action); err != nil {
				t.Fatal(err)
			}
			mock.reset()

			if err := sched.RemoveAction(ctx, "action-"+tt.name); err != nil {
				t.Fatal(err)
			}

			calls := mock.getCalls()
			if len(calls) != 1 {
				t.Fatalf("expected 1 revert call, got %d", len(calls))
			}
			if calls[0].DesiredState != pb.DesiredState_DESIRED_STATE_ABSENT {
				t.Errorf("expected ABSENT, got %s", calls[0].DesiredState)
			}
			if calls[0].Type != tt.actionType {
				t.Errorf("expected %s, got %s", tt.actionType, calls[0].Type)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RemoveAction — original action is not mutated
// ---------------------------------------------------------------------------

func TestRemoveAction_OriginalNotMutated(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	action := makeTestAction("sudo-001", pb.ActionType_ACTION_TYPE_ADMIN_POLICY, pb.DesiredState_DESIRED_STATE_PRESENT)
	if err := sched.AddAction(action); err != nil {
		t.Fatal(err)
	}
	mock.reset()

	if err := sched.RemoveAction(ctx, "sudo-001"); err != nil {
		t.Fatal(err)
	}

	// The original action should not have been mutated
	if action.DesiredState != pb.DesiredState_DESIRED_STATE_PRESENT {
		t.Errorf("original action was mutated to %s", action.DesiredState)
	}
}

// ---------------------------------------------------------------------------
// SyncActions — policy actions are reverted on unassignment
// ---------------------------------------------------------------------------

func TestSyncActions_PolicyActionRevertedOnRemoval(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	// Assign SSH and Package actions
	sshAction := makeTestAction("ssh-sync", pb.ActionType_ACTION_TYPE_SSH, pb.DesiredState_DESIRED_STATE_PRESENT)
	pkgAction := makeTestAction("pkg-sync", pb.ActionType_ACTION_TYPE_PACKAGE, pb.DesiredState_DESIRED_STATE_PRESENT)
	if err := sched.SyncActions(ctx, []*pb.Action{sshAction, pkgAction}, nil, true); err != nil {
		t.Fatal(err)
	}
	mock.reset()

	// Sync again with only the package action — SSH is now removed
	if err := sched.SyncActions(ctx, []*pb.Action{pkgAction}, nil, false); err != nil {
		t.Fatal(err)
	}

	calls := mock.getCalls()

	// Should have exactly 1 call — the SSH revert with ABSENT
	// (no execute calls for pkg since it's unchanged)
	var revertCalls []*pb.Action
	for _, c := range calls {
		if c.DesiredState == pb.DesiredState_DESIRED_STATE_ABSENT {
			revertCalls = append(revertCalls, c)
		}
	}
	if len(revertCalls) != 1 {
		t.Fatalf("expected 1 revert call, got %d (total calls: %d)", len(revertCalls), len(calls))
	}
	if revertCalls[0].Type != pb.ActionType_ACTION_TYPE_SSH {
		t.Errorf("expected SSH revert, got %s", revertCalls[0].Type)
	}
}

func TestSyncActions_NonPolicyActionNotRevertedOnRemoval(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	// Assign a package action
	pkgAction := makeTestAction("pkg-only", pb.ActionType_ACTION_TYPE_PACKAGE, pb.DesiredState_DESIRED_STATE_PRESENT)
	if err := sched.SyncActions(ctx, []*pb.Action{pkgAction}, nil, true); err != nil {
		t.Fatal(err)
	}
	mock.reset()

	// Sync with empty list — package action is removed but NOT reverted
	if err := sched.SyncActions(ctx, []*pb.Action{}, nil, false); err != nil {
		t.Fatal(err)
	}

	calls := mock.getCalls()
	for _, c := range calls {
		if c.DesiredState == pb.DesiredState_DESIRED_STATE_ABSENT {
			t.Errorf("unexpected ABSENT revert call for type %s", c.Type)
		}
	}

	// Verify action was still removed from store
	stored, err := sched.GetStoredActions()
	if err != nil {
		t.Fatal(err)
	}
	if len(stored) != 0 {
		t.Errorf("expected 0 stored actions, got %d", len(stored))
	}
}

func TestSyncActions_MultiplePolicyActionsReverted(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	// Assign all four policy types plus a non-policy type
	actions := []*pb.Action{
		makeTestAction("a-ssh", pb.ActionType_ACTION_TYPE_SSH, pb.DesiredState_DESIRED_STATE_PRESENT),
		makeTestAction("a-sshd", pb.ActionType_ACTION_TYPE_SSHD, pb.DesiredState_DESIRED_STATE_PRESENT),
		makeTestAction("a-sudo", pb.ActionType_ACTION_TYPE_ADMIN_POLICY, pb.DesiredState_DESIRED_STATE_PRESENT),
		makeTestAction("a-lps", pb.ActionType_ACTION_TYPE_LPS, pb.DesiredState_DESIRED_STATE_PRESENT),
		makeTestAction("a-pkg", pb.ActionType_ACTION_TYPE_PACKAGE, pb.DesiredState_DESIRED_STATE_PRESENT),
	}
	if err := sched.SyncActions(ctx, actions, nil, true); err != nil {
		t.Fatal(err)
	}
	mock.reset()

	// Remove all actions by syncing with empty list
	if err := sched.SyncActions(ctx, []*pb.Action{}, nil, false); err != nil {
		t.Fatal(err)
	}

	calls := mock.getCalls()
	revertedTypes := make(map[pb.ActionType]bool)
	for _, c := range calls {
		if c.DesiredState == pb.DesiredState_DESIRED_STATE_ABSENT {
			revertedTypes[c.Type] = true
		}
	}

	// All four policy types should have been reverted
	expectedReverts := []pb.ActionType{
		pb.ActionType_ACTION_TYPE_SSH,
		pb.ActionType_ACTION_TYPE_SSHD,
		pb.ActionType_ACTION_TYPE_ADMIN_POLICY,
		pb.ActionType_ACTION_TYPE_LPS,
	}
	for _, at := range expectedReverts {
		if !revertedTypes[at] {
			t.Errorf("expected revert for %s but it was not reverted", at)
		}
	}

	// Package should NOT have been reverted
	if revertedTypes[pb.ActionType_ACTION_TYPE_PACKAGE] {
		t.Error("package action should not be reverted on unassignment")
	}
}

func TestSyncActions_RevertPreservesActionFields(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	// Assign a sudo action with parameters
	sudoAction := &pb.Action{
		Id:           &pb.ActionId{Value: "sudo-params"},
		Type:         pb.ActionType_ACTION_TYPE_ADMIN_POLICY,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
		Params: &pb.Action_AdminPolicy{
			AdminPolicy: &pb.AdminPolicyParams{
				AccessLevel: pb.AdminAccessLevel_ADMIN_ACCESS_LEVEL_FULL,
				Users:       []string{"alice"},
			},
		},
	}
	if err := sched.SyncActions(ctx, []*pb.Action{sudoAction}, nil, true); err != nil {
		t.Fatal(err)
	}
	mock.reset()

	// Remove it
	if err := sched.SyncActions(ctx, []*pb.Action{}, nil, false); err != nil {
		t.Fatal(err)
	}

	calls := mock.getCalls()
	var revertCall *pb.Action
	for _, c := range calls {
		if c.DesiredState == pb.DesiredState_DESIRED_STATE_ABSENT {
			revertCall = c
			break
		}
	}
	if revertCall == nil {
		t.Fatal("expected a revert call")
	}

	// Verify the reverted action preserves the original type and parameters
	if revertCall.Type != pb.ActionType_ACTION_TYPE_ADMIN_POLICY {
		t.Errorf("expected SUDO type, got %s", revertCall.Type)
	}
	sudo := revertCall.GetAdminPolicy()
	if sudo == nil {
		t.Fatal("expected sudo parameters to be preserved in revert call")
	}
	if len(sudo.Users) != 1 || sudo.Users[0] != "alice" {
		t.Errorf("expected users [alice], got %v", sudo.Users)
	}
}

// ---------------------------------------------------------------------------
// Grouped sync (#45)
// ---------------------------------------------------------------------------

// When the server pushes an ActionGroup with run_on_assign=true, the
// group's first runDueActions tick walks its members in declared order,
// dispatching each through the executor — sequentially, no inter-leaving.
func TestRunDueActions_GroupRunOnAssign_OrdersMembers(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	a1 := makeTestAction("g-a1", pb.ActionType_ACTION_TYPE_SHELL, pb.DesiredState_DESIRED_STATE_PRESENT)
	a2 := makeTestAction("g-a2", pb.ActionType_ACTION_TYPE_SHELL, pb.DesiredState_DESIRED_STATE_PRESENT)
	a3 := makeTestAction("g-a3", pb.ActionType_ACTION_TYPE_SHELL, pb.DesiredState_DESIRED_STATE_PRESENT)

	group := &pb.ActionGroup{
		SourceLabel: "action_set:run-on-assign",
		Schedule:    &pb.ActionSchedule{RunOnAssign: true, IntervalHours: 8},
		Actions:     []*pb.Action{a1, a2, a3},
	}

	if err := sched.SyncActions(ctx, nil, []*pb.ActionGroup{group}, false); err != nil {
		t.Fatal(err)
	}

	// Sync itself does not execute group members; only the next tick does.
	if got := len(mock.getCalls()); got != 0 {
		t.Fatalf("sync should not execute group members directly, got %d", got)
	}

	sched.runDueActions(ctx)

	calls := mock.getCalls()
	if len(calls) != 3 {
		t.Fatalf("expected 3 group member calls, got %d", len(calls))
	}
	wantOrder := []string{"g-a1", "g-a2", "g-a3"}
	for i, want := range wantOrder {
		if calls[i].Id.Value != want {
			t.Errorf("call %d: expected %q got %q", i, want, calls[i].Id.Value)
		}
	}
}

// TestRunDueActions_MaintenanceWindowGatedByInjectedClock pins that the
// offline scheduler's maintenance-window gate is evaluated against the
// INJECTED clock, not the wall clock: the same due action defers when the
// injected time is outside the window and fires when it is inside. This
// is the security-relevant property of the clock seam — an agent that
// ignored its maintenance window (or read the wrong clock) could run
// disruptive actions at a forbidden time.
func TestRunDueActions_MaintenanceWindowGatedByInjectedClock(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	// A RunOnAssign group is due on the next tick (see
	// TestRunDueActions_GroupRunOnAssign_OrdersMembers).
	a := makeTestAction("mw-a", pb.ActionType_ACTION_TYPE_SHELL, pb.DesiredState_DESIRED_STATE_PRESENT)
	group := &pb.ActionGroup{
		SourceLabel: "action_set:mw",
		Schedule:    &pb.ActionSchedule{RunOnAssign: true, IntervalHours: 8},
		Actions:     []*pb.Action{a},
	}
	if err := sched.SyncActions(ctx, nil, []*pb.ActionGroup{group}, false); err != nil {
		t.Fatal(err)
	}

	// Allow only Monday 02:00–03:00 (device-local).
	sched.SetMaintenanceWindow(&pb.MaintenanceWindow{
		Schedule: []*pb.MaintenanceWindowEntry{{Days: []string{"mon"}, Allow: "02:00-03:00"}},
	})

	// 2024-01-01 is a Monday. Clock at 12:00 local is OUTSIDE the window:
	// the due dispatch must defer (next_execute_at is not advanced), so
	// the executor is never called.
	sched.now = func() time.Time { return time.Date(2024, 1, 1, 12, 0, 0, 0, time.Local) }
	sched.runDueActions(ctx)
	if got := len(mock.getCalls()); got != 0 {
		t.Fatalf("window closed per injected clock: expected 0 executions, got %d", got)
	}

	// Move the injected clock INSIDE the window (Monday 02:30 local).
	// The still-due action now fires exactly once.
	sched.now = func() time.Time { return time.Date(2024, 1, 1, 2, 30, 0, 0, time.Local) }
	sched.runDueActions(ctx)
	if got := len(mock.getCalls()); got != 1 {
		t.Fatalf("window open per injected clock: expected 1 execution, got %d", got)
	}
}

// Same action id can appear at multiple positions within a group (e.g.
// AAA in two sets that compose the same definition). Each occurrence
// dispatches the executor — idempotent action contracts absorb the cost.
func TestRunDueActions_GroupAllowsDuplicateMembers(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	common := makeTestAction("dup-action", pb.ActionType_ACTION_TYPE_SHELL, pb.DesiredState_DESIRED_STATE_PRESENT)
	other := makeTestAction("other", pb.ActionType_ACTION_TYPE_SHELL, pb.DesiredState_DESIRED_STATE_PRESENT)

	group := &pb.ActionGroup{
		SourceLabel: "definition:dup-positions",
		Schedule:    &pb.ActionSchedule{RunOnAssign: true},
		Actions:     []*pb.Action{common, other, common},
	}
	if err := sched.SyncActions(ctx, nil, []*pb.ActionGroup{group}, false); err != nil {
		t.Fatal(err)
	}

	sched.runDueActions(ctx)

	calls := mock.getCalls()
	if len(calls) != 3 {
		t.Fatalf("expected 3 calls (dup-action runs twice), got %d", len(calls))
	}
	gotOrder := []string{calls[0].Id.Value, calls[1].Id.Value, calls[2].Id.Value}
	wantOrder := []string{"dup-action", "other", "dup-action"}
	for i, want := range wantOrder {
		if gotOrder[i] != want {
			t.Errorf("call %d: expected %q got %q", i, want, gotOrder[i])
		}
	}
}

// Group members are NOT picked up by the standalone-tick — they only
// fire when their group fires. This is the load-bearing invariant for
// the ordering guarantee: members must not race each other on
// independent per-action schedules.
func TestRunDueActions_GroupedActionsSkipStandaloneTick(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	a1 := makeTestAction("g-only", pb.ActionType_ACTION_TYPE_SHELL, pb.DesiredState_DESIRED_STATE_PRESENT)
	// Cron "0 0 1 1 *" = Jan 1 at midnight; far-future for almost any
	// year except a brief Jan-1 window. This guarantees the group is
	// not currently due so we can assert the standalone tick is not
	// silently picking up grouped members on its own.
	group := &pb.ActionGroup{
		SourceLabel: "action_set:far-future",
		Schedule:    &pb.ActionSchedule{Cron: "0 0 1 1 *"},
		Actions:     []*pb.Action{a1},
	}
	if err := sched.SyncActions(ctx, nil, []*pb.ActionGroup{group}, false); err != nil {
		t.Fatal(err)
	}

	sched.runDueActions(ctx)

	if got := len(mock.getCalls()); got != 0 {
		t.Fatalf("far-future group must not fire AND its member must not run via standalone tick, got %d calls", got)
	}
}

// ---------------------------------------------------------------------------
// Maintenance window gate
// ---------------------------------------------------------------------------

// A window that allows every weekday and every hour acts like "no
// constraint" — useful as a control for the deny case below.
//
// Uses a group rather than a standalone action because SyncActions
// runs new standalone actions inline (advancing their cursor), which
// would leave runDueActions with nothing due. Group members never
// run on the inline-sync path, so a freshly-synced group is still
// due on the first runDueActions tick.
func TestRunDueActions_MaintenanceWindow_AllAllowed(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	g := &pb.ActionGroup{
		SourceLabel: "action_set:permissive",
		Schedule:    &pb.ActionSchedule{RunOnAssign: true, IntervalHours: 8},
		Actions: []*pb.Action{
			makeTestAction("g-a", pb.ActionType_ACTION_TYPE_SHELL, pb.DesiredState_DESIRED_STATE_PRESENT),
		},
	}
	if err := sched.SyncActions(ctx, nil, []*pb.ActionGroup{g}, false); err != nil {
		t.Fatal(err)
	}
	mock.reset()

	sched.SetMaintenanceWindow(&pb.MaintenanceWindow{Schedule: []*pb.MaintenanceWindowEntry{
		{Days: []string{"mon", "tue", "wed", "thu", "fri", "sat", "sun"}, Allow: "00:00-23:59"},
	}})

	sched.runDueActions(ctx)
	if got := len(mock.getCalls()); got != 1 {
		t.Fatalf("permissive window should not gate dispatch, got %d calls", got)
	}
}

// A window with no entry matching the current weekday must defer
// every due group dispatch without advancing the group's next-fire
// cursor — reopening the window in the next tick replays the work.
//
// Standalone actions stay out of this case on purpose: SyncActions
// executes new/changed standalone actions inline as part of the sync
// (firstSync / new-action codepath), which leaves them with an
// already-advanced next_execute_at by the time runDueActions runs.
// The group path is the load-bearing one for the gate — group
// members never run on the inline-sync path; they only fire through
// runDueActions, so deferring them is observable.
func TestRunDueActions_MaintenanceWindow_NoMatchingDayDefersAll(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	g := &pb.ActionGroup{
		SourceLabel: "action_set:gated",
		Schedule:    &pb.ActionSchedule{RunOnAssign: true, IntervalHours: 8},
		Actions: []*pb.Action{
			makeTestAction("g-a", pb.ActionType_ACTION_TYPE_SHELL, pb.DesiredState_DESIRED_STATE_PRESENT),
		},
	}
	if err := sched.SyncActions(ctx, nil, []*pb.ActionGroup{g}, false); err != nil {
		t.Fatal(err)
	}
	mock.reset()

	// Pick a weekday three days from today so neither today nor
	// yesterday matches — the latter check is what catches a window
	// that crosses midnight from the previous day.
	now := time.Now().Local()
	farDay := weekdayToken((int(now.Weekday()) + 3) % 7)
	sched.SetMaintenanceWindow(&pb.MaintenanceWindow{Schedule: []*pb.MaintenanceWindowEntry{
		{Days: []string{farDay}, Allow: "00:01-23:58"},
	}})

	sched.runDueActions(ctx)
	if got := len(mock.getCalls()); got != 0 {
		t.Fatalf("closed window must defer due group, got %d calls", got)
	}

	// Reopening the window and re-ticking must run the deferred
	// group — proves the defer didn't advance the group's
	// next_execute_at past now.
	sched.SetMaintenanceWindow(nil)
	sched.runDueActions(ctx)
	if got := len(mock.getCalls()); got != 1 {
		t.Fatalf("after reopening, deferred group member must fire exactly once, got %d", got)
	}
}

// SetMaintenanceWindow round-trips through the agent store so a
// scheduler restored via New() picks up the previously-set window.
func TestSetMaintenanceWindow_PersistsAcrossSchedulerRestart(t *testing.T) {
	dir := t.TempDir()
	st, err := store.New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()

	first := New(st, &mockExecutor{}, slog.Default())
	w := &pb.MaintenanceWindow{Schedule: []*pb.MaintenanceWindowEntry{
		{Days: []string{"mon", "tue", "wed", "thu", "fri"}, Allow: "22:00-06:00"},
	}}
	first.SetMaintenanceWindow(w)

	// Fresh scheduler against the same store — simulates a restart.
	restored := New(st, &mockExecutor{}, slog.Default())
	got := restored.activeWindow()
	if got == nil || len(got.Schedule) != 1 {
		t.Fatalf("expected restored window, got %v", got)
	}
	if got.Schedule[0].Allow != "22:00-06:00" {
		t.Fatalf("restored allow range mismatch: %q", got.Schedule[0].Allow)
	}

	// Clearing the window deletes the persisted row.
	first.SetMaintenanceWindow(nil)
	cleared := New(st, &mockExecutor{}, slog.Default())
	if w := cleared.activeWindow(); w != nil && len(w.Schedule) != 0 {
		t.Fatalf("clearing the window should remove persistence, got %v", w)
	}
}

// weekdayToken maps a 0..6 weekday index (Sunday=0) to the lowercase
// three-letter token used in MaintenanceWindowEntry.Days.
func weekdayToken(idx int) string {
	tokens := [7]string{"sun", "mon", "tue", "wed", "thu", "fri", "sat"}
	return tokens[idx]
}
