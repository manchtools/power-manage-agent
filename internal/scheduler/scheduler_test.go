package scheduler

import (
	"context"
	"log/slog"
	"sync"
	"testing"

	"github.com/manchtools/power-manage/agent/internal/store"
	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// mockExecutor records all Execute calls for test assertions.
type mockExecutor struct {
	mu    sync.Mutex
	calls []*pb.Action
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
		pb.ActionType_ACTION_TYPE_SUDO,
		pb.ActionType_ACTION_TYPE_LPS,
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
		pb.ActionType_ACTION_TYPE_SYSTEMD,
		pb.ActionType_ACTION_TYPE_USER,
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
		{"Sudo", pb.ActionType_ACTION_TYPE_SUDO},
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

	action := makeTestAction("sudo-001", pb.ActionType_ACTION_TYPE_SUDO, pb.DesiredState_DESIRED_STATE_PRESENT)
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
	if err := sched.SyncActions(ctx, []*pb.Action{sshAction, pkgAction}, true); err != nil {
		t.Fatal(err)
	}
	mock.reset()

	// Sync again with only the package action — SSH is now removed
	if err := sched.SyncActions(ctx, []*pb.Action{pkgAction}, false); err != nil {
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
	if err := sched.SyncActions(ctx, []*pb.Action{pkgAction}, true); err != nil {
		t.Fatal(err)
	}
	mock.reset()

	// Sync with empty list — package action is removed but NOT reverted
	if err := sched.SyncActions(ctx, []*pb.Action{}, false); err != nil {
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
		makeTestAction("a-sudo", pb.ActionType_ACTION_TYPE_SUDO, pb.DesiredState_DESIRED_STATE_PRESENT),
		makeTestAction("a-lps", pb.ActionType_ACTION_TYPE_LPS, pb.DesiredState_DESIRED_STATE_PRESENT),
		makeTestAction("a-pkg", pb.ActionType_ACTION_TYPE_PACKAGE, pb.DesiredState_DESIRED_STATE_PRESENT),
	}
	if err := sched.SyncActions(ctx, actions, true); err != nil {
		t.Fatal(err)
	}
	mock.reset()

	// Remove all actions by syncing with empty list
	if err := sched.SyncActions(ctx, []*pb.Action{}, false); err != nil {
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
		pb.ActionType_ACTION_TYPE_SUDO,
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
		Type:         pb.ActionType_ACTION_TYPE_SUDO,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
		Params: &pb.Action_Sudo{
			Sudo: &pb.SudoParams{
				AccessLevel: pb.SudoAccessLevel_SUDO_ACCESS_LEVEL_FULL,
				Users:       []string{"alice"},
			},
		},
	}
	if err := sched.SyncActions(ctx, []*pb.Action{sudoAction}, true); err != nil {
		t.Fatal(err)
	}
	mock.reset()

	// Remove it
	if err := sched.SyncActions(ctx, []*pb.Action{}, false); err != nil {
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
	if revertCall.Type != pb.ActionType_ACTION_TYPE_SUDO {
		t.Errorf("expected SUDO type, got %s", revertCall.Type)
	}
	sudo := revertCall.GetSudo()
	if sudo == nil {
		t.Fatal("expected sudo parameters to be preserved in revert call")
	}
	if len(sudo.Users) != 1 || sudo.Users[0] != "alice" {
		t.Errorf("expected users [alice], got %v", sudo.Users)
	}
}
