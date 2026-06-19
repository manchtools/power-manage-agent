package scheduler

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"sync"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/manchtools/power-manage/agent/internal/store"
	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/verify"
)

// testSigner is the per-process CA signer used by makeTestAction to mint a
// real SignedActionEnvelope for every stored action, and the matching
// ActionVerifier the mock executor uses. WHAT runs is the verified envelope,
// so test actions must carry a genuine signature — an unsigned test action
// would (correctly) be refused by the scheduler's verify-then-execute path.
var (
	testSigner   *verify.ActionSigner
	testVerifier *verify.ActionVerifier
)

// init builds the package-level signer/verifier. It cannot use the shared
// sdk/go/cryptotest fixtures because those require a *testing.TB (for t.Helper /
// t.Fatalf) and init() has none; the other agent test packages, whose CA setup
// runs inside a test helper, consume cryptotest.GenCA instead.
func init() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "scheduler-test-ca"},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	testSigner = verify.NewActionSigner(key)
	v, err := verify.NewActionVerifier(certPEM)
	if err != nil {
		panic(err)
	}
	testVerifier = v
}

// mockExecutor records executed envelopes for test assertions. It verifies
// envelope bytes against the test CA exactly like the real executor, so a
// tampered or unsigned envelope returns an error from VerifyEnvelope and the
// scheduler refuses to execute it.
type mockExecutor struct {
	mu     sync.Mutex
	calls  []*pb.SignedActionEnvelope
	resets int
	// script maps an action id to the result ExecuteEnvelope should return
	// (default SUCCESS when absent), so a test can drive a FAILED execution /
	// Changed=false / Error path. WS14 #3.
	script map[string]*pb.ActionResult
	// block, if non-nil for an action id, is received-from before ExecuteEnvelope
	// returns — lets a test hold an execution in-flight (WS14 #9).
	block map[string]chan struct{}
}

// VerifyEnvelope mirrors the real executor: verify the CA signature over the
// exact bytes, then unmarshal THOSE bytes into a SignedActionEnvelope.
func (m *mockExecutor) VerifyEnvelope(envelopeBytes, signature []byte) (*pb.SignedActionEnvelope, error) {
	if err := testVerifier.Verify(envelopeBytes, signature); err != nil {
		return nil, err
	}
	env := &pb.SignedActionEnvelope{}
	if err := proto.Unmarshal(envelopeBytes, env); err != nil {
		return nil, err
	}
	return env, nil
}

// ExecuteEnvelope records the verified envelope the scheduler asked to run.
func (m *mockExecutor) ExecuteEnvelope(_ context.Context, env *pb.SignedActionEnvelope) *pb.ActionResult {
	id := env.GetActionId().GetValue()
	m.mu.Lock()
	m.calls = append(m.calls, env)
	scripted := m.script[id]
	blockCh := m.block[id]
	m.mu.Unlock()

	if blockCh != nil {
		<-blockCh // hold the execution in-flight until the test releases it
	}
	if scripted != nil {
		return scripted
	}
	return &pb.ActionResult{
		ActionId: env.GetActionId(),
		Status:   pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS,
	}
}

// setScript makes ExecuteEnvelope return result for the given action id.
func (m *mockExecutor) setScript(id string, result *pb.ActionResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.script == nil {
		m.script = map[string]*pb.ActionResult{}
	}
	m.script[id] = result
}

// setBlock makes ExecuteEnvelope for the given action id block on ch until the
// test closes/sends to it (WS14 #9 in-flight hold).
func (m *mockExecutor) setBlock(id string, ch chan struct{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.block == nil {
		m.block = map[string]chan struct{}{}
	}
	m.block[id] = ch
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

func (m *mockExecutor) getCalls() []*pb.SignedActionEnvelope {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]*pb.SignedActionEnvelope, len(m.calls))
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

// makeTestAction builds an action and signs a matching SignedActionEnvelope,
// stamping signed_envelope + signature onto the wire Action. The stored
// action therefore carries the bytes the scheduler verifies and executes.
func makeTestAction(id string, actionType pb.ActionType, state pb.DesiredState) *pb.Action {
	a := &pb.Action{
		Id:           &pb.ActionId{Value: id},
		Type:         actionType,
		DesiredState: state,
	}
	signTestAction(a)
	return a
}

// signTestAction builds the SignedActionEnvelope from an action's fields
// (id, type, desired_state, params) and stamps the signed bytes + signature
// onto the action, mirroring the server's dbActionToWireAction.
func signTestAction(a *pb.Action) {
	env := &pb.SignedActionEnvelope{
		ActionId:     a.Id,
		ActionType:   a.Type,
		DesiredState: a.DesiredState,
	}
	// Copy the action's typed param oneof into the envelope. The envelope
	// oneof's wrapper interface is unexported in the generated package, so
	// the assignment must happen here where the concrete wrapper type binds
	// directly to the Params field. Only the param types used by scheduler
	// tests are handled.
	switch p := a.Params.(type) {
	case *pb.Action_AdminPolicy:
		env.Params = &pb.SignedActionEnvelope_AdminPolicy{AdminPolicy: p.AdminPolicy}
	case *pb.Action_Shell:
		env.Params = &pb.SignedActionEnvelope_Shell{Shell: p.Shell}
	}
	b, err := verify.MarshalEnvelope(env)
	if err != nil {
		panic(err)
	}
	sig, err := testSigner.Sign(b)
	if err != nil {
		panic(err)
	}
	a.SignedEnvelope = b
	a.Signature = sig
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
	if calls[0].GetDesiredState() != pb.DesiredState_DESIRED_STATE_ABSENT {
		t.Errorf("expected ABSENT desired state, got %s", calls[0].GetDesiredState())
	}
	if calls[0].GetActionType() != pb.ActionType_ACTION_TYPE_SSH {
		t.Errorf("expected SSH type, got %s", calls[0].GetActionType())
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
	// All SIX revertible types per shouldRevertOnUnassign — USER and GROUP join
	// the policy-style reverters (a user/group created by an assignment must not
	// outlive it). This list must stay in lockstep with shouldRevertOnUnassign;
	// the self-discovering partition test (scheduler_ws14_test.go) guards that.
	policyTypes := []struct {
		name       string
		actionType pb.ActionType
	}{
		{"SSH", pb.ActionType_ACTION_TYPE_SSH},
		{"SSHD", pb.ActionType_ACTION_TYPE_SSHD},
		{"Sudo", pb.ActionType_ACTION_TYPE_ADMIN_POLICY},
		{"LPS", pb.ActionType_ACTION_TYPE_LPS},
		{"User", pb.ActionType_ACTION_TYPE_USER},
		{"Group", pb.ActionType_ACTION_TYPE_GROUP},
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
			if calls[0].GetDesiredState() != pb.DesiredState_DESIRED_STATE_ABSENT {
				t.Errorf("expected ABSENT, got %s", calls[0].GetDesiredState())
			}
			if calls[0].GetActionType() != tt.actionType {
				t.Errorf("expected %s, got %s", tt.actionType, calls[0].GetActionType())
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
	var revertCalls []*pb.SignedActionEnvelope
	for _, c := range calls {
		if c.GetDesiredState() == pb.DesiredState_DESIRED_STATE_ABSENT {
			revertCalls = append(revertCalls, c)
		}
	}
	if len(revertCalls) != 1 {
		t.Fatalf("expected 1 revert call, got %d (total calls: %d)", len(revertCalls), len(calls))
	}
	if revertCalls[0].GetActionType() != pb.ActionType_ACTION_TYPE_SSH {
		t.Errorf("expected SSH revert, got %s", revertCalls[0].GetActionType())
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
		if c.GetDesiredState() == pb.DesiredState_DESIRED_STATE_ABSENT {
			t.Errorf("unexpected ABSENT revert call for type %s", c.GetActionType())
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
		if c.GetDesiredState() == pb.DesiredState_DESIRED_STATE_ABSENT {
			revertedTypes[c.GetActionType()] = true
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

	// Assign a sudo action with parameters. Sign a matching envelope so the
	// revert path can verify the stored bytes and recover the params it must
	// preserve into the ABSENT revert envelope.
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
	signTestAction(sudoAction)
	if err := sched.SyncActions(ctx, []*pb.Action{sudoAction}, nil, true); err != nil {
		t.Fatal(err)
	}
	mock.reset()

	// Remove it
	if err := sched.SyncActions(ctx, []*pb.Action{}, nil, false); err != nil {
		t.Fatal(err)
	}

	calls := mock.getCalls()
	var revertCall *pb.SignedActionEnvelope
	for _, c := range calls {
		if c.GetDesiredState() == pb.DesiredState_DESIRED_STATE_ABSENT {
			revertCall = c
			break
		}
	}
	if revertCall == nil {
		t.Fatal("expected a revert call")
	}

	// Verify the reverted action preserves the original type and parameters
	if revertCall.GetActionType() != pb.ActionType_ACTION_TYPE_ADMIN_POLICY {
		t.Errorf("expected SUDO type, got %s", revertCall.GetActionType())
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
		if calls[i].GetActionId().GetValue() != want {
			t.Errorf("call %d: expected %q got %q", i, want, calls[i].GetActionId().GetValue())
		}
	}
}

// TestExecuteGroup_FailingMiddleMemberStillRunsLaterAndAdvancesGroup pins WS14
// #3: a group member that FAILS must not abort the group — later members still
// run in order — and the group cursor must still advance (MarkGroupExecuted), so
// a failing member can't wedge the group into re-running every tick.
func TestExecuteGroup_FailingMiddleMemberStillRunsLaterAndAdvancesGroup(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	a1 := makeTestAction("fm-a1", pb.ActionType_ACTION_TYPE_SHELL, pb.DesiredState_DESIRED_STATE_PRESENT)
	a2 := makeTestAction("fm-a2", pb.ActionType_ACTION_TYPE_SHELL, pb.DesiredState_DESIRED_STATE_PRESENT)
	a3 := makeTestAction("fm-a3", pb.ActionType_ACTION_TYPE_SHELL, pb.DesiredState_DESIRED_STATE_PRESENT)
	group := &pb.ActionGroup{
		SourceLabel: "action_set:fail-middle",
		Schedule:    &pb.ActionSchedule{RunOnAssign: true, IntervalHours: 8},
		Actions:     []*pb.Action{a1, a2, a3},
	}
	if err := sched.SyncActions(ctx, nil, []*pb.ActionGroup{group}, false); err != nil {
		t.Fatal(err)
	}

	// The MIDDLE member fails. The group must not abort on it.
	mock.setScript("fm-a2", &pb.ActionResult{
		ActionId: &pb.ActionId{Value: "fm-a2"},
		Status:   pb.ExecutionStatus_EXECUTION_STATUS_FAILED,
		Error:    "boom",
	})

	sched.runDueActions(ctx)

	calls := mock.getCalls()
	if len(calls) != 3 {
		t.Fatalf("a failing middle member must not abort the group — expected all 3 members to run, got %d", len(calls))
	}
	for i, want := range []string{"fm-a1", "fm-a2", "fm-a3"} {
		if calls[i].GetActionId().GetValue() != want {
			t.Errorf("member %d: expected %q, got %q", i, want, calls[i].GetActionId().GetValue())
		}
	}

	// The cursor must have advanced (MarkGroupExecuted ran despite the failure):
	// a second immediate tick does NOT re-run the group.
	mock.reset()
	sched.runDueActions(ctx)
	if got := len(mock.getCalls()); got != 0 {
		t.Fatalf("the group's next_execute_at must advance past this tick despite the middle-member failure; got %d re-runs", got)
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
	gotOrder := []string{calls[0].GetActionId().GetValue(), calls[1].GetActionId().GetValue(), calls[2].GetActionId().GetValue()}
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

// ---------------------------------------------------------------------------
// Verify-then-execute the verified envelope (sdk#82)
// ---------------------------------------------------------------------------

// TestExecuteAction_RunsVerifiedEnvelope pins that the scheduler verifies the
// stored SignedEnvelope and executes THAT verified envelope. A synced action
// that carries a valid signature runs, and the executed envelope carries the
// signed type/id — i.e. WHAT runs is the verified envelope, not the wire
// Action's advisory typed oneof.
func TestExecuteAction_RunsVerifiedEnvelope(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	// makeTestAction signs a real envelope. Store it, then force-execute.
	action := makeTestAction("forced-good", pb.ActionType_ACTION_TYPE_SHELL, pb.DesiredState_DESIRED_STATE_PRESENT)
	if err := sched.AddAction(action); err != nil {
		t.Fatal(err)
	}
	mock.reset()

	res, err := sched.ForceExecute(ctx, "forced-good")
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.Status != pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS {
		t.Fatalf("expected SUCCESS from a validly signed action, got %v", res)
	}

	calls := mock.getCalls()
	if len(calls) != 1 {
		t.Fatalf("expected exactly 1 envelope execution, got %d", len(calls))
	}
	if calls[0].GetActionId().GetValue() != "forced-good" {
		t.Errorf("executed envelope id = %q, want forced-good", calls[0].GetActionId().GetValue())
	}
	if calls[0].GetActionType() != pb.ActionType_ACTION_TYPE_SHELL {
		t.Errorf("executed envelope type = %s, want SHELL", calls[0].GetActionType())
	}
}

// TestExecuteAction_RefusesTamperedEnvelope pins the fail-closed invariant in
// the scheduler: a stored action whose SignedEnvelope has been tampered (a
// byte flipped after signing) is refused — the executor's ExecuteEnvelope is
// NEVER called, and the recorded result is FAILED. This is the offline-
// scheduler analogue of the wire-path tamper rejection: a compromised local
// store (or a relay that wrote bad bytes) cannot drive execution.
func TestExecuteAction_RefusesTamperedEnvelope(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	action := makeTestAction("forced-tampered", pb.ActionType_ACTION_TYPE_SHELL, pb.DesiredState_DESIRED_STATE_PRESENT)
	// Flip a byte of the signed envelope so the signature no longer matches.
	tampered := make([]byte, len(action.SignedEnvelope))
	copy(tampered, action.SignedEnvelope)
	tampered[len(tampered)/2] ^= 0xFF
	action.SignedEnvelope = tampered

	if err := sched.AddAction(action); err != nil {
		t.Fatal(err)
	}
	mock.reset()

	res, err := sched.ForceExecute(ctx, "forced-tampered")
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.Status != pb.ExecutionStatus_EXECUTION_STATUS_FAILED {
		t.Fatalf("expected FAILED for a tampered envelope, got %v", res)
	}
	if got := len(mock.getCalls()); got != 0 {
		t.Fatalf("a tampered envelope must NOT reach the executor, got %d calls", got)
	}
}

// TestExecuteAction_RefusesEmptySignature pins that a synced action with NO
// signature at all (empty SignedEnvelope/Signature — e.g. a downgraded or
// forged store row) is refused before execution.
func TestExecuteAction_RefusesEmptySignature(t *testing.T) {
	sched, mock := newTestScheduler(t)
	ctx := context.Background()

	action := &pb.Action{
		Id:           &pb.ActionId{Value: "forced-unsigned"},
		Type:         pb.ActionType_ACTION_TYPE_SHELL,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
		// No SignedEnvelope, no Signature.
	}
	if err := sched.AddAction(action); err != nil {
		t.Fatal(err)
	}
	mock.reset()

	res, err := sched.ForceExecute(ctx, "forced-unsigned")
	if err != nil {
		t.Fatal(err)
	}
	if res == nil || res.Status != pb.ExecutionStatus_EXECUTION_STATUS_FAILED {
		t.Fatalf("expected FAILED for an unsigned action, got %v", res)
	}
	if got := len(mock.getCalls()); got != 0 {
		t.Fatalf("an unsigned action must NOT reach the executor, got %d calls", got)
	}
}
