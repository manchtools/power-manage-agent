package executor

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	sysuser "github.com/manchtools/power-manage-sdk/sys/user"

	"github.com/manchtools/power-manage/agent/internal/store"
)

// This file replaces lps_sealed_test.go. Spec 41 deleted the seal: rotated
// passwords used to be encrypted to a CA-signed control public key and carried
// out inside the action result's metadata, because a gateway relayed that
// result and had to be unable to read it. The agent now reports them to control
// on its own mTLS session.
//
// The three ApplyLpsPublicKey tests are gone with the key they verified — there
// is no longer a key to swap, so "a hostile gateway cannot swap it" is not a
// property that can hold or fail. What survives, and is tested harder here, is
// the ordering invariant those tests protected: NEVER rotate a credential that
// cannot be returned to the operator.

// lpsRecorder observes both sides of the rotation in one ordered log, so a test
// can assert not just that the password was reported and set, but that the
// report came FIRST.
type lpsRecorder struct {
	mu        sync.Mutex
	events    []string
	reported  []*pb.LpsPasswordRotation
	setCalls  []string // revealed plaintexts, in call order
	storeErr  error
	actionIDs []string
}

func (r *lpsRecorder) StorePasswords(_ context.Context, actionID string, rotations []*pb.LpsPasswordRotation) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, "report")
	r.actionIDs = append(r.actionIDs, actionID)
	if r.storeErr != nil {
		return r.storeErr
	}
	r.reported = append(r.reported, rotations...)
	return nil
}

// lpsRecorderUser is the sysuser fake, writing into the same log. Every
// unlisted method panics via the embedded nil interface.
type lpsRecorderUser struct {
	sysuser.Manager
	rec *lpsRecorder
}

func (f *lpsRecorderUser) Exists(context.Context, string) (bool, error) { return true, nil }
func (f *lpsRecorderUser) SetPassword(_ context.Context, _ string, pw sysexec.Secret) error {
	f.rec.mu.Lock()
	defer f.rec.mu.Unlock()
	f.rec.events = append(f.rec.events, "set")
	f.rec.setCalls = append(f.rec.setCalls, pw.Reveal())
	return nil
}
func (f *lpsRecorderUser) KillSessions(context.Context, string) error { return nil }

// newLpsExecutor wires an executor with a store, a device id, and the recorder
// installed on both the user manager and the password store.
func newLpsExecutor(t *testing.T, rec *lpsRecorder, wireStore bool) *Executor {
	t.Helper()
	e := NewExecutor(nil, nil)
	s, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	e.SetStore(s)
	e.SetDeviceID("01HKDEVICE0000000000000000")
	if wireStore {
		e.SetLpsPasswordStore(rec)
	}

	prevUser, prevNotify := userMgr, notifyUsers
	t.Cleanup(func() { userMgr = prevUser; notifyUsers = prevNotify })
	userMgr = &lpsRecorderUser{rec: rec}
	notifyUsers = func(context.Context, []string, string, string) {} // no host notify
	return e
}

func runLps(t *testing.T, e *Executor, actionID string) (bool, map[string]string, error) {
	t.Helper()
	// Cancel the ctx so the 60s post-rotation grace returns immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, changed, metadata, err := e.executeLps(ctx, &pb.LpsParams{
		Usernames:            []string{"alice"},
		PasswordLength:       20,
		RotationIntervalDays: 30,
	}, pb.DesiredState_DESIRED_STATE_PRESENT, actionID)
	return changed, metadata, err
}

// The invariant, in its new form: with no route to control the action fails
// BEFORE any account is touched. Previously this was "no sealing key"; a
// disconnected agent is the same condition — a password it could not return.
func TestExecuteLps_NotConnectedFailsClosedBeforeRotation(t *testing.T) {
	rec := &lpsRecorder{}
	e := newLpsExecutor(t, rec, false) // no password store wired

	_, _, err := runLps(t, e, "01HKACTION0000000000000000")
	if err == nil {
		t.Fatal("executeLps without a connection to the server must fail")
	}
	if !strings.Contains(err.Error(), "connection to the server") {
		t.Errorf("expected a not-connected error, got: %v", err)
	}
	if len(rec.setCalls) != 0 {
		t.Errorf("SetPassword was called %d times while disconnected — must not rotate a password it cannot report", len(rec.setCalls))
	}
}

// The ordering itself, which is the whole point: the password reaches control
// BEFORE it is applied locally. A test that only checked "both happened" would
// pass on the reverse order, which is the order that strands a credential.
func TestExecuteLps_ReportsBeforeSettingThePassword(t *testing.T) {
	rec := &lpsRecorder{}
	e := newLpsExecutor(t, rec, true)
	const actionID = "01HKACTION0000000000000000"

	changed, metadata, err := runLps(t, e, actionID)
	if err != nil {
		t.Fatalf("executeLps: %v", err)
	}
	if !changed {
		t.Fatal("expected the action to report a change")
	}
	if len(rec.setCalls) != 1 {
		t.Fatalf("expected exactly one SetPassword, got %d", len(rec.setCalls))
	}
	if len(rec.reported) != 1 {
		t.Fatalf("expected exactly one reported rotation, got %d", len(rec.reported))
	}

	want := []string{"report", "set"}
	if len(rec.events) != 2 || rec.events[0] != want[0] || rec.events[1] != want[1] {
		t.Fatalf("wrong order: got %v, want %v — a password set before it is reported is one the operator can lose", rec.events, want)
	}

	// The reported password must be the one actually on the account.
	if rec.reported[0].GetPassword() != rec.setCalls[0] {
		t.Error("the reported password is not the one set on the account")
	}
	if rec.reported[0].GetUsername() != "alice" {
		t.Errorf("reported username = %q, want alice", rec.reported[0].GetUsername())
	}
	if rec.reported[0].GetReason() == pb.RotationReason_ROTATION_REASON_UNSPECIFIED {
		t.Error("reported rotation carries no reason; control stores UNSPECIFIED")
	}
	if len(rec.actionIDs) != 1 || rec.actionIDs[0] != actionID {
		t.Errorf("reported under action %v, want %q", rec.actionIDs, actionID)
	}

	// The action result must carry no password at all. It used to carry a
	// sealed one; now the credential travels only on the stream, so any
	// metadata here would be a second copy on a path with no reader.
	for k, v := range metadata {
		if strings.Contains(v, rec.setCalls[0]) {
			t.Errorf("action metadata %q leaks the rotated password", k)
		}
	}
	if metadata["lps.rotations"] != "" {
		t.Errorf("lps.rotations metadata is still emitted (%q); nothing parses it since the gateway was removed",
			metadata["lps.rotations"])
	}
}

// A report that control REJECTS must leave the account alone. This is the case
// the old suite could not express: sealing failed only on local misconfiguration,
// whereas a rejected report is a routine server-side outcome.
func TestExecuteLps_ReportRejectedLeavesPasswordUnchanged(t *testing.T) {
	rec := &lpsRecorder{storeErr: errors.New("control refused the rotation")}
	e := newLpsExecutor(t, rec, true)

	changed, _, err := runLps(t, e, "01HKACTION0000000000000000")
	if err == nil {
		t.Fatal("a rejected report must surface as an action error")
	}
	if changed {
		t.Error("action reported a change although no password was rotated")
	}
	if len(rec.setCalls) != 0 {
		t.Errorf("SetPassword ran %d times after the report was rejected — the account now holds a credential control never received", len(rec.setCalls))
	}
}
