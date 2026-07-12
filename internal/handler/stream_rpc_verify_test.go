package handler

import (
	"context"
	"log/slog"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/verify"
	"github.com/manchtools/power-manage/agent/internal/executor"
)

// ============================================================================
// WS4 — the four root stream-RPCs are CA-signed and verified fail-closed.
//
// Contract restated: OnQuery / OnLogQuery / OnRevokeLuksDeviceKey /
// OnRequestInventory must verify the control-server signature over the message
// BEFORE any root work (osquery, journalctl, LUKS wipe). An absent, byte-
// tampered, field-swapped, or wrong-domain signature is refused and the root
// work never runs. A nil verifier fails closed (production always has one).
// "Wrong" data is sourced from intent (a swapped table/unit/action_id, a
// flipped byte), never from the validation rule under test.
// ============================================================================

// fakeOsquery records calls so a test can prove osquery was (or was NOT)
// invoked under a given signature state.
type fakeOsquery struct {
	queryCalls int
	tableCalls []string
}

func (f *fakeOsquery) Query(_ context.Context, q *pb.OSQuery) (*pb.OSQueryResult, error) {
	f.queryCalls++
	return &pb.OSQueryResult{QueryId: q.GetQueryId(), Success: true}, nil
}

func (f *fakeOsquery) QueryTable(_ context.Context, name string) ([]*pb.OSQueryRow, error) {
	f.tableCalls = append(f.tableCalls, name)
	return []*pb.OSQueryRow{{Data: map[string]string{"k": "v"}}}, nil
}

// verifierHandler builds a handler whose executor verifies against caPEM, with
// an injected fake osquery so tests can assert call counts.
func verifierHandler(t *testing.T, caPEM []byte, oq osqueryRunner) *Handler {
	t.Helper()
	verifier, err := verify.NewActionVerifier(caPEM)
	require.NoError(t, err)
	exec := executor.NewExecutor(verifier, nil)
	exec.SetDeviceID(testDeviceID)
	h := NewHandler(slog.Default(), exec, nil, nil, make(chan struct{}, 1))
	if oq != nil {
		h.setOsqueryForTest(oq)
	}
	return h
}

// noVerifierHandler builds a handler with NO verifier (executor.NewExecutor(nil, nil)).
func noVerifierHandler(t *testing.T, oq osqueryRunner) *Handler {
	t.Helper()
	h := NewHandler(slog.Default(), executor.NewExecutor(nil, nil), nil, nil, make(chan struct{}, 1))
	if oq != nil {
		h.setOsqueryForTest(oq)
	}
	return h
}

// signOSQuery / signLogQuery / signRevoke / signInventory set the message's
// signature to a valid control-server signature over its canonical bytes.
func signOSQuery(t *testing.T, s *verify.ActionSigner, q *pb.OSQuery) {
	t.Helper()
	c, err := verify.OSQueryCanonical(q)
	require.NoError(t, err)
	sig, err := s.SignDomain(verify.OSQuerySignatureDomain, c)
	require.NoError(t, err)
	q.Signature = sig
}

func signLogQuery(t *testing.T, s *verify.ActionSigner, q *pb.LogQuery) {
	t.Helper()
	c, err := verify.LogQueryCanonical(q)
	require.NoError(t, err)
	sig, err := s.SignDomain(verify.LogQuerySignatureDomain, c)
	require.NoError(t, err)
	q.Signature = sig
}

func signRevoke(t *testing.T, s *verify.ActionSigner, m *pb.RevokeLuksDeviceKey) {
	t.Helper()
	c, err := verify.RevokeLuksDeviceKeyCanonical(m)
	require.NoError(t, err)
	sig, err := s.SignDomain(verify.LuksRevokeSignatureDomain, c)
	require.NoError(t, err)
	m.Signature = sig
}

func signInventory(t *testing.T, s *verify.ActionSigner, m *pb.RequestInventory) {
	t.Helper()
	c, err := verify.RequestInventoryCanonical(m)
	require.NoError(t, err)
	sig, err := s.SignDomain(verify.InventorySignatureDomain, c)
	require.NoError(t, err)
	m.Signature = sig
}

func flipLastByte(b []byte) []byte {
	out := append([]byte(nil), b...)
	if len(out) > 0 {
		out[len(out)-1] ^= 0xFF
	}
	return out
}

// recordingRunner is a fake exec.Runner that records each command (OnLogQuery now
// runs journalctl through the SDK sys/log source, which dispatches via
// handlerRunner) and returns a canned success — so the WS4 charter can assert
// journalctl is NOT invoked for an unsigned/invalid/over-cap log query.
type recordingRunner struct{ calls *[][]string }

func (r recordingRunner) Run(_ context.Context, c sysexec.Command) (sysexec.Result, error) {
	*r.calls = append(*r.calls, append([]string{c.Name}, c.Args...))
	return sysexec.Result{ExitCode: 0, Stdout: "logline\n"}, nil
}

func (r recordingRunner) Stream(ctx context.Context, c sysexec.Command, _ sysexec.OutputCallback) (sysexec.Result, error) {
	// Propagate the caller's ctx (#174): swallowing it here meant a test
	// could never catch a production bug that drops cancellation on the
	// streaming path.
	return r.Run(ctx, c)
}

func (r recordingRunner) Backend() sysexec.PrivilegeBackend { return sysexec.Direct }

// fakeJournalctl swaps the handler's runner for the duration of the test,
// recording the args journalctl receives via the SDK sys/log source. Returns a
// pointer to a slice of arg-sets (each prefixed with the command name).
func fakeJournalctl(t *testing.T) *[][]string {
	t.Helper()
	var calls [][]string
	orig := handlerRunner
	t.Cleanup(func() { handlerRunner = orig })
	handlerRunner = recordingRunner{calls: &calls}
	return &calls
}

const testQueryID = "01J0Q00000000000000000000Q" // 26-char ULID shape

func validULID(t *testing.T) string {
	t.Helper()
	return testQueryID
}

// ---------------------------------------------------------------------------
// OnQuery (#1)
// ---------------------------------------------------------------------------

func TestOnQuery_EnforcesSignature(t *testing.T) {
	caPEM, signer := testCAAndSigner(t)

	// correct: a control-signed table query reaches osquery.
	t.Run("correct_signed_table", func(t *testing.T) {
		oq := &fakeOsquery{}
		h := verifierHandler(t, caPEM, oq)
		q := &pb.OSQuery{QueryId: validULID(t), Table: "processes"}
		signOSQuery(t, signer, q)
		res, err := h.OnQuery(context.Background(), q)
		require.NoError(t, err)
		assert.True(t, res.Success, "a signed query must run")
		assert.Equal(t, 1, oq.queryCalls, "osquery must be invoked for a signed query")
	})

	// ABSENT: no signature → refused, osquery NOT invoked.
	t.Run("absent_signature", func(t *testing.T) {
		oq := &fakeOsquery{}
		h := verifierHandler(t, caPEM, oq)
		q := &pb.OSQuery{QueryId: validULID(t), Table: "processes"} // no Signature
		res, err := h.OnQuery(context.Background(), q)
		require.NoError(t, err)
		assert.False(t, res.Success)
		assert.Contains(t, res.Error, "refusing")
		assert.Equal(t, 0, oq.queryCalls, "unsigned query must NOT reach osquery")
	})

	// present-but-WRONG (byte-tampered).
	t.Run("byte_tampered", func(t *testing.T) {
		oq := &fakeOsquery{}
		h := verifierHandler(t, caPEM, oq)
		q := &pb.OSQuery{QueryId: validULID(t), Table: "processes"}
		signOSQuery(t, signer, q)
		q.Signature = flipLastByte(q.Signature)
		res, err := h.OnQuery(context.Background(), q)
		require.NoError(t, err)
		assert.False(t, res.Success)
		assert.Equal(t, 0, oq.queryCalls)
	})

	// present-but-WRONG (field swap): sign over table=processes, then mutate the
	// table to shadow after signing — proves the signature binds the table.
	t.Run("field_swap_table", func(t *testing.T) {
		oq := &fakeOsquery{}
		h := verifierHandler(t, caPEM, oq)
		q := &pb.OSQuery{QueryId: validULID(t), Table: "processes"}
		signOSQuery(t, signer, q)
		q.Table = "shadow"
		res, err := h.OnQuery(context.Background(), q)
		require.NoError(t, err)
		assert.False(t, res.Success)
		assert.Equal(t, 0, oq.queryCalls, "a swapped table must not reach osquery")
	})
}

// TestOnQuery_SignedRawSQLAllowed pins decision A: raw SQL is signed like any
// other query (not refused). A signed raw query runs; an unsigned/tampered raw
// query is refused.
func TestOnQuery_SignedRawSQLAllowed(t *testing.T) {
	caPEM, signer := testCAAndSigner(t)

	t.Run("signed_raw_sql_runs", func(t *testing.T) {
		oq := &fakeOsquery{}
		h := verifierHandler(t, caPEM, oq)
		q := &pb.OSQuery{QueryId: validULID(t), RawSql: "SELECT 1"}
		signOSQuery(t, signer, q)
		res, err := h.OnQuery(context.Background(), q)
		require.NoError(t, err)
		assert.True(t, res.Success, "a signed raw-SQL query must run")
		assert.Equal(t, 1, oq.queryCalls)
	})

	t.Run("unsigned_raw_sql_refused", func(t *testing.T) {
		oq := &fakeOsquery{}
		h := verifierHandler(t, caPEM, oq)
		q := &pb.OSQuery{QueryId: validULID(t), RawSql: "SELECT * FROM shadow"} // no Signature
		res, err := h.OnQuery(context.Background(), q)
		require.NoError(t, err)
		assert.False(t, res.Success)
		assert.Equal(t, 0, oq.queryCalls, "unsigned raw SQL must NOT reach osquery")
	})

	// field swap on raw_sql: sign "SELECT 1", mutate to a shadow read.
	t.Run("raw_sql_swap_refused", func(t *testing.T) {
		oq := &fakeOsquery{}
		h := verifierHandler(t, caPEM, oq)
		q := &pb.OSQuery{QueryId: validULID(t), RawSql: "SELECT 1"}
		signOSQuery(t, signer, q)
		q.RawSql = "SELECT * FROM shadow"
		res, err := h.OnQuery(context.Background(), q)
		require.NoError(t, err)
		assert.False(t, res.Success)
		assert.Equal(t, 0, oq.queryCalls)
	})
}

// TestOnQuery_NoVerifierFailsClosed: a handler with no verifier refuses every
// query — table OR raw — and never reaches osquery.
func TestOnQuery_NoVerifierFailsClosed(t *testing.T) {
	_, signer := testCAAndSigner(t)
	oq := &fakeOsquery{}
	h := noVerifierHandler(t, oq)

	// Even a (would-be) signed query is refused without a verifier.
	q := &pb.OSQuery{QueryId: validULID(t), Table: "processes"}
	signOSQuery(t, signer, q)
	res, err := h.OnQuery(context.Background(), q)
	require.NoError(t, err)
	assert.False(t, res.Success, "no verifier must fail closed")
	assert.Equal(t, 0, oq.queryCalls)
}

// TestOnQuery_ValidatesBeforeVerifying: an absent/malformed query_id is rejected
// before any signature work, and osquery is never invoked.
func TestOnQuery_ValidatesBeforeVerifying(t *testing.T) {
	caPEM, _ := testCAAndSigner(t)

	for _, tc := range []struct {
		name string
		q    *pb.OSQuery
	}{
		{"absent_query_id", &pb.OSQuery{Table: "processes"}},
		{"malformed_query_id", &pb.OSQuery{QueryId: "not-a-ulid", Table: "processes"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			oq := &fakeOsquery{}
			h := verifierHandler(t, caPEM, oq)
			res, err := h.OnQuery(context.Background(), tc.q)
			require.NoError(t, err)
			assert.False(t, res.Success, "invalid query_id must be rejected")
			assert.Equal(t, 0, oq.queryCalls, "validation failure must not reach osquery")
		})
	}
}

// ---------------------------------------------------------------------------
// OnLogQuery (#3, #4, #5, #6)
// ---------------------------------------------------------------------------

func TestOnLogQuery_EnforcesSignature(t *testing.T) {
	caPEM, signer := testCAAndSigner(t)

	t.Run("correct_signed", func(t *testing.T) {
		calls := fakeJournalctl(t)
		h := verifierHandler(t, caPEM, nil)
		q := &pb.LogQuery{QueryId: validULID(t), Unit: "nginx.service", Lines: 10}
		signLogQuery(t, signer, q)
		res, err := h.OnLogQuery(context.Background(), q)
		require.NoError(t, err)
		assert.True(t, res.Success)
		require.Len(t, *calls, 1, "signed log query must invoke journalctl")
	})

	t.Run("absent_signature", func(t *testing.T) {
		calls := fakeJournalctl(t)
		h := verifierHandler(t, caPEM, nil)
		q := &pb.LogQuery{QueryId: validULID(t), Unit: "nginx.service"} // no Signature
		res, err := h.OnLogQuery(context.Background(), q)
		require.NoError(t, err)
		assert.False(t, res.Success)
		assert.Contains(t, res.Error, "refusing")
		assert.Empty(t, *calls, "unsigned log query must NOT invoke journalctl")
	})

	t.Run("byte_tampered", func(t *testing.T) {
		calls := fakeJournalctl(t)
		h := verifierHandler(t, caPEM, nil)
		q := &pb.LogQuery{QueryId: validULID(t), Unit: "nginx.service"}
		signLogQuery(t, signer, q)
		q.Signature = flipLastByte(q.Signature)
		res, err := h.OnLogQuery(context.Background(), q)
		require.NoError(t, err)
		assert.False(t, res.Success)
		assert.Empty(t, *calls)
	})

	// field swap: sign over unit=nginx, mutate to ssh — proves unit binding.
	t.Run("unit_swap", func(t *testing.T) {
		calls := fakeJournalctl(t)
		h := verifierHandler(t, caPEM, nil)
		q := &pb.LogQuery{QueryId: validULID(t), Unit: "nginx.service"}
		signLogQuery(t, signer, q)
		q.Unit = "ssh.service"
		res, err := h.OnLogQuery(context.Background(), q)
		require.NoError(t, err)
		assert.False(t, res.Success)
		assert.Empty(t, *calls, "a swapped unit must not reach journalctl")
	})
}

func TestOnLogQuery_NoVerifierFailsClosed(t *testing.T) {
	_, signer := testCAAndSigner(t)
	calls := fakeJournalctl(t)
	h := noVerifierHandler(t, nil)
	q := &pb.LogQuery{QueryId: validULID(t), Unit: "nginx.service"}
	signLogQuery(t, signer, q)
	res, err := h.OnLogQuery(context.Background(), q)
	require.NoError(t, err)
	assert.False(t, res.Success, "no verifier must fail closed")
	assert.Empty(t, *calls)
}

// TestOnLogQuery_PriorityAllowList drives the priority switch through the REAL
// (signed) handler and pins it as an exact-set allow-list discovered from
// intent: the 8 numeric + 8 keyword journald levels are accepted; anything
// else is rejected and journalctl is never invoked.
func TestOnLogQuery_PriorityAllowList(t *testing.T) {
	caPEM, signer := testCAAndSigner(t)

	allowed := []string{
		"0", "1", "2", "3", "4", "5", "6", "7",
		"emerg", "alert", "crit", "err", "warning", "notice", "info", "debug",
	}
	for _, p := range allowed {
		t.Run("accept_"+p, func(t *testing.T) {
			calls := fakeJournalctl(t)
			h := verifierHandler(t, caPEM, nil)
			q := &pb.LogQuery{QueryId: validULID(t), Priority: p}
			signLogQuery(t, signer, q)
			res, err := h.OnLogQuery(context.Background(), q)
			require.NoError(t, err)
			assert.True(t, res.Success, "priority %q must be accepted", p)
			require.Len(t, *calls, 1)
			joined := strings.Join((*calls)[0], " ")
			assert.Contains(t, joined, "-p", "accepted priority must pass -p to journalctl")
		})
	}

	rejected := []string{
		"7;rm -rf /", // injection
		"trace",      // real-ish word that is NOT a journald level
		"8",          // one past the numeric range
		"INFO ",      // trailing space
		" info",      // leading space
		"-1",
	}
	for _, p := range rejected {
		t.Run("reject_"+p, func(t *testing.T) {
			calls := fakeJournalctl(t)
			h := verifierHandler(t, caPEM, nil)
			q := &pb.LogQuery{QueryId: validULID(t), Priority: p}
			signLogQuery(t, signer, q)
			res, err := h.OnLogQuery(context.Background(), q)
			require.NoError(t, err)
			assert.False(t, res.Success, "priority %q must be rejected", p)
			assert.Contains(t, res.Error, "priority")
			assert.Empty(t, *calls, "rejected priority must not reach journalctl")
		})
	}

	// ABSENT priority: empty → success path, no -p flag.
	t.Run("absent_priority_no_flag", func(t *testing.T) {
		calls := fakeJournalctl(t)
		h := verifierHandler(t, caPEM, nil)
		q := &pb.LogQuery{QueryId: validULID(t)}
		signLogQuery(t, signer, q)
		res, err := h.OnLogQuery(context.Background(), q)
		require.NoError(t, err)
		assert.True(t, res.Success)
		require.Len(t, *calls, 1)
		assert.NotContains(t, strings.Join((*calls)[0], " "), " -p ")
	})
}

// TestOnLogQuery_GrepLengthCap: 257 chars (one past max 256) rejected; 256
// accepted. The reject input is 256+1, derived from intent, not read off the rule.
func TestOnLogQuery_GrepLengthCap(t *testing.T) {
	caPEM, signer := testCAAndSigner(t)

	t.Run("over_cap_rejected", func(t *testing.T) {
		calls := fakeJournalctl(t)
		h := verifierHandler(t, caPEM, nil)
		q := &pb.LogQuery{QueryId: validULID(t), Grep: strings.Repeat("a", 257)}
		signLogQuery(t, signer, q)
		res, err := h.OnLogQuery(context.Background(), q)
		require.NoError(t, err)
		assert.False(t, res.Success)
		// The boundary validator (max=256) catches the over-cap grep first; the
		// exact layer is an implementation detail, so assert intent: rejected,
		// mentions the cap, and journalctl is never invoked.
		assert.Contains(t, res.Error, "256")
		assert.Empty(t, *calls)
	})

	t.Run("at_cap_accepted", func(t *testing.T) {
		calls := fakeJournalctl(t)
		h := verifierHandler(t, caPEM, nil)
		q := &pb.LogQuery{QueryId: validULID(t), Grep: strings.Repeat("a", 256)}
		signLogQuery(t, signer, q)
		res, err := h.OnLogQuery(context.Background(), q)
		require.NoError(t, err)
		assert.True(t, res.Success)
		require.Len(t, *calls, 1)
	})
}

// TestOnLogQuery_PathologicalGrepRejectedThroughHandler proves the ReDoS guard
// is wired into the verified handler path (not just unit-tested in isolation).
func TestOnLogQuery_PathologicalGrepRejectedThroughHandler(t *testing.T) {
	caPEM, signer := testCAAndSigner(t)
	calls := fakeJournalctl(t)
	h := verifierHandler(t, caPEM, nil)
	q := &pb.LogQuery{QueryId: validULID(t), Grep: "(a+)+b"} // classic catastrophic shape
	signLogQuery(t, signer, q)
	res, err := h.OnLogQuery(context.Background(), q)
	require.NoError(t, err)
	assert.False(t, res.Success)
	assert.Contains(t, res.Error, "grep pattern rejected")
	assert.Empty(t, *calls, "a pathological grep must not reach journalctl")
}

// ---------------------------------------------------------------------------
// OnRevokeLuksDeviceKey (#2)
// ---------------------------------------------------------------------------

func TestOnRevokeLuksDeviceKey_EnforcesSignature(t *testing.T) {
	caPEM, signer := testCAAndSigner(t)
	const actionID = "01J0R00000000000000000000R"

	// correct: a signed revocation passes the gate and reaches the executor
	// (which, with no store wired, returns the distinct "agent store not
	// configured" error — proving the wipe path was entered, not the gate).
	t.Run("correct_signed", func(t *testing.T) {
		h := verifierHandler(t, caPEM, nil)
		m := &pb.RevokeLuksDeviceKey{ActionId: actionID}
		signRevoke(t, signer, m)
		ok, msg := h.OnRevokeLuksDeviceKey(context.Background(), m)
		assert.False(t, ok)
		assert.Contains(t, msg, "agent store not configured",
			"a signed revoke must reach the executor, not the signature gate")
	})

	t.Run("absent_signature", func(t *testing.T) {
		h := verifierHandler(t, caPEM, nil)
		m := &pb.RevokeLuksDeviceKey{ActionId: actionID} // no Signature
		ok, msg := h.OnRevokeLuksDeviceKey(context.Background(), m)
		assert.False(t, ok)
		assert.Contains(t, msg, "refusing", "unsigned LUKS revoke must be refused at the gate")
	})

	t.Run("byte_tampered", func(t *testing.T) {
		h := verifierHandler(t, caPEM, nil)
		m := &pb.RevokeLuksDeviceKey{ActionId: actionID}
		signRevoke(t, signer, m)
		m.Signature = flipLastByte(m.Signature)
		ok, msg := h.OnRevokeLuksDeviceKey(context.Background(), m)
		assert.False(t, ok)
		assert.Contains(t, msg, "refusing")
	})

	// action_id swap: sign over one id, present another — no cross-action replay.
	t.Run("action_id_swap", func(t *testing.T) {
		h := verifierHandler(t, caPEM, nil)
		m := &pb.RevokeLuksDeviceKey{ActionId: actionID}
		signRevoke(t, signer, m)
		m.ActionId = "01J0R00000000000000000000S"
		ok, msg := h.OnRevokeLuksDeviceKey(context.Background(), m)
		assert.False(t, ok)
		assert.Contains(t, msg, "refusing", "a swapped action_id must be refused")
	})
}

func TestOnRevokeLuksDeviceKey_NoVerifierFailsClosed(t *testing.T) {
	_, signer := testCAAndSigner(t)
	h := noVerifierHandler(t, nil)
	m := &pb.RevokeLuksDeviceKey{ActionId: "01J0R00000000000000000000R"}
	signRevoke(t, signer, m)
	ok, msg := h.OnRevokeLuksDeviceKey(context.Background(), m)
	assert.False(t, ok, "no verifier must fail closed")
	assert.Contains(t, msg, "refusing")
}

// ---------------------------------------------------------------------------
// OnRequestInventory (#7)
// ---------------------------------------------------------------------------

func TestOnRequestInventory_EnforcesSignature(t *testing.T) {
	caPEM, signer := testCAAndSigner(t)

	t.Run("correct_signed_runs_osquery", func(t *testing.T) {
		oq := &fakeOsquery{}
		h := verifierHandler(t, caPEM, oq)
		m := &pb.RequestInventory{QueryId: validULID(t)}
		signInventory(t, signer, m)
		inv := h.OnRequestInventory(context.Background(), m)
		assert.NotNil(t, inv)
		assert.NotEmpty(t, oq.tableCalls, "a signed inventory request must query osquery tables")
	})

	t.Run("absent_signature", func(t *testing.T) {
		oq := &fakeOsquery{}
		h := verifierHandler(t, caPEM, oq)
		m := &pb.RequestInventory{QueryId: validULID(t)} // no Signature
		inv := h.OnRequestInventory(context.Background(), m)
		assert.Nil(t, inv, "unsigned inventory request must return nil")
		assert.Empty(t, oq.tableCalls, "unsigned inventory request must NOT query osquery")
	})

	t.Run("byte_tampered", func(t *testing.T) {
		oq := &fakeOsquery{}
		h := verifierHandler(t, caPEM, oq)
		m := &pb.RequestInventory{QueryId: validULID(t)}
		signInventory(t, signer, m)
		m.Signature = flipLastByte(m.Signature)
		inv := h.OnRequestInventory(context.Background(), m)
		assert.Nil(t, inv)
		assert.Empty(t, oq.tableCalls)
	})
}

func TestOnRequestInventory_NoVerifierFailsClosed(t *testing.T) {
	_, signer := testCAAndSigner(t)
	oq := &fakeOsquery{}
	h := noVerifierHandler(t, oq)
	m := &pb.RequestInventory{QueryId: validULID(t)}
	signInventory(t, signer, m)
	inv := h.OnRequestInventory(context.Background(), m)
	assert.Nil(t, inv, "no verifier must fail closed")
	assert.Empty(t, oq.tableCalls)
}

// TestCollectInventory_TableSetIsHardcoded pins that the osquery tables queried
// are EXACTLY the hardcoded union of inventoryCoreTables + inventoryPackageTables
// (self-discovering from the package vars), and that RequestInventory carries no
// field that could introduce a server-supplied table name.
func TestCollectInventory_TableSetIsHardcoded(t *testing.T) {
	caPEM, signer := testCAAndSigner(t)
	oq := &fakeOsquery{}
	h := verifierHandler(t, caPEM, oq)

	m := &pb.RequestInventory{QueryId: validULID(t)}
	signInventory(t, signer, m)
	require.NotNil(t, h.OnRequestInventory(context.Background(), m))

	want := map[string]bool{}
	for _, tbl := range inventoryCoreTables {
		want[tbl] = true
	}
	for _, tbl := range inventoryPackageTables {
		want[tbl] = true
	}
	require.NotEmpty(t, want)

	got := map[string]bool{}
	for _, tbl := range oq.tableCalls {
		got[tbl] = true
		assert.Truef(t, want[tbl], "osquery queried table %q outside the hardcoded set", tbl)
	}
	for tbl := range want {
		assert.Truef(t, got[tbl], "hardcoded table %q was not queried", tbl)
	}

	// RequestInventory must carry NO field that could smuggle a table name: its
	// fields are exactly query_id + signature. A new field fails here, forcing a
	// review of whether it could carry a table name.
	fields := (&pb.RequestInventory{}).ProtoReflect().Descriptor().Fields()
	names := map[string]bool{}
	for i := 0; i < fields.Len(); i++ {
		names[string(fields.Get(i).Name())] = true
	}
	assert.Equal(t, map[string]bool{"query_id": true, "signature": true}, names,
		"RequestInventory gained a field — confirm it cannot carry a table name")
}
