package handler

import (
	"context"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/agent/internal/executor"
	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/cryptotest"
	"github.com/manchtools/power-manage-sdk/verify"
)

// testCAAndSigner returns a self-signed CA cert (PEM) and a matching
// ActionSigner. The agent's verifier is built from the same cert, so a
// signature minted here verifies on the agent side — and a signature minted
// by any OTHER key (or no signature) is rejected.
func testCAAndSigner(t *testing.T) ([]byte, *verify.ActionSigner) {
	t.Helper()
	caPEM, key, _ := cryptotest.GenCA(t, "test-ca")
	return caPEM, verify.NewActionSigner(key)
}

// signEnvelope marshals env into its deterministic wire bytes and signs
// those bytes with the CA signer, returning the bytes the agent receives
// (envelope) and the CA signature over them. The agent MUST verify over,
// and unmarshal-then-execute, THESE SAME bytes (sdk#82).
func signEnvelope(t *testing.T, signer *verify.ActionSigner, env *pb.SignedActionEnvelope) (envelope []byte, signature []byte) {
	t.Helper()
	envBytes, err := verify.MarshalEnvelope(env)
	require.NoError(t, err)
	sig, err := signer.Sign(envBytes)
	require.NoError(t, err)
	return envBytes, sig
}

// newVerifierHandler builds a handler whose executor verifies against the
// given CA, with a buffered sync trigger so the test can assert how many
// times a resync was enqueued.
func newVerifierHandler(t *testing.T, caPEM []byte) (*Handler, chan struct{}) {
	t.Helper()
	verifier, err := verify.NewActionVerifier(caPEM)
	require.NoError(t, err)
	syncTrigger := make(chan struct{}, 1)
	h := NewHandler(slog.Default(), executor.NewExecutor(verifier), nil, nil, syncTrigger)
	return h, syncTrigger
}

// TestOnAction_UnsignedDispatchRefusedAndNoSync pins the fail-closed
// invariant on the wire path: a dispatch with no signature (the shape a
// compromised gateway/Valkey could inject) is refused, and — critically —
// a SYNC payload delivered without a valid signature must NOT trigger a
// resync. The envelope-binding is what makes SYNC safe; without a verified
// envelope the handler must do nothing.
func TestOnAction_UnsignedDispatchRefusedAndNoSync(t *testing.T) {
	caPEM, signer := testCAAndSigner(t)
	h, syncTrigger := newVerifierHandler(t, caPEM)

	// Build a real SYNC envelope and its bytes, but deliver it with an
	// EMPTY signature. The handler must reject it and not fire sync.
	env := &pb.SignedActionEnvelope{
		ActionId:   &pb.ActionId{Value: "01HSYNCUNSIGNED"},
		ActionType: pb.ActionType_ACTION_TYPE_SYNC,
	}
	envBytes, err := verify.MarshalEnvelope(env)
	require.NoError(t, err)

	res, err := h.OnAction(context.Background(), envBytes, nil)
	require.NoError(t, err)
	assert.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_FAILED, res.Status,
		"an unsigned dispatch must be refused")
	assert.Len(t, syncTrigger, 0, "a refused SYNC must not enqueue a resync")

	// Belt-and-braces: a non-empty but WRONG-key signature is also refused.
	// Sign different bytes so the signature is structurally valid but does
	// not match envBytes.
	_, wrongSig := signEnvelope(t, signer, &pb.SignedActionEnvelope{
		ActionId:   &pb.ActionId{Value: "01HDIFFERENT"},
		ActionType: pb.ActionType_ACTION_TYPE_SYNC,
	})
	res2, err := h.OnAction(context.Background(), envBytes, wrongSig)
	require.NoError(t, err)
	assert.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_FAILED, res2.Status,
		"a signature over different bytes must be refused")
	assert.Len(t, syncTrigger, 0, "a refused SYNC must not enqueue a resync")
}

// TestOnAction_ValidSyncTriggersExactlyOnce pins that a properly signed
// SYNC envelope triggers a resync exactly once and reports SUCCESS.
func TestOnAction_ValidSyncTriggersExactlyOnce(t *testing.T) {
	caPEM, signer := testCAAndSigner(t)
	h, syncTrigger := newVerifierHandler(t, caPEM)

	env := &pb.SignedActionEnvelope{
		ActionId:   &pb.ActionId{Value: "01HSYNCSIGNED"},
		ActionType: pb.ActionType_ACTION_TYPE_SYNC,
	}
	envBytes, sig := signEnvelope(t, signer, env)

	res, err := h.OnAction(context.Background(), envBytes, sig)
	require.NoError(t, err)
	assert.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS, res.Status)
	assert.Len(t, syncTrigger, 1, "a signed SYNC must enqueue exactly one resync")
}

// TestOnAction_NonSyncEnvelopeNeverTriggersSync pins that the type binding
// lives in the SIGNED envelope: a validly signed REBOOT envelope delivered
// on OnAction must NOT be treated as a SYNC, even though it travels the same
// dispatch path. A compromised relay cannot lift a non-SYNC signature onto a
// SYNC because the type is inside the signed bytes. (REBOOT is an instant
// action that does not reach the executor's typed switch here; the load-
// bearing assertion is that NO resync is enqueued.)
func TestOnAction_NonSyncEnvelopeNeverTriggersSync(t *testing.T) {
	caPEM, signer := testCAAndSigner(t)
	h, syncTrigger := newVerifierHandler(t, caPEM)

	env := &pb.SignedActionEnvelope{
		ActionId:   &pb.ActionId{Value: "01HREBOOT"},
		ActionType: pb.ActionType_ACTION_TYPE_REBOOT,
	}
	envBytes, sig := signEnvelope(t, signer, env)

	_, err := h.OnAction(context.Background(), envBytes, sig)
	require.NoError(t, err)
	assert.Len(t, syncTrigger, 0,
		"a non-SYNC envelope must never enqueue a resync — the type is bound")
}

// TestOnAction_ParamsTamperRefused pins the params-binding invariant: sign a
// SHELL envelope (script "true"), then flip one byte of the envelope bytes
// before delivery. Verification over the tampered bytes must fail, so the
// handler returns FAILED and the script is never executed.
func TestOnAction_ParamsTamperRefused(t *testing.T) {
	caPEM, signer := testCAAndSigner(t)
	h, _ := newVerifierHandler(t, caPEM)

	env := &pb.SignedActionEnvelope{
		ActionId:   &pb.ActionId{Value: "01HSHELLTAMPER"},
		ActionType: pb.ActionType_ACTION_TYPE_SHELL,
		Params:     &pb.SignedActionEnvelope_Shell{Shell: &pb.ShellParams{Script: "true", RunAsRoot: true}},
	}
	envBytes, sig := signEnvelope(t, signer, env)

	// Flip a byte. The signature was minted over the original bytes, so the
	// tampered bytes will not verify.
	tampered := make([]byte, len(envBytes))
	copy(tampered, envBytes)
	tampered[len(tampered)/2] ^= 0xFF

	res, err := h.OnAction(context.Background(), tampered, sig)
	require.NoError(t, err)
	assert.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_FAILED, res.Status,
		"tampered envelope bytes must be refused before any execution")
}

// TestOnAction_NoVerifierIsFailClosed pins that an executor with no verifier
// refuses every dispatch — the agent must always carry a verifier (the CA
// cert is required at startup). A nil-verifier deployment must never become a
// silent "execute everything unsigned" hole.
func TestOnAction_NoVerifierIsFailClosed(t *testing.T) {
	_, signer := testCAAndSigner(t)
	syncTrigger := make(chan struct{}, 1)
	h := NewHandler(slog.Default(), executor.NewExecutor(nil), nil, nil, syncTrigger)

	env := &pb.SignedActionEnvelope{
		ActionId:   &pb.ActionId{Value: "01HSYNCNOVERIFIER"},
		ActionType: pb.ActionType_ACTION_TYPE_SYNC,
	}
	envBytes, sig := signEnvelope(t, signer, env)

	res, err := h.OnAction(context.Background(), envBytes, sig)
	require.NoError(t, err)
	assert.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_FAILED, res.Status,
		"a handler with no verifier must fail closed")
	assert.Len(t, syncTrigger, 0, "no verifier means no SYNC may fire")
}

// TestOnActionWithStreaming_MalformedEnvelopeNoPanic pins the WS15 #2 intent on
// the agent's real streaming dispatch surface (the method the SDK Client calls):
// a malformed "Action" on the wire — garbage envelope bytes that fail signature
// verification / proto-unmarshal, an absent envelope, or a nil signature — must
// be REFUSED with a FAILED ActionResult and never crash the handler. Intent: an
// Action on the wire carries a signed envelope; one that doesn't is malformed
// and is fail-closed, not dereferenced. (The action-signing-envelope refactor
// closed the original nil-Id deref; this is the regression guard.)
func TestOnActionWithStreaming_MalformedEnvelopeNoPanic(t *testing.T) {
	caPEM, signer := testCAAndSigner(t)

	// A real, validly signed envelope for the "correct" leg.
	good := &pb.SignedActionEnvelope{
		ActionId:   &pb.ActionId{Value: "01HSTREAMGOODACTION00000A"},
		ActionType: pb.ActionType_ACTION_TYPE_SYNC,
	}
	goodBytes, goodSig := signEnvelope(t, signer, good)

	cases := []struct {
		name     string
		envelope []byte
		sig      []byte
		wantFail bool
	}{
		{"correct: signed SYNC envelope", goodBytes, goodSig, false},
		{"absent: nil envelope + nil signature", nil, nil, true},
		{"absent: empty envelope bytes", []byte{}, []byte("sig"), true},
		{"present-but-wrong: garbage bytes that are not a valid envelope", []byte{0xff, 0x00, 0x13, 0x37, 0xde, 0xad}, []byte("sig"), true},
		{"present-but-wrong: real bytes, no signature", goodBytes, nil, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h, _ := newVerifierHandler(t, caPEM)
			var res *pb.ActionResult
			var err error
			// Must not panic on any malformed input.
			require.NotPanics(t, func() {
				res, err = h.OnActionWithStreaming(context.Background(), tc.envelope, tc.sig, nil)
			})
			require.NoError(t, err, "dispatch must be non-fatal (no returned error)")
			require.NotNil(t, res, "a result must always be returned")
			if tc.wantFail {
				assert.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_FAILED, res.Status,
					"a malformed/unsigned Action must be refused, not executed")
			} else {
				assert.NotEqual(t, pb.ExecutionStatus_EXECUTION_STATUS_FAILED, res.Status,
					"a validly signed envelope must not be rejected as malformed")
			}
		})
	}
}
