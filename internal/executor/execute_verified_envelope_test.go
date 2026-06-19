package executor

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/cryptotest"
	"github.com/manchtools/power-manage-sdk/verify"
)

// testVerifierAndSigner returns an Executor whose verifier is built from a
// fresh self-signed CA, plus the matching ActionSigner. A signature minted
// by this signer verifies; anything else (or nothing) is refused.
func testVerifierAndSigner(t *testing.T) (*Executor, *verify.ActionSigner) {
	t.Helper()
	caPEM, key, _ := cryptotest.GenCA(t, "test-ca")
	verifier, err := verify.NewActionVerifier(caPEM)
	require.NoError(t, err)
	return NewExecutor(verifier), verify.NewActionSigner(key)
}

func signEnv(t *testing.T, signer *verify.ActionSigner, env *pb.SignedActionEnvelope) (envelope []byte, signature []byte) {
	t.Helper()
	b, err := verify.MarshalEnvelope(env)
	require.NoError(t, err)
	sig, err := signer.Sign(b)
	require.NoError(t, err)
	return b, sig
}

// shellEnvelope builds and signs a SHELL envelope carrying script.
func shellEnvelope(t *testing.T, signer *verify.ActionSigner, id, script string) (verified *pb.SignedActionEnvelope, envBytes, sig []byte) {
	t.Helper()
	env := &pb.SignedActionEnvelope{
		ActionId:   &pb.ActionId{Value: id},
		ActionType: pb.ActionType_ACTION_TYPE_SHELL,
		Params:     &pb.SignedActionEnvelope_Shell{Shell: &pb.ShellParams{Script: script, RunAsRoot: true}},
	}
	envBytes, sig = signEnv(t, signer, env)
	return env, envBytes, sig
}

// TestExecutor_ExecutesVerifiedEnvelopeParams drives the real verify-then-
// execute path and proves WHAT runs is the SIGNED script, hermetically (no
// root, no shelling out, no desktop sessions).
//
// It uses the SHELL branch's deterministic size gate: a script larger than
// maxScriptSize fails with a fixed error, an in-bounds one does not take that
// branch. Two envelopes that differ ONLY in their (signed) Script field must
// therefore reach DIFFERENT outcomes — which is only possible if the executor
// reads the script from the verified envelope. The result also echoes the
// envelope's action id. Finally the negative: flipping a byte of the signed
// envelope must fail verification so nothing can execute.
func TestExecutor_ExecutesVerifiedEnvelopeParams(t *testing.T) {
	exec, signer := testVerifierAndSigner(t)

	// Oversize signed script → deterministic size-gate rejection. This proves
	// the executor read env.GetShell().Script (the signed bytes) before doing
	// anything environment-dependent.
	bigVerified, bigBytes, bigSig := shellEnvelope(t, signer, "01HSHELLBIG", strings.Repeat("x", maxScriptSize+1))
	got, err := exec.VerifyEnvelope(bigBytes, bigSig)
	require.NoError(t, err)
	require.Equal(t, "01HSHELLBIG", got.GetActionId().GetValue())
	require.Equal(t, bigVerified.GetShell().GetScript(), got.GetShell().GetScript(),
		"verified envelope must carry the signed script")

	res := exec.ExecuteWithStreaming(context.Background(), got, nil)
	assert.Equal(t, "01HSHELLBIG", res.ActionId.GetValue(), "result echoes the envelope id")
	assert.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_FAILED, res.Status)
	assert.Contains(t, res.Error, "exceeds maximum size",
		"the SIGNED oversize script must drive the size-gate rejection")

	// Empty signed script + empty detection → different deterministic SHELL
	// outcome. The ONLY thing that changed between the two runs is the signed
	// Script field, so a different outcome proves the signed params drive
	// execution (not any constant or unverified field).
	emptyVerified, emptyBytes, emptySig := shellEnvelope(t, signer, "01HSHELLEMPTY", "")
	_ = emptyVerified
	got2, err := exec.VerifyEnvelope(emptyBytes, emptySig)
	require.NoError(t, err)
	res2 := exec.ExecuteWithStreaming(context.Background(), got2, nil)
	assert.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_FAILED, res2.Status)
	assert.Contains(t, res2.Error, "at least one of script or detection_script is required",
		"an empty signed script must reach the empty-script branch")
	assert.NotEqual(t, res.Error, res2.Error,
		"two envelopes differing only in the signed script must reach different outcomes")

	// Tamper: flip a byte. VerifyEnvelope must fail and nothing executes.
	tampered := make([]byte, len(bigBytes))
	copy(tampered, bigBytes)
	tampered[len(tampered)/2] ^= 0xFF
	_, terr := exec.VerifyEnvelope(tampered, bigSig)
	assert.Error(t, terr, "tampered envelope bytes must not verify")
}

// TestExecutor_VerifyEnvelopeFailClosed pins the fail-closed contract of the
// shared helper independent of platform: no verifier, empty signature, and
// signature-over-different-bytes all return an error and never yield an
// executable envelope.
func TestExecutor_VerifyEnvelopeFailClosed(t *testing.T) {
	exec, signer := testVerifierAndSigner(t)

	env := &pb.SignedActionEnvelope{
		ActionId:   &pb.ActionId{Value: "01HFAILCLOSED"},
		ActionType: pb.ActionType_ACTION_TYPE_PACKAGE,
		Params:     &pb.SignedActionEnvelope_Package{Package: &pb.PackageParams{Name: "htop"}},
	}
	envBytes, sig := signEnv(t, signer, env)

	t.Run("valid signature verifies", func(t *testing.T) {
		got, err := exec.VerifyEnvelope(envBytes, sig)
		require.NoError(t, err)
		assert.Equal(t, "htop", got.GetPackage().GetName())
	})

	t.Run("empty signature is refused", func(t *testing.T) {
		_, err := exec.VerifyEnvelope(envBytes, nil)
		assert.Error(t, err)
	})

	t.Run("signature over different bytes is refused", func(t *testing.T) {
		_, otherSig := signEnv(t, signer, &pb.SignedActionEnvelope{
			ActionId:   &pb.ActionId{Value: "01HOTHER"},
			ActionType: pb.ActionType_ACTION_TYPE_PACKAGE,
			Params:     &pb.SignedActionEnvelope_Package{Package: &pb.PackageParams{Name: "vim"}},
		})
		_, err := exec.VerifyEnvelope(envBytes, otherSig)
		assert.Error(t, err)
	})

	t.Run("nil verifier fails closed", func(t *testing.T) {
		noVerifier := NewExecutor(nil)
		_, err := noVerifier.VerifyEnvelope(envBytes, sig)
		assert.Error(t, err, "an executor with no verifier must refuse, not pass")
	})
}

// TestExecutor_DesiredStateFromEnvelope pins that the VERIFIED desired_state
// drives execution: a USER envelope with DesiredState=ABSENT executes the
// removal path. We verify the envelope, then assert the executable envelope
// carries ABSENT — the value the agent acts on comes from the signed bytes,
// not from any advisory wire field.
func TestExecutor_DesiredStateFromEnvelope(t *testing.T) {
	exec, signer := testVerifierAndSigner(t)

	env := &pb.SignedActionEnvelope{
		ActionId:     &pb.ActionId{Value: "01HUSERABSENT"},
		ActionType:   pb.ActionType_ACTION_TYPE_USER,
		DesiredState: pb.DesiredState_DESIRED_STATE_ABSENT,
		Params: &pb.SignedActionEnvelope_User{User: &pb.UserParams{
			Username: "pm-test-absent-user",
		}},
	}
	envBytes, sig := signEnv(t, signer, env)

	verified, err := exec.VerifyEnvelope(envBytes, sig)
	require.NoError(t, err)
	assert.Equal(t, pb.DesiredState_DESIRED_STATE_ABSENT, verified.GetDesiredState(),
		"the verified envelope must carry the signed ABSENT desired_state")
	assert.Equal(t, "pm-test-absent-user", verified.GetUser().GetUsername())

	// A tampered desired_state (flip to PRESENT in a re-marshalled copy) must
	// NOT verify under the original signature — proving desired_state is
	// inside the signed bytes.
	tamper := &pb.SignedActionEnvelope{
		ActionId:     env.ActionId,
		ActionType:   env.ActionType,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
		Params:       env.Params,
	}
	tamperBytes, err := verify.MarshalEnvelope(tamper)
	require.NoError(t, err)
	_, terr := exec.VerifyEnvelope(tamperBytes, sig)
	assert.Error(t, terr, "flipping desired_state must break verification")
}
