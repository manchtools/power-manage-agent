package executor

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage-sdk/cryptotest"
	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/verify"
)

// testDeviceID is the device id the test executor is configured with, and the
// default target every signed test envelope is bound to (see signEnv), so the
// PMSEC-001 target check passes for a matching envelope. Cross-device tests set
// a different TargetDeviceId explicitly.
const testDeviceID = "01TESTDEVICE0000000000000A"

// testVerifierAndSigner returns an Executor whose verifier is built from a
// fresh self-signed CA and whose device id is testDeviceID, plus the matching
// ActionSigner. A signature minted by this signer verifies; anything else (or
// nothing) is refused.
func testVerifierAndSigner(t *testing.T) (*Executor, *verify.ActionSigner) {
	t.Helper()
	caPEM, key, _ := cryptotest.GenCA(t, "test-ca")
	verifier, err := verify.NewActionVerifier(caPEM)
	require.NoError(t, err)
	exec := NewExecutor(verifier, nil)
	exec.SetDeviceID(testDeviceID)
	return exec, verify.NewActionSigner(key)
}

func signEnv(t *testing.T, signer *verify.ActionSigner, env *pb.SignedActionEnvelope) (envelope []byte, signature []byte) {
	t.Helper()
	// Default the signed target to this test device so a plain envelope passes
	// the PMSEC-001 target check; a test that wants a cross-device envelope sets
	// TargetDeviceId itself before calling.
	if env.GetTargetDeviceId() == "" {
		env.TargetDeviceId = testDeviceID
	}
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
		noVerifier := NewExecutor(nil, nil)
		_, err := noVerifier.VerifyEnvelope(envBytes, sig)
		assert.Error(t, err, "an executor with no verifier must refuse, not pass")
	})
}

// TestExecutor_VerifyEnvelope_EnforcesTargetBinding is the PMSEC-001 regression:
// verification is an AUTHORIZATION step, not just an authenticity check. A
// compromised gateway/relay that captures device A's validly-signed (same-CA)
// envelope and routes it to device B must be refused, even though the signature
// is genuine — because the SIGNED target_device_id does not match B. Fail closed
// on an empty target and on an agent that does not know its own device id.
func TestExecutor_VerifyEnvelope_EnforcesTargetBinding(t *testing.T) {
	exec, signer := testVerifierAndSigner(t) // exec device id == testDeviceID

	shell := func(id, target string) *pb.SignedActionEnvelope {
		return &pb.SignedActionEnvelope{
			ActionId:       &pb.ActionId{Value: id},
			ActionType:     pb.ActionType_ACTION_TYPE_SHELL,
			TargetDeviceId: target,
			Params:         &pb.SignedActionEnvelope_Shell{Shell: &pb.ShellParams{Script: "echo hi", RunAsRoot: true}},
		}
	}
	signRaw := func(env *pb.SignedActionEnvelope) (b, sig []byte) {
		var err error
		b, err = verify.MarshalEnvelope(env) // no defaulting: sign exactly what's given
		require.NoError(t, err)
		sig, err = signer.Sign(b)
		require.NoError(t, err)
		return b, sig
	}

	t.Run("matching target verifies", func(t *testing.T) {
		b, sig := signRaw(shell("01HMATCH", testDeviceID))
		got, err := exec.VerifyEnvelope(b, sig)
		require.NoError(t, err)
		require.Equal(t, testDeviceID, got.GetTargetDeviceId())
	})

	t.Run("cross-device target is refused", func(t *testing.T) {
		// Genuine signature (same CA), only the target differs — the exact
		// compromised-relay cross-device replay PMSEC-001 describes.
		b, sig := signRaw(shell("01HOTHERDEV", "01OTHERDEVICE0000000000B"))
		_, err := exec.VerifyEnvelope(b, sig)
		require.Error(t, err, "a validly-signed envelope for a DIFFERENT device must be refused")
		require.Contains(t, err.Error(), "target device")
	})

	t.Run("empty signed target is refused (fail closed)", func(t *testing.T) {
		b, sig := signRaw(shell("01HNOTARGET", ""))
		_, err := exec.VerifyEnvelope(b, sig)
		require.Error(t, err, "an envelope that binds no target device must be refused")
	})

	t.Run("agent without a configured device id fails closed", func(t *testing.T) {
		caPEM, key, _ := cryptotest.GenCA(t, "test-ca-2")
		verifier, err := verify.NewActionVerifier(caPEM)
		require.NoError(t, err)
		noID := NewExecutor(verifier, nil) // deliberately no SetDeviceID
		s := verify.NewActionSigner(key)
		b, err := verify.MarshalEnvelope(shell("01HNOID", testDeviceID))
		require.NoError(t, err)
		sig, err := s.Sign(b)
		require.NoError(t, err)
		_, verr := noID.VerifyEnvelope(b, sig)
		require.Error(t, verr, "an agent that does not know its own device id must refuse to execute")
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
