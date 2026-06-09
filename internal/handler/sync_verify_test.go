package handler

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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/agent/internal/executor"
	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/verify"
)

// syncCanonicalParams is the canonical params the control server signs
// for an instant action — `{}` (see the executor verification comment
// and server action_dispatch.go). The agent verifies SYNC against the
// same bytes.
var syncCanonicalParams = []byte("{}")

func testCAAndSigner(t *testing.T) ([]byte, *verify.ActionSigner) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return certPEM, verify.NewActionSigner(key)
}

func syncAction(id string) *pb.Action {
	return &pb.Action{Id: &pb.ActionId{Value: id}, Type: pb.ActionType_ACTION_TYPE_SYNC}
}

// The SYNC instant action returns before ExecuteWithStreaming, so the
// handler — not the executor — is the only thing that can enforce the
// CA signature on this path. An UNSIGNED SYNC from a compromised
// gateway must be rejected and must NOT trigger a resync; a properly
// signed SYNC must succeed and fire the trigger exactly once.
func TestOnAction_SyncEnforcesSignature(t *testing.T) {
	caPEM, signer := testCAAndSigner(t)
	verifier, err := verify.NewActionVerifier(caPEM)
	require.NoError(t, err)

	syncTrigger := make(chan struct{}, 1)
	h := NewHandler(slog.Default(), executor.NewExecutor(verifier), nil, nil, syncTrigger)

	t.Run("unsigned SYNC is rejected and does not trigger sync", func(t *testing.T) {
		res, err := h.OnAction(context.Background(), syncAction("01HSYNCUNSIGNED"))
		require.NoError(t, err)
		assert.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_FAILED, res.Status,
			"unsigned SYNC from a compromised gateway must be refused")
		assert.Len(t, syncTrigger, 0, "a rejected SYNC must not enqueue a resync")
	})

	t.Run("validly signed SYNC succeeds and triggers exactly one sync", func(t *testing.T) {
		a := syncAction("01HSYNCSIGNED")
		sig, err := signer.Sign(a.Id.Value, int32(a.Type), syncCanonicalParams)
		require.NoError(t, err)
		a.ParamsCanonical = syncCanonicalParams
		a.Signature = sig

		res, err := h.OnAction(context.Background(), a)
		require.NoError(t, err)
		assert.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS, res.Status)
		assert.Len(t, syncTrigger, 1, "a signed SYNC must enqueue exactly one resync")
	})

	t.Run("tampered SYNC (id swapped after signing) is rejected", func(t *testing.T) {
		a := syncAction("01HSYNCORIGINAL")
		sig, err := signer.Sign(a.Id.Value, int32(a.Type), syncCanonicalParams)
		require.NoError(t, err)
		a.ParamsCanonical = syncCanonicalParams
		a.Signature = sig
		a.Id = &pb.ActionId{Value: "01HSYNCSWAPPED"} // signature no longer matches id

		res, err := h.OnAction(context.Background(), a)
		require.NoError(t, err)
		assert.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_FAILED, res.Status)
	})
}

// When no verifier is configured (signing disabled), VerifyAction is a
// no-op and SYNC continues to work — the fast-path must not hard-require
// a signature in deployments that haven't enabled action signing.
func TestOnAction_SyncWithoutVerifierStillWorks(t *testing.T) {
	syncTrigger := make(chan struct{}, 1)
	h := NewHandler(slog.Default(), executor.NewExecutor(nil), nil, nil, syncTrigger)

	res, err := h.OnAction(context.Background(), syncAction("01HSYNCNOVERIFIER"))
	require.NoError(t, err)
	assert.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS, res.Status)
	assert.Len(t, syncTrigger, 1)
}
