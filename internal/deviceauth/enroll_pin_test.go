package deviceauth

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
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pm "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"

	"github.com/manchtools/power-manage/agent/internal/credentials"
	pmcrypto "github.com/manchtools/power-manage/sdk/go/crypto"
)

const fakeLeafPEM = "-----BEGIN CERTIFICATE-----\nleaf\n-----END CERTIFICATE-----\n"

// genTestCAPEM creates a self-signed CA certificate (PEM) for pin tests.
func genTestCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func caReturningMock(caPEM []byte) *mockRegisterService {
	return &mockRegisterService{
		registerFunc: func(_ context.Context, _ *connect.Request[pm.RegisterRequest]) (*connect.Response[pm.RegisterResponse], error) {
			return connect.NewResponse(&pm.RegisterResponse{
				DeviceId:    &pm.DeviceId{Value: "01HZZZZZZZZZZZZZZZZZZZZZZZZ"},
				CaCert:      caPEM,
				Certificate: []byte(fakeLeafPEM),
				GatewayUrl:  "https://gw.example.com:8443",
			}), nil
		},
	}
}

// TestEnroll_CAPinMatchAccepted pins the optional OOB CA-pin happy path
// (#5): when the returned CA matches the pin, enrollment proceeds.
func TestEnroll_CAPinMatchAccepted(t *testing.T) {
	caPEM := genTestCAPEM(t)
	wantFP, err := pmcrypto.CAFingerprintFromPEM(caPEM)
	require.NoError(t, err)

	srv := startMockControlServer(t, caReturningMock(caPEM))
	credStore := credentials.NewStore(t.TempDir())
	h := NewEnrollHandler("test-host", "dev", credStore, slog.Default(), nil)
	h.registerOpts = trustServer(srv)

	resp, err := h.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{
		ServerUrl:        srv.URL,
		Token:            "tok",
		CaFingerprintPin: wantFP,
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Success, "matching pin must enroll: %s", resp.Msg.Error)
	assert.True(t, credStore.Exists())
}

// TestEnroll_CAPinMatchNormalized pins case-insensitive + colon-stripped
// matching (operators paste from openssl: uppercase, colon-separated).
func TestEnroll_CAPinMatchNormalized(t *testing.T) {
	caPEM := genTestCAPEM(t)
	fp, err := pmcrypto.CAFingerprintFromPEM(caPEM)
	require.NoError(t, err)

	// Uppercase + colon-separated, as openssl prints it.
	var b strings.Builder
	up := strings.ToUpper(fp)
	for i := 0; i < len(up); i += 2 {
		if i > 0 {
			b.WriteByte(':')
		}
		b.WriteString(up[i : i+2])
	}
	pinPasted := b.String()

	srv := startMockControlServer(t, caReturningMock(caPEM))
	credStore := credentials.NewStore(t.TempDir())
	h := NewEnrollHandler("test-host", "dev", credStore, slog.Default(), nil)
	h.registerOpts = trustServer(srv)

	resp, err := h.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{
		ServerUrl:        srv.URL,
		Token:            "tok",
		CaFingerprintPin: pinPasted,
	}))
	require.NoError(t, err)
	assert.True(t, resp.Msg.Success, "normalized (uppercase, colon) pin must match: %s", resp.Msg.Error)
}

// TestEnroll_CAPinMismatchRejected pins fail-closed on a wrong pin (#5):
// no Save, no callback, no status — the trust-anchor swap is refused.
func TestEnroll_CAPinMismatchRejected(t *testing.T) {
	caPEM := genTestCAPEM(t)
	srv := startMockControlServer(t, caReturningMock(caPEM))

	credStore := credentials.NewStore(t.TempDir())
	called := false
	h := NewEnrollHandler("test-host", "dev", credStore, slog.Default(), func(*credentials.Credentials) { called = true })
	h.registerOpts = trustServer(srv)

	resp, err := h.Enroll(context.Background(), connect.NewRequest(&pm.EnrollRequest{
		ServerUrl:        srv.URL,
		Token:            "tok",
		CaFingerprintPin: strings.Repeat("0", 64), // wrong pin
	}))
	require.NoError(t, err)
	assert.False(t, resp.Msg.Success)
	assert.Contains(t, resp.Msg.Error, "fingerprint mismatch")
	assert.False(t, credStore.Exists(), "no credentials on a pin mismatch")
	assert.False(t, called, "onEnrolled must not fire on a pin mismatch")

	// Status cache must not be primed.
	st, err := h.GetEnrollmentStatus(context.Background(), connect.NewRequest(&pm.GetEnrollmentStatusRequest{}))
	require.NoError(t, err)
	assert.False(t, st.Msg.Enrolled)
}
