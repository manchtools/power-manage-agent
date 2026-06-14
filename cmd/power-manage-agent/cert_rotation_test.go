package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/manchtools/power-manage/agent/internal/credentials"
	sdk "github.com/manchtools/power-manage/sdk/go"
)

// genCAPEM creates a self-signed CA certificate (PEM).
func genCAPEM(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("key: %v", err)
	}
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
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestRenewAt_Computation pins the 80%-of-lifetime schedule and the
// already-past clamp to a 1-minute minimum.
func TestRenewAt_Computation(t *testing.T) {
	nb := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	na := nb.Add(100 * 24 * time.Hour) // 100-day cert → renew at +80d

	if got, want := renewAt(nb, na, nb), 80*24*time.Hour; got != want {
		t.Errorf("renewAt at issuance = %v, want %v", got, want)
	}
	if got := renewAt(nb, na, nb.Add(50*24*time.Hour)); got != 30*24*time.Hour {
		t.Errorf("renewAt at +50d = %v, want 30d", got)
	}
	if got := renewAt(nb, na, nb.Add(90*24*time.Hour)); got != time.Minute {
		t.Errorf("renewAt past the renewal point = %v, want 1m clamp", got)
	}
	if got := renewAt(nb, na, na.Add(time.Hour)); got != time.Minute {
		t.Errorf("renewAt for an expired cert = %v, want 1m clamp", got)
	}
}

// TestShouldEscalateRotation pins the escalation boundary.
func TestShouldEscalateRotation(t *testing.T) {
	if shouldEscalateRotation(2, 3) {
		t.Error("2 < 3 must not escalate")
	}
	if !shouldEscalateRotation(3, 3) {
		t.Error("3 >= 3 must escalate")
	}
	if !shouldEscalateRotation(7, 3) {
		t.Error("7 >= 3 must escalate")
	}
}

// TestApplyRenewal_RefusesNonContinuousCA pins finding #4: a returned CA
// that does not chain to the enrolled CA is refused and creds is left
// untouched (old cert + CA stay on disk).
func TestApplyRenewal_RefusesNonContinuousCA(t *testing.T) {
	oldCA := genCAPEM(t)
	unrelatedCA := genCAPEM(t)
	creds := &credentials.Credentials{CACert: oldCA, Certificate: []byte("old-cert")}

	err := applyRenewal(creds, &sdk.RenewCertificateResult{
		Certificate: []byte("new-cert"),
		CACert:      unrelatedCA,
	})
	if err == nil {
		t.Fatal("expected refusal of an unrelated (non-continuous) CA")
	}
	if string(creds.Certificate) != "old-cert" || string(creds.CACert) != string(oldCA) {
		t.Error("creds were mutated on a refused renewal — must stay untouched")
	}
}

// TestApplyRenewal_AcceptsIdenticalCA — the common case: the server
// returns the same CA; the new cert is adopted.
func TestApplyRenewal_AcceptsIdenticalCA(t *testing.T) {
	oldCA := genCAPEM(t)
	creds := &credentials.Credentials{CACert: oldCA, Certificate: []byte("old-cert")}

	if err := applyRenewal(creds, &sdk.RenewCertificateResult{
		Certificate: []byte("new-cert"),
		CACert:      oldCA,
	}); err != nil {
		t.Fatalf("identical CA refused: %v", err)
	}
	if string(creds.Certificate) != "new-cert" {
		t.Error("certificate not updated on an accepted renewal")
	}
}

// TestApplyRenewal_NoCAReturned keeps the enrolled CA and still adopts
// the new cert (renewal without rotation).
func TestApplyRenewal_NoCAReturned(t *testing.T) {
	oldCA := genCAPEM(t)
	creds := &credentials.Credentials{CACert: oldCA, Certificate: []byte("old-cert")}

	if err := applyRenewal(creds, &sdk.RenewCertificateResult{Certificate: []byte("new-cert")}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(creds.CACert) != string(oldCA) {
		t.Error("CA changed when the server returned none")
	}
	if string(creds.Certificate) != "new-cert" {
		t.Error("certificate not updated")
	}
}
