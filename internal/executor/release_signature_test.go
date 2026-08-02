package executor

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"
)

func testReleaseSigningKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate release signing key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatalf("marshal release public key: %v", err)
	}
	previous := releaseSigningPublicKey
	releaseSigningPublicKey = base64.StdEncoding.EncodeToString(der)
	t.Cleanup(func() { releaseSigningPublicKey = previous })
	return private
}

func TestVerifyReleaseManifestRejectsAnythingButTheConfiguredSigner(t *testing.T) {
	private := testReleaseSigningKey(t)
	manifest := []byte("abc  power-manage-agent-linux-amd64\n")
	signature := ed25519.Sign(private, manifest)

	if err := verifyReleaseManifest(manifest, signature); err != nil {
		t.Fatalf("valid release manifest rejected: %v", err)
	}
	tampered := append([]byte(nil), manifest...)
	tampered[0] ^= 1
	if err := verifyReleaseManifest(tampered, signature); err == nil {
		t.Fatal("tampered release manifest accepted")
	}
	_, otherPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate other release signing key: %v", err)
	}
	wrongSignature := ed25519.Sign(otherPrivate, manifest)
	if err := verifyReleaseManifest(manifest, wrongSignature); err == nil {
		t.Fatal("signature from the wrong bytes accepted")
	}
}

func TestVerifyReleaseManifestFailsClosedWithoutAProductionKey(t *testing.T) {
	previous := releaseSigningPublicKey
	releaseSigningPublicKey = "__RELEASE_SIGNING_PUBLIC_KEY__"
	t.Cleanup(func() { releaseSigningPublicKey = previous })

	if err := verifyReleaseManifest([]byte("manifest"), make([]byte, ed25519.SignatureSize)); err == nil {
		t.Fatal("placeholder release key accepted")
	}
}

func TestReleaseSignatureURLPreservesSignedQuery(t *testing.T) {
	got, err := releaseSignatureURL("https://releases.example/SHA256SUMS?token=signed")
	if err != nil {
		t.Fatalf("derive signature URL: %v", err)
	}
	want := "https://releases.example/SHA256SUMS.sig?token=signed"
	if got != want {
		t.Fatalf("signature URL = %q, want %q", got, want)
	}
}
