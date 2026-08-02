package executor

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// releaseSigningPublicKey is a base64-encoded PKIX Ed25519 public key injected
// by the protected release workflow. A normal development build deliberately
// cannot trust checksum_url; control-pinned expected_sha256 updates still work.
var releaseSigningPublicKey = "__RELEASE_SIGNING_PUBLIC_KEY__"

func verifyReleaseManifest(manifest, signature []byte) error {
	encoded := strings.TrimSpace(releaseSigningPublicKey)
	if encoded == "" || encoded == "__RELEASE_SIGNING_PUBLIC_KEY__" {
		return errors.New("release signing public key is not configured")
	}
	der, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return errors.New("release signing public key is invalid")
	}
	parsed, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return errors.New("release signing public key is invalid")
	}
	publicKey, ok := parsed.(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return errors.New("release signing key is not Ed25519")
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, manifest, signature) {
		return errors.New("release manifest signature is invalid")
	}
	return nil
}

func releaseSignatureURL(manifestURL string) (string, error) {
	parsed, err := url.Parse(manifestURL)
	if err != nil || parsed.Path == "" {
		return "", fmt.Errorf("invalid release manifest URL")
	}
	parsed.Path += ".sig"
	parsed.RawPath = ""
	return parsed.String(), nil
}
