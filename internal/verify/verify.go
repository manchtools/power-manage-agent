// Package verify provides action signature verification for the agent.
package verify

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

// ActionVerifier verifies action signatures using the CA's public key.
type ActionVerifier struct {
	pubKey crypto.PublicKey
}

// NewActionVerifier creates a new action verifier from a PEM-encoded CA certificate.
func NewActionVerifier(caCertPEM []byte) (*ActionVerifier, error) {
	block, _ := pem.Decode(caCertPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode CA certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse CA certificate: %w", err)
	}

	return &ActionVerifier{pubKey: cert.PublicKey}, nil
}

// Verify checks the signature of an action payload.
// The canonical format is: "actionID:actionType:base64(paramsJSON)"
func (v *ActionVerifier) Verify(actionID string, actionType int32, paramsJSON, signature []byte) error {
	if len(signature) == 0 {
		return fmt.Errorf("no signature provided for action %s", actionID)
	}

	canonical := fmt.Sprintf("%s:%d:%s", actionID, actionType,
		base64.StdEncoding.EncodeToString(paramsJSON))
	hash := sha256.Sum256([]byte(canonical))

	switch key := v.pubKey.(type) {
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, hash[:], signature) {
			return fmt.Errorf("invalid ECDSA signature for action %s", actionID)
		}
		return nil
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, hash[:], signature); err != nil {
			return fmt.Errorf("invalid RSA signature for action %s: %w", actionID, err)
		}
		return nil
	default:
		return fmt.Errorf("unsupported public key type: %T", v.pubKey)
	}
}
