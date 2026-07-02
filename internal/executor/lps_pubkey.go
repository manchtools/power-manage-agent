package executor

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	sdkcrypto "github.com/manchtools/power-manage-sdk/crypto"
	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/verify"
)

// lpsPublicKeySettingKey is the agent-store settings key holding the raw
// 32-byte control LPS public key, persisted ONLY after its CA signature is
// verified (ApplyLpsPublicKey). The seal path (lps.go) reads it back here.
// Persisting across restarts means LPS rotation keeps working between syncs.
const lpsPublicKeySettingKey = "lps_public_key"

// ApplyLpsPublicKey verifies the control server's LPS sealing key against the
// agent's enrollment CA and, on success, persists the raw public key so the
// LPS executor can seal to it. Fail-closed:
//
//   - a nil message (control has no keypair configured) is a no-op that keeps
//     any previously-verified key — sealing later fails closed if none exists;
//   - a nil verifier (misconfiguration) or a signature that does not verify
//     leaves the stored key untouched and returns an error, so a relaying
//     gateway cannot swap in a key the agent would seal readable passwords to.
func (e *Executor) ApplyLpsPublicKey(signed *pb.LpsPublicKey) error {
	if signed == nil {
		return nil
	}
	if e.verifier == nil {
		return errors.New("lps public key: no verifier configured; refusing to trust key")
	}
	canonical, err := verify.LpsPublicKeyCanonical(signed)
	if err != nil {
		return fmt.Errorf("canonicalize lps public key: %w", err)
	}
	if err := e.verifier.VerifyDomain(verify.LpsPublicKeySignatureDomain, canonical, signed.GetSignature()); err != nil {
		return fmt.Errorf("verify lps public key signature: %w", err)
	}
	// Validate the key parses as X25519 before persisting, so the seal path
	// never loads a stored-but-unusable key.
	if _, err := sdkcrypto.ParseX25519PublicKey(signed.GetPublicKey()); err != nil {
		return fmt.Errorf("parse lps public key: %w", err)
	}
	st := e.getStore()
	if st == nil {
		return errors.New("lps public key: agent store not configured")
	}
	if err := st.SetSetting(lpsPublicKeySettingKey, string(signed.GetPublicKey())); err != nil {
		return fmt.Errorf("persist lps public key: %w", err)
	}
	return nil
}

// lpsPublicKey loads and parses the persisted control LPS public key. Returns
// an error if none has been verified/stored yet — the LPS seal path treats
// that as fail-closed (no rotation without a key to seal to).
func (e *Executor) lpsPublicKey() (*ecdh.PublicKey, error) {
	st := e.getStore()
	if st == nil {
		return nil, errors.New("agent store not configured")
	}
	raw, err := st.GetSetting(lpsPublicKeySettingKey)
	if err != nil {
		return nil, fmt.Errorf("load lps public key: %w", err)
	}
	if raw == "" {
		return nil, errors.New("no control LPS public key stored; sync with the server first")
	}
	return sdkcrypto.ParseX25519PublicKey([]byte(raw))
}

// sealedUserCreateMetadata builds the lps.rotations metadata for a freshly
// created user's temporary password, sealed to the control LPS public key so
// the operator can retrieve it — without the gateway ever seeing cleartext.
// Returns nil (and logs to output) if no key is available or sealing fails:
// the user was still created, we simply do not report the password rather than
// leak it. Shares the seal path with LPS rotation (spec 18).
func (e *Executor) sealedUserCreateMetadata(username, actionID, plaintext string, output *strings.Builder) map[string]string {
	pub, err := e.lpsPublicKey()
	if err != nil {
		e.logger.Warn("user create: no control LPS public key; temp password not reported", "username", username, "error", err)
		output.WriteString("warning: temporary password not reported (no control LPS key; reset out of band)\n")
		return nil
	}
	deviceID := e.getDeviceID()
	if deviceID == "" {
		e.logger.Warn("user create: no device ID; temp password not reported", "username", username)
		return nil
	}
	sealed, err := sdkcrypto.SealLpsPassword(pub, plaintext, deviceID, actionID, username)
	if err != nil {
		e.logger.Warn("user create: failed to seal temp password; not reported", "username", username, "error", err)
		output.WriteString("warning: temporary password not reported (seal failed; reset out of band)\n")
		return nil
	}
	rotations := []lpsRotationEntry{{
		Username:       username,
		SealedPassword: base64.StdEncoding.EncodeToString(sealed),
		RotatedAt:      e.now().UTC().Format(time.RFC3339),
		Reason:         "user_created",
	}}
	rotationsJSON, err := json.Marshal(rotations)
	if err != nil {
		e.logger.Warn("user create: failed to marshal sealed rotation; not reported", "username", username, "error", err)
		return nil
	}
	return map[string]string{"lps.rotations": string(rotationsJSON)}
}
