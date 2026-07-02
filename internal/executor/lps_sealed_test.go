package executor

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	sdkcrypto "github.com/manchtools/power-manage-sdk/crypto"
	"github.com/manchtools/power-manage-sdk/cryptotest"
	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	sysuser "github.com/manchtools/power-manage-sdk/sys/user"
	"github.com/manchtools/power-manage-sdk/verify"

	"github.com/manchtools/power-manage/agent/internal/store"
)

// newVerifierExecutor builds an executor with a real CA verifier + store, and
// returns the matching signer so a test can mint signed keys.
func newVerifierExecutor(t *testing.T) (*Executor, *verify.ActionSigner) {
	t.Helper()
	certPEM, caKey, _ := cryptotest.GenCA(t, "Test CA")
	verifier, err := verify.NewActionVerifier(certPEM)
	if err != nil {
		t.Fatalf("verifier: %v", err)
	}
	e := NewExecutor(verifier, nil)
	s, err := store.New(t.TempDir())
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	e.SetStore(s)
	e.SetDeviceID("01HKDEVICE0000000000000000")
	return e, verify.NewActionSigner(caKey)
}

// Criterion 13: a validly CA-signed key verifies, persists, and is loadable.
func TestApplyLpsPublicKey_VerifiesAndPersists(t *testing.T) {
	e, signer := newVerifierExecutor(t)
	priv, err := sdkcrypto.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	msg := &pb.LpsPublicKey{PublicKey: priv.PublicKey().Bytes()}
	canonical, _ := verify.LpsPublicKeyCanonical(msg)
	sig, _ := signer.SignDomain(verify.LpsPublicKeySignatureDomain, canonical)
	msg.Signature = sig

	if err := e.ApplyLpsPublicKey(msg); err != nil {
		t.Fatalf("ApplyLpsPublicKey(valid): %v", err)
	}
	loaded, err := e.lpsPublicKey()
	if err != nil {
		t.Fatalf("lpsPublicKey after apply: %v", err)
	}
	if !loaded.Equal(priv.PublicKey()) {
		t.Error("loaded key does not match the applied key")
	}
}

// Criterion 14: a key whose signature does not verify is refused, and any
// previously-stored key is kept — a hostile gateway cannot swap the key.
func TestApplyLpsPublicKey_RejectsBadSignatureKeepsPrior(t *testing.T) {
	e, signer := newVerifierExecutor(t)

	// Store a good key first.
	goodPriv, err := sdkcrypto.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	good := &pb.LpsPublicKey{PublicKey: goodPriv.PublicKey().Bytes()}
	gc, _ := verify.LpsPublicKeyCanonical(good)
	gsig, _ := signer.SignDomain(verify.LpsPublicKeySignatureDomain, gc)
	good.Signature = gsig
	if err := e.ApplyLpsPublicKey(good); err != nil {
		t.Fatalf("apply good: %v", err)
	}

	// A different key with a forged/mismatched signature.
	evilPriv, _ := sdkcrypto.GenerateX25519()
	evil := &pb.LpsPublicKey{PublicKey: evilPriv.PublicKey().Bytes(), Signature: gsig}
	if err := e.ApplyLpsPublicKey(evil); err == nil {
		t.Fatal("ApplyLpsPublicKey accepted a key with a mismatched signature")
	}

	// The good key must still be the stored one.
	loaded, err := e.lpsPublicKey()
	if err != nil {
		t.Fatalf("lpsPublicKey: %v", err)
	}
	if !loaded.Equal(goodPriv.PublicKey()) {
		t.Error("a rejected key overwrote the previously-verified key")
	}
}

// A nil verifier must fail closed rather than trust an unverifiable key.
func TestApplyLpsPublicKey_NilVerifierFailsClosed(t *testing.T) {
	e := NewExecutor(nil, nil)
	s, _ := store.New(t.TempDir())
	e.SetStore(s)
	if err := e.ApplyLpsPublicKey(&pb.LpsPublicKey{PublicKey: make([]byte, 32), Signature: []byte("x")}); err == nil {
		t.Fatal("nil verifier accepted a key")
	}
	// nil message is a no-op (server without a keypair).
	if err := e.ApplyLpsPublicKey(nil); err != nil {
		t.Errorf("nil message should be a no-op, got %v", err)
	}
}

// fakeLpsUser is a userMgr fake for the rotation path: it reports the target
// user as existing and records SetPassword plaintext, without touching the
// host. Every unlisted method panics via the embedded nil interface.
type fakeLpsUser struct {
	sysuser.Manager
	setCalls []string // revealed plaintexts, in call order
}

func (f *fakeLpsUser) Exists(context.Context, string) (bool, error) { return true, nil }
func (f *fakeLpsUser) SetPassword(_ context.Context, _ string, pw sysexec.Secret) error {
	f.setCalls = append(f.setCalls, pw.Reveal())
	return nil
}
func (f *fakeLpsUser) KillSessions(context.Context, string) error { return nil }

// Criterion 15 + 17 (ordering): with no stored key the LPS action fails BEFORE
// any SetPassword — sealing is a precondition to rotating. The fake panics if
// SetPassword is ever reached, proving no account is touched.
func TestExecuteLps_NoKeyFailsClosedBeforeRotation(t *testing.T) {
	e := NewExecutor(nil, nil)
	s, _ := store.New(t.TempDir())
	e.SetStore(s)
	e.SetDeviceID("01HKDEVICE0000000000000000")

	prev := userMgr
	t.Cleanup(func() { userMgr = prev })
	userMgr = &fakeLpsUser{} // its SetPassword records; must never be called here

	_, _, _, err := e.executeLps(context.Background(), &pb.LpsParams{
		Usernames:            []string{"alice"},
		PasswordLength:       20,
		RotationIntervalDays: 30,
	}, pb.DesiredState_DESIRED_STATE_PRESENT, "01HKACTION0000000000000000")
	if err == nil {
		t.Fatal("executeLps without a stored control key must fail")
	}
	if !strings.Contains(err.Error(), "control public key") {
		t.Errorf("expected a control-public-key error, got: %v", err)
	}
	if fu := userMgr.(*fakeLpsUser); len(fu.setCalls) != 0 {
		t.Errorf("SetPassword was called %d times despite no seal key — must not rotate", len(fu.setCalls))
	}
}

// Criterion 16 + 17: a rotation seals the password (metadata carries
// sealed_password, never cleartext) and the sealed blob unseals to exactly the
// password that was set — proving seal-before-set and no cleartext leak.
func TestExecuteLps_SealsRotatedPassword(t *testing.T) {
	e, _ := newVerifierExecutor(t) // verifier unused here; gives us a store + device id
	const deviceID, actionID, username = "01HKDEVICE0000000000000000", "01HKACTION0000000000000000", "alice"

	// Persist a control key the test owns the private half of.
	priv, err := sdkcrypto.GenerateX25519()
	if err != nil {
		t.Fatal(err)
	}
	if err := e.getStore().SetSetting(lpsPublicKeySettingKey, string(priv.PublicKey().Bytes())); err != nil {
		t.Fatal(err)
	}

	fake := &fakeLpsUser{}
	prevUser, prevNotify := userMgr, notifyUsers
	t.Cleanup(func() { userMgr = prevUser; notifyUsers = prevNotify })
	userMgr = fake
	notifyUsers = func(context.Context, []string, string, string) {} // no host notify

	// Cancel the ctx so the 60s post-rotation grace returns immediately.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, changed, metadata, err := e.executeLps(ctx, &pb.LpsParams{
		Usernames:            []string{username},
		PasswordLength:       20,
		RotationIntervalDays: 30,
	}, pb.DesiredState_DESIRED_STATE_PRESENT, actionID)
	if err != nil {
		t.Fatalf("executeLps: %v", err)
	}
	if !changed || metadata["lps.rotations"] == "" {
		t.Fatalf("expected a rotation with metadata, changed=%v meta=%q", changed, metadata["lps.rotations"])
	}
	if len(fake.setCalls) != 1 {
		t.Fatalf("expected exactly one SetPassword, got %d", len(fake.setCalls))
	}

	// The metadata must carry a sealed_password (never a cleartext password),
	// and it must unseal to the exact secret that was set on the account.
	if strings.Contains(metadata["lps.rotations"], "\"password\"") {
		t.Error("metadata contains a cleartext password field")
	}
	var entries []struct {
		Username       string `json:"username"`
		SealedPassword string `json:"sealed_password"`
	}
	if err := json.Unmarshal([]byte(metadata["lps.rotations"]), &entries); err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].SealedPassword == "" {
		t.Fatalf("expected one sealed entry, got %+v", entries)
	}
	sealed, err := base64.StdEncoding.DecodeString(entries[0].SealedPassword)
	if err != nil {
		t.Fatal(err)
	}
	opened, err := sdkcrypto.OpenLpsPassword(priv, sealed, deviceID, actionID, username)
	if err != nil {
		t.Fatalf("sealed metadata did not unseal: %v", err)
	}
	if opened != fake.setCalls[0] {
		t.Error("sealed password does not match the password set on the account")
	}
}
