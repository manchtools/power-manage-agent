package executor

import (
	"bytes"
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkcrypto "github.com/manchtools/power-manage-sdk/crypto"
	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysenc "github.com/manchtools/power-manage-sdk/sys/encryption"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage/agent/internal/store"
)

// CHARTER — sealed LUKS passphrase transport (spec 25, AGENT side).
//
//   - The managed passphrase is sealed to the verified control public key
//     BEFORE it leaves the executor; the key store (and everything past it)
//     only ever sees opaque sealed bytes.
//   - Without a verified control key the store path fails closed BEFORE any
//     LUKS mutation — no cleartext fallback, no half-rotated volume.

// fakeSealEncManager stubs the encryption Manager for the seal tests: AddKey
// and RemoveKey are recorded no-ops, VerifyPassphrase always matches. Every
// un-overridden method nil-panics via the embedded interface.
type fakeSealEncManager struct {
	sysenc.Manager
	addKeyCalls    int
	removeKeyCalls int
}

func (f *fakeSealEncManager) AddKey(_ context.Context, _ string, _, _ sysexec.Secret, _ sysenc.AddKeyOptions) error {
	f.addKeyCalls++
	return nil
}

func (f *fakeSealEncManager) RemoveKey(_ context.Context, _ string, _ sysexec.Secret) error {
	f.removeKeyCalls++
	return nil
}

func (f *fakeSealEncManager) VerifyPassphrase(_ context.Context, _ string, _ sysexec.Secret) (bool, error) {
	return true, nil
}

// swapEncMgr installs a fake encryption manager for the test's duration.
func swapEncMgr(t *testing.T, m sysenc.Manager) {
	t.Helper()
	old := encMgr
	encMgr = m
	t.Cleanup(func() { encMgr = old })
}

// TestTakeOwnership_SealsPassphraseToControlKey pins spec 25 AC 1: the
// passphrase that reaches the key store is a sealed blob the control private
// key opens under the (device, action) context — and it never contains the
// cleartext.
func TestTakeOwnership_SealsPassphraseToControlKey(t *testing.T) {
	const (
		actionID = "01HXSEAL000000000000000000"
		deviceID = "01HXDEVICE0000000000000000"
	)

	priv, err := sdkcrypto.GenerateX25519()
	require.NoError(t, err)

	st, err := store.New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()
	require.NoError(t, st.SetSetting(lpsPublicKeySettingKey, string(priv.PublicKey().Bytes())))

	fakeEnc := &fakeSealEncManager{}
	swapEncMgr(t, fakeEnc)

	var captured []byte
	ks := &fakeLuksKeyStore{
		getKeyFunc: func(_ context.Context, aID string) (string, error) {
			if captured == nil {
				return "", nil // no server-side key yet → PSK ownership path
			}
			// Simulated server: unseal like ProxyStoreLuksKey would.
			return sdkcrypto.OpenLuksPassphrase(priv, captured, deviceID, aID)
		},
		storeKeyFunc: func(_ context.Context, _, _ string, sealed []byte, _ pb.RotationReason) error {
			captured = append([]byte(nil), sealed...)
			return nil
		},
	}

	e := &Executor{logger: slog.Default(), now: time.Now}
	e.SetStore(st)
	e.SetDeviceID(deviceID)
	e.SetLuksKeyStore(ks)

	params := &pb.EncryptionParams{PresharedKey: "psk-value", MinWords: 3}
	require.NoError(t, e.takeOwnership(context.Background(), params, actionID, "/dev/mapper/test"))

	require.NotNil(t, captured, "StoreKey must have been called with sealed bytes")
	assert.GreaterOrEqual(t, len(captured), sdkcrypto.MinSealedLen)

	plaintext, err := sdkcrypto.OpenLuksPassphrase(priv, captured, deviceID, actionID)
	require.NoError(t, err, "control private key must open the agent-sealed blob under the device|action context")
	assert.NotEmpty(t, plaintext)
	assert.NotContains(t, string(captured), plaintext, "sealed blob must not embed the cleartext passphrase")
	assert.False(t, bytes.Contains(captured, []byte(plaintext)))
}

// TestTakeOwnership_NoControlKey_FailsClosedBeforeMutation pins spec 25 AC 5:
// without a verified control public key nothing is stored AND nothing is
// mutated — the gate fires before AddKey, so no half-owned volume is left.
func TestTakeOwnership_NoControlKey_FailsClosedBeforeMutation(t *testing.T) {
	st, err := store.New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()
	// No lps_public_key setting stored.

	fakeEnc := &fakeSealEncManager{}
	swapEncMgr(t, fakeEnc)

	ks := &fakeLuksKeyStore{}
	e := &Executor{logger: slog.Default(), now: time.Now}
	e.SetStore(st)
	e.SetDeviceID("01HXDEVICE0000000000000000")
	e.SetLuksKeyStore(ks)

	params := &pb.EncryptionParams{PresharedKey: "psk-value", MinWords: 3}
	err = e.takeOwnership(context.Background(), params, "01HXNOKEY00000000000000000", "/dev/mapper/test")
	require.Error(t, err, "no verified control key → fail closed, no cleartext fallback")
	assert.Contains(t, err.Error(), "control")
	assert.Zero(t, ks.storeKeyCalls, "nothing may be sent without a key to seal to")
	assert.Zero(t, fakeEnc.addKeyCalls, "no LUKS mutation may happen when the store is doomed")
}

// TestCheckAndRotate_NoControlKey_FailsClosedBeforeMutation is the rotation
// counterpart: a due rotation without a control key must not add a slot.
func TestCheckAndRotate_NoControlKey_FailsClosedBeforeMutation(t *testing.T) {
	st, err := store.New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	fakeEnc := &fakeSealEncManager{}
	swapEncMgr(t, fakeEnc)

	ks := &fakeLuksKeyStore{
		getKeyFunc: func(_ context.Context, _ string) (string, error) {
			return "current-key", nil
		},
	}
	e := &Executor{logger: slog.Default(), now: time.Now}
	e.SetStore(st)
	e.SetDeviceID("01HXDEVICE0000000000000000")
	e.SetLuksKeyStore(ks)

	// Rotation due: last rotated far beyond the interval.
	localState := &store.LuksState{
		DevicePath:    "/dev/mapper/test",
		LastRotatedAt: time.Now().Add(-90 * 24 * time.Hour),
	}
	params := &pb.EncryptionParams{RotationIntervalDays: 30, MinWords: 3}

	changed, err := e.checkAndRotate(context.Background(), params, localState, "01HXROTNOKEY00000000000000", "/dev/mapper/test")
	require.Error(t, err)
	assert.False(t, changed)
	assert.Contains(t, err.Error(), "control")
	assert.Zero(t, ks.storeKeyCalls)
	assert.Zero(t, fakeEnc.addKeyCalls, "no new slot may be added when the sealed store is doomed")
}
