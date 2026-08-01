package executor

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	sysenc "github.com/manchtools/power-manage-sdk/sys/encryption"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage/agent/internal/store"
)

// CHARTER — LUKS passphrase custody (AGENT side).
//
//   - The passphrase control receives is EXACTLY the one added to the volume.
//   - Without a route to control the store path fails closed BEFORE any LUKS
//     mutation — no half-owned volume, no slot holding a passphrase nobody can
//     recover.
//
// Spec 41 removed the seal these tests were originally written around (the
// passphrase was encrypted to a control public key so a relaying gateway could
// not read it). The relay is gone and the agent holds a direct mTLS session
// with control, so the confidentiality boundary the seal drew no longer has an
// untrusted party on the far side. What has NOT changed is custody: a volume
// must never end up with a passphrase control did not receive, and that is what
// these tests still pin.

// fakeSealEncManager stubs the encryption Manager for the seal tests: AddKey
// and RemoveKey are recorded no-ops, VerifyPassphrase always matches. Every
// un-overridden method nil-panics via the embedded interface.
type fakeSealEncManager struct {
	sysenc.Manager
	addKeyCalls    int
	removeKeyCalls int
	// onAddKey observes the NEW key handed to AddKey, so a test can compare it
	// against what reached the key store.
	onAddKey func(newKey sysexec.Secret)
}

func (f *fakeSealEncManager) AddKey(_ context.Context, _ string, _, newKey sysexec.Secret, _ sysenc.AddKeyOptions) error {
	f.addKeyCalls++
	if f.onAddKey != nil {
		f.onAddKey(newKey)
	}
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

// The custody property: the passphrase control is given is the same one the
// volume now accepts, and it is stored BEFORE the PSK is removed — so a store
// failure can never strand a volume whose only remaining key is unknown to the
// server.
func TestTakeOwnership_StoresTheSamePassphraseItAddsToTheVolume(t *testing.T) {
	const (
		actionID = "01HXSTORE00000000000000000"
		deviceID = "01HXDEVICE0000000000000000"
	)

	st, err := store.New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	fakeEnc := &fakeSealEncManager{}
	swapEncMgr(t, fakeEnc)

	var stored string
	var storedAtRemoveCount int
	var addedPassphrase string
	fakeEnc.onAddKey = func(newKey sysexec.Secret) { addedPassphrase = newKey.Reveal() }

	ks := &fakeLuksKeyStore{
		getKeyFunc: func(_ context.Context, _ string) (string, error) {
			if stored == "" {
				return "", nil // no server-side key yet → PSK ownership path
			}
			return stored, nil
		},
		storeKeyFunc: func(_ context.Context, gotAction, _, passphrase string, _ pb.RotationReason) error {
			assert.Equal(t, actionID, gotAction, "the key must be stored under the action that generated it")
			stored = passphrase
			storedAtRemoveCount = fakeEnc.removeKeyCalls
			return nil
		},
	}

	e := &Executor{logger: slog.Default(), now: time.Now}
	e.SetStore(st)
	e.SetDeviceID(deviceID)
	e.SetLuksKeyStore(ks)

	params := &pb.EncryptionParams{PresharedKey: "psk-value", MinWords: 3}
	require.NoError(t, e.takeOwnership(context.Background(), params, actionID, "/dev/mapper/test"))

	require.NotEmpty(t, stored, "StoreKey must have been called with the managed passphrase")
	require.NotEmpty(t, addedPassphrase, "AddKey must have been called")
	assert.Equal(t, addedPassphrase, stored,
		"control holds a different passphrase than the one in the LUKS slot — the volume would be unrecoverable")
	assert.NotEqual(t, "psk-value", stored, "the PSK must not be what gets stored as the managed key")
	assert.Zero(t, storedAtRemoveCount,
		"the passphrase must reach control BEFORE the PSK slot is removed")
}

// Without a device identity nothing is stored AND nothing is mutated — the gate
// fires before AddKey, so no half-owned volume is left. Same gate as before;
// only its precondition changed, from "a verified control key exists" to "the
// store could actually succeed".
func TestTakeOwnership_NoDeviceID_FailsClosedBeforeMutation(t *testing.T) {
	st, err := store.New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	fakeEnc := &fakeSealEncManager{}
	swapEncMgr(t, fakeEnc)

	ks := &fakeLuksKeyStore{}
	e := &Executor{logger: slog.Default(), now: time.Now}
	e.SetStore(st)
	e.SetLuksKeyStore(ks)
	// No device ID set.

	params := &pb.EncryptionParams{PresharedKey: "psk-value", MinWords: 3}
	err = e.takeOwnership(context.Background(), params, "01HXNOKEY00000000000000000", "/dev/mapper/test")
	require.Error(t, err, "no device identity → fail closed")
	assert.Zero(t, ks.storeKeyCalls, "nothing may be sent that cannot be attributed to a device")
	assert.Zero(t, fakeEnc.addKeyCalls, "no LUKS mutation may happen when the store is doomed")
}

// The disconnected case, which is the one that actually happens in the field:
// no key store wired means no route to control.
func TestTakeOwnership_NotConnected_FailsClosedBeforeMutation(t *testing.T) {
	st, err := store.New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	fakeEnc := &fakeSealEncManager{}
	swapEncMgr(t, fakeEnc)

	e := &Executor{logger: slog.Default(), now: time.Now}
	e.SetStore(st)
	e.SetDeviceID("01HXDEVICE0000000000000000")
	// No key store wired: the agent is not connected.

	params := &pb.EncryptionParams{PresharedKey: "psk-value", MinWords: 3}
	err = e.takeOwnership(context.Background(), params, "01HXNOCONN0000000000000000", "/dev/mapper/test")
	require.Error(t, err, "not connected → fail closed")
	assert.Zero(t, fakeEnc.addKeyCalls,
		"a volume must not be taken over while the passphrase cannot be reported")
}

// The rotation counterpart: a due rotation that cannot be reported must not add
// a slot.
func TestCheckAndRotate_NoDeviceID_FailsClosedBeforeMutation(t *testing.T) {
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
	e.SetLuksKeyStore(ks)
	// No device ID set.

	// Rotation due: last rotated far beyond the interval.
	localState := &store.LuksState{
		DevicePath:    "/dev/mapper/test",
		LastRotatedAt: time.Now().Add(-90 * 24 * time.Hour),
	}
	params := &pb.EncryptionParams{RotationIntervalDays: 30, MinWords: 3}

	changed, err := e.checkAndRotate(context.Background(), params, localState, "01HXROTNOKEY00000000000000", "/dev/mapper/test")
	require.Error(t, err)
	assert.False(t, changed)
	assert.Zero(t, ks.storeKeyCalls)
	assert.Zero(t, fakeEnc.addKeyCalls, "no new slot may be added when the store is doomed")
}
