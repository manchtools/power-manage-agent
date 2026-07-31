package executor

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/agent/internal/store"
)

// fakeLuksKeyStore is a recording LuksKeyStore for custody tests.
type fakeLuksKeyStore struct {
	getKeyFunc   func(ctx context.Context, actionID string) (string, error)
	storeKeyFunc func(ctx context.Context, actionID, devicePath, passphrase string, reason pb.RotationReason) error

	getKeyCalls   int
	storeKeyCalls int
}

func (f *fakeLuksKeyStore) GetKey(ctx context.Context, actionID string) (string, error) {
	f.getKeyCalls++
	if f.getKeyFunc != nil {
		return f.getKeyFunc(ctx, actionID)
	}
	return "", nil
}

func (f *fakeLuksKeyStore) StoreKey(ctx context.Context, actionID, devicePath, passphrase string, reason pb.RotationReason) error {
	f.storeKeyCalls++
	if f.storeKeyFunc != nil {
		return f.storeKeyFunc(ctx, actionID, devicePath, passphrase, reason)
	}
	return nil
}

// WS6 #13: setupLuks read local state with `localState, _ :=`, swallowing
// the error. A read failure (anything other than "no rows") would then be
// mistaken for "first run", causing the agent to re-take ownership / add
// keys against a volume it may already manage — exactly the destructive
// outcome the state row exists to prevent. setupLuks must fail closed.
//
// Driven via a CLOSED store so GetLuksState returns a real non-ErrNoRows
// error; the test asserts setupLuks propagates it rather than proceeding
// to volume detection / ownership.
func TestSetupLuks_GetLuksStateError_FailsClosed(t *testing.T) {
	st, err := store.New(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, st.Close()) // subsequent queries error (not ErrNoRows)

	e := &Executor{logger: slog.Default(), now: time.Now}
	e.SetStore(st)
	e.SetLuksKeyStore(&fakeLuksKeyStore{})

	params := &pb.EncryptionParams{PresharedKey: "psk", MinWords: 5}
	_, _, _, err = e.setupLuks(context.Background(), params, "01HXFAILCLOSED000000000000")
	require.Error(t, err, "setupLuks must fail closed on a state-read error")
	assert.Contains(t, err.Error(), "luks state",
		"the error must be the state read failing closed, not a downstream volume-detection error")
}

// WS6 #3 (lockout safety): when the server is unreachable, takeOwnership
// must NOT proceed to manage keys — the PSK may already have been consumed
// by a prior run and StoreKey will also fail, so adding/removing slots
// risks locking the volume out. It must return an error before any key
// management (no StoreKey).
func TestTakeOwnership_FailsClosedWhenServerUnreachable(t *testing.T) {
	st, err := store.New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	ks := &fakeLuksKeyStore{
		getKeyFunc: func(ctx context.Context, actionID string) (string, error) {
			return "", errors.New("connection refused")
		},
	}
	e := &Executor{logger: slog.Default(), now: time.Now}
	e.SetStore(st)
	e.SetLuksKeyStore(ks)

	params := &pb.EncryptionParams{PresharedKey: "psk", MinWords: 5}
	err = e.takeOwnership(context.Background(), params, "01HXUNREACH0000000000000000", "/dev/mapper/test")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not reachable")
	assert.Equal(t, 1, ks.getKeyCalls, "GetKey is attempted once")
	assert.Equal(t, 0, ks.storeKeyCalls, "no key is stored when the server is unreachable (fail closed)")
}
