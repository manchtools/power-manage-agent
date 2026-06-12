package executor

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage/agent/internal/store"
	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// reconcileDeviceKey for USER_PASSPHRASE revokes any current key and
// then leaves slot 7 for the user's CLI passphrase flow — but it must
// still persist the MODE (device_key_type="user_passphrase"). Without
// that, localState stays "none", so currentType != desiredType holds on
// every tick and the action reports changed=true forever (and never
// converges) until the user happens to run the CLI flow.
func TestReconcileDeviceKey_UserPassphrasePersistsModeAndConverges(t *testing.T) {
	st, err := store.New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	const actionID = "01HXLUKSUSERPASS0000000000"
	const devicePath = "/dev/mapper/test"
	require.NoError(t, st.SetLuksOwnershipTaken(actionID, devicePath))

	e := &Executor{logger: slog.Default(), now: time.Now}
	e.SetStore(st)

	params := &pb.EncryptionParams{
		DeviceBoundKeyType: pb.EncryptionDeviceBoundKeyType_ENCRYPTION_DEVICE_BOUND_KEY_TYPE_USER_PASSPHRASE,
	}

	// First reconcile from a fresh "none" device: a real change.
	ls, err := st.GetLuksState(actionID)
	require.NoError(t, err)
	require.Equal(t, "none", ls.DeviceKeyType)

	changed, err := e.reconcileDeviceKey(context.Background(), params, ls, actionID, devicePath)
	require.NoError(t, err)
	assert.True(t, changed, "first reconcile to user_passphrase is a change")

	// The mode must be persisted.
	ls2, err := st.GetLuksState(actionID)
	require.NoError(t, err)
	assert.Equal(t, "user_passphrase", ls2.DeviceKeyType,
		"reconcile must persist the user_passphrase mode so it converges")

	// Second reconcile must be a no-op — the action has converged.
	changed2, err := e.reconcileDeviceKey(context.Background(), params, ls2, actionID, devicePath)
	require.NoError(t, err)
	assert.False(t, changed2, "user_passphrase must converge, not report changed=true forever")
}
