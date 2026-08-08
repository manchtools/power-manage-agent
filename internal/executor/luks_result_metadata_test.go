package executor

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	sdkcrypto "github.com/manchtools/power-manage-sdk/crypto"
	pb "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1"
	sysenc "github.com/manchtools/power-manage-sdk/sys/encryption"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage/agent/internal/store"
)

// CHARTER — an ENCRYPTION result must carry no metadata.
//
// Control refuses any ActionResult with a non-empty metadata map, and the
// agent's outbox marks a frame synced as soon as the local send returns. A
// LUKS result that stamps metadata onto itself is therefore either discarded
// outright or replayed forever — the result never reaches control either way.
// device_path already reaches control through StoreLuksKey, so there is
// nothing on this path for metadata to carry.

// fakeDetectEncManager adds first-run volume detection to the recorded-no-op
// manager, which is what setupLuks needs before it can take ownership.
type fakeDetectEncManager struct {
	fakeSealEncManager
	devicePath string
}

func (f *fakeDetectEncManager) DetectVolumeByKey(context.Context, sysexec.Secret) (sysenc.Volume, error) {
	return sysenc.Volume{DevicePath: f.devicePath}, nil
}

// newLuksExecutor wires the SUCCESS path: the key store echoes back whatever
// the agent stored, so ownership completes its round-trip verification and
// setupLuks reaches the metadata it builds at the end. A key store that
// cannot answer GetKey aborts before that point and would make an
// "empty metadata" assertion pass for the wrong reason.
func newLuksExecutor(t *testing.T, devicePath string) *Executor {
	t.Helper()
	st, err := store.New(t.TempDir())
	require.NoError(t, err)
	t.Cleanup(func() { _ = st.Close() })
	swapEncMgr(t, &fakeDetectEncManager{devicePath: devicePath})

	var stored string
	keys := &fakeLuksKeyStore{
		getKeyFunc: func(context.Context, string) (string, error) { return stored, nil },
		storeKeyFunc: func(_ context.Context, _, _, passphrase string, _ pb.RotationReason) error {
			stored = passphrase
			return nil
		},
	}
	e := &Executor{logger: slog.Default(), now: time.Now}
	e.SetStore(st)
	e.SetDeviceID("01HXDEVICE0000000000000000")
	e.SetLuksKeyStore(keys)
	return e
}

func TestSetupLuksReportsNoMetadata(t *testing.T) {
	e := newLuksExecutor(t, "/dev/mapper/root")

	_, _, metadata, err := e.setupLuks(context.Background(),
		&pb.EncryptionParams{MinWords: 3},
		"01HXLUKSMETA00000000000000", "psk-value")
	require.NoError(t, err)
	assert.Empty(t, metadata, "control rejects every result that carries metadata")
}

func TestExecuteEncryptionActionReportsNoResultMetadata(t *testing.T) {
	e := newLuksExecutor(t, "/dev/mapper/root")
	agentKey, err := sdkcrypto.GenerateX25519()
	require.NoError(t, err)
	controlKey, err := sdkcrypto.GenerateX25519()
	require.NoError(t, err)
	require.NoError(t, e.ConfigureSealing(agentKey.Bytes(), controlKey.PublicKey().Bytes()))
	const actionID = "01HXLUKSEXEC00000000000000"
	aad, info, err := sdkcrypto.FieldSealContext(sdkcrypto.DirectionControlToAgent,
		"powermanage.v1.EncryptionParams", "preshared_key", e.getDeviceID(), actionID)
	require.NoError(t, err)
	sealed, err := sdkcrypto.SealToPublicKey(agentKey.PublicKey(), []byte("psk-value"), aad, info)
	require.NoError(t, err)

	result := e.ExecuteAction(context.Background(), &pb.Action{
		Id:           &pb.ActionId{Value: actionID},
		Type:         pb.ActionType_ACTION_TYPE_ENCRYPTION,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
		Params: &pb.Action_Encryption{Encryption: &pb.EncryptionParams{
			PresharedKey: &pb.SealedValue{Version: 1, Ciphertext: sealed}, MinWords: 3,
		}},
	})
	require.NotNil(t, result)
	// The action has to have SUCCEEDED, or "no metadata" would be satisfied
	// by an action that never reached the point where metadata was built.
	require.Equal(t, pb.ExecutionStatus_EXECUTION_STATUS_SUCCESS, result.Status, result.Error)
	assert.Empty(t, result.Metadata,
		"a result control refuses is lost on send or replayed on every reconnect")
}
