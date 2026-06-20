package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// TestCommandOutput_RoundTripsViaProtojson pins WS1b#5 (agent side): a recorded
// CommandOutput round-trips through the local SQLite result store
// byte-faithfully. The store now writes protojson (canonicalProtoJSON, which
// emits the camelCase `exitCode`) and reads protojson. A regression of the
// reader back to stdlib encoding/json would only know the `exit_code` struct
// tag, silently zero the camelCase `exitCode`, and fail proto.Equal here.
func TestCommandOutput_RoundTripsViaProtojson(t *testing.T) {
	st, err := New(t.TempDir())
	require.NoError(t, err)
	defer st.Close()

	a := &pb.Action{
		Id:           &pb.ActionId{Value: "act-cmdout"},
		Type:         pb.ActionType_ACTION_TYPE_SHELL,
		DesiredState: pb.DesiredState_DESIRED_STATE_PRESENT,
	}
	require.NoError(t, st.SaveAction(a))

	want := &pb.CommandOutput{
		Stdout:   "líne1\nzwei\n", // multibyte UTF-8
		Stderr:   "warn: café",
		ExitCode: 137, // non-zero, non-default
	}
	_, err = st.RecordExecution(a.Id.Value, &pb.ActionResult{
		ActionId: a.Id,
		Status:   pb.ExecutionStatus_EXECUTION_STATUS_FAILED,
		Output:   want,
	}, true)
	require.NoError(t, err)

	results, err := st.GetUnsyncedResults()
	require.NoError(t, err)
	require.Len(t, results, 1)

	got := results[0].Output
	require.NotNil(t, got, "stored CommandOutput must read back")
	assert.Truef(t, proto.Equal(want, got),
		"CommandOutput must round-trip losslessly via protojson:\n want=%v\n  got=%v", want, got)
	assert.Equal(t, int32(137), got.ExitCode,
		"exit_code must survive the round-trip (a stdlib-json reader would miss the camelCase exitCode and zero it)")
}
