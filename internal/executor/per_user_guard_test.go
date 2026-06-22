package executor

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage-sdk/sys/desktop"
)

// WS6 #15: runAsUserStreaming must reject a missing command name or an
// empty session username with sentinel errors BEFORE constructing/running
// any child — a caller bug must not reach runuser. Root-free: the guards
// return before exec.
func TestRunAsUserStreaming_EmptyNameRejected(t *testing.T) {
	_, err := runAsUserStreaming(context.Background(),
		desktop.Session{Username: "alice", Home: "/home/alice"}, nil, "", "", nil, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errEmptyName), "want errEmptyName, got %v", err)
}

func TestRunAsUserStreaming_EmptyUsernameRejected(t *testing.T) {
	_, err := runAsUserStreaming(context.Background(),
		desktop.Session{Username: ""}, nil, "", "echo", []string{"hi"}, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, errEmptyUsername), "want errEmptyUsername, got %v", err)
}

// The per-user output cap (SDK MaxOutputBytes + truncation marker) is now the
// SDK's concern — runAsUserStreaming dispatches through desktop.RunAsRunner over
// the SDK exec.Runner, which applies the cap. The agent's former capture helper
// (runCapturedCapped) and its TestRunAsUserCmd_OutputCapped were removed with the
// hand-built runuser path.
