package executor

import (
	"context"
	"errors"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage-sdk/sys/desktop"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
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

// WS6 #14: per-user command output was buffered into an unbounded
// bytes.Buffer, so a child emitting unbounded output pins the root agent's
// memory. The capture path must route through the SDK's MaxOutputBytes cap
// and mark the output truncated. Tested via the shared capture helper with
// a plain child (no runuser, so no root needed).
func TestRunAsUserCmd_OutputCapped(t *testing.T) {
	// Emit well over the cap on stdout.
	big := sysexec.MaxOutputBytes + (1 << 16)
	cmd := exec.CommandContext(context.Background(), "/bin/sh", "-c",
		"head -c "+strconv.Itoa(big)+" /dev/zero | tr '\\0' 'A'")

	out, err := runCapturedCapped(cmd)
	require.NoError(t, err)
	require.NotNil(t, out)

	if len(out.Stdout) > sysexec.MaxOutputBytes+len("\n[output truncated]") {
		t.Errorf("stdout = %d bytes, want capped near MaxOutputBytes (%d)", len(out.Stdout), sysexec.MaxOutputBytes)
	}
	assert.True(t, strings.HasSuffix(out.Stdout, "[output truncated]"),
		"capped output must carry the truncation marker")
}
