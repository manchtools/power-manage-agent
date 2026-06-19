package executor

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// Pinning is part of the requested desired state. ensureFlatpakMasked
// must (a) converge — mask an already-installed-but-unpinned app, not
// skip it; (b) be idempotent — not re-mask an already-masked app; and
// (c) surface a mask failure as a real error, never a silent success.
func TestEnsureFlatpakMasked(t *testing.T) {
	const app = "org.example.App"

	t.Run("already masked -> no change, mask not re-run", func(t *testing.T) {
		var maskCalled bool
		run := func(args ...string) (*pb.CommandOutput, error) {
			if len(args) == 0 { // the list call
				return &pb.CommandOutput{Stdout: "org.other.Thing\n" + app + "\n"}, nil
			}
			maskCalled = true
			return &pb.CommandOutput{}, nil
		}
		changed, err := ensureFlatpakMasked(app, run)
		require.NoError(t, err)
		assert.False(t, changed, "an already-masked app must not report a change")
		assert.False(t, maskCalled, "must not re-mask an already-masked app")
	})

	t.Run("not masked -> applies mask and reports change", func(t *testing.T) {
		var maskedArg string
		run := func(args ...string) (*pb.CommandOutput, error) {
			if len(args) == 0 {
				return &pb.CommandOutput{Stdout: "org.other.Thing\n"}, nil // app absent from list
			}
			maskedArg = args[0]
			return &pb.CommandOutput{}, nil
		}
		changed, err := ensureFlatpakMasked(app, run)
		require.NoError(t, err)
		assert.True(t, changed, "newly masking an unpinned app must report a change")
		assert.Equal(t, app, maskedArg, "must mask the requested app id")
	})

	t.Run("mask failure is a real error, not a success", func(t *testing.T) {
		run := func(args ...string) (*pb.CommandOutput, error) {
			if len(args) == 0 {
				return &pb.CommandOutput{Stdout: ""}, nil
			}
			return &pb.CommandOutput{ExitCode: 1}, fmt.Errorf("permission denied")
		}
		_, err := ensureFlatpakMasked(app, run)
		require.Error(t, err, "a failed pin must surface as an error so the action reports FAILED")
	})
}

func TestFlatpakMaskListed(t *testing.T) {
	list := "org.a.A\norg.b.B\n"
	assert.True(t, flatpakMaskListed(list, "org.b.B"))
	assert.False(t, flatpakMaskListed(list, "org.b"))
	assert.False(t, flatpakMaskListed(list, "org.c.C"))
}
