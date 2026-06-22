package executor

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/manchtools/power-manage-sdk/sys/desktop"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// recordingBaseRunner records each command the base runner receives — under
// desktop.RunAsRunner that is the fully-wrapped `runuser …` command — so a test
// can assert how per-user execution is built without a real runuser/root.
type recordingBaseRunner struct{ cmds []sysexec.Command }

func (r *recordingBaseRunner) Run(_ context.Context, c sysexec.Command) (sysexec.Result, error) {
	r.cmds = append(r.cmds, c)
	return sysexec.Result{}, nil
}

func (r *recordingBaseRunner) Stream(_ context.Context, c sysexec.Command, _ sysexec.OutputCallback) (sysexec.Result, error) {
	r.cmds = append(r.cmds, c)
	return sysexec.Result{}, nil
}

func (r *recordingBaseRunner) Backend() sysexec.PrivilegeBackend { return sysexec.Direct }

// TestRunAsUserStreaming_WorkingDirAndPerUserEnv pins the A4 adoption: per-user
// script execution now goes through desktop.RunAsRunner, so the wrapped runuser
// command carries the action's working directory (Command.Dir, now honored by
// RunAsRunner), the per-user HOME/USER, and the curated per-user PATH (not the
// agent root's). No hand-built runuser/env splicing remains in the agent.
func TestRunAsUserStreaming_WorkingDirAndPerUserEnv(t *testing.T) {
	prev := executorRunner
	t.Cleanup(func() { executorRunner = prev })
	rec := &recordingBaseRunner{}
	executorRunner = rec

	s := desktop.Session{Username: "alice", UID: 1000, Home: "/home/alice"}

	// An explicit working directory must reach the wrapped runuser command.
	_, err := runAsUserStreaming(context.Background(), s, nil, "/work/dir", "/bin/echo", []string{"hi"}, nil)
	require.NoError(t, err)
	require.Len(t, rec.cmds, 1)
	cmd := rec.cmds[0]
	assert.Equal(t, "/work/dir", cmd.Dir,
		"WorkingDirectory must reach the wrapped runuser command (RunAsRunner honors Command.Dir)")
	joined := strings.Join(cmd.Args, " ")
	assert.Contains(t, joined, "HOME=/home/alice", "per-user HOME set via RunAsRunner")
	assert.Contains(t, joined, "USER=alice", "per-user USER set via RunAsRunner")
	assert.Contains(t, joined, "PATH="+desktop.UserPath(s), "curated per-user PATH (not the agent root's)")
	assert.Contains(t, joined, "alice", "command runs as the session user")

	// An empty working directory defaults to the user's home.
	rec.cmds = nil
	_, err = runAsUserStreaming(context.Background(), s, nil, "", "/bin/echo", []string{"hi"}, nil)
	require.NoError(t, err)
	require.Len(t, rec.cmds, 1)
	assert.Equal(t, "/home/alice", rec.cmds[0].Dir, "empty WorkingDirectory defaults to the user's home")
}
