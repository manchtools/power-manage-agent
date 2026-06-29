//go:build integration

package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// =============================================================================
// Container-bound tests that exercise real SDK managers against the host
// =============================================================================

// TestIntegration_DirectoryCreateAndRemove verifies that executeDirectory
// with PRESENT creates a directory with correct mode and ABSENT removes it.
func TestIntegration_DirectoryCreateAndRemove(t *testing.T) {
	e := newTestExecutor()
	root := t.TempDir()

	target := filepath.Join(root, "managed")
	_, changed, err := e.executeDirectory(context.Background(),
		&pb.DirectoryParams{Path: target, Mode: "0750"},
		pb.DesiredState_DESIRED_STATE_PRESENT)
	require.NoError(t, err)
	assert.True(t, changed)

	info, statErr := os.Stat(target)
	require.NoError(t, statErr)
	assert.True(t, info.IsDir())
	assert.Equal(t, os.FileMode(0o750), info.Mode().Perm())

	// Idempotent
	_, changed, err = e.executeDirectory(context.Background(),
		&pb.DirectoryParams{Path: target, Mode: "0750"},
		pb.DesiredState_DESIRED_STATE_PRESENT)
	require.NoError(t, err)
	assert.False(t, changed)

	// ABSENT
	_, changed, err = e.executeDirectory(context.Background(),
		&pb.DirectoryParams{Path: target},
		pb.DesiredState_DESIRED_STATE_ABSENT)
	require.NoError(t, err)
	assert.True(t, changed)

	_, statErr = os.Stat(target)
	assert.True(t, os.IsNotExist(statErr))

	// ABSENT again: idempotent
	_, changed, err = e.executeDirectory(context.Background(),
		&pb.DirectoryParams{Path: target},
		pb.DesiredState_DESIRED_STATE_ABSENT)
	require.NoError(t, err)
	assert.False(t, changed)
}

// TestIntegration_DirectoryRefusesSymlinkOnCreate verifies that
// createDirectoryWithPermissions refuses a symlink swap (ELOOP).
func TestIntegration_DirectoryRefusesSymlinkOnCreate(t *testing.T) {
	_ = newTestExecutor() // injects the real fs Manager into package vars
	root := t.TempDir()

	victim := filepath.Join(root, "victim")
	require.NoError(t, os.Mkdir(victim, 0o700))
	link := filepath.Join(root, "managed")
	require.NoError(t, os.Symlink(victim, link))

	err := createDirectoryWithPermissions(context.Background(), link, "0777", "", "", false)
	require.Error(t, err)

	info, statErr := os.Stat(victim)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(),
		"symlink target's mode must be unchanged")
}

// TestIntegration_DirectoryRefusesSymlinkOnRemove verifies that removeDirectory
// aborts on a symlinked target.
func TestIntegration_DirectoryRefusesSymlinkOnRemove(t *testing.T) {
	_ = newTestExecutor() // injects the real fs Manager into package vars
	root := t.TempDir()

	victim := filepath.Join(root, "victim")
	require.NoError(t, os.MkdirAll(victim, 0o755))
	link := filepath.Join(root, "managed")
	require.NoError(t, os.Symlink(victim, link))

	err := removeDirectory(context.Background(), link)
	require.Error(t, err)
	_, statErr := os.Stat(victim)
	assert.NoError(t, statErr, "symlink target must not be removed")
}

// TestIntegration_FileCreateAndRemove exercises executeFile PRESENT/ABSENT
// through a real fs Manager.
func TestIntegration_FileCreateAndRemove(t *testing.T) {
	e := newTestExecutor()
	root := t.TempDir()

	target := filepath.Join(root, "test.txt")
	content := "hello world"

	_, changed, err := e.executeFile(context.Background(),
		&pb.FileParams{Path: target, Content: content, Mode: "0644"},
		pb.DesiredState_DESIRED_STATE_PRESENT)
	require.NoError(t, err)
	assert.True(t, changed)

	data, readErr := os.ReadFile(target)
	require.NoError(t, readErr)
	assert.Equal(t, content, string(data))

	// Idempotent
	_, changed, err = e.executeFile(context.Background(),
		&pb.FileParams{Path: target, Content: content, Mode: "0644"},
		pb.DesiredState_DESIRED_STATE_PRESENT)
	require.NoError(t, err)
	assert.False(t, changed)

	// ABSENT
	_, changed, err = e.executeFile(context.Background(),
		&pb.FileParams{Path: target},
		pb.DesiredState_DESIRED_STATE_ABSENT)
	require.NoError(t, err)
	assert.True(t, changed)
	_, statErr := os.Stat(target)
	assert.True(t, os.IsNotExist(statErr))
}

// TestIntegration_FileManagedBlock exercises the ManagedBlock append/remove flow.
func TestIntegration_FileManagedBlock(t *testing.T) {
	e := newTestExecutor()
	root := t.TempDir()
	target := filepath.Join(root, "config.txt")

	initial := "line1\nline2\n"
	require.NoError(t, os.WriteFile(target, []byte(initial), 0644))

	block := "# managed block\nmanaged-setting=true\n"
	params := &pb.FileParams{Path: target, Content: block, ManagedBlock: true, Mode: "0644"}
	_, changed, err := e.executeFile(context.Background(), params, pb.DesiredState_DESIRED_STATE_PRESENT)
	require.NoError(t, err)
	assert.True(t, changed)

	data, _ := os.ReadFile(target)
	assert.Contains(t, string(data), initial)
	assert.Contains(t, string(data), block)

	// ABSENT with ManagedBlock: remove block
	_, changed, err = e.executeFile(context.Background(), params, pb.DesiredState_DESIRED_STATE_ABSENT)
	require.NoError(t, err)
	assert.True(t, changed)

	data, _ = os.ReadFile(target)
	assert.Contains(t, string(data), initial)
	assert.NotContains(t, string(data), block)
}

// TestIntegration_ShellScriptRunsThroughRealRunner verifies that runShellScript
// dispatches through a real Direct runner and executes /bin/true.
func TestIntegration_ShellScriptRunsThroughRealRunner(t *testing.T) {
	e := newTestExecutor()

	out, err := e.runShellScript(context.Background(),
		&pb.ShellParams{RunAsRoot: true}, "true", nil)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, int32(0), out.ExitCode)

	// Script that fails
	out, err = e.runShellScript(context.Background(),
		&pb.ShellParams{RunAsRoot: true}, "exit 42", nil)
	require.NoError(t, err)
	require.NotNil(t, out)
	assert.Equal(t, int32(42), out.ExitCode)
}

// TestIntegration_SSHKeysCreatedViaRealFSManager verifies that setupSSHKeys
// creates .ssh directory and authorized_keys through the real fs Manager.
