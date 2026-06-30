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
// Validation-only unit tests: these test rejection paths and must never
// reach a privileged call. Use no privilege runner.
// =============================================================================

// TestExecuteDirectory_RejectsNilParams verifies nil params rejection.
func TestExecuteDirectory_RejectsNilParams(t *testing.T) {
	e := NewExecutor(nil, nil)
	_, changed, err := e.executeDirectory(context.Background(), nil, pb.DesiredState_DESIRED_STATE_PRESENT)
	require.Error(t, err)
	assert.False(t, changed)
	assert.Contains(t, err.Error(), "required")
}

// TestExecuteDirectory_RejectsEmptyPath verifies empty path rejection.
func TestExecuteDirectory_RejectsEmptyPath(t *testing.T) {
	e := NewExecutor(nil, nil)
	_, changed, err := e.executeDirectory(context.Background(),
		&pb.DirectoryParams{Path: ""}, pb.DesiredState_DESIRED_STATE_PRESENT)
	require.Error(t, err)
	assert.False(t, changed)
}

// TestExecuteDirectory_RejectsUnknownState verifies unknown state rejection.
func TestExecuteDirectory_RejectsUnknownState(t *testing.T) {
	e := NewExecutor(nil, nil)
	_, changed, err := e.executeDirectory(context.Background(),
		&pb.DirectoryParams{Path: "/tmp/test"}, pb.DesiredState(999))
	require.Error(t, err)
	assert.False(t, changed)
}

// TestExecuteDirectory_PRESENT_RefusesProtectedPath verifies that protected
// system paths are rejected BEFORE any privileged filesystem access. The
// "correct" (non-protected) creation path moved to container_test.go.
func TestExecuteDirectory_PRESENT_RefusesProtectedPath(t *testing.T) {
	e := NewExecutor(nil, nil)

	for _, p := range []string{
		"/etc", "/", "/usr",
		"/etc/sudoers.d", "/etc/sudoers.d/custom",
		"/var/lib/postgresql", "/home/alice", "/boot/efi", "/usr/local/bin",
	} {
		_, changed, err := e.executeDirectory(context.Background(),
			&pb.DirectoryParams{Path: p, Mode: "0777"},
			pb.DesiredState_DESIRED_STATE_PRESENT)
		require.Errorf(t, err, "PRESENT on protected %q must be refused", p)
		assert.Contains(t, err.Error(), "protected")
		assert.False(t, changed)
	}
}

// TestExecuteDirectory_ABSENT_DenyByDefault verifies subtree protection
// for ABSENT — refuse deletion before the existence check uses Stat.
func TestExecuteDirectory_ABSENT_DenyByDefault(t *testing.T) {
	e := NewExecutor(nil, nil)

	for _, p := range []string{
		"/etc/sudoers.d/pm-ws6-nope",
		"/etc/cron.d/pm-ws6-nope",
		"/boot/efi/pm-ws6-nope",
		"/var/lib/pm-ws6-nope",
		"/home/pm-ws6-victim",
		"/root/.ssh",
		"/usr/lib/pm-ws6-nope",
	} {
		_, changed, err := e.executeDirectory(context.Background(),
			&pb.DirectoryParams{Path: p},
			pb.DesiredState_DESIRED_STATE_ABSENT)
		require.Errorf(t, err, "ABSENT on protected subtree %q must be refused", p)
		assert.Contains(t, err.Error(), "protected")
		assert.False(t, changed)
	}
}

// TestDirectoryMatchesDesired_ReturnsFalseForNonExistent verifies that
// directoryMatchesDesired returns false for missing paths and non-directories.
func TestDirectoryMatchesDesired_ReturnsFalseForNonExistent(t *testing.T) {
	e := &Executor{}

	// Non-existent path
	assert.False(t, e.directoryMatchesDesired(context.Background(), "/nonexistent/dir", &pb.DirectoryParams{}))

	// Path exists but is a regular file, not a directory
	tmpFile := filepath.Join(t.TempDir(), "regular-file")
	require.NoError(t, os.WriteFile(tmpFile, []byte("content"), 0644))
	assert.False(t, e.directoryMatchesDesired(context.Background(), tmpFile, &pb.DirectoryParams{}))
}
