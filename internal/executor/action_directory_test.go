package executor

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// withRootBackend forces the Root privilege backend (restored on cleanup)
// so the executor's fs helpers run their fd-based, direct-syscall path
// against test-user-owned temp dirs instead of escalating via sudo.
func withRootBackend(t *testing.T) {
	t.Helper()
	prev := sysexec.CurrentPrivilegeBackend()
	sysexec.SetPrivilegeBackend(sysexec.Direct)
	t.Cleanup(func() { sysexec.SetPrivilegeBackend(prev) })
}

func newDirExecutor() *Executor {
	return &Executor{logger: slog.Default(), now: time.Now}
}

// WS6 #6: the DIRECTORY PRESENT branch had no protected-path guard while
// ABSENT did — an asymmetry that let a PRESENT action chmod/chown a
// protected system directory. PRESENT must refuse the same protected
// paths ABSENT does.
func TestExecuteDirectory_PRESENT_RefusesProtectedPath(t *testing.T) {
	e := newDirExecutor()

	// Top-level protected paths AND subtree paths (symmetric with ABSENT):
	// a PRESENT chmod/chown of /etc/sudoers.d or /var/lib/<x> is as
	// dangerous as deleting it, so deny-by-default the whole subtree.
	for _, p := range []string{
		"/etc", "/", "/usr",
		"/etc/sudoers.d", "/etc/sudoers.d/custom",
		"/var/lib/postgresql", "/home/alice", "/boot/efi", "/usr/local/bin",
	} {
		_, changed, err := e.executeDirectory(context.Background(),
			// A mode the target almost certainly does not have, so the
			// guard (not the "already in desired state" short-circuit) is
			// what rejects it.
			&pb.DirectoryParams{Path: p, Mode: "0777"},
			pb.DesiredState_DESIRED_STATE_PRESENT)
		require.Errorf(t, err, "PRESENT on protected %q must be refused", p)
		assert.Contains(t, err.Error(), "protected")
		assert.False(t, changed)
	}

	// Correct: a benign managed dir under a writable tmp succeeds.
	withRootBackend(t)
	target := filepath.Join(t.TempDir(), "managed")
	_, changed, err := e.executeDirectory(context.Background(),
		&pb.DirectoryParams{Path: target, Mode: "0750"},
		pb.DesiredState_DESIRED_STATE_PRESENT)
	require.NoError(t, err)
	assert.True(t, changed)
	info, statErr := os.Stat(target)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0o750), info.Mode().Perm())
}

// WS6 #12: ABSENT recursive delete was guarded by a top-level-only
// denylist, so a path one level down (a drop-in dir, a home, a state
// dir) slipped through to rm -rf. Deny-by-default must refuse the whole
// subtree of every protected prefix — BEFORE the existence check, so the
// refusal does not depend on the path being present.
func TestExecuteDirectory_ABSENT_DenyByDefault(t *testing.T) {
	e := newDirExecutor()

	// Sourced from intent (security-relevant subtrees), not the impl list.
	// Use non-existent leaves to prove the refusal precedes the stat.
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

	// Correct: a managed dir under a non-protected prefix is deletable.
	withRootBackend(t)
	target := filepath.Join(t.TempDir(), "managed")
	require.NoError(t, os.MkdirAll(filepath.Join(target, "sub"), 0o755))
	_, changed, err := e.executeDirectory(context.Background(),
		&pb.DirectoryParams{Path: target},
		pb.DesiredState_DESIRED_STATE_ABSENT)
	require.NoError(t, err)
	assert.True(t, changed)
	_, statErr := os.Stat(target)
	assert.True(t, os.IsNotExist(statErr), "managed dir should be removed")
}

// WS6 #5: directory permission changes must go through the fd-based,
// no-follow helper — a symlink swapped in where a managed dir is expected
// must abort (ELOOP), not have its target chmod'd/chowned.
func TestCreateDirectoryWithPermissions_RefusesSymlink(t *testing.T) {
	withRootBackend(t)
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	require.NoError(t, os.Mkdir(victim, 0o700))
	link := filepath.Join(root, "managed")
	require.NoError(t, os.Symlink(victim, link))

	err := createDirectoryWithPermissions(context.Background(), link, "0777", "", "", false)
	require.Error(t, err, "chmod/chown on a symlinked dir path must be refused")

	info, statErr := os.Stat(victim)
	require.NoError(t, statErr)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm(),
		"the symlink target's mode must be unchanged")
}

// WS6 #4: recursive delete must use the fd-anchored, symlink-refusing
// helper — a symlinked target (or component) must abort, not be followed.
func TestRemoveDirectory_RefusesSymlinkLeaf(t *testing.T) {
	withRootBackend(t)
	root := t.TempDir()
	victim := filepath.Join(root, "victim")
	require.NoError(t, os.MkdirAll(victim, 0o755))
	link := filepath.Join(root, "managed")
	require.NoError(t, os.Symlink(victim, link))

	err := removeDirectory(context.Background(), link)
	require.Error(t, err, "removing a symlinked dir path must be refused")
	_, statErr := os.Stat(victim)
	assert.NoError(t, statErr, "the symlink target must not be removed")
}
