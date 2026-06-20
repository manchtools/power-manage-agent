package executor

import (
	"context"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// WS6 #8: the critical-file denylist had zero rejection coverage. This is
// a self-discovering exhaustiveness check: every entry currently in the
// slice must be recognised, the slice must be non-empty (guard against it
// being silently emptied), and — sourced from INTENT, not the slice — the
// account/auth/boot-critical files MUST be denied. If someone drops
// /etc/shadow from criticalFiles, the mustDeny loop fails.
func TestIsCriticalFile_DenylistExhaustive(t *testing.T) {
	require.NotEmpty(t, criticalFiles, "criticalFiles must not be empty")

	for _, f := range criticalFiles {
		assert.Truef(t, isCriticalFile(f), "listed critical file %q must be recognised", f)
	}

	// Sourced from intent (account/auth/boot/identity state), independent
	// of the slice's current contents.
	mustDeny := []string{
		"/etc/passwd", "/etc/shadow", "/etc/group", "/etc/gshadow",
		"/etc/sudoers", "/etc/fstab", "/etc/ssh/sshd_config",
	}
	for _, f := range mustDeny {
		assert.Truef(t, isCriticalFile(f), "intent-critical file %q must be denied", f)
	}

	// Managed config under a drop-in dir is the point of the file action;
	// it must NOT be treated as critical.
	assert.False(t, isCriticalFile("/etc/foo.d/bar.conf"))
	assert.False(t, isCriticalFile("/opt/myapp/app.conf"))

	// resolv.conf is commonly a symlink to /run/...; the cleaned path must
	// still be caught.
	assert.True(t, isCriticalFile("/etc/resolv.conf"))
}

// WS6 #8: protected-path predicate covers the listed system directories,
// every immediate child of / (e.g. /lost+found), and the critical files,
// but NOT managed config two levels down.
func TestIsProtectedPath_DirsAndTopLevelChildren(t *testing.T) {
	require.NotEmpty(t, protectedPaths)

	for _, p := range protectedPaths {
		assert.Truef(t, isProtectedPath(p), "listed protected path %q must be recognised", p)
	}

	assert.True(t, isProtectedPath("/lost+found"), "immediate children of / are protected")
	assert.True(t, isProtectedPath("/etc/passwd"), "critical files are protected")

	assert.False(t, isProtectedPath("/etc/foo.d/bar.conf"), "managed config under a drop-in is not protected")
	assert.False(t, isProtectedPath("/opt/myapp/data"))
}

// WS6 #8: drive the REAL executeFile (not the helpers) to prove the guard
// runs on the action path. ABSENT on a critical file must refuse with
// changed=false.
func TestExecuteFile_ABSENT_RefusesCriticalFile(t *testing.T) {
	e := &Executor{logger: slog.Default(), now: time.Now}

	for _, p := range []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers"} {
		_, changed, err := e.executeFile(context.Background(),
			&pb.FileParams{Path: p}, pb.DesiredState_DESIRED_STATE_ABSENT)
		require.Errorf(t, err, "ABSENT delete of critical file %q must be refused", p)
		assert.Contains(t, err.Error(), "protected")
		assert.False(t, changed)
	}
}

// PRESENT overwrite of a critical file must refuse with changed=false.
func TestExecuteFile_PRESENT_RefusesOverwriteOfSudoers(t *testing.T) {
	e := &Executor{logger: slog.Default(), now: time.Now}

	_, changed, err := e.executeFile(context.Background(),
		&pb.FileParams{Path: "/etc/sudoers", Content: "pwned ALL=(ALL) NOPASSWD: ALL\n", Mode: "0440"},
		pb.DesiredState_DESIRED_STATE_PRESENT)
	require.Error(t, err, "PRESENT overwrite of /etc/sudoers must be refused")
	assert.Contains(t, err.Error(), "critical")
	assert.False(t, changed)
}
