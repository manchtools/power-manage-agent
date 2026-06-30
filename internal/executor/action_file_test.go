package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysfs "github.com/manchtools/power-manage-sdk/sys/fs"
)

// TestExecuteFile_RejectsNilParams verifies that nil FileParams is rejected.
func TestExecuteFile_RejectsNilParams(t *testing.T) {
	e := NewExecutor(nil, nil)
	_, changed, err := e.executeFile(context.Background(), nil, pb.DesiredState_DESIRED_STATE_PRESENT)
	if err == nil {
		t.Fatal("expected error for nil params, got nil")
	}
	if changed {
		t.Error("changed must be false when params are nil")
	}
}

// TestExecuteFile_RejectsContentExceedingMaxSize verifies that file content
// exceeding maxFileContentSize (10 MiB) is rejected before any I/O.
func TestExecuteFile_RejectsContentExceedingMaxSize(t *testing.T) {
	e := NewExecutor(nil, nil)
	oversized := strings.Repeat("x", maxFileContentSize+1)
	params := &pb.FileParams{Path: "/tmp/test.txt", Content: oversized}
	_, changed, err := e.executeFile(context.Background(), params, pb.DesiredState_DESIRED_STATE_PRESENT)
	if err == nil {
		t.Fatal("expected error for oversized content, got nil")
	}
	if changed {
		t.Error("changed must be false when content exceeds max size")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("error should mention size limit, got %q", err)
	}
}

// TestExecuteFile_RejectsContentAtMaxSizeBoundary verifies that content right
// at maxFileContentSize is accepted (not rejected as oversized). The guard
// uses `>` not `>=`.
func TestExecuteFile_ContentAtMaxSizeAccepted(t *testing.T) {
	e := NewExecutor(nil, nil)
	atLimit := strings.Repeat("x", maxFileContentSize)
	params := &pb.FileParams{Path: "/tmp/nonexistent/test.txt", Content: atLimit}
	_, _, err := e.executeFile(context.Background(), params, pb.DesiredState_DESIRED_STATE_PRESENT)
	// The file doesn't exist and we have no runner, so it will fail later —
	// but the size check must NOT be the gate that rejects it.
	if err != nil && strings.Contains(err.Error(), "exceeds maximum size") {
		t.Errorf("content at exactly maxFileContentSize must not be rejected as oversized: %v", err)
	}
}

// TestExecuteFile_RejectsUnknownDesiredState verifies rejection of unknown state.
func TestExecuteFile_RejectsUnknownDesiredState(t *testing.T) {
	e := NewExecutor(nil, nil)
	params := &pb.FileParams{Path: "/tmp/test.txt", Content: "hello"}
	_, changed, err := e.executeFile(context.Background(), params, pb.DesiredState(999))
	if err == nil {
		t.Fatal("expected error for unknown desired state, got nil")
	}
	if changed {
		t.Error("changed must be false for unknown state")
	}
}

// TestFileMatchesDesired_ReturnsFalseForMissingFile verifies that
// fileMatchesDesired returns false when the file does not exist.
func TestFileMatchesDesired_ReturnsFalseForMissingFile(t *testing.T) {
	e := NewExecutor(nil, nil)
	if e.fileMatchesDesired(context.Background(), "/nonexistent/path/that/does/not/exist.txt", &pb.FileParams{
		Content: "hello",
	}) {
		t.Error("fileMatchesDesired must return false for a non-existent file")
	}
}

// TestFileMatchesDesired_ReturnsFalseWhenPathIsDirectory verifies that a
// directory (not a regular file) is not considered a match.
func TestFileMatchesDesired_ReturnsFalseWhenPathIsDirectory(t *testing.T) {
	e := NewExecutor(nil, nil)
	if e.fileMatchesDesired(context.Background(), "/tmp", &pb.FileParams{Content: "hello"}) {
		t.Error("fileMatchesDesired must return false for a directory")
	}
}

// TestFileMatchesDesired_OwnerOnlyCheck verifies that when only Owner is
// specified, Group is ignored in the comparison (not compared against the
// empty string, which would always mismatch). Per audit: a group-only request
// used to compare currentOwner against empty, making fileMatchesDesired never
// return true.
func TestFileMatchesDesired_OwnerOnlyCheck(t *testing.T) {
	e := NewExecutor(nil, nil)
	ctx := context.Background()

	// Real file owned by the test user, with known content. fileMatchesDesired
	// compares content first, then owner/group only for the fields that were
	// requested — the bug was a group-only request comparing the (empty) Owner
	// and so never matching. Exercise that real comparison path.
	dir := t.TempDir()
	path := filepath.Join(dir, "f")
	const content = "hello world"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}
	owner, group := getFileOwnership(path)
	if owner == "" || group == "" {
		t.Skip("ownership lookup unavailable on this platform")
	}

	// group-only request (matching content + group) must MATCH — the regression:
	// a group-only request used to compare the empty Owner and never match.
	if !e.fileMatchesDesired(ctx, path, &pb.FileParams{Content: content, Group: group}) {
		t.Error("group-only request with the file's own group must match (empty-Owner regression)")
	}
	// owner-only request (matching content + owner) must MATCH.
	if !e.fileMatchesDesired(ctx, path, &pb.FileParams{Content: content, Owner: owner}) {
		t.Error("owner-only request with the file's own owner must match")
	}
	// owner-only request with a WRONG owner must NOT match — proves the owner is
	// actually compared, not ignored.
	if e.fileMatchesDesired(ctx, path, &pb.FileParams{Content: content, Owner: owner + "-nope"}) {
		t.Error("owner-only request with a non-matching owner must not match")
	}

	// Sentinel: a non-existent file returns false without panicking on the
	// empty-string ownership comparison.
	if e.fileMatchesDesired(ctx, "/nonexistent/test.txt", &pb.FileParams{Group: "wheel"}) {
		t.Error("must return false for a non-existent file")
	}
}

// TestDirectoryMatchesDesired_OwnerOnlyCheck mirrors TestFileMatchesDesired_OwnerOnlyCheck
// for the directory variant (same bug class was fixed there too).
func TestDirectoryMatchesDesired_ReturnsFalseForMissingDir(t *testing.T) {
	e := NewExecutor(nil, nil)
	if e.directoryMatchesDesired(context.Background(), "/nonexistent/dir", &pb.DirectoryParams{}) {
		t.Error("directoryMatchesDesired must return false for a non-existent directory")
	}
}

// TestDirectoryMatchesDesired_ReturnsFalseForRegularFile verifies that a
// regular file (not a directory) is not considered a match.
func TestDirectoryMatchesDesired_ReturnsFalseForRegularFile(t *testing.T) {
	e := NewExecutor(nil, nil)
	// /etc/hostname is a regular file on most systems
	if e.directoryMatchesDesired(context.Background(), "/etc/hostname", &pb.DirectoryParams{}) {
		t.Error("directoryMatchesDesired must return false for a regular file")
	}
}

// TestIsProtectedPath_CriticalFiles verifies that each entry in the
// criticalFiles denylist is individually recognized.
func TestIsProtectedPath_CriticalFiles(t *testing.T) {
	for _, path := range criticalFiles {
		t.Run(path, func(t *testing.T) {
			if !isCriticalFile(path) {
				t.Errorf("isCriticalFile(%q) = false, want true", path)
			}
		})
	}
	// Non-critical files should not match
	if isCriticalFile("/etc/hosts.allow") {
		t.Error("/etc/hosts.allow is not in the denylist, must not be critical")
	}
	if isCriticalFile("/etc/ssh/sshd_config.d/01-pm-test.conf") {
		t.Error("drop-in config file must not be flagged as critical")
	}
}

// TestIsProtectedPath_TopLevelChildren verifies that immediate children of /
// are protected (the "any immediate child of /" rule).
func TestIsProtectedPath_TopLevelChildren(t *testing.T) {
	if !isProtectedPath("/lost+found") {
		t.Error("immediate child of / (lost+found) must be protected")
	}
	if !isProtectedPath("/opt") {
		t.Error("immediate child of / (opt) must be protected")
	}
}

// TestIsProtectedPath_DenyAllUnderEtc verifies that sysfs.IsUnderProtectedPrefix
// blocks deletion under /etc. This mirrors the TestExecuteDirectory_ABSENT_DenyByDefault
// test but covers the PATH-level protection (not action-level).
func TestIsProtectedPath_DeniesEtcSubdirs(t *testing.T) {
	protectedSubdirs := []string{
		"/etc/sudoers.d",
		"/etc/systemd/system",
		"/etc/ssh",
		"/etc/pam.d",
	}
	for _, path := range protectedSubdirs {
		t.Run(path, func(t *testing.T) {
			// Mirror the exact guard the directory/file ABSENT handlers apply: a
			// path is refused if it is in the agent's own denylist OR under a
			// protected prefix. A regression in either branch (a new /etc subtree
			// slipping through) fails here.
			if !isProtectedPath(path) && !sysfs.IsUnderProtectedPrefix(path) {
				t.Errorf("%s must be refused by the protection guard (isProtectedPath || IsUnderProtectedPrefix)", path)
			}
		})
	}
}

// TestExecuteFile_RejectsBeforePrivilegedRemount verifies that a protected file
// is rejected BEFORE requireWritableFS (remount) is called. The existing
// action_file_protected_test.go covers this for ABSENT critical files; this
// test covers the PRESENT overwrite path for critical files.
func TestExecuteFile_PRESENT_RejectsBeforeRemount(t *testing.T) {
	var remountCalled bool
	e := NewExecutor(nil, nil)
	e.repairFS = func(ctx context.Context) bool {
		remountCalled = true
		return true
	}
	// /etc/sudoers is in criticalFiles — PRESENT must refuse to overwrite it
	params := &pb.FileParams{Path: "/etc/sudoers", Content: "# evil config"}
	_, _, err := e.executeFile(context.Background(), params, pb.DesiredState_DESIRED_STATE_PRESENT)
	if err == nil {
		t.Fatal("expected error for PRESENT overwrite of sudoers, got nil")
	}
	if remountCalled {
		t.Error("requireWritableFS must NOT be called for a critical-file PRESENT rejection")
	}
}
