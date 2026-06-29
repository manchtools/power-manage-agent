package executor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// TestStatFile_RejectsSymlink pins the fail-closed contract of the statFile
// chokepoint: it must NOT follow a symlink. Following one lets a symlinked
// privileged path be reported as an already-matching regular file/dir, so the
// idempotency check skips the guarded write and leaves an attacker-controlled
// link in place. A symlink must read as an error so the caller falls through to
// the privilege-routed write instead.
func TestStatFile_RejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o644); err != nil {
		t.Fatalf("write target: %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	if _, err := statFile(context.Background(), link); err == nil {
		t.Fatal("statFile must reject a symlink (fail closed), got nil error")
	}
	// A real regular file still stats cleanly.
	if _, err := statFile(context.Background(), target); err != nil {
		t.Fatalf("statFile on a regular file must succeed, got %v", err)
	}
}
