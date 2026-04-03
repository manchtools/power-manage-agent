package updater

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestReadState_NoFile(t *testing.T) {
	dir := t.TempDir()
	state, err := ReadState(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if state != nil {
		t.Fatalf("expected nil state, got %+v", state)
	}
}

func TestWriteAndReadState(t *testing.T) {
	dir := t.TempDir()
	want := &State{Phase: "complete", Version: "2026.04.1"}

	if err := WriteState(dir, want); err != nil {
		t.Fatalf("WriteState: %v", err)
	}

	got, err := ReadState(dir)
	if err != nil {
		t.Fatalf("ReadState: %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil state")
	}
	if got.Phase != want.Phase || got.Version != want.Version {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestClearState(t *testing.T) {
	dir := t.TempDir()
	if err := WriteState(dir, &State{Phase: "complete", Version: "1.0"}); err != nil {
		t.Fatalf("WriteState: %v", err)
	}

	ClearState(dir)

	state, err := ReadState(dir)
	if err != nil {
		t.Fatalf("ReadState after clear: %v", err)
	}
	if state != nil {
		t.Fatalf("expected nil state after clear, got %+v", state)
	}
}

func TestReadState_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	udir := filepath.Join(dir, "update")
	if err := os.MkdirAll(udir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(udir, "state.json"), []byte("{invalid"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := ReadState(dir)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestWriteAndReadCooldown(t *testing.T) {
	dir := t.TempDir()
	version := "2026.04.2"
	duration := 1 * time.Hour

	if err := WriteCooldown(dir, version, duration); err != nil {
		t.Fatalf("WriteCooldown: %v", err)
	}

	c, err := ReadCooldown(dir)
	if err != nil {
		t.Fatalf("ReadCooldown: %v", err)
	}
	if c == nil {
		t.Fatal("expected non-nil cooldown")
	}
	if c.Version != version {
		t.Fatalf("version: got %q, want %q", c.Version, version)
	}
	if time.Until(c.Until) < 59*time.Minute {
		t.Fatalf("cooldown Until too soon: %v", c.Until)
	}
}

func TestReadCooldown_NoFile(t *testing.T) {
	dir := t.TempDir()
	c, err := ReadCooldown(dir)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if c != nil {
		t.Fatalf("expected nil cooldown, got %+v", c)
	}
}

func TestIsCoolingDown_Active(t *testing.T) {
	dir := t.TempDir()
	version := "2026.04.3"

	if err := WriteCooldown(dir, version, 1*time.Hour); err != nil {
		t.Fatalf("WriteCooldown: %v", err)
	}

	if !IsCoolingDown(dir, version) {
		t.Fatal("expected cooling down for matching version")
	}
}

func TestIsCoolingDown_Expired(t *testing.T) {
	dir := t.TempDir()
	version := "2026.04.3"

	// Write a cooldown that is already expired.
	if err := WriteCooldown(dir, version, -1*time.Hour); err != nil {
		t.Fatalf("WriteCooldown: %v", err)
	}

	if IsCoolingDown(dir, version) {
		t.Fatal("expected not cooling down for expired cooldown")
	}
}

func TestIsCoolingDown_DifferentVersion(t *testing.T) {
	dir := t.TempDir()

	if err := WriteCooldown(dir, "2026.04.3", 1*time.Hour); err != nil {
		t.Fatalf("WriteCooldown: %v", err)
	}

	if IsCoolingDown(dir, "2026.04.4") {
		t.Fatal("expected not cooling down for different version")
	}
}

func TestIsCoolingDown_NoFile(t *testing.T) {
	dir := t.TempDir()
	if IsCoolingDown(dir, "any") {
		t.Fatal("expected not cooling down when no file exists")
	}
}

func TestWriteState_CreatesDirectory(t *testing.T) {
	dir := t.TempDir()
	// Remove the temp dir to test directory creation
	subdir := filepath.Join(dir, "nested", "data")

	if err := WriteState(subdir, &State{Phase: "staged", Version: "1.0"}); err != nil {
		t.Fatalf("WriteState should create directories: %v", err)
	}

	state, err := ReadState(subdir)
	if err != nil {
		t.Fatalf("ReadState: %v", err)
	}
	if state == nil || state.Phase != "staged" {
		t.Fatalf("unexpected state: %+v", state)
	}
}

func TestUpdateDir(t *testing.T) {
	got := updateDir("/var/lib/power-manage")
	want := "/var/lib/power-manage/update"
	if got != want {
		t.Fatalf("updateDir: got %q, want %q", got, want)
	}
}
