package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

func TestGetArchEntry(t *testing.T) {
	amd := &pb.AgentUpdateArch{BinaryUrl: "https://example.com/amd64"}
	arm := &pb.AgentUpdateArch{BinaryUrl: "https://example.com/arm64"}
	params := &pb.AgentUpdateParams{Amd64: amd, Arm64: arm}

	entry := getArchEntry(params)
	if entry == nil {
		t.Fatal("expected non-nil arch entry for current runtime")
	}
}

func TestGetArchEntry_NilForMissing(t *testing.T) {
	// Only arm64 set, if we're on amd64 this returns nil (or vice versa)
	params := &pb.AgentUpdateParams{}
	entry := getArchEntry(params)
	if entry != nil {
		t.Error("expected nil for empty params")
	}
}

func TestDownloadToFile(t *testing.T) {
	content := []byte("test binary content")
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(content)
	}))
	defer srv.Close()

	tmpFile, err := os.CreateTemp(t.TempDir(), "dl-test-*")
	if err != nil {
		t.Fatal(err)
	}
	defer tmpFile.Close()

	checksum, err := downloadToFile(context.Background(), srv.Client(), srv.URL+"/binary", tmpFile)
	if err != nil {
		t.Fatal(err)
	}

	expectedHash := sha256.Sum256(content)
	expected := hex.EncodeToString(expectedHash[:])
	if checksum != expected {
		t.Errorf("checksum mismatch: got %s, want %s", checksum, expected)
	}
}

// writeStateForTest writes the legacy update/state.json that the
// production self-test path no longer creates. The reader and the
// startup cleanup still consume the format (for crash recovery from
// an older agent that wrote one), so the read+clear round-trip stays
// covered. Audit F018: the production writer was deleted; tests
// fabricate the file directly.
func writeStateForTest(t *testing.T, dataDir, phase, version string) {
	t.Helper()
	dir := filepath.Join(dataDir, "update")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	data := fmt.Sprintf(`{"phase":%q,"version":%q}`, phase, version)
	if err := os.WriteFile(filepath.Join(dir, "state.json"), []byte(data), 0o600); err != nil {
		t.Fatalf("write state.json: %v", err)
	}
}

func TestWriteAndReadUpdateState(t *testing.T) {
	dir := t.TempDir()

	writeStateForTest(t, dir, "staged", "v2026.04.01")

	phase, version, err := readUpdateState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if phase != "staged" {
		t.Errorf("phase = %q, want %q", phase, "staged")
	}
	if version != "v2026.04.01" {
		t.Errorf("version = %q, want %q", version, "v2026.04.01")
	}
}

func TestReadUpdateState_NotFound(t *testing.T) {
	dir := t.TempDir()
	phase, version, err := readUpdateState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if phase != "" || version != "" {
		t.Errorf("expected empty state for missing file, got phase=%q version=%q", phase, version)
	}
}

func TestClearUpdateState(t *testing.T) {
	dir := t.TempDir()
	writeStateForTest(t, dir, "staged", "v1.0")
	clearUpdateState(dir)

	phase, _, err := readUpdateState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if phase != "" {
		t.Errorf("expected empty phase after clear, got %q", phase)
	}
}

func TestMarkAgentUpdateExecuted(t *testing.T) {
	// Per-instance dedup: each Executor owns its own flag (audit
	// F042 + F048). Construct a fresh Executor for the test and
	// exercise the methods directly instead of the deprecated
	// package-level globals.
	e := &Executor{now: time.Now}

	// First call should succeed
	if !e.markAgentUpdateExecuted() {
		t.Error("expected first markAgentUpdateExecuted to return true")
	}

	// Second call should fail (already executed)
	if e.markAgentUpdateExecuted() {
		t.Error("expected second markAgentUpdateExecuted to return false")
	}

	// After reset, should succeed again
	e.ResetUpdateCycle()
	if !e.markAgentUpdateExecuted() {
		t.Error("expected markAgentUpdateExecuted to return true after reset")
	}
}

func TestCheckStartupUpdateState_CleansStaleState(t *testing.T) {
	dir := t.TempDir()
	writeStateForTest(t, dir, "staged", "2026.04.01")

	logger := &testLogger{}
	CheckStartupUpdateState(dir, logger, time.Now)

	// State should be cleared
	phase, _, _ := readUpdateState(dir)
	if phase != "" {
		t.Errorf("expected state to be cleared, got phase=%q", phase)
	}

	if len(logger.infos) == 0 {
		t.Error("expected info log for stale state cleanup")
	}
}

func TestCheckStartupUpdateState_NoState(t *testing.T) {
	dir := t.TempDir()

	logger := &testLogger{}
	CheckStartupUpdateState(dir, logger, time.Now)

	// No logs expected
	if len(logger.infos) > 0 || len(logger.warns) > 0 {
		t.Error("expected no logs for clean startup without state file")
	}
}

func TestGetBinaryVersion(t *testing.T) {
	// Create a fake binary that prints a version
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-agent")
	err := os.WriteFile(script, []byte("#!/bin/sh\necho 'v2026.04.01'\n"), 0755)
	if err != nil {
		t.Fatal(err)
	}

	version, err := getBinaryVersion(script)
	if err != nil {
		t.Fatal(err)
	}
	if version != "v2026.04.01" {
		t.Errorf("version = %q, want %q", version, "v2026.04.01")
	}
}

func TestGetBinaryVersion_Empty(t *testing.T) {
	dir := t.TempDir()
	script := filepath.Join(dir, "fake-agent")
	err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0755)
	if err != nil {
		t.Fatal(err)
	}

	_, err = getBinaryVersion(script)
	if err == nil {
		t.Error("expected error for empty version output")
	}
}

func TestSelfTestScript_ExitCode(t *testing.T) {
	// Test that a shell script returning exit 0 vs exit 1 is correctly detected.
	// This validates the exec.CommandContext pattern used in executeAgentUpdate.
	dir := t.TempDir()

	// Create a "binary" that exits 0
	successScript := filepath.Join(dir, "success")
	os.WriteFile(successScript, []byte("#!/bin/sh\nexit 0\n"), 0755)

	// Create a "binary" that exits 1
	failScript := filepath.Join(dir, "fail")
	os.WriteFile(failScript, []byte("#!/bin/sh\necho 'connection failed' >&2\nexit 1\n"), 0755)

	ctx := context.Background()

	// Success case
	cmd := exec.CommandContext(ctx, successScript)
	if err := cmd.Run(); err != nil {
		t.Errorf("expected exit 0 script to succeed, got: %v", err)
	}

	// Failure case
	cmd = exec.CommandContext(ctx, failScript)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Error("expected exit 1 script to fail")
	}
	if !strings.Contains(string(out), "connection failed") {
		t.Errorf("expected error output, got: %s", string(out))
	}
}

// testLogger is a simple logger for testing.
type testLogger struct {
	infos  []string
	warns  []string
	errors []string
}

func (l *testLogger) Info(msg string, args ...any) {
	l.infos = append(l.infos, msg)
}

func (l *testLogger) Warn(msg string, args ...any) {
	l.warns = append(l.warns, msg)
}

func (l *testLogger) Error(msg string, args ...any) {
	l.errors = append(l.errors, msg)
}

// TestNoStaleSwapComment is a self-discovering guard against the WS7 #8
// stale comment: the agent-update flow no longer does cp → chmod → mv, it
// uses SafeBackupAndReplace. Pins the source so a future edit can't
// reintroduce the misleading description.
func TestNoStaleSwapComment(t *testing.T) {
	src, err := os.ReadFile("agent_update.go")
	if err != nil {
		t.Fatalf("read agent_update.go: %v", err)
	}
	s := string(src)
	if strings.Contains(s, "cp → chmod → mv") {
		t.Error("agent_update.go still describes the swap as 'cp → chmod → mv'; it uses SafeBackupAndReplace")
	}
	if !strings.Contains(s, "SafeBackupAndReplace") {
		t.Error("agent_update.go should document the swap goes through SafeBackupAndReplace")
	}
}
