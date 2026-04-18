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

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

func TestValidateHTTPS(t *testing.T) {
	tests := []struct {
		url     string
		wantErr bool
	}{
		{"https://example.com/binary", false},
		{"http://example.com/binary", true},
		{"ftp://example.com/binary", true},
		{"", true},
	}
	for _, tt := range tests {
		err := validateHTTPS(tt.url)
		if (err != nil) != tt.wantErr {
			t.Errorf("validateHTTPS(%q) error = %v, wantErr %v", tt.url, err, tt.wantErr)
		}
	}
}

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

func TestDownloadAndExtractChecksum(t *testing.T) {
	checksumContent := "abc123def456  some-other-binary\n" +
		"deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567  power-manage-agent-linux-amd64\n" +
		"1111111122222222333333334444444455555555666666667777777788888888  power-manage-agent-linux-arm64\n"

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(checksumContent))
	}))
	defer srv.Close()

	client := srv.Client()

	checksum, err := downloadAndExtractChecksum(context.Background(), client, srv.URL+"/SHA256SUMS", "power-manage-agent-linux-amd64")
	if err != nil {
		t.Fatal(err)
	}
	if checksum != "deadbeef0123456789abcdef0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("unexpected checksum: %s", checksum)
	}
}

func TestDownloadAndExtractChecksum_NotFound(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("abc123  other-binary\n"))
	}))
	defer srv.Close()

	_, err := downloadAndExtractChecksum(context.Background(), srv.Client(), srv.URL+"/SHA256SUMS", "nonexistent")
	if err == nil {
		t.Error("expected error for missing binary in checksum file")
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

func TestWriteAndReadUpdateState(t *testing.T) {
	dir := t.TempDir()

	err := writeUpdateState(dir, "staged", "v2026.04.01")
	if err != nil {
		t.Fatal(err)
	}

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
	writeUpdateState(dir, "staged", "v1.0")
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
	// Reset first
	ResetAgentUpdateCycle()

	// First call should succeed
	if !markAgentUpdateExecuted() {
		t.Error("expected first markAgentUpdateExecuted to return true")
	}

	// Second call should fail (already executed)
	if markAgentUpdateExecuted() {
		t.Error("expected second markAgentUpdateExecuted to return false")
	}

	// After reset, should succeed again
	ResetAgentUpdateCycle()
	if !markAgentUpdateExecuted() {
		t.Error("expected markAgentUpdateExecuted to return true after reset")
	}
}

func TestCheckStartupUpdateState_CleansStaleState(t *testing.T) {
	dir := t.TempDir()
	writeUpdateState(dir, "staged", "2026.04.01")

	logger := &testLogger{}
	CheckStartupUpdateState(dir, logger)

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
	CheckStartupUpdateState(dir, logger)

	// No logs expected
	if len(logger.infos) > 0 || len(logger.warns) > 0 {
		t.Error("expected no logs for clean startup without state file")
	}
}

func TestDownloadAndExtractChecksum_WithPrefixes(t *testing.T) {
	// Test with "./" and "*" prefixes (common in SHA256SUMS files)
	checksumContent := fmt.Sprintf(
		"%s  ./my-binary\n%s  *other-binary\n",
		"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(checksumContent))
	}))
	defer srv.Close()

	// Should find "my-binary" even with "./" prefix
	checksum, err := downloadAndExtractChecksum(context.Background(), srv.Client(), srv.URL+"/SHA256SUMS", "my-binary")
	if err != nil {
		t.Fatal(err)
	}
	if checksum != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("unexpected checksum: %s", checksum)
	}

	// Should find "other-binary" even with "*" prefix
	checksum, err = downloadAndExtractChecksum(context.Background(), srv.Client(), srv.URL+"/SHA256SUMS", "other-binary")
	if err != nil {
		t.Fatal(err)
	}
	if checksum != "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" {
		t.Errorf("unexpected checksum: %s", checksum)
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

func TestExtractFilename(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{"https://github.com/org/repo/releases/latest/download/agent-linux-amd64", "agent-linux-amd64"},
		{"https://s3.amazonaws.com/bucket/agent-linux-amd64?X-Amz-Signature=abc&token=xyz", "agent-linux-amd64"},
		{"https://example.com/path/to/binary?v=2", "binary"},
		{"https://example.com/binary", "binary"},
	}
	for _, tt := range tests {
		got := extractFilename(tt.url)
		if got != tt.want {
			t.Errorf("extractFilename(%q) = %q, want %q", tt.url, got, tt.want)
		}
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
