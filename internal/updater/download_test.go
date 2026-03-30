package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestDownloadAndVerify_Success(t *testing.T) {
	content := []byte("#!/bin/bash\necho hello\n")
	sum := sha256.Sum256(content)
	checksum := hex.EncodeToString(sum[:])

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(content)
	}))
	defer server.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "agent.new")

	if err := DownloadAndVerify(context.Background(), server.URL, checksum, dest); err != nil {
		t.Fatalf("DownloadAndVerify: %v", err)
	}

	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	if string(got) != string(content) {
		t.Fatalf("content mismatch: got %q, want %q", got, content)
	}

	info, err := os.Stat(dest)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if info.Mode().Perm() != 0755 {
		t.Fatalf("permissions: got %o, want 0755", info.Mode().Perm())
	}
}

func TestDownloadAndVerify_ChecksumMismatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("some content"))
	}))
	defer server.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "agent.new")

	err := DownloadAndVerify(context.Background(), server.URL, "0000000000000000000000000000000000000000000000000000000000000000", dest)
	if err == nil {
		t.Fatal("expected checksum mismatch error")
	}

	// Verify the destination file was NOT created (cleanup on failure).
	if _, err := os.Stat(dest); !os.IsNotExist(err) {
		t.Fatal("expected dest file to be cleaned up after failure")
	}
}

func TestDownloadAndVerify_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	dir := t.TempDir()
	dest := filepath.Join(dir, "agent.new")

	err := DownloadAndVerify(context.Background(), server.URL, "abc123", dest)
	if err == nil {
		t.Fatal("expected error for HTTP 404")
	}
}

func TestDownloadAndVerify_ContextCanceled(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("data"))
	}))
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	dir := t.TempDir()
	dest := filepath.Join(dir, "agent.new")

	err := DownloadAndVerify(ctx, server.URL, "abc123", dest)
	if err == nil {
		t.Fatal("expected error for canceled context")
	}
}
