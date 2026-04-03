package updater

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFetchChecksum_Success(t *testing.T) {
	checksumContent := `abc123def456  power-manage-agent-linux-amd64
789012fed345  power-manage-agent-linux-arm64
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(checksumContent))
	}))
	defer server.Close()

	checksum, err := fetchChecksum(context.Background(), server.URL, "power-manage-agent-linux-amd64")
	if err != nil {
		t.Fatalf("fetchChecksum: %v", err)
	}
	if checksum != "abc123def456" {
		t.Fatalf("checksum: got %q, want %q", checksum, "abc123def456")
	}
}

func TestFetchChecksum_Arm64(t *testing.T) {
	checksumContent := `abc123def456  power-manage-agent-linux-amd64
789012fed345  power-manage-agent-linux-arm64
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(checksumContent))
	}))
	defer server.Close()

	checksum, err := fetchChecksum(context.Background(), server.URL, "power-manage-agent-linux-arm64")
	if err != nil {
		t.Fatalf("fetchChecksum: %v", err)
	}
	if checksum != "789012fed345" {
		t.Fatalf("checksum: got %q, want %q", checksum, "789012fed345")
	}
}

func TestFetchChecksum_NotFound(t *testing.T) {
	checksumContent := `abc123def456  power-manage-agent-linux-amd64
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(checksumContent))
	}))
	defer server.Close()

	_, err := fetchChecksum(context.Background(), server.URL, "power-manage-agent-linux-riscv64")
	if err == nil {
		t.Fatal("expected error for missing architecture")
	}
}

func TestFetchChecksum_HTTPError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := fetchChecksum(context.Background(), server.URL, "power-manage-agent-linux-amd64")
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
}

func TestFetchChecksum_EmptyResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(""))
	}))
	defer server.Close()

	_, err := fetchChecksum(context.Background(), server.URL, "power-manage-agent-linux-amd64")
	if err == nil {
		t.Fatal("expected error for empty checksum file")
	}
}

func TestFetchChecksum_MalformedLines(t *testing.T) {
	// Lines with wrong number of fields should be skipped.
	checksumContent := `
only-one-field
abc123  power-manage-agent-linux-amd64
too many   fields here
`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(checksumContent))
	}))
	defer server.Close()

	checksum, err := fetchChecksum(context.Background(), server.URL, "power-manage-agent-linux-amd64")
	if err != nil {
		t.Fatalf("fetchChecksum: %v", err)
	}
	if checksum != "abc123" {
		t.Fatalf("checksum: got %q, want %q", checksum, "abc123")
	}
}
