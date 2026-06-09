package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDownloadFile(t *testing.T) {
	content := []byte("hello-appimage-payload")
	sum := sha256.Sum256(content)
	hexSum := hex.EncodeToString(sum[:])

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/404" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write(content)
	}))
	defer srv.Close()
	e := &Executor{httpClient: srv.Client()}
	ctx := context.Background()

	// Operators paste uppercase / whitespace-padded sha256 hashes; a
	// case-sensitive compare rejected a correct-but-uppercase checksum.
	t.Run("uppercase checksum is accepted", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "f")
		require.NoError(t, e.downloadFile(ctx, srv.URL+"/ok", dest, "  "+strings.ToUpper(hexSum)+"  "))
		got, _ := os.ReadFile(dest)
		assert.Equal(t, content, got)
	})

	// A failed download must not destroy an existing file at dest — the
	// previous os.Create truncated it in place before downloading.
	t.Run("failed download leaves the existing file intact", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "app")
		require.NoError(t, os.WriteFile(dest, []byte("WORKING"), 0o755))
		require.Error(t, e.downloadFile(ctx, srv.URL+"/404", dest, ""))
		got, _ := os.ReadFile(dest)
		assert.Equal(t, []byte("WORKING"), got, "existing file must survive a failed re-download")
	})

	t.Run("checksum mismatch leaves the existing file intact", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "app")
		require.NoError(t, os.WriteFile(dest, []byte("WORKING"), 0o755))
		require.Error(t, e.downloadFile(ctx, srv.URL+"/ok", dest, hex.EncodeToString(make([]byte, 32))))
		got, _ := os.ReadFile(dest)
		assert.Equal(t, []byte("WORKING"), got)
	})

	t.Run("successful download writes the content", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "app")
		require.NoError(t, os.WriteFile(dest, []byte("OLD"), 0o755))
		require.NoError(t, e.downloadFile(ctx, srv.URL+"/ok", dest, hexSum))
		got, _ := os.ReadFile(dest)
		assert.Equal(t, content, got)
	})
}

// A response exceeding maxDownloadSize must be rejected, and — like every
// other failure path — must NOT clobber an existing file at dest (the
// temp-file-then-rename rewrite's whole point). The cap is shrunk via the
// test seam so the branch is reachable without streaming 2 GiB.
func TestDownloadFile_OversizeRejectedAndLeavesDestIntact(t *testing.T) {
	oversize := make([]byte, 200)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Flush after the first write so the response goes out chunked
		// with NO Content-Length — this bypasses the early ContentLength
		// check and forces the rewritten streamed-size guard (written >
		// maxDownloadSize) to be what rejects the body.
		_, _ = w.Write(oversize)
		if f, ok := w.(http.Flusher); ok {
			f.Flush()
		}
		_, _ = w.Write(oversize)
	}))
	defer srv.Close()

	orig := maxDownloadSize
	maxDownloadSize = 16
	t.Cleanup(func() { maxDownloadSize = orig })

	e := &Executor{httpClient: srv.Client()}
	dest := filepath.Join(t.TempDir(), "app")
	require.NoError(t, os.WriteFile(dest, []byte("WORKING"), 0o755))

	err := e.downloadFile(context.Background(), srv.URL+"/ok", dest, "")
	require.Error(t, err, "a body over the cap must be rejected")
	assert.Contains(t, err.Error(), "maximum size")
	got, _ := os.ReadFile(dest)
	assert.Equal(t, []byte("WORKING"), got, "an oversize download must not destroy the existing file")
}
