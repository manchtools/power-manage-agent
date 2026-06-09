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
