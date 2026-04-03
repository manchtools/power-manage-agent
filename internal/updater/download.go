// Package updater handles the complete auto-update lifecycle for the agent.
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
)

// DownloadAndVerify downloads a file from url, verifies it matches the expected
// SHA256 hex checksum, and atomically moves it to destPath.
func DownloadAndVerify(ctx context.Context, url, checksum, destPath string) error {
	// Ensure the destination directory exists (first update on a fresh agent).
	dir := filepath.Dir(destPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("create destination dir: %w", err)
	}

	// Create temp file in the same directory as destPath so rename is atomic.
	tmp, err := os.CreateTemp(dir, "pm-update-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmp.Name()

	// Ensure cleanup on any failure path.
	defer func() {
		tmp.Close()
		os.Remove(tmpPath)
	}()

	// Download the file.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download: unexpected status %d", resp.StatusCode)
	}

	// Stream to disk while computing SHA256.
	hasher := sha256.New()
	w := io.MultiWriter(tmp, hasher)

	if _, err := io.Copy(w, resp.Body); err != nil {
		return fmt.Errorf("download write: %w", err)
	}

	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp file: %w", err)
	}

	// Verify checksum.
	actual := hex.EncodeToString(hasher.Sum(nil))
	if actual != checksum {
		return fmt.Errorf("checksum mismatch: expected %s, got %s", checksum, actual)
	}

	// Make executable before rename.
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return fmt.Errorf("chmod temp file: %w", err)
	}

	// Atomic rename to final destination.
	if err := os.Rename(tmpPath, destPath); err != nil {
		return fmt.Errorf("rename to dest: %w", err)
	}

	return nil
}
