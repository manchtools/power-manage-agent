package updater

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// gitHubRelease is the relevant subset of the GitHub Releases API response.
type gitHubRelease struct {
	TagName string        `json:"tag_name"`
	Assets  []gitHubAsset `json:"assets"`
}

// gitHubAsset represents a single release asset.
type gitHubAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

// CheckGitHubRelease queries the GitHub Releases API for the latest release
// of the given repo (e.g. "manchtools/power-manage-agent"). It returns the
// new version, download URL, and SHA256 checksum for the matching architecture.
//
// Returns empty strings (and nil error) if the latest release matches
// currentVersion, indicating no update is needed.
func CheckGitHubRelease(ctx context.Context, repo, currentVersion, arch string) (version, url, checksum string, err error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	apiURL := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiURL, nil)
	if err != nil {
		return "", "", "", fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", "", fmt.Errorf("github api: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", "", fmt.Errorf("github api: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", "", fmt.Errorf("read response: %w", err)
	}

	var release gitHubRelease
	if err := json.Unmarshal(body, &release); err != nil {
		return "", "", "", fmt.Errorf("parse release: %w", err)
	}

	// Strip leading "v" for comparison (tags are "v2026.04.1", versions are "2026.04.1").
	latestVersion := strings.TrimPrefix(release.TagName, "v")
	if latestVersion == currentVersion {
		return "", "", "", nil
	}

	// Find the matching binary asset for this architecture.
	// Expected naming: power-manage-agent-linux-{arch}
	binaryName := fmt.Sprintf("power-manage-agent-linux-%s", arch)
	var binaryURL string
	for _, asset := range release.Assets {
		if asset.Name == binaryName {
			binaryURL = asset.BrowserDownloadURL
			break
		}
	}
	if binaryURL == "" {
		return "", "", "", fmt.Errorf("no binary asset found for arch %s in release %s", arch, release.TagName)
	}

	// Find and download the SHA256SUMS asset.
	var sumsURL string
	for _, asset := range release.Assets {
		if asset.Name == "SHA256SUMS" {
			sumsURL = asset.BrowserDownloadURL
			break
		}
	}
	if sumsURL == "" {
		return "", "", "", fmt.Errorf("no SHA256SUMS asset found in release %s", release.TagName)
	}

	sha256sum, err := fetchChecksum(ctx, sumsURL, binaryName)
	if err != nil {
		return "", "", "", fmt.Errorf("fetch checksum: %w", err)
	}

	return latestVersion, binaryURL, sha256sum, nil
}

// fetchChecksum downloads the SHA256SUMS file and extracts the checksum for
// the given filename. The expected format is "hash  filename" per line.
func fetchChecksum(ctx context.Context, sumsURL, filename string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, sumsURL, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("download checksums: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("download checksums: unexpected status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		// Format: "sha256hash  filename" (two spaces between hash and name)
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[1] == filename {
			return parts[0], nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("scan checksums: %w", err)
	}

	return "", fmt.Errorf("checksum not found for %s", filename)
}
