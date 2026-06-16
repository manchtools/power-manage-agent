// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysfs "github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// sha256File streams the file at path through sha256 and returns
// the hex digest. Used by checksum-gated install paths so AppImage
// (and any other large-file action) can verify identity without
// buffering the entire payload — an io.ReadAll + sha256.Sum256
// pattern would push tens-to-hundreds of megabytes through the
// heap on every idempotency check.
func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (e *Executor) executeAppImage(ctx context.Context, params *pb.AppInstallParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("app params required")
	}

	installPath := params.InstallPath
	if installPath == "" {
		installPath = "/opt/appimages"
	}

	// Validate the download URL BEFORE deriving the on-disk
	// filename. The previous shape ran filepath.Base(params.Url)
	// directly, so a URL like "https://evil.example/../../etc/" or
	// a malformed input could produce a path-meaningful filename
	// and either escape installPath or land on an unexpected name.
	// Require a parseable HTTPS URL with a non-empty host (WS7 #2:
	// https-only — the previous code also allowed http://); derive the
	// filename from a path segment that has no slashes or other directory
	// components.
	parsedURL, err := url.Parse(strings.TrimSpace(params.Url))
	if err != nil ||
		parsedURL.Scheme != "https" ||
		parsedURL.Opaque != "" ||
		parsedURL.Host == "" {
		return nil, false, fmt.Errorf("invalid appimage URL (must be https): %q", params.Url)
	}
	filename := filepath.Base(parsedURL.Path)
	// Reject ".." too — filepath.Base of e.g. https://x.example/.. returns
	// "..", which would land at the parent of installPath when joined.
	if filename == "." || filename == ".." || filename == "/" || filename == "" || strings.ContainsAny(filename, `/\`) {
		return nil, false, fmt.Errorf("appimage URL %q does not yield a usable filename", params.Url)
	}

	// Defense-in-depth (parity with rpm/deb): refuse to INSTALL an unverified
	// artifact — require https + a non-empty checksum — before any path
	// resolution, privileged remount, or download. The control server validator
	// already mandates a checksum for AppInstallParams, so this is belt-and-
	// suspenders, not a behaviour change for legitimate dispatches. ABSENT
	// (removal) needs no checksum, so the guard is PRESENT-only.
	if state == pb.DesiredState_DESIRED_STATE_PRESENT {
		if err := requireVerifiedArtifact(params.Url, params.ChecksumSha256); err != nil {
			return nil, false, err
		}
	}

	fullPath := filepath.Join(installPath, filename)

	// Resolve symlinks to prevent traversal attacks
	resolvedPath, err := sysfs.ResolveAndValidatePath(fullPath)
	if err != nil {
		return nil, false, fmt.Errorf("invalid path: %w", err)
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Check if file already exists with correct checksum.
		// Stream-hash the existing file rather than os.ReadFile +
		// sha256.Sum256 — AppImages are routinely tens to hundreds
		// of megabytes; buffering the entire payload to derive a
		// hash that's compared once is wasteful and risks tipping
		// the agent into OOM territory on small VMs.
		if params.ChecksumSha256 != "" {
			if actualHash, hashErr := sha256File(resolvedPath); hashErr == nil {
				// EqualFold + TrimSpace: sha256File returns lowercase
				// hex, but operators commonly paste uppercase hashes
				// from `sha256sum` output / web pages / clipboard
				// trimming. Without case-insensitive compare an
				// uppercase-but-correct checksum forces a redownload
				// on every run.
				if strings.EqualFold(actualHash, strings.TrimSpace(params.ChecksumSha256)) {
					return &pb.CommandOutput{
						ExitCode: 0,
						Stdout:   fmt.Sprintf("appimage %s already installed with correct checksum", filename),
					}, false, nil
				}
			}
		} else if _, err := os.Stat(resolvedPath); err == nil {
			// No checksum specified, file exists
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("appimage %s already installed", filename),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		// Create directory
		if err := os.MkdirAll(filepath.Dir(resolvedPath), 0755); err != nil {
			return nil, false, fmt.Errorf("create directory: %w", err)
		}

		// Download file
		if err := e.downloadFile(ctx, params.Url, resolvedPath, params.ChecksumSha256); err != nil {
			return nil, false, fmt.Errorf("download: %w", err)
		}

		// Make executable
		if err := os.Chmod(resolvedPath, 0755); err != nil {
			return nil, false, fmt.Errorf("chmod: %w", err)
		}

		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("installed %s to %s", filename, resolvedPath),
		}, true, nil

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		// Check if file already doesn't exist
		if _, err := os.Stat(resolvedPath); os.IsNotExist(err) {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("appimage %s already not present", filename),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		if err := os.Remove(resolvedPath); err != nil {
			return nil, false, fmt.Errorf("remove: %w", err)
		}
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("removed %s", resolvedPath),
		}, true, nil
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}
