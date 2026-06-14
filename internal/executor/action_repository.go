// Package executor provides implementations for action executors.
package executor

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/pkg"
	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// rpmImportArgs builds `rpm --import -- <ref>` so a flag-shaped GPG key
// ref can never be reparsed as an option to `rpm --import`. The ref's
// grammar is enforced upstream by pkg.ValidateGpgKeyRef in
// validateRepositoryParams; this is the argv-shape half of that guard.
func rpmImportArgs(ref string) []string {
	return sysexec.SeparatePositionals([]string{"--import"}, ref)
}

// executeRepository configures an external package repository.
func (e *Executor) executeRepository(ctx context.Context, params *pb.RepositoryParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("repository params required")
	}

	if params.Name == "" {
		return nil, false, fmt.Errorf("repository name required")
	}

	// Validate BEFORE requireWritableFS: requireWritableFS can
	// invoke sudo-backed remount/repair on a read-only root, so
	// dispatching it for a malformed action (invalid name, oversized
	// name, newline injection in a URL/GPG field, etc.) leaks
	// privileged side-effects that the action should have been
	// rejected for up front. Keep validation cheap and before any
	// system mutation.
	if !validRepoName.MatchString(params.Name) {
		return nil, false, fmt.Errorf("invalid repository name: must match [a-zA-Z0-9][a-zA-Z0-9._-]*")
	}
	if len(params.Name) > 128 {
		return nil, false, fmt.Errorf("repository name too long: max 128 characters")
	}

	// Reject config-injection or shape-violating values in every
	// repository string field, not just URL/description. See
	// validateRepositoryParams for the per-field rules.
	if err := validateRepositoryParams(params); err != nil {
		return nil, false, err
	}

	// Per-manager skip-check moved BEFORE requireWritableFS: if
	// the action carries no config for the host's package manager,
	// it's a no-op and shouldn't trigger a sudo-backed remount on
	// a read-only root just to bail out on the first line of the
	// dispatcher. The skip path returns changed=false; remount
	// only fires when we're about to actually mutate state.
	switch {
	case pkg.IsApt():
		if params.Apt == nil || params.Apt.Disabled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   "skipped: no APT repository configuration provided",
			}, false, nil
		}
	case pkg.IsDnf():
		if params.Dnf == nil || params.Dnf.Disabled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   "skipped: no DNF repository configuration provided",
			}, false, nil
		}
	case pkg.IsPacman():
		if params.Pacman == nil || params.Pacman.Disabled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   "skipped: no Pacman repository configuration provided",
			}, false, nil
		}
	case pkg.IsZypper():
		if params.Zypper == nil || params.Zypper.Disabled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   "skipped: no Zypper repository configuration provided",
			}, false, nil
		}
	default:
		return nil, false, fmt.Errorf("no supported package manager found for repository configuration")
	}

	// Repair filesystem if mounted read-only. Only reached once we
	// know we have actual work to do for THIS host's package
	// manager — a no-op skip never triggers it.
	if out, err := e.requireWritableFS(ctx); err != nil {
		return out, false, err
	}

	switch {
	case pkg.IsApt():
		return e.executeAptRepository(ctx, params.Name, params.Apt, state)
	case pkg.IsDnf():
		return e.executeDnfRepository(ctx, params.Name, params.Dnf, state)
	case pkg.IsPacman():
		return e.executePacmanRepository(ctx, params.Name, params.Pacman, state)
	case pkg.IsZypper():
		return e.executeZypperRepository(ctx, params.Name, params.Zypper, state)
	default:
		// Unreachable: the per-manager skip switch above already
		// rejects unknown managers. Defensive return.
		return nil, false, fmt.Errorf("no supported package manager found for repository configuration")
	}
}

// cleanupConflictingAptRepos scans /etc/apt/sources.list.d/ for any repository configs
// that contain the given URL and removes them along with their associated GPG keys.
// This prevents "conflicting values set for option Signed-By" errors when the same
// repository URL was previously configured under a different name or with different keys.
// The skipRepoFile and skipKeyFile parameters specify files that should NOT be deleted
// (typically the target repository being configured).
//
// Returns true if any conflicting file was removed so the caller can
// flip the action's `changed` flag — silently removing config files
// while reporting `changed=false` would make compliance projections
// miss real on-disk state mutations.
func (e *Executor) cleanupConflictingAptRepos(ctx context.Context, url, skipRepoFile, skipKeyFile string, output *strings.Builder) bool {
	sourcesDir := "/etc/apt/sources.list.d"
	entries, err := os.ReadDir(sourcesDir)
	if err != nil {
		return false // Directory might not exist, that's fine
	}
	cleanedUp := false

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		filename := entry.Name()
		if !strings.HasSuffix(filename, ".sources") && !strings.HasSuffix(filename, ".list") {
			continue
		}

		filePath := filepath.Join(sourcesDir, filename)

		// Skip the target repository file we're about to create/update
		if filePath == skipRepoFile {
			continue
		}
		// Also skip if it's a legacy .list version of the same repo
		if strings.TrimSuffix(filePath, ".list")+".sources" == skipRepoFile {
			continue
		}

		content, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}

		// Check if this file contains our URL
		if !strings.Contains(string(content), url) {
			continue
		}

		output.WriteString(fmt.Sprintf("removing conflicting repository config: %s\n", filePath))
		cleanedUp = true

		// Extract Signed-By path from DEB822 format (.sources files)
		if strings.HasSuffix(filename, ".sources") {
			for _, line := range strings.Split(string(content), "\n") {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "Signed-By:") {
					keyPath := strings.TrimSpace(strings.TrimPrefix(line, "Signed-By:"))
					// Skip if this is our target key file
					if keyPath == skipKeyFile {
						continue
					}
					if keyPath != "" && strings.HasPrefix(keyPath, "/") {
						output.WriteString(fmt.Sprintf("removing associated GPG key: %s\n", keyPath))
						if _, err := runSudoCmd(ctx, "rm", "-f", "--", keyPath); err != nil {
							e.logger.Warn("cleanupConflictingAptRepos: failed to remove conflicting GPG key",
								"key_path", keyPath, "error", err)
						}
					}
				}
			}
		}

		// Extract signed-by from one-line format (.list files)
		// Format: deb [signed-by=/path/to/key.gpg] https://...
		if strings.HasSuffix(filename, ".list") {
			re := regexp.MustCompile(`signed-by=([^\s\]]+)`)
			matches := re.FindAllStringSubmatch(string(content), -1)
			for _, match := range matches {
				keyPath := match[1]
				// Skip if this is our target key file
				if keyPath == skipKeyFile {
					continue
				}
				if len(match) > 1 && strings.HasPrefix(keyPath, "/") {
					output.WriteString(fmt.Sprintf("removing associated GPG key: %s\n", keyPath))
					if _, err := runSudoCmd(ctx, "rm", "-f", "--", keyPath); err != nil {
						e.logger.Warn("cleanupConflictingAptRepos: failed to remove conflicting GPG key",
							"key_path", keyPath, "error", err)
					}
				}
			}
		}

		// Remove the repository file. A failure here would leave the
		// stale config in /etc/apt/sources.list.d/ and the next apt
		// update would still see the conflict — surface the error so
		// the operator can clean it up manually.
		if _, err := runSudoCmd(ctx, "rm", "-f", "--", filePath); err != nil {
			e.logger.Warn("cleanupConflictingAptRepos: failed to remove conflicting repo file",
				"file_path", filePath, "error", err)
		}
	}
	return cleanedUp
}

// executeAptRepository configures an APT repository.
// This function is idempotent - it checks if files already exist with correct content
// and only updates them if they differ.
func (e *Executor) executeAptRepository(ctx context.Context, name string, repo *pb.AptRepository, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	var output strings.Builder
	repoFile := fmt.Sprintf("/etc/apt/sources.list.d/%s.sources", name)
	keyFile := fmt.Sprintf("/etc/apt/keyrings/%s.gpg", name)

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		// Remove repository file
		if _, err := runSudoCmd(ctx, "rm", "-f", "--", repoFile); err != nil {
			return nil, false, fmt.Errorf("failed to remove repo file: %w", err)
		}
		// Also try to remove legacy .list format. A failed rm here
		// leaves a stale config that apt will still parse; surface
		// to the operator instead of silently swallowing.
		legacyFile := fmt.Sprintf("/etc/apt/sources.list.d/%s.list", name)
		if _, err := runSudoCmd(ctx, "rm", "-f", "--", legacyFile); err != nil {
			e.logger.Warn("apt ABSENT: failed to remove legacy repo file",
				"file", legacyFile, "error", err)
		}
		// Remove GPG key. A leftover key with no .sources file is
		// inert today but a future re-apply would compare against
		// the wrong fingerprint — log so the divergence is visible.
		if _, err := runSudoCmd(ctx, "rm", "-f", "--", keyFile); err != nil {
			e.logger.Warn("apt ABSENT: failed to remove GPG key",
				"key_file", keyFile, "error", err)
		}
		output.WriteString(fmt.Sprintf("removed repository: %s\n", name))
		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, true, nil

	case pb.DesiredState_DESIRED_STATE_PRESENT:
		changed := false

		// First, scan for and remove any existing repository configs that use the same URL
		// This prevents "conflicting values set for option Signed-By" errors when the same
		// repository was previously configured under a different name or with different keys
		// We skip our own repo file and key file to allow the comparison logic to work.
		// Track whether anything was removed so the action's `changed`
		// flag reflects the on-disk mutation — without this, an
		// idempotent re-apply that quietly resolves a conflict would
		// look like a no-op to compliance projections.
		if e.cleanupConflictingAptRepos(ctx, repo.Url, repoFile, keyFile, &output) {
			changed = true
		}

		// Clean up legacy .list file if it exists
		legacyFile := fmt.Sprintf("/etc/apt/sources.list.d/%s.list", name)
		if _, err := os.Stat(legacyFile); err == nil {
			output.WriteString(fmt.Sprintf("removing legacy repository file: %s\n", legacyFile))
			if _, err := runSudoCmd(ctx, "rm", "-f", "--", legacyFile); err != nil {
				e.logger.Warn("apt PRESENT: failed to remove legacy repo file",
					"file", legacyFile, "error", err)
			}
			changed = true
		}
		// Clean up legacy GPG key location
		legacyKeyFile := fmt.Sprintf("/etc/apt/trusted.gpg.d/%s.gpg", name)
		if _, err := os.Stat(legacyKeyFile); err == nil {
			output.WriteString(fmt.Sprintf("removing legacy GPG key: %s\n", legacyKeyFile))
			if _, err := runSudoCmd(ctx, "rm", "-f", "--", legacyKeyFile); err != nil {
				e.logger.Warn("apt PRESENT: failed to remove legacy GPG key",
					"key_file", legacyKeyFile, "error", err)
			}
			changed = true
		}

		// Ensure keyrings directory exists
		if _, err := runSudoCmd(ctx, "mkdir", "-p", "--", "/etc/apt/keyrings"); err != nil {
			return nil, false, fmt.Errorf("failed to create keyrings directory: %w", err)
		}

		// Import GPG key if provided
		// We download/process to a temp file first and only update if content differs
		if repo.GpgKeyUrl != "" || repo.GpgKey != "" {
			keyUpdated, keyErr := e.updateGpgKeyIfNeeded(ctx, keyFile, repo.GpgKeyUrl, repo.GpgKey, &output)
			if keyErr != nil {
				return &pb.CommandOutput{ExitCode: 1, Stdout: output.String(), Stderr: keyErr.Error()}, false, keyErr
			}
			if keyUpdated {
				output.WriteString("GPG key updated\n")
				changed = true
			} else {
				output.WriteString("GPG key unchanged\n")
			}
		}

		// Build DEB822 format sources file (modern format)
		var content strings.Builder
		content.WriteString(fmt.Sprintf("# Repository: %s\n", name))
		content.WriteString("Types: deb\n")
		content.WriteString(fmt.Sprintf("URIs: %s\n", repo.Url))

		if repo.Distribution != "" {
			content.WriteString(fmt.Sprintf("Suites: %s\n", repo.Distribution))
		} else {
			content.WriteString("Suites: /\n")
		}

		if len(repo.Components) > 0 {
			content.WriteString(fmt.Sprintf("Components: %s\n", strings.Join(repo.Components, " ")))
		}

		if repo.Arch != "" {
			content.WriteString(fmt.Sprintf("Architectures: %s\n", repo.Arch))
		}

		if repo.GpgKeyUrl != "" || repo.GpgKey != "" {
			content.WriteString(fmt.Sprintf("Signed-By: %s\n", keyFile))
		} else if repo.Trusted {
			content.WriteString("Trusted: yes\n")
		}

		// Compare with existing file — skip write and apt update if unchanged
		desiredContent := content.String()
		existing, _ := readFileWithSudo(ctx, repoFile)
		if existing == desiredContent && !changed {
			output.WriteString(fmt.Sprintf("repository already up to date: %s\n", name))
			return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, false, nil
		}

		// Write the sources file
		if existing != desiredContent {
			if _, err := writeFileWithSudo(ctx, repoFile, desiredContent); err != nil {
				return nil, false, fmt.Errorf("failed to write repo file: %w", err)
			}
			output.WriteString(fmt.Sprintf("configured repository: %s\n", name))
			changed = true
		}

		// Update package index only when something changed
		if changed {
			apt := pkg.NewAptWithContext(ctx)
			updateOutput, updateErr := apt.Update()
			if updateOutput != nil {
				output.WriteString(updateOutput.Stdout)
			}
			if updateErr != nil {
				// Mirror the dnf/pacman/zypper refresh-failure handling:
				// a typo'd repo URL or unreadable key fails the post-config
				// index refresh, but the repository file was still written.
				// Surface it (don't silently report a clean SUCCESS) while
				// keeping the configuration that did land.
				e.logger.Warn("apt PRESENT: failed to refresh package index after repo config",
					"repo", name, "error", updateErr)
				output.WriteString(fmt.Sprintf("warning: apt update failed after configuring %s: %v\n", name, updateErr))
			}
		}

		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, changed, nil

	default:
		return nil, false, fmt.Errorf("unknown desired state: %v", state)
	}
}

// updateGpgKeyIfNeeded downloads/processes a GPG key and only updates the target file if content differs.
// Returns true if the key was updated, false if unchanged.
func (e *Executor) updateGpgKeyIfNeeded(ctx context.Context, keyFile, keyUrl, keyContent string, output *strings.Builder) (bool, error) {
	// Validate URL scheme to prevent file:// or other protocol abuse
	if keyUrl != "" {
		if !strings.HasPrefix(keyUrl, "https://") {
			return false, fmt.Errorf("GPG key URL must use https:// scheme, got: %s", keyUrl)
		}
	}

	// Create a temp file for the new key under the agent's data dir
	// rather than $TMPDIR (audit F024). install.sh sets the systemd
	// unit's PrivateTmp=false so sudo keeps working, which means a
	// co-resident process in the same tmp namespace could otherwise
	// race the dearmor write. The agent's data dir is 0700 root-owned
	// and not shared, so a temp file underneath it isn't reachable by
	// other UIDs. Falls back to $TMPDIR only if the data dir isn't
	// configured (test paths, ad-hoc invocations).
	gpgTmpDir := ""
	if cfg := e.updateCfg; cfg != nil && cfg.DataDir != "" {
		gpgTmpDir = filepath.Join(cfg.DataDir, "gpg-tmp")
		if err := os.MkdirAll(gpgTmpDir, 0o700); err != nil {
			return false, fmt.Errorf("failed to create gpg-tmp dir %s: %w", gpgTmpDir, err)
		}
	}
	tempFile, err := os.CreateTemp(gpgTmpDir, "gpgkey-*.gpg")
	if err != nil {
		return false, fmt.Errorf("failed to create temp file: %w", err)
	}
	tempPath := tempFile.Name()
	_ = tempFile.Close()
	defer os.Remove(tempPath)

	// Obtain raw key bytes (download or use provided content)
	var rawKey []byte
	if keyUrl != "" {
		output.WriteString(fmt.Sprintf("downloading GPG key from %s\n", keyUrl))
		req, err := http.NewRequestWithContext(ctx, "GET", keyUrl, nil)
		if err != nil {
			return false, fmt.Errorf("failed to create GPG key request: %w", err)
		}
		resp, err := e.httpClient.Do(req)
		if err != nil {
			return false, fmt.Errorf("failed to download GPG key: %w", err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false, fmt.Errorf("GPG key download failed: HTTP %d", resp.StatusCode)
		}
		rawKey, err = io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10 MB limit
		if err != nil {
			return false, fmt.Errorf("failed to read GPG key response: %w", err)
		}
	} else if keyContent != "" {
		output.WriteString("processing GPG key from content\n")
		rawKey = []byte(keyContent)
	} else {
		return false, nil // No key to process
	}

	// Dearmor the key using gpg with stdin piping (no shell involved)
	if _, err := runCmdWithStdin(ctx, bytes.NewReader(rawKey), "gpg", "--yes", "--dearmor", "-o", tempPath); err != nil {
		return false, fmt.Errorf("failed to dearmor GPG key: %w", err)
	}

	// Read the new key content
	newKey, err := os.ReadFile(tempPath)
	if err != nil {
		return false, fmt.Errorf("failed to read temp key file: %w", err)
	}

	// Check if existing key file exists and compare content
	existingKey, err := os.ReadFile(keyFile)
	if err == nil {
		// File exists, compare content
		if bytes.Equal(existingKey, newKey) {
			output.WriteString("GPG key already installed and matches\n")
			return false, nil
		}
		output.WriteString("GPG key differs, updating\n")
	} else if os.IsNotExist(err) {
		output.WriteString("GPG key not found, installing\n")
	} else {
		// Other error reading the file - try to read with sudo
		cmdOutput, sudoErr := runSudoCmd(ctx, "cat", "--", keyFile)
		if sudoErr == nil && cmdOutput != nil {
			if bytes.Equal([]byte(cmdOutput.Stdout), newKey) {
				output.WriteString("GPG key already installed and matches\n")
				return false, nil
			}
			output.WriteString("GPG key differs, updating\n")
		} else {
			output.WriteString("GPG key not found, installing\n")
		}
	}

	// Copy the new key to the target location with sudo
	_, err = runSudoCmd(ctx, "cp", "--", tempPath, keyFile)
	if err != nil {
		return false, fmt.Errorf("failed to install GPG key: %w", err)
	}

	// Set proper permissions. A failed chmod on the keyring leaves
	// dpkg with "the file is unreadable to apt", which masquerades
	// as a repository fetch problem on the next apt update — return
	// the error so the operator sees the real cause.
	if _, err := runSudoCmd(ctx, "chmod", "644", "--", keyFile); err != nil {
		return false, fmt.Errorf("failed to chmod GPG key %s: %w", keyFile, err)
	}

	return true, nil
}

// executeDnfRepository configures a DNF/YUM repository.
func (e *Executor) executeDnfRepository(ctx context.Context, name string, repo *pb.DnfRepository, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	var output strings.Builder
	repoFile := fmt.Sprintf("/etc/yum.repos.d/%s.repo", name)

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		// No-op when the repo file is already absent. Reporting
		// changed=true here used to flood operators with spurious
		// state-change events for actions that did nothing.
		if _, err := os.Stat(repoFile); os.IsNotExist(err) {
			output.WriteString(fmt.Sprintf("repository %s already absent\n", name))
			return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, false, nil
		}
		if _, err := runSudoCmd(ctx, "rm", "-f", "--", repoFile); err != nil {
			return nil, false, fmt.Errorf("failed to remove repo file: %w", err)
		}
		output.WriteString(fmt.Sprintf("removed repository: %s\n", name))
		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, true, nil

	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Build the desired repo file content first so we can
		// compare against on-disk state and skip the rewrite when
		// the file already matches.
		var content strings.Builder
		content.WriteString(fmt.Sprintf("[%s]\n", name))
		if repo.Description != "" {
			content.WriteString(fmt.Sprintf("name=%s\n", repo.Description))
		} else {
			content.WriteString(fmt.Sprintf("name=%s\n", name))
		}
		content.WriteString(fmt.Sprintf("baseurl=%s\n", repo.Baseurl))
		if repo.Enabled {
			content.WriteString("enabled=1\n")
		} else {
			content.WriteString("enabled=0\n")
		}
		if repo.Gpgcheck {
			content.WriteString("gpgcheck=1\n")
			if repo.Gpgkey != "" {
				content.WriteString(fmt.Sprintf("gpgkey=%s\n", repo.Gpgkey))
			}
		} else {
			content.WriteString("gpgcheck=0\n")
		}
		if repo.ModuleHotfixes {
			content.WriteString("module_hotfixes=1\n")
		}
		desired := content.String()

		// Idempotency: if the existing file matches byte-for-byte,
		// don't rewrite + report changed.
		if existing, err := os.ReadFile(repoFile); err == nil && string(existing) == desired {
			output.WriteString(fmt.Sprintf("repository %s already up to date\n", name))
			return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, false, nil
		}

		// Cleanup any existing repository configuration first
		// (handles previous configurations with different settings).
		if _, err := os.Stat(repoFile); err == nil {
			output.WriteString(fmt.Sprintf("replacing existing repository: %s\n", name))
			if _, err := runSudoCmd(ctx, "rm", "-f", "--", repoFile); err != nil {
				e.logger.Warn("dnf PRESENT: failed to remove existing repo file before rewrite",
					"file", repoFile, "error", err)
			}
		}

		if _, err := writeFileWithSudo(ctx, repoFile, desired); err != nil {
			return nil, false, fmt.Errorf("failed to write repo file: %w", err)
		}
		output.WriteString(fmt.Sprintf("configured repository: %s\n", name))

		// Import GPG key if provided.
		// rpm --import is idempotent - re-importing an existing key is a no-op.
		if repo.Gpgkey != "" {
			keyOutput, keyErr := runSudoCmd(ctx, "rpm", rpmImportArgs(repo.Gpgkey)...)
			if keyOutput != nil && keyOutput.Stdout != "" {
				output.WriteString(keyOutput.Stdout)
			}
			if keyErr != nil {
				e.logger.Warn("dnf PRESENT: failed to import GPG key",
					"gpgkey", repo.Gpgkey, "error", keyErr)
			}
		}

		// Refresh metadata (use -y for non-interactive mode).
		refreshOutput, refreshErr := runSudoCmd(ctx, "dnf", "-y", "makecache", "--repo", name)
		if refreshOutput != nil {
			output.WriteString(refreshOutput.Stdout)
		}
		if refreshErr != nil {
			e.logger.Warn("dnf PRESENT: failed to refresh repo metadata",
				"repo", name, "error", refreshErr)
		}

		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, true, nil

	default:
		return nil, false, fmt.Errorf("unknown desired state: %v", state)
	}
}

// removePacmanSection removes a [name] section from pacman.conf content.
// A section extends from [name] to the next [section] line (exclusive) or end of file.
func removePacmanSection(content, name string) string {
	sectionHeader := "[" + name + "]"
	lines := strings.Split(content, "\n")
	var result []string
	inSection := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == sectionHeader {
			inSection = true
			continue
		}
		if inSection && strings.HasPrefix(trimmed, "[") {
			inSection = false
		}
		if !inSection {
			result = append(result, line)
		}
	}
	return strings.Join(result, "\n")
}

// executePacmanRepository configures a Pacman repository.
func (e *Executor) executePacmanRepository(ctx context.Context, name string, repo *pb.PacmanRepository, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	var output strings.Builder
	confFile := "/etc/pacman.conf"

	// Read current pacman.conf
	confContent, err := os.ReadFile(confFile)
	if err != nil {
		return nil, false, fmt.Errorf("failed to read pacman.conf: %w", err)
	}
	confStr := string(confContent)

	// Check if repo section exists
	repoSection := fmt.Sprintf("[%s]", name)
	hasRepo := strings.Contains(confStr, repoSection)

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		if !hasRepo {
			output.WriteString(fmt.Sprintf("repository %s not found, nothing to remove\n", name))
			return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, false, nil
		}

		// Remove the repository section in Go (no sed, no shell injection risk)
		newConf := removePacmanSection(confStr, name)
		if _, err := writeFileWithSudo(ctx, confFile, newConf); err != nil {
			return nil, false, fmt.Errorf("failed to update pacman.conf: %w", err)
		}

		output.WriteString(fmt.Sprintf("removed repository: %s\n", name))
		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, true, nil

	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Build new repo section
		var section strings.Builder
		section.WriteString(fmt.Sprintf("\n[%s]\n", name))
		if repo.SigLevel != "" {
			section.WriteString(fmt.Sprintf("SigLevel = %s\n", repo.SigLevel))
		}
		section.WriteString(fmt.Sprintf("Server = %s\n", repo.Server))

		// Remove old section if it exists, then append new one (single atomic write)
		newConf := confStr
		if hasRepo {
			newConf = removePacmanSection(confStr, name)
		}
		newConf += section.String()

		// Idempotency: skip the write + db-sync if pacman.conf
		// already matches.
		if newConf == confStr {
			output.WriteString(fmt.Sprintf("repository %s already configured\n", name))
			return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, false, nil
		}

		if _, err := writeFileWithSudo(ctx, confFile, newConf); err != nil {
			return nil, false, fmt.Errorf("failed to write pacman.conf: %w", err)
		}

		output.WriteString(fmt.Sprintf("configured repository: %s\n", name))

		// Sync database (--noconfirm for non-interactive mode)
		syncOutput, syncErr := runSudoCmd(ctx, "pacman", "-Sy", "--noconfirm")
		if syncOutput != nil {
			output.WriteString(syncOutput.Stdout)
		}
		if syncErr != nil {
			e.logger.Warn("pacman PRESENT: failed to sync repository database",
				"repo", name, "error", syncErr)
		}

		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, true, nil

	default:
		return nil, false, fmt.Errorf("unknown desired state: %v", state)
	}
}

// executeZypperRepository configures a Zypper repository.
func (e *Executor) executeZypperRepository(ctx context.Context, name string, repo *pb.ZypperRepository, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	var output strings.Builder

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		cmdOutput, err := runSudoCmd(ctx, "zypper", "--non-interactive", "removerepo", name)
		if err != nil {
			// Already-absent is the no-op case — surface as
			// changed=false so operators don't see spurious
			// state-change events.
			if cmdOutput != nil && strings.Contains(cmdOutput.Stderr, "not found") {
				output.WriteString(fmt.Sprintf("repository %s not found, nothing to remove\n", name))
				return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, false, nil
			}
			return nil, false, fmt.Errorf("failed to remove repository: %w", err)
		}
		output.WriteString(fmt.Sprintf("removed repository: %s\n", name))
		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, true, nil

	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Build zypper addrepo command
		args := []string{"--non-interactive", "addrepo", "--refresh"}

		if !repo.Gpgcheck {
			args = append(args, "--no-gpgcheck")
		}

		if repo.Type != "" {
			args = append(args, "--type", repo.Type)
		}

		// Check if repo exists, remove first if it does. A failure
		// here is non-fatal — the addrepo below will surface a real
		// conflict — but log so the operator can investigate the
		// cleanup half if addrepo also fails.
		if _, err := runSudoCmd(ctx, "zypper", "--non-interactive", "removerepo", name); err != nil {
			e.logger.Debug("zypper PRESENT: pre-add removerepo failed (often expected if repo absent)",
				"repo", name, "error", err)
		}

		args = append(args, repo.Url, name)
		cmdOutput, err := runSudoCmd(ctx, "zypper", args...)
		if err != nil {
			if cmdOutput != nil {
				output.WriteString(cmdOutput.Stderr)
			}
			return nil, false, fmt.Errorf("failed to add repository: %w", err)
		}

		output.WriteString(fmt.Sprintf("configured repository: %s\n", name))

		// Set description if provided. modifyrepo is a state-changing
		// operation — a failure leaves the repo with a wrong/missing
		// description versus operator intent. Return as error.
		if repo.Description != "" {
			if _, err := runSudoCmd(ctx, "zypper", "--non-interactive", "modifyrepo", "--name", repo.Description, name); err != nil {
				return nil, false, fmt.Errorf("failed to set zypper repo description: %w", err)
			}
		}

		// Enable/disable. Same reasoning as description: a failed
		// enable/disable diverges from operator intent silently.
		if repo.Enabled {
			if _, err := runSudoCmd(ctx, "zypper", "--non-interactive", "modifyrepo", "--enable", name); err != nil {
				return nil, false, fmt.Errorf("failed to enable zypper repo %s: %w", name, err)
			}
		} else {
			if _, err := runSudoCmd(ctx, "zypper", "--non-interactive", "modifyrepo", "--disable", name); err != nil {
				return nil, false, fmt.Errorf("failed to disable zypper repo %s: %w", name, err)
			}
		}

		// Set autorefresh
		if repo.Autorefresh {
			if _, err := runSudoCmd(ctx, "zypper", "--non-interactive", "modifyrepo", "--refresh", name); err != nil {
				return nil, false, fmt.Errorf("failed to enable autorefresh on zypper repo %s: %w", name, err)
			}
		}

		// Import GPG key if provided
		if repo.Gpgkey != "" {
			keyOutput, keyErr := runSudoCmd(ctx, "rpm", rpmImportArgs(repo.Gpgkey)...)
			if keyOutput != nil && keyOutput.Stdout != "" {
				output.WriteString(keyOutput.Stdout)
			}
			if keyErr != nil {
				e.logger.Warn("zypper PRESENT: failed to import GPG key",
					"gpgkey", repo.Gpgkey, "error", keyErr)
			}
		}

		// Refresh repository
		refreshOutput, refreshErr := runSudoCmd(ctx, "zypper", "--non-interactive", "refresh", name)
		if refreshOutput != nil {
			output.WriteString(refreshOutput.Stdout)
		}
		if refreshErr != nil {
			e.logger.Warn("zypper PRESENT: failed to refresh repo",
				"repo", name, "error", refreshErr)
		}

		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, true, nil

	default:
		return nil, false, fmt.Errorf("unknown desired state: %v", state)
	}
}
