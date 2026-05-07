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
)

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

	// Repair filesystem if mounted read-only. Only reached once the
	// action has passed every structural check, so the sudo-backed
	// remount never fires for a payload we were going to refuse.
	if out, err := e.requireWritableFS(ctx); err != nil {
		return out, false, err
	}

	// Detect package manager and execute the appropriate configuration
	// Repository actions always report changed=true since they write config files
	switch {
	case pkg.IsApt():
		if params.Apt == nil || params.Apt.Disabled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   "skipped: no APT repository configuration provided",
			}, false, nil
		}
		return e.executeAptRepository(ctx, params.Name, params.Apt, state)

	case pkg.IsDnf():
		if params.Dnf == nil || params.Dnf.Disabled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   "skipped: no DNF repository configuration provided",
			}, false, nil
		}
		output, err := e.executeDnfRepository(ctx, params.Name, params.Dnf, state)
		return output, err == nil, err

	case pkg.IsPacman():
		if params.Pacman == nil || params.Pacman.Disabled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   "skipped: no Pacman repository configuration provided",
			}, false, nil
		}
		output, err := e.executePacmanRepository(ctx, params.Name, params.Pacman, state)
		return output, err == nil, err

	case pkg.IsZypper():
		if params.Zypper == nil || params.Zypper.Disabled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   "skipped: no Zypper repository configuration provided",
			}, false, nil
		}
		output, err := e.executeZypperRepository(ctx, params.Name, params.Zypper, state)
		return output, err == nil, err

	default:
		return nil, false, fmt.Errorf("no supported package manager found for repository configuration")
	}
}

// cleanupConflictingAptRepos scans /etc/apt/sources.list.d/ for any repository configs
// that contain the given URL and removes them along with their associated GPG keys.
// This prevents "conflicting values set for option Signed-By" errors when the same
// repository URL was previously configured under a different name or with different keys.
// The skipRepoFile and skipKeyFile parameters specify files that should NOT be deleted
// (typically the target repository being configured).
func (e *Executor) cleanupConflictingAptRepos(ctx context.Context, url, skipRepoFile, skipKeyFile string, output *strings.Builder) {
	sourcesDir := "/etc/apt/sources.list.d"
	entries, err := os.ReadDir(sourcesDir)
	if err != nil {
		return // Directory might not exist, that's fine
	}

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
						runSudoCmd(ctx, "rm", "-f", keyPath)
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
					runSudoCmd(ctx, "rm", "-f", keyPath)
				}
			}
		}

		// Remove the repository file
		runSudoCmd(ctx, "rm", "-f", filePath)
	}
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
		if _, err := runSudoCmd(ctx, "rm", "-f", repoFile); err != nil {
			return nil, false, fmt.Errorf("failed to remove repo file: %w", err)
		}
		// Also try to remove legacy .list format
		legacyFile := fmt.Sprintf("/etc/apt/sources.list.d/%s.list", name)
		runSudoCmd(ctx, "rm", "-f", legacyFile)
		// Remove GPG key
		runSudoCmd(ctx, "rm", "-f", keyFile)
		output.WriteString(fmt.Sprintf("removed repository: %s\n", name))
		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, true, nil

	case pb.DesiredState_DESIRED_STATE_PRESENT:
		changed := false

		// First, scan for and remove any existing repository configs that use the same URL
		// This prevents "conflicting values set for option Signed-By" errors when the same
		// repository was previously configured under a different name or with different keys
		// We skip our own repo file and key file to allow the comparison logic to work
		e.cleanupConflictingAptRepos(ctx, repo.Url, repoFile, keyFile, &output)

		// Clean up legacy .list file if it exists
		legacyFile := fmt.Sprintf("/etc/apt/sources.list.d/%s.list", name)
		if _, err := os.Stat(legacyFile); err == nil {
			output.WriteString(fmt.Sprintf("removing legacy repository file: %s\n", legacyFile))
			runSudoCmd(ctx, "rm", "-f", legacyFile)
			changed = true
		}
		// Clean up legacy GPG key location
		legacyKeyFile := fmt.Sprintf("/etc/apt/trusted.gpg.d/%s.gpg", name)
		if _, err := os.Stat(legacyKeyFile); err == nil {
			output.WriteString(fmt.Sprintf("removing legacy GPG key: %s\n", legacyKeyFile))
			runSudoCmd(ctx, "rm", "-f", legacyKeyFile)
			changed = true
		}

		// Ensure keyrings directory exists
		if _, err := runSudoCmd(ctx, "mkdir", "-p", "/etc/apt/keyrings"); err != nil {
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
			updateOutput, _ := apt.Update()
			if updateOutput != nil {
				output.WriteString(updateOutput.Stdout)
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

	// Create a temp file for the new key
	tempFile, err := os.CreateTemp("", "gpgkey-*.gpg")
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
		cmdOutput, sudoErr := runSudoCmd(ctx, "cat", keyFile)
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
	_, err = runSudoCmd(ctx, "cp", tempPath, keyFile)
	if err != nil {
		return false, fmt.Errorf("failed to install GPG key: %w", err)
	}

	// Set proper permissions
	runSudoCmd(ctx, "chmod", "644", keyFile)

	return true, nil
}

// executeDnfRepository configures a DNF/YUM repository.
func (e *Executor) executeDnfRepository(ctx context.Context, name string, repo *pb.DnfRepository, state pb.DesiredState) (*pb.CommandOutput, error) {
	var output strings.Builder
	repoFile := fmt.Sprintf("/etc/yum.repos.d/%s.repo", name)

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		if _, err := runSudoCmd(ctx, "rm", "-f", repoFile); err != nil {
			return nil, fmt.Errorf("failed to remove repo file: %w", err)
		}
		output.WriteString(fmt.Sprintf("removed repository: %s\n", name))
		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil

	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Clean up any existing repository configuration to ensure clean state
		// This handles cases where the repository was previously configured with different settings
		if _, err := os.Stat(repoFile); err == nil {
			output.WriteString(fmt.Sprintf("replacing existing repository: %s\n", name))
			runSudoCmd(ctx, "rm", "-f", repoFile)
		}

		// Build repo file content
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

		// Write the repo file
		if _, err := writeFileWithSudo(ctx, repoFile, content.String()); err != nil {
			return nil, fmt.Errorf("failed to write repo file: %w", err)
		}

		output.WriteString(fmt.Sprintf("configured repository: %s\n", name))

		// Import GPG key if provided
		// rpm --import is idempotent - re-importing an existing key is a no-op
		if repo.Gpgkey != "" {
			keyOutput, _ := runSudoCmd(ctx, "rpm", "--import", repo.Gpgkey)
			if keyOutput != nil && keyOutput.Stdout != "" {
				output.WriteString(keyOutput.Stdout)
			}
		}

		// Refresh metadata (use -y for non-interactive mode)
		refreshOutput, _ := runSudoCmd(ctx, "dnf", "-y", "makecache", "--repo", name)
		if refreshOutput != nil {
			output.WriteString(refreshOutput.Stdout)
		}

		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil

	default:
		return nil, fmt.Errorf("unknown desired state: %v", state)
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
func (e *Executor) executePacmanRepository(ctx context.Context, name string, repo *pb.PacmanRepository, state pb.DesiredState) (*pb.CommandOutput, error) {
	var output strings.Builder
	confFile := "/etc/pacman.conf"

	// Read current pacman.conf
	confContent, err := os.ReadFile(confFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read pacman.conf: %w", err)
	}
	confStr := string(confContent)

	// Check if repo section exists
	repoSection := fmt.Sprintf("[%s]", name)
	hasRepo := strings.Contains(confStr, repoSection)

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		if !hasRepo {
			output.WriteString(fmt.Sprintf("repository %s not found, nothing to remove\n", name))
			return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil
		}

		// Remove the repository section in Go (no sed, no shell injection risk)
		newConf := removePacmanSection(confStr, name)
		if _, err := writeFileWithSudo(ctx, confFile, newConf); err != nil {
			return nil, fmt.Errorf("failed to update pacman.conf: %w", err)
		}

		output.WriteString(fmt.Sprintf("removed repository: %s\n", name))
		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil

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

		if _, err := writeFileWithSudo(ctx, confFile, newConf); err != nil {
			return nil, fmt.Errorf("failed to write pacman.conf: %w", err)
		}

		output.WriteString(fmt.Sprintf("configured repository: %s\n", name))

		// Sync database (--noconfirm for non-interactive mode)
		syncOutput, _ := runSudoCmd(ctx, "pacman", "-Sy", "--noconfirm")
		if syncOutput != nil {
			output.WriteString(syncOutput.Stdout)
		}

		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil

	default:
		return nil, fmt.Errorf("unknown desired state: %v", state)
	}
}

// executeZypperRepository configures a Zypper repository.
func (e *Executor) executeZypperRepository(ctx context.Context, name string, repo *pb.ZypperRepository, state pb.DesiredState) (*pb.CommandOutput, error) {
	var output strings.Builder

	switch state {
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		cmdOutput, err := runSudoCmd(ctx, "zypper", "--non-interactive", "removerepo", name)
		if err != nil {
			// Ignore if repo doesn't exist
			if cmdOutput != nil && strings.Contains(cmdOutput.Stderr, "not found") {
				output.WriteString(fmt.Sprintf("repository %s not found, nothing to remove\n", name))
				return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil
			}
			return nil, fmt.Errorf("failed to remove repository: %w", err)
		}
		output.WriteString(fmt.Sprintf("removed repository: %s\n", name))
		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil

	case pb.DesiredState_DESIRED_STATE_PRESENT:
		// Build zypper addrepo command
		args := []string{"--non-interactive", "addrepo", "--refresh"}

		if !repo.Gpgcheck {
			args = append(args, "--no-gpgcheck")
		}

		if repo.Type != "" {
			args = append(args, "--type", repo.Type)
		}

		// Check if repo exists, remove first if it does
		runSudoCmd(ctx, "zypper", "--non-interactive", "removerepo", name)

		args = append(args, repo.Url, name)
		cmdOutput, err := runSudoCmd(ctx, "zypper", args...)
		if err != nil {
			if cmdOutput != nil {
				output.WriteString(cmdOutput.Stderr)
			}
			return nil, fmt.Errorf("failed to add repository: %w", err)
		}

		output.WriteString(fmt.Sprintf("configured repository: %s\n", name))

		// Set description if provided
		if repo.Description != "" {
			runSudoCmd(ctx, "zypper", "--non-interactive", "modifyrepo", "--name", repo.Description, name)
		}

		// Enable/disable
		if repo.Enabled {
			runSudoCmd(ctx, "zypper", "--non-interactive", "modifyrepo", "--enable", name)
		} else {
			runSudoCmd(ctx, "zypper", "--non-interactive", "modifyrepo", "--disable", name)
		}

		// Set autorefresh
		if repo.Autorefresh {
			runSudoCmd(ctx, "zypper", "--non-interactive", "modifyrepo", "--refresh", name)
		}

		// Import GPG key if provided
		if repo.Gpgkey != "" {
			keyOutput, _ := runSudoCmd(ctx, "rpm", "--import", repo.Gpgkey)
			if keyOutput != nil && keyOutput.Stdout != "" {
				output.WriteString(keyOutput.Stdout)
			}
		}

		// Refresh repository
		refreshOutput, _ := runSudoCmd(ctx, "zypper", "--non-interactive", "refresh", name)
		if refreshOutput != nil {
			output.WriteString(refreshOutput.Stdout)
		}

		return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, nil

	default:
		return nil, fmt.Errorf("unknown desired state: %v", state)
	}
}
