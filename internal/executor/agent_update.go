package executor

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
	sysfs "github.com/manchtools/power-manage/sdk/go/sys/fs"
)

// AgentUpdateConfig holds configuration for the agent self-update executor.
type AgentUpdateConfig struct {
	Version    string // Current running agent version
	DataDir    string // Data directory for update staging
	BinaryPath string // Path to the installed agent binary (e.g., /usr/local/bin/power-manage-agent)
	Shutdown   func() // Called after a successful update to trigger graceful agent shutdown
}

// ResetUpdateCycle resets the per-cycle AGENT_UPDATE dedup flag on
// this executor. Called by the scheduler at the start of each execution
// cycle so a single sync containing both a standalone and a grouped
// AGENT_UPDATE only runs the update once.
//
// Audit F042 + F048: previously a package-level global guarded by its
// own mutex. The global state leaked across parallel runs, and a
// future second scheduler/executor pair would silently share the flag
// with production. Now the flag is per-executor, scheduler reaches
// it via the ActionExecutor interface.
func (e *Executor) ResetUpdateCycle() {
	e.agentUpdateExecutedMu.Lock()
	e.agentUpdateExecuted = false
	e.agentUpdateExecutedMu.Unlock()
}

// markAgentUpdateExecuted marks that an agent update ran in this cycle.
// Returns true if this is the first execution, false if already executed.
func (e *Executor) markAgentUpdateExecuted() bool {
	e.agentUpdateExecutedMu.Lock()
	defer e.agentUpdateExecutedMu.Unlock()
	if e.agentUpdateExecuted {
		return false
	}
	e.agentUpdateExecuted = true
	return true
}

// executeAgentUpdate implements the ACTION_TYPE_AGENT_UPDATE executor.
//
// Flow:
//  1. Check if another AGENT_UPDATE already ran this cycle → skip
//  2. Look up AgentUpdateArch for own architecture
//  3. If no entry → skip (success, no changes)
//  4. Validate URLs are HTTPS
//  5. Download checksum file, extract checksum for binary filename
//  6. Download binary to temp file, verify SHA256
//  7. Run ./agent-new version → extract version string
//  8. Compare with running version → skip if same
//  9. Run ./agent-new self-test → subprocess validates connectivity
//     (credentials load, mTLS, stream, SyncActions). If it fails,
//     the old binary stays untouched.
//  10. Atomically swap binary (cp → chmod → mv)
//  11. Signal graceful shutdown (systemd restarts with new binary)
//
// Retry behavior: if the self-test fails, the update is reported as
// EXECUTION_STATUS_FAILED and the old binary continues running. There is no
// cooldown between retries — if the admin schedules AGENT_UPDATE to run
// every 30 minutes and the target version is broken, the agent will
// re-download and re-test it every 30 minutes until a fixed release is
// published. This is an intentional trade-off: retry frequency is governed
// entirely by the admin's schedule, the old binary is never replaced.
func (e *Executor) executeAgentUpdate(ctx context.Context, params *pb.AgentUpdateParams) (*pb.CommandOutput, bool, error) {
	cfg := e.updateCfg
	if cfg == nil {
		return nil, false, fmt.Errorf("agent update not configured")
	}

	// Step 1: Dedup — only one AGENT_UPDATE per sync cycle
	if !e.markAgentUpdateExecuted() {
		e.logger.Warn("skipping duplicate AGENT_UPDATE action in this sync cycle")
		return &pb.CommandOutput{Stdout: "Skipped: another AGENT_UPDATE already executed this cycle"}, false, nil
	}

	// Step 2: Look up architecture entry
	arch := getArchEntry(params)
	if arch == nil {
		e.logger.Info("no agent update entry for this architecture", "arch", runtime.GOARCH)
		return &pb.CommandOutput{Stdout: fmt.Sprintf("No update entry for architecture %s", runtime.GOARCH)}, false, nil
	}

	// Step 3: Validate HTTPS
	if err := validateHTTPS(arch.BinaryUrl); err != nil {
		return nil, false, fmt.Errorf("binary URL validation: %w", err)
	}
	if err := validateHTTPS(arch.ChecksumUrl); err != nil {
		return nil, false, fmt.Errorf("checksum URL validation: %w", err)
	}

	// Step 4: Download checksum file and extract checksum for our binary.
	// Use url.Parse to strip query parameters (e.g. S3 presigned URLs).
	binaryFilename := extractFilename(arch.BinaryUrl)
	expectedChecksum, err := downloadAndExtractChecksum(ctx, e.httpClient, arch.ChecksumUrl, binaryFilename)
	if err != nil {
		return nil, false, fmt.Errorf("download checksum: %w", err)
	}

	// Step 5: Download binary to temp file in DataDir (agent-owned).
	// The final install uses sudo cp since the target dir is root-owned.
	updateDir := filepath.Join(cfg.DataDir, "update")
	if err := os.MkdirAll(updateDir, 0755); err != nil {
		return nil, false, fmt.Errorf("create update dir: %w", err)
	}

	tmpFile, err := os.CreateTemp(updateDir, "agent-update-*.tmp")
	if err != nil {
		return nil, false, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		tmpFile.Close()
		os.Remove(tmpPath) // cleanup on any failure path
	}()

	actualChecksum, err := downloadToFile(ctx, e.httpClient, arch.BinaryUrl, tmpFile)
	if err != nil {
		return nil, false, fmt.Errorf("download binary: %w", err)
	}
	tmpFile.Close()

	if actualChecksum != expectedChecksum {
		return nil, false, fmt.Errorf("checksum mismatch: expected %s, got %s", expectedChecksum, actualChecksum)
	}

	// Make executable
	if err := os.Chmod(tmpPath, 0755); err != nil {
		return nil, false, fmt.Errorf("chmod: %w", err)
	}

	// Step 6: Run version command on downloaded binary
	newVersion, err := getBinaryVersion(tmpPath)
	if err != nil {
		return nil, false, fmt.Errorf("version check on downloaded binary: %w", err)
	}

	// Step 7: Compare versions — skip if same
	if newVersion == cfg.Version {
		e.logger.Info("agent is already at the latest version", "version", cfg.Version)
		return &pb.CommandOutput{Stdout: fmt.Sprintf("Already at version %s", cfg.Version)}, false, nil
	}

	e.logger.Info("updating agent", "from", cfg.Version, "to", newVersion)

	// Step 8: Run the new binary in self-test mode. This validates
	// connectivity (mTLS, stream, SyncActions) WITHOUT replacing the
	// live binary. If the self-test fails, the old binary continues
	// running unchanged. See the function doc comment for retry semantics.
	selfTestCtx, selfTestCancel := context.WithTimeout(ctx, 60*time.Second)
	defer selfTestCancel()

	e.logger.Info("running self-test on new binary", "path", tmpPath)
	selfTestResult, selfTestErr := sysexec.Run(selfTestCtx, tmpPath, "self-test",
		"--data-dir="+cfg.DataDir,
		"--timeout=55s",
	)
	if selfTestErr != nil {
		var combined string
		if selfTestResult != nil {
			combined = strings.TrimSpace(selfTestResult.Stdout + "\n" + selfTestResult.Stderr)
		}
		e.logger.Error("self-test failed, keeping current binary",
			"error", selfTestErr,
			"output", combined)
		out := &pb.CommandOutput{
			Stdout: fmt.Sprintf("Self-test failed for version %s: %v", newVersion, selfTestErr),
			Stderr: combined,
		}
		return out, false, fmt.Errorf("self-test failed: %w", selfTestErr)
	}
	e.logger.Info("self-test passed", "output", selfTestResult.Stdout)

	// Step 9: Self-test passed — swap the binary. The old binary is
	// still running in memory, so this is safe. Use atomic
	// cp → chmod → mv so the live path is only updated after the
	// new file is fully written and executable.
	//
	// Before the swap, save the currently-installed binary to a
	// `.bak` sibling so an operator can roll back manually with
	// `mv <BinaryPath>.bak <BinaryPath> && systemctl restart
	// pm-agent` if the new binary fails to start (the systemd
	// restart-loop case the self-test cannot catch — bad config
	// load, missing kernel feature, broken libc dependency, etc.).
	// We keep only the most recent previous version; older `.bak`s
	// are rarely useful and accumulate disk cost with frequent
	// updates. If the backup fails we abort the upgrade rather
	// than swap without a fallback.
	// Audit F023: replace the prior cp/chmod/mv dance with the SDK's
	// SafeBackupAndReplace, which uses O_NOFOLLOW + renameat2 to defeat
	// symlink-replacement races on both the .bak path AND the live
	// binary. The previous shape used `cp --` + `mv --` which protect
	// against option-injection but NOT against an attacker (a member of
	// a group-writable install dir, for example) planting a symlink at
	// `${BinaryPath}.bak` to redirect the backup. The agent runs as
	// root, so direct file IO works without sudo.
	//
	// SafeBackupAndReplace reads the new binary content, mvs current →
	// .bak under renameat2 (clobbering an existing .bak per the
	// `removeExistingBackup=true` flag — operators expect the latest
	// rollback to win), then writes the new binary atomically via
	// SafeReplaceFile. On any failure the live binary is left intact
	// because the rename is atomic and the new write happens last.
	bakPath := cfg.BinaryPath + ".bak"
	newBinary, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, false, fmt.Errorf("read staged binary %s: %w", tmpPath, err)
	}
	if err := sysfs.SafeBackupAndReplace(cfg.BinaryPath, bakPath, newBinary, 0o755, true); err != nil {
		return nil, false, fmt.Errorf("swap binary at %s: %w", cfg.BinaryPath, err)
	}

	// Step 10: Signal graceful shutdown — systemd restarts with new binary
	stdout := fmt.Sprintf("Updated from %s to %s. Restarting.", cfg.Version, newVersion)
	e.logger.Info(stdout)

	// Delay shutdown to allow the result to be recorded and sent to the server.
	if cfg.Shutdown != nil {
		go func() {
			time.Sleep(3 * time.Second)
			cfg.Shutdown()
		}()
	}

	return &pb.CommandOutput{Stdout: stdout}, true, nil
}

// extractFilename returns the filename from a URL, stripping query parameters.
func extractFilename(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return filepath.Base(rawURL)
	}
	return filepath.Base(u.Path)
}

// getArchEntry returns the AgentUpdateArch for the current runtime architecture.
func getArchEntry(params *pb.AgentUpdateParams) *pb.AgentUpdateArch {
	switch runtime.GOARCH {
	case "amd64":
		return params.Amd64
	case "arm64":
		return params.Arm64
	default:
		return nil
	}
}

// validateHTTPS checks that a URL uses the HTTPS scheme.
func validateHTTPS(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL %q: %w", rawURL, err)
	}
	if u.Scheme != "https" {
		return fmt.Errorf("URL must use HTTPS, got %q", u.Scheme)
	}
	return nil
}

// downloadAndExtractChecksum downloads a SHA256SUMS-style file and extracts
// the checksum for the given filename. Format: "<hex>  <filename>" or "<hex> <filename>".
func downloadAndExtractChecksum(ctx context.Context, client *http.Client, checksumURL, filename string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, checksumURL, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	// Parse SHA256SUMS format: each line is "<hex>  <filename>" or "<hex> <filename>"
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Split on whitespace (double-space or single-space)
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}

		checksumHex := parts[0]
		name := parts[1]

		// Strip leading "./" or "*" prefix from filename (common in SHA256SUMS)
		name = strings.TrimPrefix(name, "./")
		name = strings.TrimPrefix(name, "*")

		if name == filename {
			// Validate it looks like a hex SHA256
			if len(checksumHex) != 64 {
				return "", fmt.Errorf("invalid checksum length for %s: %d", filename, len(checksumHex))
			}
			return strings.ToLower(checksumHex), nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("read checksum file: %w", err)
	}

	return "", fmt.Errorf("checksum for %q not found in checksum file", filename)
}

// downloadToFile downloads a URL to a file and returns the SHA256 hex checksum.
// Downloads are capped at maxDownloadSize (2 GiB).
func downloadToFile(ctx context.Context, client *http.Client, downloadURL string, dst *os.File) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("unexpected status %d", resp.StatusCode)
	}

	if resp.ContentLength > maxDownloadSize {
		return "", fmt.Errorf("download rejected: Content-Length %d exceeds maximum %d bytes", resp.ContentLength, maxDownloadSize)
	}

	hasher := sha256.New()
	w := io.MultiWriter(dst, hasher)

	// Cap the download at maxDownloadSize + 1 to detect overflows.
	reader := io.LimitReader(resp.Body, maxDownloadSize+1)
	written, err := io.Copy(w, reader)
	if err != nil {
		return "", fmt.Errorf("write: %w", err)
	}
	if written > maxDownloadSize {
		return "", fmt.Errorf("download exceeded maximum size of %d bytes", maxDownloadSize)
	}

	return hex.EncodeToString(hasher.Sum(nil)), nil
}

// getBinaryVersion runs the binary with "version" subcommand and returns the trimmed output.
func getBinaryVersion(binaryPath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := sysexec.Run(ctx, binaryPath, "version")
	if err != nil {
		return "", fmt.Errorf("run %s version: %w", binaryPath, err)
	}
	v := strings.TrimSpace(result.Stdout)
	if v == "" {
		return "", fmt.Errorf("binary returned empty version")
	}
	// Output is "power-manage-agent <version>" today; an evolved
	// format like "power-manage-agent 2026.05.07 (commit abc123)"
	// would have made the previous "last whitespace token" parser
	// return "abc123)". Match the documented two-field format
	// explicitly. Audit F028.
	parts := strings.Fields(v)
	if len(parts) >= 2 {
		v = parts[1]
	}
	return v, nil
}

// readUpdateState reads state.json. Returns nil if not found.
func readUpdateState(dataDir string) (phase, version string, err error) {
	data, err := os.ReadFile(filepath.Join(dataDir, "update", "state.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return "", "", nil
		}
		return "", "", err
	}

	type state struct {
		Phase   string `json:"phase"`
		Version string `json:"version"`
	}
	var s state
	if err := json.Unmarshal(data, &s); err != nil {
		return "", "", err
	}
	return s.Phase, s.Version, nil
}

// clearUpdateState removes state.json.
func clearUpdateState(dataDir string) {
	os.Remove(filepath.Join(dataDir, "update", "state.json"))
}

// CheckStartupUpdateState cleans up stale update state from a previous cycle.
// With the self-test approach, updates are validated before swapping the binary,
// so there is no rollback logic needed at startup. This function cleans up
// state files left behind by interrupted updates AND any leftover
// agent-update-*.tmp staging files older than 24h that os.CreateTemp left
// behind when the agent crashed mid-download.
//
// Parameters:
//   - dataDir: agent data directory containing update/state.json + update/
//   - logger: structured logger
func CheckStartupUpdateState(dataDir string, logger interface {
	Info(string, ...any)
	Warn(string, ...any)
}) {
	phase, _, err := readUpdateState(dataDir)
	if err != nil {
		logger.Warn("failed to read update state", "error", err)
		return
	}
	if phase != "" {
		logger.Info("cleaning up stale update state", "phase", phase)
		clearUpdateState(dataDir)
	}

	// Sweep stale staging files. The defer os.Remove(tmpPath) inside
	// executeAgentUpdate handles the happy path AND any return-with-
	// error path inside that function, but a hard crash (OOM, kernel
	// panic, power loss) can leave agent-update-*.tmp files behind.
	// 24h is a generous threshold — a single update completes in
	// seconds, so anything older is definitively orphaned.
	updateDir := filepath.Join(dataDir, "update")
	entries, err := os.ReadDir(updateDir)
	if err != nil {
		// update/ doesn't exist on a never-updated agent — not an
		// error and not worth a log line. Anything else (EACCES,
		// IO failure on the device) IS worth surfacing because it
		// means future self-updates will silently fail to clean up
		// after themselves.
		if !os.IsNotExist(err) {
			logger.Warn("failed to read update dir for stale tmp sweep",
				"dir", updateDir, "error", err)
		}
		return
	}
	cutoff := time.Now().Add(-24 * time.Hour)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, "agent-update-") || !strings.HasSuffix(name, ".tmp") {
			continue
		}
		info, err := entry.Info()
		if err != nil || info.ModTime().After(cutoff) {
			continue
		}
		path := filepath.Join(updateDir, name)
		if err := os.Remove(path); err != nil {
			logger.Warn("failed to remove stale update tmp file", "path", path, "error", err)
			continue
		}
		logger.Info("removed stale update tmp file", "path", path, "age", time.Since(info.ModTime()).Round(time.Second))
	}
}
