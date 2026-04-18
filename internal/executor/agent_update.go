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
	"sync"
	"time"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// AgentUpdateConfig holds configuration for the agent self-update executor.
type AgentUpdateConfig struct {
	Version    string       // Current running agent version
	DataDir    string       // Data directory for update staging
	BinaryPath string       // Path to the installed agent binary (e.g., /usr/local/bin/power-manage-agent)
	Shutdown   func()       // Called after a successful update to trigger graceful agent shutdown
}

// agentUpdateExecuted tracks whether an AGENT_UPDATE action already ran in the current sync cycle.
// Reset by the scheduler between cycles.
var (
	agentUpdateExecuted   bool
	agentUpdateExecutedMu sync.Mutex
)

// ResetAgentUpdateCycle resets the per-cycle dedup flag.
// Called by the scheduler at the start of each execution cycle.
func ResetAgentUpdateCycle() {
	agentUpdateExecutedMu.Lock()
	agentUpdateExecuted = false
	agentUpdateExecutedMu.Unlock()
}

// markAgentUpdateExecuted marks that an agent update ran in this cycle.
// Returns true if this is the first execution, false if already executed.
func markAgentUpdateExecuted() bool {
	agentUpdateExecutedMu.Lock()
	defer agentUpdateExecutedMu.Unlock()
	if agentUpdateExecuted {
		return false
	}
	agentUpdateExecuted = true
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
	if !markAgentUpdateExecuted() {
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
	stagePath := cfg.BinaryPath + ".new"
	if _, err := runSudoCmd(ctx, "cp", tmpPath, stagePath); err != nil {
		return nil, false, fmt.Errorf("stage binary: %w", err)
	}
	if _, err := runSudoCmd(ctx, "chmod", "+x", stagePath); err != nil {
		runSudoCmd(ctx, "rm", "-f", stagePath)
		return nil, false, fmt.Errorf("chmod staged binary: %w", err)
	}
	if _, err := runSudoCmd(ctx, "mv", stagePath, cfg.BinaryPath); err != nil {
		runSudoCmd(ctx, "rm", "-f", stagePath)
		return nil, false, fmt.Errorf("swap binary: %w", err)
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
	// Output may be "power-manage-agent 2026.04.04" — extract just the version.
	if parts := strings.Fields(v); len(parts) > 1 {
		v = parts[len(parts)-1]
	}
	return v, nil
}

// writeUpdateState writes a state.json file atomically.
func writeUpdateState(dataDir, phase, version string) error {
	dir := filepath.Join(dataDir, "update")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	data := fmt.Sprintf(`{"phase":%q,"version":%q}`, phase, version)

	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()

	if _, err := tmp.WriteString(data); err != nil {
		tmp.Close()
		os.Remove(tmpPath)
		return err
	}
	tmp.Close()

	return os.Rename(tmpPath, filepath.Join(dir, "state.json"))
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
// so there is no rollback logic needed at startup. This function only cleans up
// state files left behind by interrupted updates.
//
// Parameters:
//   - dataDir: agent data directory containing update/state.json
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
}
