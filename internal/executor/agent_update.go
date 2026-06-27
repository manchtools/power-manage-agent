package executor

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	sdk "github.com/manchtools/power-manage-sdk"
	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	sysfs "github.com/manchtools/power-manage-sdk/sys/fs"
	"github.com/manchtools/power-manage-sdk/sys/remote"
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
//  4. Validate the binary URL is HTTPS
//  5. Download binary to temp file, verify SHA256 against the CA-signed
//     expected_sha256 (WS7 #1 — NOT a same-origin checksum file)
//  6. Run ./agent-new version → extract version string
//  7. Compare with running version → skip if same; refuse a downgrade
//     unless allow_downgrade is set on the signed action (anti-rollback)
//  8. Run ./agent-new self-test → subprocess validates connectivity
//     (credentials load, mTLS, stream, SyncActions). If it fails,
//     the old binary stays untouched.
//  9. Atomically swap binary via SafeBackupAndReplace (O_NOFOLLOW +
//     renameat2; copies the old binary to .bak first)
//  10. Signal graceful shutdown (systemd restarts with new binary)
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

	// Step 3: Validate the binary URL is HTTPS (fail-closed before any
	// network).
	if err := sdk.ValidateHTTPSURL(arch.BinaryUrl); err != nil {
		return nil, false, fmt.Errorf("binary URL validation: %w", err)
	}

	// Step 4: determine the expected binary hash. Operator's choice (WS7):
	//   - expected_sha256 set → AUTHORITATIVE, CA-signed pin. It rides
	//     inside the signed action, so even a compromised download origin
	//     cannot vouch for a tampered binary. Overrides checksum_url.
	//   - otherwise → fetch the operator's checksum_url (SHA256SUMS) and
	//     verify against it. This is the default that lets binary_url +
	//     checksum_url track "latest" hands-off; authenticity is
	//     origin-trust (the action is signed, so only an origin-manipulated
	//     hash is a concern, which an operator can mitigate by hosting the
	//     checksum file on a separate host).
	// At least one must be present (also enforced server-side) so an update
	// never runs with no integrity check.
	expectedChecksum := strings.ToLower(arch.ExpectedSha256)
	if expectedChecksum == "" {
		if arch.ChecksumUrl == "" {
			return nil, false, fmt.Errorf("agent update rejected: action sets neither expected_sha256 nor checksum_url")
		}
		if err := sdk.ValidateHTTPSURL(arch.ChecksumUrl); err != nil {
			return nil, false, fmt.Errorf("checksum URL validation: %w", err)
		}
		fileChecksum, err := downloadAndExtractChecksum(ctx, arch.ChecksumUrl, extractFilename(arch.BinaryUrl), updateRedirectPolicy(params))
		if err != nil {
			return nil, false, fmt.Errorf("download checksum: %w", err)
		}
		expectedChecksum = fileChecksum
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
	_ = tmpFile.Close() // remote.Fetch writes via its own temp + atomic rename onto tmpPath
	defer os.Remove(tmpPath)

	// Download the binary, verify it against the (operator-or-CA-pinned)
	// expected sha256, and place it at mode 0755 (executable for the version
	// self-test below) — all in one atomic step via the SDK remote source. An
	// integrity failure is the binary-doesn't-match-the-pin case.
	if err := fetchArtifact(ctx, arch.BinaryUrl, tmpPath, expectedChecksum, "0755", updateRedirectPolicy(params)); err != nil {
		if errors.Is(err, remote.ErrIntegrity) {
			return nil, false, fmt.Errorf("binary does not match the expected_sha256 pin: %w", err)
		}
		return nil, false, fmt.Errorf("download binary: %w", err)
	}

	// Step 6: Run version command on downloaded binary
	newVersion, err := getBinaryVersion(tmpPath)
	if err != nil {
		return nil, false, fmt.Errorf("version check on downloaded binary: %w", err)
	}

	// Step 7: Compare versions — skip if same (fast exact-string path).
	if newVersion == cfg.Version {
		e.logger.Info("agent is already at the latest version", "version", cfg.Version)
		return &pb.CommandOutput{Stdout: fmt.Sprintf("Already at version %s", cfg.Version)}, false, nil
	}

	// Anti-rollback (WS7 #7): refuse a candidate that is older than the
	// running version unless the signed action explicitly allows a
	// downgrade. An unparseable version fails CLOSED — never treated as
	// newer. allow_downgrade rides inside the CA-signed action, so a
	// downgrade is an explicit, authenticated operator decision.
	if !params.AllowDowngrade {
		cmp, cmpErr := compareAgentVersion(cfg.Version, newVersion)
		if cmpErr != nil {
			return nil, false, fmt.Errorf("refusing update: cannot compare versions (running %q, candidate %q): %w", cfg.Version, newVersion, cmpErr)
		}
		if cmp > 0 {
			return nil, false, fmt.Errorf("refusing downgrade: candidate %s is older than running %s (set allow_downgrade on the action to override)", newVersion, cfg.Version)
		}
		if cmp == 0 {
			// Semantically equal despite differing strings — nothing to do.
			e.logger.Info("agent is already at an equivalent version", "running", cfg.Version, "candidate", newVersion)
			return &pb.CommandOutput{Stdout: fmt.Sprintf("Already at version %s", cfg.Version)}, false, nil
		}
	}

	e.logger.Info("updating agent", "from", cfg.Version, "to", newVersion)

	// Step 8: Run the new binary in self-test mode. This validates
	// connectivity (mTLS, stream, SyncActions) WITHOUT replacing the
	// live binary. If the self-test fails, the old binary continues
	// running unchanged. See the function doc comment for retry semantics.
	selfTestCtx, selfTestCancel := context.WithTimeout(ctx, 60*time.Second)
	defer selfTestCancel()

	e.logger.Info("running self-test on new binary", "path", tmpPath)
	selfTestResult, selfTestErr := executorRunner.Run(selfTestCtx, sysexec.Command{
		Name: tmpPath,
		Args: []string{"self-test", "--data-dir=" + cfg.DataDir, "--timeout=55s"},
	})
	// The reworked Runner reports a non-zero exit in Result.ExitCode, not as
	// selfTestErr (which is set only when the process could not run). A self-test
	// binary that exits non-zero IS a failure, so check both.
	if selfTestErr != nil || selfTestResult.ExitCode != 0 {
		if selfTestErr == nil {
			selfTestErr = fmt.Errorf("self-test exited with code %d", selfTestResult.ExitCode)
		}
		combined := strings.TrimSpace(selfTestResult.Stdout + "\n" + selfTestResult.Stderr)
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
	// still running in memory, so this is safe. The swap goes through the
	// SDK's SafeBackupAndReplace (O_NOFOLLOW + renameat2), so the live
	// path is only updated after the new file is fully written, and a
	// symlink-replacement race on the live path or the .bak cannot
	// redirect the write.
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
	// SafeBackupAndReplace COPIES the current binary → .bak (clobbering
	// an existing .bak per `removeExistingBackup=true` — operators
	// expect the latest rollback to win), then writes the new binary
	// atomically over the live path via SafeReplaceFile. Because the
	// backup is a copy (not a move), the live binary is the only thing
	// the final atomic rename touches, so on ANY failure — backup error,
	// write error, or a crash/power-loss mid-update — the live binary is
	// left intact rather than absent.
	bakPath := cfg.BinaryPath + ".bak"
	newBinary, err := os.ReadFile(tmpPath)
	if err != nil {
		return nil, false, fmt.Errorf("read staged binary %s: %w", tmpPath, err)
	}
	// fs.Manager.WriteFile with Backup set copies the live binary → .bak
	// (clobbering an existing .bak) and writes the new binary atomically over the
	// live path — the same crash-safe backup-then-replace SafeBackupAndReplace did.
	if err := fsMgr.WriteFile(ctx, cfg.BinaryPath, newBinary, sysfs.WriteOptions{Mode: 0o755, Backup: bakPath}); err != nil {
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

// compareAgentVersion compares two vYYYY.MM.PP version strings and returns
// -1 if a < b, 0 if equal, +1 if a > b. The leading "v" is optional. A
// version that does not parse to exactly three numeric components is an
// error — callers MUST treat that as fail-closed (never "newer"), so a
// malformed candidate cannot bypass anti-rollback (WS7 #7).
func compareAgentVersion(a, b string) (int, error) {
	pa, err := parseAgentVersion(a)
	if err != nil {
		return 0, err
	}
	pb, err := parseAgentVersion(b)
	if err != nil {
		return 0, err
	}
	for i := 0; i < len(pa); i++ {
		if pa[i] != pb[i] {
			if pa[i] < pb[i] {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
}

// parseAgentVersion parses "vYYYY.MM.PP" (leading v optional) into its
// three numeric components.
func parseAgentVersion(v string) ([3]int, error) {
	var out [3]int
	v = strings.TrimPrefix(strings.TrimSpace(v), "v")
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return out, fmt.Errorf("invalid version %q: want vYYYY.MM.PP", v)
	}
	for i, p := range parts {
		n, err := strconv.Atoi(p)
		if err != nil {
			return out, fmt.Errorf("invalid version component %q in %q: %w", p, v, err)
		}
		out[i] = n
	}
	return out, nil
}

// extractFilename returns the filename from a URL, stripping query parameters.
func extractFilename(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return filepath.Base(rawURL)
	}
	return filepath.Base(u.Path)
}

// updateRedirectPolicy resolves the redirect policy for a self-update download
// from the operator's explicit AllowRedirect choice on the action. Default false
// keeps the strict same-origin guard; true follows cross-origin redirects (e.g.
// a CDN such as GitHub releases). The binary is always verified against a SHA-256
// (expected_sha256, or the hash resolved from checksum_url) and an https->http
// downgrade is refused by the SDK regardless, so the flag opts into a
// host-changing hop, not into unchecked bytes — mirroring allow_downgrade as a
// security-sensitive operator decision that rides inside the signed action.
func updateRedirectPolicy(params *pb.AgentUpdateParams) remote.RedirectPolicy {
	if params.GetAllowRedirect() {
		return remote.RedirectCrossOrigin
	}
	return remote.RedirectSameOrigin
}

// downloadAndExtractChecksum downloads a SHA256SUMS-style file and extracts
// the checksum for the given filename (format: "<hex>  <filename>"). Used
// as the default integrity source when the action does not pin
// expected_sha256 (WS7: operator tracks "latest" via checksum_url).
func downloadAndExtractChecksum(ctx context.Context, checksumURL, filename string, redirect remote.RedirectPolicy) (string, error) {
	// Fetch the manifest through the SDK remote path (size-capped, scheme-validated,
	// same redirect policy as the binary — including the https->http downgrade
	// refusal) rather than a bespoke client. The manifest is the integrity source,
	// so it carries no ChecksumSHA256 of its own.
	body, err := remote.FetchBytes(ctx, remote.HTTPConfig{
		URL:      checksumURL,
		Redirect: redirect,
		Client:   remoteHTTPClient, // nil in prod (default client honours Redirect); tests inject a TLS client
	})
	if err != nil {
		return "", fmt.Errorf("download: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(body))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) != 2 {
			continue
		}
		checksumHex := parts[0]
		name := strings.TrimPrefix(strings.TrimPrefix(parts[1], "./"), "*")
		if name == filename {
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

// getBinaryVersion runs the binary with "version" subcommand and returns the trimmed output.
func getBinaryVersion(binaryPath string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := executorRunner.Run(ctx, sysexec.Command{Name: binaryPath, Args: []string{"version"}})
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
//   - now: clock seam (pass time.Now in production); injected so the
//     24h stale-tmp cutoff is deterministically testable.
func CheckStartupUpdateState(dataDir string, logger interface {
	Info(string, ...any)
	Warn(string, ...any)
}, now func() time.Time) {
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
	cutoff := now().Add(-24 * time.Hour)
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
		logger.Info("removed stale update tmp file", "path", path, "age", now().Sub(info.ModTime()).Round(time.Second))
	}
}
