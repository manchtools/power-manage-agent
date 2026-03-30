package updater

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// StartupConfig holds the configuration for the startup update check.
type StartupConfig struct {
	Version     string
	DataDir     string
	BinaryPath  string
	ServiceName string
	ControlAddr string
	Arch        string
	TLSConfig   *tls.Config
	Repo        string
	Logger      *slog.Logger
}

// StartupUpdateCheck performs the startup self-heal update check (Path B).
// It never blocks agent startup: errors are logged as warnings and the
// function returns nil.
//
// Flow:
//  1. Read cooldown -- skip if active for the discovered version
//  2. Try server first (5s timeout)
//  3. If server fails -- fall back to GitHub (10s timeout)
//  4. If update available -- download, verify, validate (run `version`), launch updater
//  5. If anything fails -- log warning, return nil
func StartupUpdateCheck(ctx context.Context, cfg StartupConfig) error {
	logger := cfg.Logger

	// Discover update from server or GitHub.
	version, url, checksum, err := discoverUpdate(ctx, cfg)
	if err != nil {
		logger.Warn("update check failed", "error", err)
		return nil
	}

	if version == "" {
		logger.Debug("no update available")
		return nil
	}

	// Check cooldown for this specific version.
	if IsCoolingDown(cfg.DataDir, version) {
		logger.Info("skipping update due to cooldown", "version", version)
		return nil
	}

	logger.Info("update available", "current", cfg.Version, "latest", version)

	// Download and verify the new binary.
	destPath := filepath.Join(updateDir(cfg.DataDir), "agent.new")
	if err := DownloadAndVerify(ctx, url, checksum, destPath); err != nil {
		logger.Warn("failed to download update", "error", err)
		return nil
	}

	// Validate: run the downloaded binary with "version" to ensure it is functional.
	out, err := exec.Command(destPath, "version").Output()
	if err != nil {
		logger.Warn("downloaded binary failed validation", "error", err)
		os.Remove(destPath)
		return nil
	}
	logger.Info("validated new binary", "reported_version", strings.TrimSpace(string(out)))

	// Launch the updater as a transient systemd service.
	if err := launchUpdater(destPath, cfg.BinaryPath, cfg.DataDir, cfg.ServiceName, logger); err != nil {
		logger.Warn("failed to launch updater", "error", err)
		return nil
	}

	return nil
}

// discoverUpdate tries the server first, then falls back to GitHub.
func discoverUpdate(ctx context.Context, cfg StartupConfig) (version, url, checksum string, err error) {
	// Try server first if control address is configured.
	if cfg.ControlAddr != "" && cfg.TLSConfig != nil {
		version, url, checksum, err = CheckServer(ctx, cfg.ControlAddr, cfg.Arch, cfg.TLSConfig)
		if err == nil {
			return version, url, checksum, nil
		}
		cfg.Logger.Warn("server update check failed, falling back to GitHub", "error", err)
	}

	// Fall back to GitHub.
	if cfg.Repo != "" {
		version, url, checksum, err = CheckGitHubRelease(ctx, cfg.Repo, cfg.Version, cfg.Arch)
		if err == nil {
			return version, url, checksum, nil
		}
		return "", "", "", fmt.Errorf("github check: %w", err)
	}

	return "", "", "", fmt.Errorf("no update source configured")
}

// launchUpdater writes a transient systemd service unit and starts it.
// The service runs the downloaded binary with the "update" subcommand.
func launchUpdater(newBinaryPath, agentBinaryPath, dataDir, serviceName string, logger *slog.Logger) error {
	unit := fmt.Sprintf(`[Unit]
Description=Power Manage Agent Auto-Update
After=network.target

[Service]
Type=oneshot
ExecStart=%s update --binary-path %s --data-dir %s --service-name %s
RemainAfterExit=no
`, newBinaryPath, agentBinaryPath, dataDir, serviceName)

	servicePath := "/etc/systemd/system/pm-agent-update.service"

	// Write the unit file via sudo tee.
	cmd := exec.Command("sudo", "tee", servicePath)
	cmd.Stdin = strings.NewReader(unit)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("write service unit: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Daemon-reload to pick up the new unit.
	if out, err := exec.Command("sudo", "systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("daemon-reload: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Start the update service (non-blocking for a oneshot with RemainAfterExit=no).
	logger.Info("launching update service", "service", "pm-agent-update.service")
	if out, err := exec.Command("sudo", "systemctl", "start", "pm-agent-update.service").CombinedOutput(); err != nil {
		return fmt.Errorf("start update service: %s: %w", strings.TrimSpace(string(out)), err)
	}

	return nil
}
