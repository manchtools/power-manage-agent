package updater

import (
	"context"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// WelcomeConfig holds the configuration for a Welcome-triggered update (Path A).
// The server has already provided the version, URL, and checksum in the Welcome
// message, so no discovery step is needed.
type WelcomeConfig struct {
	LatestVersion  string
	UpdateURL      string
	UpdateChecksum string
	CurrentVersion string
	DataDir        string
	BinaryPath     string
	ServiceName    string
	Logger         *slog.Logger
}

// HandleWelcome processes a Welcome message that includes auto-update
// information. It downloads, verifies, validates, and launches the updater.
//
// Like StartupUpdateCheck, this function never blocks the agent: errors
// are logged as warnings and nil is returned.
func HandleWelcome(ctx context.Context, cfg WelcomeConfig) error {
	logger := cfg.Logger

	// No update needed if versions match or no URL provided.
	if cfg.LatestVersion == "" || cfg.UpdateURL == "" || cfg.LatestVersion == cfg.CurrentVersion {
		return nil
	}

	// Check cooldown for this specific version.
	if IsCoolingDown(cfg.DataDir, cfg.LatestVersion) {
		logger.Info("skipping welcome update due to cooldown", "version", cfg.LatestVersion)
		return nil
	}

	logger.Info("welcome update available", "current", cfg.CurrentVersion, "latest", cfg.LatestVersion)

	// Download and verify the new binary.
	destPath := filepath.Join(updateDir(cfg.DataDir), "agent.new")
	if err := DownloadAndVerify(ctx, cfg.UpdateURL, cfg.UpdateChecksum, destPath); err != nil {
		logger.Warn("failed to download welcome update", "error", err)
		return nil
	}

	// Validate: run the downloaded binary with "version" to ensure it is functional.
	out, err := exec.Command(destPath, "version").Output()
	if err != nil {
		logger.Warn("downloaded binary failed validation", "error", err)
		os.Remove(destPath)
		return nil
	}
	logger.Info("validated new binary from welcome", "reported_version", strings.TrimSpace(string(out)))

	// Launch the updater as a transient systemd service.
	if err := launchUpdater(destPath, cfg.BinaryPath, cfg.DataDir, cfg.ServiceName, logger); err != nil {
		logger.Warn("failed to launch updater from welcome", "error", err)
		return nil
	}

	return nil
}
