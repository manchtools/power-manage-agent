package updater

import (
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// RunUpdate performs the update installation. It is invoked as the NEW binary
// running inside the pm-agent-update transient systemd service.
//
// Steps:
//  1. Stop the agent service
//  2. Backup the current binary
//  3. Install self (the currently running executable) as the new agent binary
//  4. chmod +x the installed binary
//  5. Start the agent service
//  6. Health check: poll systemctl is-active every 2s for 30s
//  7. If healthy: write state complete, cleanup
//  8. If unhealthy: restore backup, restart, write cooldown, write state rolled_back
//  9. Always cleanup: remove transient service, daemon-reload
func RunUpdate(binaryPath, dataDir, serviceName string, logger *slog.Logger) error {
	dir := updateDir(dataDir)
	backupPath := filepath.Join(dir, "agent.backup")

	// Determine the path to ourselves (the new binary).
	self, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve self executable: %w", err)
	}

	// Step 1: Stop the agent service.
	logger.Info("stopping agent service", "service", serviceName)
	if out, err := exec.Command("sudo", "systemctl", "stop", serviceName).CombinedOutput(); err != nil {
		return fmt.Errorf("stop service: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Step 2: Backup the current binary.
	logger.Info("backing up current binary", "src", binaryPath, "dst", backupPath)
	if out, err := exec.Command("sudo", "cp", binaryPath, backupPath).CombinedOutput(); err != nil {
		return fmt.Errorf("backup binary: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Step 3: Install self as the new binary.
	logger.Info("installing new binary", "src", self, "dst", binaryPath)
	if out, err := exec.Command("sudo", "cp", self, binaryPath).CombinedOutput(); err != nil {
		// Restore backup before returning.
		restoreBackup(backupPath, binaryPath, logger)
		return fmt.Errorf("install binary: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Step 4: Make executable.
	if out, err := exec.Command("sudo", "chmod", "+x", binaryPath).CombinedOutput(); err != nil {
		restoreBackup(backupPath, binaryPath, logger)
		return fmt.Errorf("chmod binary: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Get the installed version for state reporting.
	installedVersion := getVersion(binaryPath)
	logger.Info("installed version", "version", installedVersion)

	// Step 5: Start the agent service.
	logger.Info("starting agent service", "service", serviceName)
	if out, err := exec.Command("sudo", "systemctl", "start", serviceName).CombinedOutput(); err != nil {
		logger.Error("failed to start service after install", "error", err, "output", strings.TrimSpace(string(out)))
		rollback(backupPath, binaryPath, serviceName, dataDir, installedVersion, logger)
		return fmt.Errorf("start service: %s: %w", strings.TrimSpace(string(out)), err)
	}

	// Step 6: Health check — poll is-active every 2s for 30s.
	healthy := waitHealthy(serviceName, 30*time.Second, 2*time.Second, logger)

	if healthy {
		// Step 7: Success.
		logger.Info("update successful", "version", installedVersion)
		if err := WriteState(dataDir, &State{Phase: "complete", Version: installedVersion}); err != nil {
			logger.Warn("failed to write completion state", "error", err)
		}
	} else {
		// Step 8: Rollback.
		logger.Warn("health check failed, rolling back", "version", installedVersion)
		rollback(backupPath, binaryPath, serviceName, dataDir, installedVersion, logger)
	}

	// Step 9: Cleanup the transient service file and daemon-reload.
	cleanup(logger)

	return nil
}

// waitHealthy polls systemctl is-active for the service until it reports
// "active" or the timeout expires.
func waitHealthy(serviceName string, timeout, interval time.Duration, logger *slog.Logger) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		out, err := exec.Command("sudo", "systemctl", "is-active", serviceName).Output()
		status := strings.TrimSpace(string(out))
		if err == nil && status == "active" {
			logger.Info("service is healthy", "service", serviceName)
			return true
		}
		logger.Debug("waiting for service", "status", status)
		time.Sleep(interval)
	}
	return false
}

// rollback restores the backup binary, restarts the service, and writes
// cooldown and rolled_back state.
func rollback(backupPath, binaryPath, serviceName, dataDir, version string, logger *slog.Logger) {
	logger.Warn("performing rollback", "backup", backupPath, "target", binaryPath)

	restoreBackup(backupPath, binaryPath, logger)

	// Restart the service with the restored binary.
	if out, err := exec.Command("sudo", "systemctl", "restart", serviceName).CombinedOutput(); err != nil {
		logger.Error("failed to restart service after rollback", "error", err, "output", strings.TrimSpace(string(out)))
	}

	// Write cooldown (1 hour) so the agent skips this version for a while.
	if err := WriteCooldown(dataDir, version, 1*time.Hour); err != nil {
		logger.Error("failed to write cooldown", "error", err)
	}

	// Write rolled_back state.
	if err := WriteState(dataDir, &State{Phase: "rolled_back", Version: version}); err != nil {
		logger.Error("failed to write rollback state", "error", err)
	}
}

// restoreBackup copies the backup binary back to the original location.
func restoreBackup(backupPath, binaryPath string, logger *slog.Logger) {
	if out, err := exec.Command("sudo", "cp", backupPath, binaryPath).CombinedOutput(); err != nil {
		logger.Error("failed to restore backup", "error", err, "output", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("sudo", "chmod", "+x", binaryPath).CombinedOutput(); err != nil {
		logger.Error("failed to chmod restored binary", "error", err, "output", strings.TrimSpace(string(out)))
	}
}

// getVersion runs the binary with the "version" subcommand and returns
// the trimmed output. Returns "unknown" on failure.
func getVersion(binaryPath string) string {
	out, err := exec.Command(binaryPath, "version").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

// cleanup removes the transient systemd service file and runs daemon-reload.
func cleanup(logger *slog.Logger) {
	servicePath := "/etc/systemd/system/pm-agent-update.service"
	if out, err := exec.Command("sudo", "rm", "-f", servicePath).CombinedOutput(); err != nil {
		logger.Warn("failed to remove transient service", "error", err, "output", strings.TrimSpace(string(out)))
	}
	if out, err := exec.Command("sudo", "systemctl", "daemon-reload").CombinedOutput(); err != nil {
		logger.Warn("failed to daemon-reload", "error", err, "output", strings.TrimSpace(string(out)))
	}
}
