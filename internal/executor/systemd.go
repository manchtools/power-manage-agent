// Package executor provides systemd utility functions for action executors.
package executor

import (
	"context"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// =============================================================================
// Systemd Unit State Queries
// =============================================================================

// SystemdUnitStatus represents the current status of a systemd unit.
type SystemdUnitStatus struct {
	Enabled bool
	Active  bool
	Masked  bool
	Static  bool
}

// getSystemdUnitStatus retrieves the complete status of a systemd unit.
func getSystemdUnitStatus(unitName string) SystemdUnitStatus {
	status := SystemdUnitStatus{}

	// Check enabled state
	out, _, _ := queryCmdOutput("systemctl", "is-enabled", unitName)
	enabledStatus := strings.TrimSpace(out)

	switch enabledStatus {
	case "enabled", "enabled-runtime":
		status.Enabled = true
	case "static", "indirect", "generated":
		status.Enabled = true
		status.Static = true
	case "masked":
		status.Masked = true
	}

	// Check active state
	out, _, _ = queryCmdOutput("systemctl", "is-active", unitName)
	status.Active = strings.TrimSpace(out) == "active"

	return status
}

// isUnitEnabled checks if a systemd unit is enabled or in a state where
// enabling is not needed (static, indirect, generated units).
func isUnitEnabled(unitName string) bool {
	out, _, _ := queryCmdOutput("systemctl", "is-enabled", unitName)
	status := strings.TrimSpace(out)
	switch status {
	case "enabled", "enabled-runtime":
		return true
	case "static", "indirect", "generated":
		// These units cannot or don't need to be enabled explicitly
		return true
	default:
		// disabled, masked, or unknown
		return false
	}
}

// isUnitMasked checks if a systemd unit is masked.
func isUnitMasked(unitName string) bool {
	out, _, _ := queryCmdOutput("systemctl", "is-enabled", unitName)
	return strings.TrimSpace(out) == "masked"
}

// isUnitActive checks if a systemd unit is currently active (running).
func isUnitActive(unitName string) bool {
	out, _, _ := queryCmdOutput("systemctl", "is-active", unitName)
	return strings.TrimSpace(out) == "active"
}

// =============================================================================
// Systemd Unit Control Operations
// =============================================================================

// systemctlDaemonReload runs systemctl daemon-reload to reload systemd.
func systemctlDaemonReload(ctx context.Context) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "systemctl", "daemon-reload")
}

// systemctlEnable enables a systemd unit.
func systemctlEnable(ctx context.Context, unitName string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "systemctl", "enable", unitName)
}

// systemctlDisable disables a systemd unit.
func systemctlDisable(ctx context.Context, unitName string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "systemctl", "disable", unitName)
}

// systemctlStart starts a systemd unit.
func systemctlStart(ctx context.Context, unitName string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "systemctl", "start", unitName)
}

// systemctlStop stops a systemd unit.
func systemctlStop(ctx context.Context, unitName string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "systemctl", "stop", unitName)
}

// systemctlRestart restarts a systemd unit.
func systemctlRestart(ctx context.Context, unitName string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "systemctl", "restart", unitName)
}

// systemctlMask masks a systemd unit.
func systemctlMask(ctx context.Context, unitName string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "systemctl", "mask", unitName)
}

// systemctlUnmask unmasks a systemd unit.
func systemctlUnmask(ctx context.Context, unitName string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "systemctl", "unmask", unitName)
}

// =============================================================================
// Systemd Timer Operations
// =============================================================================

// systemctlEnableNow enables and starts a systemd unit.
func systemctlEnableNow(ctx context.Context, unitName string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "systemctl", "enable", "--now", unitName)
}

// systemctlDisableNow disables and stops a systemd unit.
func systemctlDisableNow(ctx context.Context, unitName string) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "systemctl", "disable", "--now", unitName)
}

// =============================================================================
// Systemd Helper Functions
// =============================================================================

// writeSystemdUnit writes a systemd unit file to /etc/systemd/system.
func writeSystemdUnit(ctx context.Context, unitName, content string) error {
	unitPath := "/etc/systemd/system/" + unitName
	return atomicWriteFile(ctx, unitPath, content, "0644", "root", "root")
}

// removeSystemdUnit removes a systemd unit file from /etc/systemd/system.
func removeSystemdUnit(ctx context.Context, unitName string) {
	unitPath := "/etc/systemd/system/" + unitName
	removeFile(ctx, unitPath)
}
