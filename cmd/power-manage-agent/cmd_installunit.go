package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"

	"github.com/manchtools/power-manage-sdk/logging"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	"github.com/manchtools/power-manage-sdk/sys/service"
	"github.com/manchtools/power-manage/agent/internal/credentials"
	"github.com/manchtools/power-manage/agent/internal/unit"
)

// runInstallUnit implements the `install-unit` subcommand (spec 27): it
// installs/refreshes the agent's systemd unit from the template embedded
// in THIS binary. Invoked once by install.sh (systemd cannot start the
// service before a unit exists, and enrollment needs the running
// daemon's socket, so the first placement is triggered from outside)
// and by the self-updater on the NEW binary between swap and respawn.
// Idempotent: an identical on-disk unit is a no-op.
func runInstallUnit(args []string) int {
	flags := flag.NewFlagSet("install-unit", flag.ContinueOnError)
	dataDir := flags.String("data-dir", credentials.DefaultDataDir, "Data directory the unit passes to the agent")
	if err := flags.Parse(args); err != nil {
		return 2
	}

	logger := logging.SetupLogger("info", "text", os.Stderr)

	if os.Geteuid() != 0 {
		logger.Error("install-unit must run as root (it writes /etc/systemd/system and reloads systemd)")
		return 1
	}

	ctx := context.Background()
	if len(service.Detect(ctx)) == 0 {
		// The install path fails LOUDLY where the startup reconcile
		// no-ops: an operator running install-unit on a host without
		// systemd must learn it now, not at the first enable --now.
		logger.Error("no usable systemd detected on this host; the agent's unit cannot be installed")
		return 1
	}

	// Root is required above, so the Direct backend applies — fd-anchored
	// writes, no sudo round-trip.
	runner, err := sysexec.NewRunner(sysexec.Direct)
	if err != nil {
		logger.Error("failed to build runner", "error", err)
		return 1
	}
	mgr, err := service.New(service.Systemd, runner)
	if err != nil {
		logger.Error("failed to build service manager", "error", err)
		return 1
	}

	binaryPath, err := os.Executable()
	if err != nil {
		logger.Error("failed to resolve own executable path", "error", err)
		return 1
	}

	if err := unit.EnsureInstalled(ctx, mgr, logger, unit.Params{BinaryPath: binaryPath, DataDir: *dataDir}); err != nil {
		logger.Error("unit install failed", "unit", unit.UnitName, "error", err)
		return 1
	}
	fmt.Fprintf(os.Stderr, "unit %s installed (data-dir=%s)\n", unit.UnitName, *dataDir)
	return 0
}

// reconcileUnitAtStartup is the daemon-path startup reconcile (spec 27):
// rewrite the on-disk unit from the embedded template when it drifted,
// daemon-reload, and log at ERROR — never restart. Fail-open by
// contract: any failure logs and the agent serves regardless; a broken
// reconcile must never take the device unmanaged. Skipped for non-root
// and hosts without a usable systemd (container/dev runs); an absent
// unit file is skipped inside unit.Reconcile itself.
func reconcileUnitAtStartup(ctx context.Context, runner sysexec.Runner, logger *slog.Logger, dataDir string) {
	if os.Geteuid() != 0 {
		logger.Debug("skipping unit reconcile: not running as root")
		return
	}
	if len(service.Detect(ctx)) == 0 {
		logger.Debug("skipping unit reconcile: no usable systemd detected")
		return
	}
	mgr, err := service.New(service.Systemd, runner)
	if err != nil {
		logger.Error("unit reconcile: failed to build service manager; agent continues with the on-disk unit", "error", err)
		return
	}
	binaryPath, err := os.Executable()
	if err != nil {
		logger.Error("unit reconcile: failed to resolve own executable path; agent continues with the on-disk unit", "error", err)
		return
	}
	drifted, err := unit.Reconcile(ctx, mgr, logger, unit.Params{BinaryPath: binaryPath, DataDir: dataDir})
	if err != nil {
		logger.Error("unit reconcile failed; agent continues with the on-disk unit", "unit", unit.UnitName, "error", err)
		return
	}
	if drifted {
		logger.Error("systemd unit was STALE and has been rewritten from the embedded template; the new settings apply at the next service restart or reboot",
			"unit", unit.UnitName)
	}
}
