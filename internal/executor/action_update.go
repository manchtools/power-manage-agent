// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/pkg"
	sysnotify "github.com/manchtools/power-manage/sdk/go/sys/notify"
)

// hasUpdatesAvailable checks if there are pending package updates.
// Uses exit codes and structured queries — language-agnostic.
func (e *Executor) hasUpdatesAvailable(ctx context.Context, securityOnly bool) bool {
	if pkg.IsDnf() {
		// dnf check-update: exit 100 = updates available, 0 = none (language-agnostic)
		args := []string{"check-update"}
		if securityOnly {
			args = append(args, "--security")
		}
		_, exitCode, _ := queryCmdOutput("dnf", args...)
		return exitCode == 100
	}
	if pkg.IsApt() {
		// apt/apt-get -s upgrade: simulate and count lines with "Inst " prefix (language-agnostic)
		aptCmd := "apt-get"
		if _, err := exec.LookPath("apt"); err == nil {
			aptCmd = "apt"
		}
		out, _, _ := queryCmdOutput(aptCmd, "-s", "upgrade")
		for _, line := range strings.Split(out, "\n") {
			if strings.HasPrefix(line, "Inst ") {
				return true
			}
		}
		return false
	}
	if pkg.IsPacman() {
		// pacman -Qu: exit 0 = updates available, 1 = none (language-agnostic)
		_, exitCode, _ := queryCmdOutput("pacman", "-Qu")
		return exitCode == 0
	}
	if pkg.IsZypper() {
		// zypper: exit 100 = updates available, 0 = none
		_, exitCode, _ := queryCmdOutput("zypper", "--non-interactive", "list-updates")
		return exitCode == 100
	}
	return true // assume updates for unknown package managers
}

// installedPackageCount returns the number of installed packages (language-agnostic).
func installedPackageCount() int {
	if pkg.IsDnf() || pkg.IsZypper() {
		out, exitCode, _ := queryCmdOutput("rpm", "-qa", "--qf", "x\n")
		if exitCode != 0 {
			return -1
		}
		return strings.Count(out, "x\n")
	}
	if pkg.IsApt() {
		out, exitCode, _ := queryCmdOutput("dpkg-query", "-f", "x\n", "-W")
		if exitCode != 0 {
			return -1
		}
		return strings.Count(out, "x\n")
	}
	if pkg.IsPacman() {
		out, exitCode, _ := queryCmdOutput("pacman", "-Qq")
		if exitCode != 0 {
			return -1
		}
		count := 0
		for _, line := range strings.Split(out, "\n") {
			if strings.TrimSpace(line) != "" {
				count++
			}
		}
		return count
	}
	return -1
}

// dnfUpgrade runs dnf upgrade. If securityOnly is true, only security updates are applied.
func dnfUpgrade(ctx context.Context, securityOnly bool) (*pb.CommandOutput, error) {
	if securityOnly {
		return runSudoCmd(ctx, "dnf", "-y", "upgrade", "--security")
	}
	return runSudoCmd(ctx, "dnf", "-y", "upgrade")
}

// dnfAutoremove runs dnf autoremove -y to remove unused packages.
func dnfAutoremove(ctx context.Context) (*pb.CommandOutput, error) {
	return runSudoCmd(ctx, "dnf", "-y", "autoremove")
}

// repairFilesystem attempts to fix read-only filesystem issues.
// This can happen when the kernel remounts the filesystem as read-only due to errors.
// It checks all real (non-virtual) filesystem mounts, not just /, because partitions
// like /usr may be mounted separately and go read-only independently.
// Returns true if all filesystems are writable, false if any repair failed.
func (e *Executor) repairFilesystem(ctx context.Context) bool {
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil {
		e.logger.Warn("could not read /proc/mounts", "error", err)
		return true // Assume writable, let operations fail naturally
	}

	allOk := true
	for _, line := range strings.Split(string(mounts), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		device := fields[0]
		mountPoint := fields[1]
		options := fields[3]

		// Only check real block device filesystems (skip virtual: proc, sys, cgroup, etc.)
		if !strings.HasPrefix(device, "/dev/") {
			continue
		}

		isReadOnly := false
		for _, opt := range strings.Split(options, ",") {
			if opt == "ro" {
				isReadOnly = true
				break
			}
		}
		if !isReadOnly {
			continue
		}

		e.logger.Warn("filesystem is mounted read-only, attempting remount",
			"mount", mountPoint, "device", device,
		)

		output, err := runSudoCmd(ctx, "mount", "-o", "remount,rw", mountPoint)
		if err != nil {
			e.logger.Error("failed to remount filesystem as read-write",
				"mount", mountPoint, "device", device,
				"error", err, "output", output,
			)
			e.logger.Error("filesystem may have errors - system likely needs reboot and fsck",
				"mount", mountPoint,
			)
			allOk = false
		} else {
			e.logger.Info("successfully remounted filesystem as read-write",
				"mount", mountPoint, "device", device,
			)
		}
	}

	return allOk
}

// isRootReadOnly checks whether the root filesystem is mounted read-only
// by parsing /proc/mounts.
func isRootReadOnly() bool {
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[1] == "/" {
			for _, opt := range strings.Split(fields[3], ",") {
				if opt == "ro" {
					return true
				}
			}
		}
	}
	return false
}

// repairPackageManager attempts to fix common broken package manager states.
// This handles issues like interrupted dpkg operations, broken dependencies,
// and stale lock files that can prevent package operations from succeeding.
func (e *Executor) repairPackageManager(ctx context.Context) {
	// If root filesystem is read-only (e.g. disk error caused kernel to remount ro),
	// all package operations will fail. Attempt to remount it read-write first.
	if isRootReadOnly() {
		slog.Warn("root filesystem is mounted read-only, attempting remount as read-write")
		if _, err := runSudoCmd(ctx, "mount", "-o", "remount,rw", "/"); err != nil {
			slog.Error("failed to remount root filesystem as read-write", "error", err)
		}
	}

	// Detect which package manager we're using and run appropriate repairs
	if pkg.IsApt() {
		e.repairApt(ctx)
	} else if pkg.IsDnf() {
		e.repairDnf(ctx)
	} else if pkg.IsPacman() {
		e.repairPacman(ctx)
	} else if pkg.IsZypper() {
		e.repairZypper(ctx)
	}

	// Flatpak can coexist with any traditional package manager
	if pkg.IsFlatpak() {
		e.repairFlatpak(ctx)
	}
}

// removeStaleLockFile removes a package-manager lock file ONLY if
// no live process currently holds it open. Unconditionally
// `rm -f`-ing a lock while a real apt/dpkg/pacman/zypper process is
// mid-flight corrupts the database — the running process keeps its
// open file descriptor (POSIX semantics) but a NEW process can now
// grab the lock and start a concurrent transaction.
//
// Liveness check uses `fuser <path>`: exit 0 means at least one
// process has the file open (skip removal), exit 1 means no holder
// (safe to remove), other exits / fuser-not-installed are treated
// as "be safe, skip" so we never delete a lock we couldn't prove
// stale.
func (e *Executor) removeStaleLockFile(ctx context.Context, path string) {
	if _, err := os.Stat(path); err != nil {
		// Already absent — nothing to do.
		return
	}
	// `fuser -s` runs silently and uses exit codes only:
	//   exit 0 → file is held by a live process (skip removal),
	//   exit 1 → no holder (safe to unlink),
	//   any other exit (incl. fuser-missing) → can't prove stale,
	//                                          be safe and skip.
	fuserOut, fuserErr := runSudoCmd(ctx, "fuser", "-s", path)
	if fuserErr == nil {
		slog.Warn("repair: lock file held by live process; refusing to unlink",
			"path", path)
		return
	}
	if fuserOut == nil || fuserOut.ExitCode != 1 {
		slog.Warn("repair: cannot probe lock file holder; skipping unlink",
			"path", path, "error", fuserErr)
		return
	}
	if _, err := runSudoCmd(ctx, "rm", "-f", "--", path); err != nil {
		slog.Warn("repair: failed to remove confirmed-stale lock file",
			"path", path, "error", err)
	}
}

// removeStaleZyppPidFile removes a zypper PID file ONLY if the
// recorded PID does not belong to a running process. zypp.pid
// records zypper's PID; the daemonized process closes the fd
// after writing, so fuser would report no holder even when zypper
// is mid-flight — using removeStaleLockFile here would mis-classify
// a running zypper as stale and yank the lock from under it.
//
// Liveness check uses `kill -0 <pid>`: exit 0 means the process
// exists (skip removal), nonzero means no such process (safe to
// remove). A malformed file (no parseable PID) is treated as
// stale and removed. We never delete a PID file we couldn't prove
// stale via a successful kill -0 negative.
func (e *Executor) removeStaleZyppPidFile(ctx context.Context, path string) {
	if _, err := os.Stat(path); err != nil {
		return
	}
	out, readErr := runSudoCmd(ctx, "cat", "--", path)
	if readErr != nil || out == nil {
		slog.Warn("repair: cannot read zypp PID file; skipping unlink",
			"path", path, "error", readErr)
		return
	}
	pid := strings.TrimSpace(out.Stdout)
	if pid == "" {
		// Empty PID file — no live holder to harm; remove it.
		if _, err := runSudoCmd(ctx, "rm", "-f", "--", path); err != nil {
			slog.Warn("repair: failed to remove empty zypp PID file",
				"path", path, "error", err)
		}
		return
	}
	// Validate PID is purely numeric before splicing into kill.
	for _, r := range pid {
		if r < '0' || r > '9' {
			slog.Warn("repair: zypp PID file contains non-numeric content; skipping unlink",
				"path", path, "content", pid)
			return
		}
	}
	killOut, killErr := runSudoCmd(ctx, "kill", "-0", pid)
	if killErr == nil {
		slog.Warn("repair: zypper process is still running; refusing to unlink PID file",
			"path", path, "pid", pid)
		return
	}
	if killOut == nil || killOut.ExitCode != 1 {
		// kill -0 returns 1 for "no such process" and 2 for permission/usage.
		// Anything other than 1 means we couldn't prove the process is gone.
		slog.Warn("repair: cannot probe zypp PID liveness; skipping unlink",
			"path", path, "pid", pid, "error", killErr)
		return
	}
	if _, err := runSudoCmd(ctx, "rm", "-f", "--", path); err != nil {
		slog.Warn("repair: failed to remove confirmed-stale zypp PID file",
			"path", path, "error", err)
	}
}

// repairApt fixes common apt/dpkg issues:
// - Stale lock files from interrupted operations
// - Interrupted dpkg operations (dpkg --configure -a)
// - Broken dependencies (apt -f install)
// - Stale package lists
func (e *Executor) repairApt(ctx context.Context) {
	// Remove stale lock files that may be left from interrupted operations.
	// Each removal is gated on a fuser-based liveness probe so we never
	// yank a lock from a live apt/dpkg process.
	for _, lf := range []string{
		"/var/lib/dpkg/lock-frontend",
		"/var/lib/dpkg/lock",
		"/var/lib/apt/lists/lock",
		"/var/cache/apt/archives/lock",
	} {
		e.removeStaleLockFile(ctx, lf)
	}

	// Fix any interrupted dpkg operations.
	// Uses env to set DEBIAN_FRONTEND=noninteractive so kernel/grub postinst
	// scripts don't hang waiting for debconf input. The --force-confdef and
	// --force-confold options prevent dpkg from prompting about config files.
	if _, err := runSudoCmd(ctx, "env", "DEBIAN_FRONTEND=noninteractive",
		"dpkg", "--configure", "-a", "--force-confdef", "--force-confold"); err != nil {
		slog.Warn("repairApt: dpkg --configure -a failed", "error", err)
	}

	// Use the SDK Apt abstraction which sets DEBIAN_FRONTEND=noninteractive.
	apt := pkg.NewAptWithContext(ctx)

	// Update package lists to get latest dependency info
	if _, err := apt.Update(); err != nil {
		slog.Warn("repairApt: apt update failed", "error", err)
	}

	// Fix broken dependencies and install missing ones
	if _, err := apt.FixBroken(); err != nil {
		slog.Warn("repairApt: apt fix-broken failed", "error", err)
	}
}

// repairDnf fixes common dnf/rpm issues:
// - Incomplete transactions (dnf-automatic, interrupted updates)
// - Corrupted rpm database
// - Duplicate packages
func (e *Executor) repairDnf(ctx context.Context) {
	// Complete any interrupted transactions
	// This is similar to "dnf-automatic" leaving things half-done
	if _, err := runSudoCmd(ctx, "dnf", "-y", "history", "redo", "last"); err != nil {
		slog.Warn("repairDnf: history redo failed", "error", err)
	}

	// Clean up any duplicate packages
	if _, err := runSudoCmd(ctx, "dnf", "-y", "remove", "--duplicates"); err != nil {
		slog.Warn("repairDnf: remove duplicates failed", "error", err)
	}

	// Rebuild rpm database if corrupted
	// First try to verify, if that fails, rebuild
	if output, err := runSudoCmd(ctx, "rpm", "--verifydb"); err != nil || output.ExitCode != 0 {
		if _, err := runSudoCmd(ctx, "rpm", "--rebuilddb"); err != nil {
			slog.Warn("repairDnf: rpm --rebuilddb failed", "error", err)
		}
	}
}

// repairPacman fixes common pacman issues:
// - Stale lock files from interrupted operations
// - Corrupted package database
// - Keyring issues
func (e *Executor) repairPacman(ctx context.Context) {
	// Remove stale lock file if held by no live process — handles
	// "unable to lock database" errors from interrupted operations
	// without yanking the lock from a real concurrent transaction.
	e.removeStaleLockFile(ctx, "/var/lib/pacman/db.lck")

	// Refresh package database to fix potential corruption
	// Using -Syy to force refresh even if recently updated
	if _, err := runSudoCmd(ctx, "pacman", "-Syy", "--noconfirm"); err != nil {
		slog.Warn("repairPacman: database refresh failed", "error", err)
	}

	// Reinitialize keyring if there are signature issues
	// This fixes "signature is unknown trust" errors
	if _, err := runSudoCmd(ctx, "pacman-key", "--init"); err != nil {
		slog.Warn("repairPacman: pacman-key init failed", "error", err)
	}
	if _, err := runSudoCmd(ctx, "pacman-key", "--populate", "archlinux"); err != nil {
		slog.Warn("repairPacman: pacman-key populate failed", "error", err)
	}
}

// repairZypper fixes common zypper/rpm issues:
// - Stale lock files
// - Corrupted rpm database
// - Repository metadata issues
// - Broken dependencies
func (e *Executor) repairZypper(ctx context.Context) {
	// /var/run/zypp.pid is a PID file, not a flock-style lockfile.
	// `fuser` would report no holder even when zypper is running
	// because the daemonized zypper writes the PID and closes the
	// file descriptor. Use a PID-based liveness probe instead.
	e.removeStaleZyppPidFile(ctx, "/var/run/zypp.pid")

	// Clean repository metadata cache to fix stale metadata issues
	if _, err := runSudoCmd(ctx, "zypper", "--non-interactive", "clean", "--all"); err != nil {
		slog.Warn("repairZypper: clean failed", "error", err)
	}

	// Refresh repositories to get fresh metadata
	if _, err := runSudoCmd(ctx, "zypper", "--non-interactive", "refresh"); err != nil {
		slog.Warn("repairZypper: refresh failed", "error", err)
	}

	// Verify and fix dependency issues
	if _, err := runSudoCmd(ctx, "zypper", "--non-interactive", "verify", "--recommends"); err != nil {
		slog.Warn("repairZypper: verify failed", "error", err)
	}

	// Rebuild rpm database if corrupted
	if output, err := runSudoCmd(ctx, "rpm", "--verifydb"); err != nil || output.ExitCode != 0 {
		if _, err := runSudoCmd(ctx, "rpm", "--rebuilddb"); err != nil {
			slog.Warn("repairZypper: rpm --rebuilddb failed", "error", err)
		}
	}
}

// executeUpdate performs a system-wide package update.
// It respects version pinning (apt-mark hold / dnf versionlock).
func (e *Executor) executeUpdate(ctx context.Context, params *pb.UpdateParams) (*pb.CommandOutput, bool, error) {
	if e.pkgManager == nil {
		return nil, false, fmt.Errorf("no supported package manager found")
	}

	// Repair filesystem if mounted read-only (common after kernel errors)
	if out, err := e.requireWritableFS(ctx); err != nil {
		return out, false, err
	}

	// Repair any broken package manager state first
	e.repairPackageManager(ctx)

	var allOutput strings.Builder
	var lastErr error

	securityOnly := params != nil && params.SecurityOnly

	// Check if updates are available before running the upgrade.
	updatesAvailable := e.hasUpdatesAvailable(ctx, securityOnly)

	// Record pre-update reboot state to detect new reboot requirements.
	rebootRequiredBefore := e.checkRebootRequired()

	// Update package index
	if updateResult, err := e.pkgManager.Update(); err != nil {
		allOutput.WriteString("=== Package Index Update ===\n")
		if updateResult != nil {
			allOutput.WriteString(updateResult.Stdout)
			allOutput.WriteString(updateResult.Stderr)
		}
		allOutput.WriteString(fmt.Sprintf("Warning: update failed: %v\n\n", err))
	} else if updateResult != nil {
		allOutput.WriteString("=== Package Index Update ===\n")
		allOutput.WriteString(updateResult.Stdout)
		if updateResult.Stderr != "" {
			allOutput.WriteString(updateResult.Stderr)
		}
		allOutput.WriteString("\n")
	}

	// Re-check after index update (new updates may now be visible)
	if !updatesAvailable {
		updatesAvailable = e.hasUpdatesAvailable(ctx, securityOnly)
	}

	// Perform the upgrade
	allOutput.WriteString("=== Package Upgrade ===\n")

	if pkg.IsApt() {
		lastErr = e.executeAptUpgrade(ctx, params, &allOutput)
	} else if pkg.IsDnf() {
		lastErr = e.executeDnfUpgrade(ctx, params, &allOutput)
	} else {
		// Fallback to generic upgrade via the builder
		upgradeResult, err := e.pkgManager.Upgrade().Run()
		if err != nil {
			allOutput.WriteString(fmt.Sprintf("Error: %v\n", err))
			if upgradeResult != nil {
				allOutput.WriteString(upgradeResult.Stdout)
				allOutput.WriteString(upgradeResult.Stderr)
			}
			lastErr = err
		} else if upgradeResult != nil {
			allOutput.WriteString(upgradeResult.Stdout)
			allOutput.WriteString(upgradeResult.Stderr)
		}
	}

	// Autoremove if requested — use package count comparison (language-agnostic)
	autoremoved := false
	if params != nil && params.Autoremove {
		allOutput.WriteString("\n=== Autoremove Unused Packages ===\n")
		countBefore := installedPackageCount()
		// Capture autoremove errors so the action result reflects
		// "we tried to autoremove and the call itself failed", not
		// "everything succeeded but stale packages quietly remain".
		// The previous shape only wrote stderr to the buffer and
		// dropped the err on the floor.
		var autoremoveErr error
		if pkg.IsApt() {
			apt := pkg.NewAptWithContext(ctx)
			output, err := apt.Autoremove()
			if output != nil {
				allOutput.WriteString(output.Stdout)
				if err != nil {
					allOutput.WriteString(output.Stderr)
				}
			}
			autoremoveErr = err
		} else if pkg.IsDnf() {
			output, err := dnfAutoremove(ctx)
			if output != nil {
				allOutput.WriteString(output.Stdout)
				if err != nil {
					allOutput.WriteString(output.Stderr)
				}
			}
			autoremoveErr = err
		}
		countAfter := installedPackageCount()
		autoremoved = countBefore > 0 && countAfter > 0 && countBefore != countAfter
		if autoremoveErr != nil && lastErr == nil {
			lastErr = fmt.Errorf("autoremove: %w", autoremoveErr)
		}
	}

	// Check if this run created a new reboot requirement.
	rebootRequiredAfter := e.checkRebootRequired()
	newRebootRequired := rebootRequiredAfter && !rebootRequiredBefore
	if rebootRequiredAfter {
		allOutput.WriteString("\n*** REBOOT REQUIRED ***\n")
		if newRebootRequired && params != nil && params.RebootIfRequired {
			// Issue the shutdown FIRST and only report success if
			// it actually went out — the prior shape printed
			// "Scheduling reboot..." regardless of whether
			// shutdown(8) accepted the request, so an operator
			// would see "scheduled" in the action result while
			// the host stayed up. Failure to schedule a reboot
			// the operator explicitly asked for is a real action
			// failure, not a logged warning. The desktop
			// notification is also gated on success so we don't
			// tell users "your system will reboot" when it won't.
			if out, err := runSudoCmd(ctx, "shutdown", "-r", "+1", "System update requires reboot"); err != nil {
				if out != nil {
					allOutput.WriteString(out.Stdout)
					allOutput.WriteString(out.Stderr)
				}
				allOutput.WriteString(fmt.Sprintf("FAILED to schedule reboot: %v\n", err))
				// Always join the reboot failure into lastErr — the
				// preceding comment claims this is a real action
				// failure, but a first-error-wins guard would silently
				// demote it whenever an earlier upgrade error already
				// occupied lastErr. errors.Join keeps both visible to
				// the caller.
				lastErr = errors.Join(lastErr, fmt.Errorf("schedule reboot: %w", err))
			} else {
				sysnotify.NotifyAll(ctx, "System Reboot", "A system update requires a reboot. This system will reboot in 1 minute.")
				allOutput.WriteString("Scheduled reboot in 1 minute.\n")
			}
		}
	}

	exitCode := int32(0)
	if lastErr != nil {
		exitCode = 1
	}

	changed := updatesAvailable || autoremoved || newRebootRequired
	return &pb.CommandOutput{
		ExitCode: exitCode,
		Stdout:   allOutput.String(),
	}, changed, lastErr
}

// executeAptUpgrade performs apt-specific upgrade.
func (e *Executor) executeAptUpgrade(ctx context.Context, params *pb.UpdateParams, output *strings.Builder) error {
	if params != nil && params.SecurityOnly {
		// Use unattended-upgrades for security-only updates if available.
		if _, err := exec.LookPath("unattended-upgrade"); err == nil {
			cmdOutput, err := runSudoCmd(ctx, "unattended-upgrade", "-v")
			if cmdOutput != nil {
				output.WriteString(cmdOutput.Stdout)
				output.WriteString(cmdOutput.Stderr)
			}
			return err
		}
		// No security-only path on this host. Fail closed instead
		// of silently falling through to a full apt.Upgrade() —
		// the caller asked for security-only because their
		// compliance posture forbids the broader upgrade, and
		// quietly delivering it anyway is a real compliance
		// violation. Operators can install unattended-upgrades or
		// switch the action to allow full upgrades.
		output.WriteString("ERROR: security-only updates requested but no security-only path is available on this host (install unattended-upgrades, or set SecurityOnly=false to allow full upgrades).\n")
		return fmt.Errorf("security-only apt updates requested but unattended-upgrade is not installed")
	}

	// Use the SDK Apt abstraction which sets DEBIAN_FRONTEND=noninteractive.
	apt := pkg.NewAptWithContext(ctx)

	// Standard upgrade
	cmdOutput, err := apt.Upgrade()
	if cmdOutput != nil {
		output.WriteString(cmdOutput.Stdout)
		output.WriteString(cmdOutput.Stderr)
	}

	// Also run dist-upgrade for held-back packages (still respects holds).
	// A dist-upgrade failure (e.g. a half-completed kernel transition)
	// must not be swallowed — joining it into the returned error so the
	// action reports FAILED instead of a clean SUCCESS with a broken
	// upgrade underneath.
	output.WriteString("\n=== Dist-Upgrade ===\n")
	distOutput, distErr := apt.DistUpgrade()
	if distOutput != nil {
		output.WriteString(distOutput.Stdout)
		output.WriteString(distOutput.Stderr)
	}

	return errors.Join(err, distErr)
}

// executeDnfUpgrade performs dnf-specific upgrade.
func (e *Executor) executeDnfUpgrade(ctx context.Context, params *pb.UpdateParams, output *strings.Builder) error {
	securityOnly := params != nil && params.SecurityOnly
	cmdOutput, err := dnfUpgrade(ctx, securityOnly)
	if cmdOutput != nil {
		output.WriteString(cmdOutput.Stdout)
		output.WriteString(cmdOutput.Stderr)
	}

	return err
}

// checkRebootRequired checks if the system requires a reboot after updates.
func (e *Executor) checkRebootRequired() bool {
	// Debian/Ubuntu: check for reboot-required file
	if _, err := os.Stat("/var/run/reboot-required"); err == nil {
		return true
	}

	// RHEL/Fedora: check needs-restarting
	if pkg.IsDnf() {
		_, exitCode, _ := queryCmdOutput("needs-restarting", "-r")
		// Exit code 1 means reboot required
		if exitCode == 1 {
			return true
		}
	}

	return false
}
