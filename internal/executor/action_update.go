// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/pkg"
	sysnotify "github.com/manchtools/power-manage-sdk/sys/notify"
	sysreboot "github.com/manchtools/power-manage-sdk/sys/reboot"
)

// Notification seams so the update/LPS paths can be exercised with fixtures
// instead of a live host. Production binds them to the real notify Manager;
// tests stub them.
var (
	// notifyAll broadcasts a desktop/wall notification through a notify Manager
	// built over the process-wide runner. Best-effort: a notification must never
	// block an update/reboot action, so delivery errors are dropped. Kept as a
	// package var (signature func(ctx, title, body)) so tests observe it.
	notifyAll = func(ctx context.Context, title, body string) {
		n, err := sysnotify.New(executorRunner)
		if err != nil {
			return
		}
		_ = n.NotifyAll(ctx, title, body)
	}
	// notifyUsers is notifyAll's targeted sibling: it notifies a specific set of
	// users (LPS rotation). Same best-effort, errors-dropped contract; a package
	// var so tests observe it.
	notifyUsers = func(ctx context.Context, users []string, title, body string) {
		n, err := sysnotify.New(executorRunner)
		if err != nil {
			return
		}
		_ = n.NotifyUsers(ctx, users, title, body)
	}
)

// repairFilesystem attempts to fix read-only filesystem issues.
// This can happen when the kernel remounts the filesystem as read-only due to errors.
// It checks all real (non-virtual) filesystem mounts, not just /, because partitions
// like /usr may be mounted separately and go read-only independently.
// Returns true if all filesystems are writable, false if any repair failed.
func (e *Executor) repairFilesystem(ctx context.Context) bool {
	mounts, err := fsMgr.ListMounts(ctx)
	if err != nil {
		e.logger.Warn("could not list mounts", "error", err)
		return true // Assume writable, let operations fail naturally
	}

	allOk := true
	for _, mnt := range mounts {
		// Only real block-device filesystems: skip virtual mounts (proc, sysfs,
		// cgroup, tmpfs, …) which are legitimately read-only and must never be
		// remounted rw.
		if !strings.HasPrefix(mnt.Source, "/dev/") {
			continue
		}
		if !mnt.ReadOnly {
			continue
		}

		e.logger.Warn("filesystem is mounted read-only, attempting remount",
			"mount", mnt.Target, "device", mnt.Source,
		)

		if err := fsMgr.RemountRW(ctx, mnt.Target); err != nil {
			e.logger.Error("failed to remount filesystem as read-write",
				"mount", mnt.Target, "device", mnt.Source, "error", err,
			)
			e.logger.Error("filesystem may have errors - system likely needs reboot and fsck",
				"mount", mnt.Target,
			)
			allOk = false
		} else {
			e.logger.Info("successfully remounted filesystem as read-write",
				"mount", mnt.Target, "device", mnt.Source,
			)
		}
	}

	return allOk
}

// repairPackageManager attempts to fix common broken package manager states.
// This handles issues like interrupted dpkg operations, broken dependencies,
// and stale lock files that can prevent package operations from succeeding.
func (e *Executor) repairPackageManager(ctx context.Context) {
	// If root filesystem is read-only (e.g. disk error caused kernel to remount ro),
	// all package operations will fail. Attempt to remount it read-write first.
	// A probe error is treated as "not read-only" (skip the remount) — the same
	// fail-safe as the previous /proc/mounts parse, letting the package op surface
	// the real failure rather than remounting speculatively.
	if ro, err := fsMgr.IsReadOnly(ctx, "/"); err == nil && ro {
		slog.Warn("root filesystem is mounted read-only, attempting remount as read-write")
		if err := fsMgr.RemountRW(ctx, "/"); err != nil {
			slog.Error("failed to remount root filesystem as read-write", "error", err)
		}
	}

	// apt/dnf/pacman repair is fully covered by the SDK pkg.Manager.Repair
	// (stale-lock removal, dpkg --configure / dnf history-redo / pacman-key init,
	// fix-broken, refresh) — delegate to it. zypper is the exception: the SDK's
	// zypper Repair does refresh + a fuser-based stale-lock, but the agent also
	// needs clean --all + verify + rpm-db rebuild and a PID-based zypp.pid probe,
	// which are not yet in the SDK (filed: SDK gap E2) — keep repairZypper until
	// E2 lands.
	switch e.pkgBackend {
	case pkg.Apt, pkg.Dnf, pkg.Pacman:
		if mgr := e.pkgManagerForCtx(ctx); mgr != nil {
			if _, err := mgr.Repair(ctx); err != nil {
				slog.Warn("package manager repair failed", "backend", e.pkgBackend, "error", err)
			}
		}
	case pkg.Zypper:
		e.repairZypper(ctx)
	}

	// Flatpak can coexist with any traditional package manager, so check
	// presence via Detect rather than the primary backend (e.pkgBackend).
	for _, b := range pkg.Detect(ctx) {
		if b == pkg.Flatpak {
			e.repairFlatpak(ctx)
			break
		}
	}
}

// removeStaleZyppPidFile removes a zypper PID file ONLY if the
// recorded PID does not belong to a running process. zypp.pid
// records zypper's PID; the daemonized process closes the fd
// after writing, so a fuser-based lock check would report no holder
// even when zypper is mid-flight and mis-classify a running zypper
// as stale, yanking the lock from under it.
//
// Liveness check uses `kill -0 <pid>`: exit 0 means the process
// exists (skip removal), nonzero means no such process (safe to
// remove). A malformed file (no parseable PID) is treated as
// stale and removed. We never delete a PID file we couldn't prove
// stale via a successful kill -0 negative.
//
// This (and repairZypper) stay agent-side until the SDK's zypper Repair gains
// clean --all / verify / rpm-db rebuild and a PID-based zypp.pid probe — see the
// SDK-GAPS-REPORT "E2" extension; apt/dnf/pacman repair already delegate to
// pkg.Manager.Repair.
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
	// WS16 #3: bind the package manager to the action ctx so the per-action
	// timeout reaches the index-update and generic-upgrade subprocesses. The
	// apt/dnf-specific upgrade paths already build a ctx-bound backend.
	mgr := e.pkgManagerForCtx(ctx)
	if mgr == nil {
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

	// Check if updates are available before running the upgrade (SDK HasUpdates).
	// A probe error fails SAFE toward running the upgrade (prior behavior).
	updatesAvailable, hasUpdErr := mgr.HasUpdates(ctx, securityOnly)
	if hasUpdErr != nil {
		updatesAvailable = true
	}

	// Record pre-update reboot state to detect new reboot requirements.
	rebootRequiredBefore := e.rebootRequired(ctx)

	// Update package index
	allOutput.WriteString("=== Package Index Update ===\n")
	if updateResult, err := mgr.Update(ctx); err != nil {
		allOutput.WriteString(updateResult.Stdout)
		allOutput.WriteString(updateResult.Stderr)
		allOutput.WriteString(fmt.Sprintf("Warning: update failed: %v\n\n", err))
	} else {
		allOutput.WriteString(updateResult.Stdout)
		if updateResult.Stderr != "" {
			allOutput.WriteString(updateResult.Stderr)
		}
		allOutput.WriteString("\n")
	}

	// Re-check after index update (new updates may now be visible).
	if !updatesAvailable {
		if u, err := mgr.HasUpdates(ctx, securityOnly); err == nil {
			updatesAvailable = u
		}
	}

	// Perform the upgrade
	allOutput.WriteString("=== Package Upgrade ===\n")

	// Full system upgrade via the SDK Manager. SecurityOnly is honored per
	// backend by the SDK: apt routes to unattended-upgrade (failing closed if it
	// is absent), dnf adds --security, zypper its security patch path; pacman and
	// flatpak return ErrSecurityOnlyUnsupported (so a security-only request fails
	// closed instead of silently widening to a full upgrade).
	upgradeResult, upgradeErr := mgr.UpgradeAll(ctx, pkg.UpgradeOptions{SecurityOnly: securityOnly})
	allOutput.WriteString(upgradeResult.Stdout)
	allOutput.WriteString(upgradeResult.Stderr)
	if upgradeErr != nil {
		allOutput.WriteString(fmt.Sprintf("Error: %v\n", upgradeErr))
		lastErr = upgradeErr
	}

	// Autoremove if requested. Delegate to the SDK Manager (a no-op on backends
	// with no native equivalent) and detect change via the SDK installed-count
	// comparison. Surface a call failure so the result reflects "we tried to
	// autoremove and it failed", not a clean success over stale packages.
	autoremoved := false
	if params != nil && params.Autoremove {
		allOutput.WriteString("\n=== Autoremove Unused Packages ===\n")
		countBefore, _ := mgr.InstalledCount(ctx)
		arOut, autoremoveErr := mgr.Autoremove(ctx)
		allOutput.WriteString(arOut.Stdout)
		if autoremoveErr != nil {
			allOutput.WriteString(arOut.Stderr)
		}
		countAfter, _ := mgr.InstalledCount(ctx)
		autoremoved = countBefore > 0 && countAfter > 0 && countBefore != countAfter
		if autoremoveErr != nil && lastErr == nil {
			lastErr = fmt.Errorf("autoremove: %w", autoremoveErr)
		}
	}

	// Check if this run created a new reboot requirement.
	rebootRequiredAfter := e.rebootRequired(ctx)
	newRebootRequired := rebootRequiredAfter && !rebootRequiredBefore
	if rebootRequiredAfter {
		allOutput.WriteString("\n*** REBOOT REQUIRED ***\n")
		if newRebootRequired && params != nil && params.RebootIfRequired {
			// errors.Join keeps the reboot failure visible even when an
			// earlier upgrade error already occupied lastErr — a
			// first-error-wins guard would silently demote a reboot the
			// operator explicitly asked for.
			lastErr = errors.Join(lastErr, e.scheduleRebootAfterUpdate(ctx, &allOutput))
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

// scheduleRebootAfterUpdate issues the reboot the operator requested via
// RebootIfRequired and notifies signed-in users ONLY if the shutdown actually
// went out. A failure to schedule a reboot the operator explicitly asked for
// is a real action failure (returned, not a logged warning); the desktop
// notification is gated on success so users are never told "your system will
// reboot" when it won't. Returns nil when the reboot was scheduled.
func (e *Executor) scheduleRebootAfterUpdate(ctx context.Context, output *strings.Builder) error {
	rb, err := sysreboot.New(e.runner)
	if err == nil {
		err = rb.Schedule(ctx, sysreboot.ScheduleOptions{Delay: "+1", Message: "System update requires reboot"})
	}
	if err != nil {
		output.WriteString(fmt.Sprintf("FAILED to schedule reboot: %v\n", err))
		return fmt.Errorf("schedule reboot: %w", err)
	}
	notifyAll(ctx, "System Reboot", "A system update requires a reboot. This system will reboot in 1 minute.")
	output.WriteString("Scheduled reboot in 1 minute.\n")
	return nil
}

// rebootRequired reports whether the system needs a reboot, via the SDK reboot
// Manager (the reboot-required marker on Debian/Ubuntu, needs-restarting on
// Fedora/RHEL). A nil runner or a probe error reports false — best-effort,
// matching the prior behavior.
func (e *Executor) rebootRequired(ctx context.Context) bool {
	rb, err := sysreboot.New(e.runner)
	if err != nil {
		return false
	}
	required, _ := rb.IsRequired(ctx)
	return required
}
