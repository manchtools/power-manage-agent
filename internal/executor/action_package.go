// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"fmt"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/pkg"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

func (e *Executor) executePackage(ctx context.Context, params *pb.PackageParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("package params required")
	}
	// WS16 #3: the package manager dispatches every command through the
	// action ctx, so the per-action timeout reaches the package-manager
	// subprocesses (install/update/remove are the long-running operations).
	mgr := e.pkgManagerForCtx(ctx)
	if mgr == nil {
		return nil, false, fmt.Errorf("no supported package manager found")
	}
	pkgName := e.getPackageNameForManager(params)
	if pkgName == "" {
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   "skipped: no package name configured for this package manager",
		}, false, nil
	}
	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		return e.ensurePackagePresent(ctx, mgr, params, pkgName)
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		return e.ensurePackageAbsent(ctx, mgr, params, pkgName)
	default:
		return nil, false, fmt.Errorf("unknown desired state: %v", state)
	}
}

// ensurePackagePresent installs a package (with optional version and pin) if not already satisfied.
func (e *Executor) ensurePackagePresent(ctx context.Context, mgr pkg.Manager, params *pb.PackageParams, pkgName string) (*pb.CommandOutput, bool, error) {
	// Fail closed if the state probe itself failed (cancelled context, backend
	// lookup error): proceeding would run a privileged install against an
	// unknown current state and misreport the result.
	isInstalled, err := mgr.IsInstalled(ctx, pkgName)
	if err != nil {
		return nil, false, fmt.Errorf("probe package state for %s: %w", pkgName, err)
	}
	if isInstalled {
		if out, changed, err := e.checkPackageVersionAndPin(ctx, mgr, params, pkgName); out != nil {
			return out, changed, err
		}
	}

	if out, err := e.requireWritableFS(ctx); err != nil {
		return out, false, err
	}
	e.repairPackageManager(ctx)

	if _, updateErr := mgr.Update(ctx); updateErr != nil {
		e.logger.Warn("package index update failed, continuing with install", "error", updateErr)
	}

	// Version and AllowDowngrade are independent — setting a version does NOT
	// imply downgrade permission. Callers must explicitly set AllowDowngrade.
	result, err := mgr.Install(ctx, pkg.InstallOptions{
		Version:        params.Version,
		AllowDowngrade: params.AllowDowngrade,
	}, pkgName)

	if err == nil && params.Pin {
		if _, pinErr := e.pinPackage(ctx, mgr, pkgName); pinErr != nil {
			// Pin is part of the requested state. The previous shape
			// degraded to a stderr warning while the action result
			// stayed success — operators saw "installed and pinned"
			// when only install happened, and the package would
			// upgrade out from under the next maintenance window.
			// Surface as a real failure: the install is durable, but
			// the action did not reach the requested state.
			result.Stderr += fmt.Sprintf("\nfailed to pin package: %v", pinErr)
			err = fmt.Errorf("install succeeded but pin failed: %w", pinErr)
		}
	}
	return packageResult(result, err)
}

// checkPackageVersionAndPin checks if an already-installed package satisfies the
// desired version and pin state. Returns (output, changed, error) when the check
// is conclusive (output != nil). Returns (nil, false, nil) when the version
// doesn't match and the package needs reinstallation.
func (e *Executor) checkPackageVersionAndPin(ctx context.Context, mgr pkg.Manager, params *pb.PackageParams, pkgName string) (*pb.CommandOutput, bool, error) {
	versionStr := ""
	if params.Version != "" {
		installedVersion, err := mgr.InstalledVersion(ctx, pkgName)
		if err != nil {
			// Fail closed (non-nil output so the caller surfaces it, per this
			// function's contract) rather than treating an unreadable version as
			// a mismatch and silently reinstalling.
			return &pb.CommandOutput{ExitCode: 1, Stderr: fmt.Sprintf("read installed version for %s: %v", pkgName, err)},
				false, fmt.Errorf("read installed version for %s: %w", pkgName, err)
		}
		if installedVersion != params.Version {
			return nil, false, nil
		}
		versionStr = " version " + params.Version
	}
	if params.Pin {
		changed, pinErr := e.ensurePackagePinned(ctx, mgr, pkgName)
		if pinErr != nil {
			return &pb.CommandOutput{
				ExitCode: 1,
				Stderr:   fmt.Sprintf("failed to pin package: %v", pinErr),
			}, false, pinErr
		}
		msg := fmt.Sprintf("package %s%s is already installed and pinned", pkgName, versionStr)
		if changed {
			msg = fmt.Sprintf("package %s%s was already installed, pinned", pkgName, versionStr)
		}
		return &pb.CommandOutput{ExitCode: 0, Stdout: msg}, changed, nil
	}
	return &pb.CommandOutput{
		ExitCode: 0,
		Stdout:   fmt.Sprintf("package %s%s is already installed", pkgName, versionStr),
	}, false, nil
}

// ensurePackageAbsent removes a package if installed.
func (e *Executor) ensurePackageAbsent(ctx context.Context, mgr pkg.Manager, _ *pb.PackageParams, pkgName string) (*pb.CommandOutput, bool, error) {
	// Fail closed if the state probe failed — proceeding would run a privileged
	// remove against an unknown current state.
	isInstalled, err := mgr.IsInstalled(ctx, pkgName)
	if err != nil {
		return nil, false, fmt.Errorf("probe package state for %s: %w", pkgName, err)
	}
	if !isInstalled {
		return &pb.CommandOutput{
			ExitCode: 0,
			Stdout:   fmt.Sprintf("package %s is already not installed", pkgName),
		}, false, nil
	}
	if out, err := e.requireWritableFS(ctx); err != nil {
		return out, false, err
	}
	e.repairPackageManager(ctx)
	// Audit F061: previously the unpin error was discarded silently —
	// a pinned package's removal would surface as the package
	// manager's "held" message instead of the underlying unpin
	// failure. Log so the operator can correlate.
	if _, err := e.ensurePackageUnpinned(ctx, mgr, pkgName); err != nil {
		e.logger.Warn("ensurePackageAbsent: failed to unpin package before removal",
			"package", pkgName, "error", err)
	}
	result, err := mgr.Remove(ctx, pkg.RemoveOptions{}, pkgName)
	return packageResult(result, err)
}

// packageResult converts a pkg mutation's (exec.Result, error) into the standard
// executor return tuple. The Result carries the package manager's stdout/stderr/
// exit on both the success and non-zero-exit paths; a runner error (the command
// could not run) yields the zero Result, so synthesise a visible failure.
func packageResult(result sysexec.Result, err error) (*pb.CommandOutput, bool, error) {
	out := &pb.CommandOutput{
		ExitCode: int32(result.ExitCode),
		Stdout:   result.Stdout,
		Stderr:   result.Stderr,
	}
	if err != nil {
		if result.ExitCode == 0 {
			// Zero Result + error == the command never ran (runner failure);
			// make the failure visible rather than reporting a clean exit.
			out.ExitCode = 1
			if out.Stderr == "" {
				out.Stderr = err.Error()
			}
		}
		return out, false, err
	}
	return out, true, nil
}

// getPackageNameForManager returns the appropriate package name for the active
// package manager. It checks for manager-specific names first, then falls back
// to the generic name. Returns empty string if no name is available.
func (e *Executor) getPackageNameForManager(params *pb.PackageParams) string {
	// Check for manager-specific names first, keyed off the backend the
	// executor's package manager actually drives.
	switch e.pkgBackend {
	case pkg.Apt:
		if params.AptName != "" {
			return params.AptName
		}
	case pkg.Dnf:
		if params.DnfName != "" {
			return params.DnfName
		}
	case pkg.Pacman:
		if params.PacmanName != "" {
			return params.PacmanName
		}
	case pkg.Zypper:
		if params.ZypperName != "" {
			return params.ZypperName
		}
	}

	// Fall back to the generic name even when other managers have
	// overrides set. The previous shape returned "" (skip) when ANY
	// manager-specific name was present but no override existed for
	// THIS manager — a curl action specifying just AptName="curl"
	// would silently no-op on dnf/zypper/pacman hosts even though
	// the generic Name=curl is the right answer for those managers
	// too. The override-only-when-set semantics belong on a
	// per-manager basis, not as a cross-manager kill switch.
	return params.Name
}

// isPackagePinned checks if a package is pinned (held from upgrades).
// Uses the underlying package manager's pinning mechanism:
// - APT: apt-mark hold
// - DNF: dnf versionlock
// - Pacman: IgnorePkg in pacman.conf
// - Zypper: zypper lock
// - Flatpak: flatpak mask
func (e *Executor) isPackagePinned(ctx context.Context, mgr pkg.Manager, pkgName string) (bool, error) {
	if mgr == nil {
		return false, fmt.Errorf("no package manager available")
	}
	return mgr.IsPinned(ctx, pkgName)
}

// pinPackage pins a package to prevent it from being upgraded.
// Returns (changed, error) where changed is true if the package was newly pinned.
func (e *Executor) pinPackage(ctx context.Context, mgr pkg.Manager, pkgName string) (bool, error) {
	if mgr == nil {
		return false, fmt.Errorf("no package manager available")
	}

	// Check if already pinned
	isPinned, err := mgr.IsPinned(ctx, pkgName)
	if err != nil {
		return false, fmt.Errorf("check pin status: %w", err)
	}
	if isPinned {
		return false, nil // Already pinned, no change
	}

	// Pin the package
	if _, err = mgr.Pin(ctx, pkgName); err != nil {
		return false, fmt.Errorf("pin package: %w", err)
	}
	return true, nil
}

// unpinPackage unpins a package to allow it to be upgraded.
// Returns (changed, error) where changed is true if the package was unpinned.
func (e *Executor) unpinPackage(ctx context.Context, mgr pkg.Manager, pkgName string) (bool, error) {
	if mgr == nil {
		return false, fmt.Errorf("no package manager available")
	}

	// Check if currently pinned
	isPinned, err := mgr.IsPinned(ctx, pkgName)
	if err != nil {
		return false, fmt.Errorf("check pin status: %w", err)
	}
	if !isPinned {
		return false, nil // Already unpinned, no change
	}

	// Unpin the package
	if _, err = mgr.Unpin(ctx, pkgName); err != nil {
		return false, fmt.Errorf("unpin package: %w", err)
	}
	return true, nil
}

// ensurePackagePinned ensures a package is pinned. Returns true if a change was made.
// This is a convenience method that handles filesystem repair before pinning.
func (e *Executor) ensurePackagePinned(ctx context.Context, mgr pkg.Manager, pkgName string) (bool, error) {
	// Check if already pinned first (no filesystem write needed). A
	// probe ERROR is surfaced, not coerced to "not pinned" (#173): the
	// old blank-identifier discard turned a transient probe failure into
	// a needless repairFilesystem + re-pin round while hiding the root
	// cause from the execution result.
	isPinned, err := e.isPackagePinned(ctx, mgr, pkgName)
	if err != nil {
		return false, fmt.Errorf("check pin state for %s: %w", pkgName, err)
	}
	if isPinned {
		return false, nil
	}

	// Repair filesystem if needed before writing
	if !e.repairFilesystem(ctx) {
		return false, errReadOnlyFS
	}

	return e.pinPackage(ctx, mgr, pkgName)
}

// ensurePackageUnpinned ensures a package is unpinned. Returns true if a change was made.
func (e *Executor) ensurePackageUnpinned(ctx context.Context, mgr pkg.Manager, pkgName string) (bool, error) {
	return e.unpinPackage(ctx, mgr, pkgName)
}
