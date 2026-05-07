// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"fmt"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage/sdk/go/pkg"
)

func (e *Executor) executePackage(ctx context.Context, params *pb.PackageParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("package params required")
	}
	if e.pkgManager == nil {
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
		return e.ensurePackagePresent(ctx, params, pkgName)
	case pb.DesiredState_DESIRED_STATE_ABSENT:
		return e.ensurePackageAbsent(ctx, params, pkgName)
	default:
		return nil, false, fmt.Errorf("unknown desired state: %v", state)
	}
}

// ensurePackagePresent installs a package (with optional version and pin) if not already satisfied.
func (e *Executor) ensurePackagePresent(ctx context.Context, params *pb.PackageParams, pkgName string) (*pb.CommandOutput, bool, error) {
	isInstalled, _ := e.pkgManager.IsInstalled(pkgName)
	if isInstalled {
		if out, changed, err := e.checkPackageVersionAndPin(ctx, params, pkgName); out != nil {
			return out, changed, err
		}
	}

	if out, err := e.requireWritableFS(ctx); err != nil {
		return out, false, err
	}
	e.repairPackageManager(ctx)

	if _, updateErr := e.pkgManager.Update(); updateErr != nil {
		e.logger.Warn("package index update failed, continuing with install", "error", updateErr)
	}

	// Version and AllowDowngrade are independent — setting a version does NOT
	// imply downgrade permission. Callers must explicitly set AllowDowngrade.
	builder := e.pkgManager.Install(pkgName)
	if params.Version != "" {
		builder = builder.Version(params.Version)
	}
	if params.AllowDowngrade {
		builder = builder.AllowDowngrade()
	}
	result, err := builder.Run()

	if err == nil && params.Pin {
		if _, pinErr := e.pinPackage(pkgName); pinErr != nil {
			result.Stderr += fmt.Sprintf("\nwarning: failed to pin package: %v", pinErr)
		}
	}
	return packageResult(result, err)
}

// checkPackageVersionAndPin checks if an already-installed package satisfies the
// desired version and pin state. Returns (output, changed, error) when the check
// is conclusive (output != nil). Returns (nil, false, nil) when the version
// doesn't match and the package needs reinstallation.
func (e *Executor) checkPackageVersionAndPin(ctx context.Context, params *pb.PackageParams, pkgName string) (*pb.CommandOutput, bool, error) {
	versionStr := ""
	if params.Version != "" {
		installedVersion, _ := e.pkgManager.GetInstalledVersion(pkgName)
		if installedVersion != params.Version {
			return nil, false, nil
		}
		versionStr = " version " + params.Version
	}
	if params.Pin {
		changed, pinErr := e.ensurePackagePinned(ctx, pkgName)
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
func (e *Executor) ensurePackageAbsent(ctx context.Context, _ *pb.PackageParams, pkgName string) (*pb.CommandOutput, bool, error) {
	isInstalled, _ := e.pkgManager.IsInstalled(pkgName)
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
	e.ensurePackageUnpinned(pkgName)
	result, err := e.pkgManager.Remove(pkgName).Run()
	return packageResult(result, err)
}

// packageResult converts a pkg.CommandResult into the standard executor return tuple.
func packageResult(result *pkg.CommandResult, err error) (*pb.CommandOutput, bool, error) {
	if err != nil {
		if result == nil {
			return &pb.CommandOutput{ExitCode: 1, Stderr: err.Error()}, false, err
		}
		return &pb.CommandOutput{
			ExitCode: int32(result.ExitCode),
			Stdout:   result.Stdout,
			Stderr:   result.Stderr,
		}, false, err
	}
	return &pb.CommandOutput{
		ExitCode: int32(result.ExitCode),
		Stdout:   result.Stdout,
		Stderr:   result.Stderr,
	}, true, nil
}

// getPackageNameForManager returns the appropriate package name for the current package manager.
// It checks for manager-specific names first, then falls back to the generic name.
// Returns empty string if no name is available for the current manager.
func (e *Executor) getPackageNameForManager(params *pb.PackageParams) string {
	// Check for manager-specific names first
	switch {
	case pkg.IsApt():
		if params.AptName != "" {
			return params.AptName
		}
	case pkg.IsDnf():
		if params.DnfName != "" {
			return params.DnfName
		}
	case pkg.IsPacman():
		if params.PacmanName != "" {
			return params.PacmanName
		}
	case pkg.IsZypper():
		if params.ZypperName != "" {
			return params.ZypperName
		}
	}

	// Check if any manager-specific names are set
	// If so, and we don't have one for this manager, return empty (skip)
	hasManagerSpecificNames := params.AptName != "" || params.DnfName != "" ||
		params.PacmanName != "" || params.ZypperName != ""

	if hasManagerSpecificNames {
		// Manager-specific names are being used, but none for this manager
		return ""
	}

	// Fall back to generic name
	return params.Name
}

// isPackagePinned checks if a package is pinned (held from upgrades).
// Uses the underlying package manager's pinning mechanism:
// - APT: apt-mark hold
// - DNF: dnf versionlock
// - Pacman: IgnorePkg in pacman.conf
// - Zypper: zypper lock
// - Flatpak: flatpak mask
func (e *Executor) isPackagePinned(pkgName string) (bool, error) {
	if e.pkgManager == nil {
		return false, fmt.Errorf("no package manager available")
	}
	return e.pkgManager.IsPinned(pkgName)
}

// pinPackage pins a package to prevent it from being upgraded.
// Returns (changed, error) where changed is true if the package was newly pinned.
func (e *Executor) pinPackage(pkgName string) (bool, error) {
	if e.pkgManager == nil {
		return false, fmt.Errorf("no package manager available")
	}

	// Check if already pinned
	isPinned, err := e.pkgManager.IsPinned(pkgName)
	if err != nil {
		return false, fmt.Errorf("check pin status: %w", err)
	}
	if isPinned {
		return false, nil // Already pinned, no change
	}

	// Pin the package
	_, err = e.pkgManager.Pin(pkgName).Run()
	if err != nil {
		return false, fmt.Errorf("pin package: %w", err)
	}
	return true, nil
}

// unpinPackage unpins a package to allow it to be upgraded.
// Returns (changed, error) where changed is true if the package was unpinned.
func (e *Executor) unpinPackage(pkgName string) (bool, error) {
	if e.pkgManager == nil {
		return false, fmt.Errorf("no package manager available")
	}

	// Check if currently pinned
	isPinned, err := e.pkgManager.IsPinned(pkgName)
	if err != nil {
		return false, fmt.Errorf("check pin status: %w", err)
	}
	if !isPinned {
		return false, nil // Already unpinned, no change
	}

	// Unpin the package
	_, err = e.pkgManager.Unpin(pkgName).Run()
	if err != nil {
		return false, fmt.Errorf("unpin package: %w", err)
	}
	return true, nil
}

// ensurePackagePinned ensures a package is pinned. Returns true if a change was made.
// This is a convenience method that handles filesystem repair before pinning.
func (e *Executor) ensurePackagePinned(ctx context.Context, pkgName string) (bool, error) {
	// Check if already pinned first (no filesystem write needed)
	isPinned, _ := e.isPackagePinned(pkgName)
	if isPinned {
		return false, nil
	}

	// Repair filesystem if needed before writing
	if !e.repairFilesystem(ctx) {
		return false, errReadOnlyFS
	}

	return e.pinPackage(pkgName)
}

// ensurePackageUnpinned ensures a package is unpinned. Returns true if a change was made.
func (e *Executor) ensurePackageUnpinned(pkgName string) (bool, error) {
	return e.unpinPackage(pkgName)
}
