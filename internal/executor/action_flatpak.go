// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

func (e *Executor) executeFlatpak(ctx context.Context, params *pb.FlatpakParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("flatpak params required")
	}

	// Skip on systems without flatpak
	if _, err := exec.LookPath("flatpak"); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return &pb.CommandOutput{Stdout: "skipped: flatpak not available on this system"}, false, nil
		}
		return nil, false, fmt.Errorf("flatpak lookup: %w", err)
	}

	if params.AppId == "" {
		return nil, false, fmt.Errorf("flatpak app_id is required")
	}

	// Default to flathub if no remote specified
	remote := params.Remote
	if remote == "" {
		remote = "flathub"
	}

	// Build base args - system-wide by default
	systemFlag := "--system"
	if !params.SystemWide {
		systemFlag = "--user"
	}

	// Check if flatpak is installed
	isInstalled := e.isFlatpakInstalled(params.AppId, systemFlag)

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		if isInstalled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("flatpak %s is already installed", params.AppId),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		// Install the flatpak application
		output, err := runSudoCmd(ctx, "flatpak", "install", "-y", "--noninteractive", systemFlag, remote, params.AppId)
		if err != nil {
			return output, false, fmt.Errorf("flatpak install failed: %w", err)
		}

		// Pin if requested (mask prevents updates)
		if params.Pin {
			pinOutput, pinErr := runSudoCmd(ctx, "flatpak", "mask", systemFlag, params.AppId)
			if pinErr != nil {
				if output != nil {
					output.Stdout += "\nWarning: failed to pin application: " + pinErr.Error()
				}
			} else if pinOutput != nil {
				output.Stdout += "\n" + pinOutput.Stdout
			}
		}

		return output, true, nil

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		if !isInstalled {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("flatpak %s is already not installed", params.AppId),
			}, false, nil
		}

		// Repair filesystem if mounted read-only
		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		// Remove pin first if it exists
		runSudoCmd(ctx, "flatpak", "mask", "--remove", systemFlag, params.AppId)

		// Uninstall the flatpak application
		output, err := runSudoCmd(ctx, "flatpak", "uninstall", "-y", "--noninteractive", systemFlag, params.AppId)
		return output, true, err
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// isFlatpakInstalled checks if a flatpak app is installed.
func (e *Executor) isFlatpakInstalled(appId, systemFlag string) bool {
	return checkCmdSuccess("flatpak", "info", systemFlag, appId)
}

// repairFlatpak fixes common Flatpak issues:
// - Stale metadata cache
// - Broken remotes
func (e *Executor) repairFlatpak(ctx context.Context) {
	// Repair any broken installations (removes partial/orphaned refs)
	if _, err := runSudoCmd(ctx, "flatpak", "repair", "--system"); err != nil {
		slog.Warn("repairFlatpak: repair failed", "error", err)
	}

	// Update appstream metadata to fix stale cache issues
	if _, err := runSudoCmd(ctx, "flatpak", "update", "--appstream", "-y", "--noninteractive", "--system"); err != nil {
		slog.Warn("repairFlatpak: appstream update failed", "error", err)
	}
}
