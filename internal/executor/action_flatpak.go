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

	// Always install system-wide. Pre-fix #79 SystemWide=false routed
	// to `flatpak --user`, but install/uninstall ran through sudo —
	// `flatpak --user` resolves the installation against $HOME, and
	// under sudo $HOME is /root, so apps landed in
	// /root/.local/share/flatpak where no desktop user could see them.
	// The agent isn't a desktop-session actor (it runs as a system
	// service with no concept of "which desktop user"), so per-user
	// installs are out of scope. Coerce SystemWide=false to a warning
	// + system-wide so existing assignments don't silently break
	// behavior when they upgrade across the fix.
	if !params.SystemWide {
		e.logger.Warn("flatpak: SystemWide=false coerced to system-wide install — per-user flatpak is unsupported by the agent (it has no notion of which desktop user); update the assignment to SystemWide=true to silence this warning",
			"app_id", params.AppId)
	}
	const systemFlag = "--system"

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

		// Pin if requested (mask prevents updates). The SDK can
		// return (nil, nil) on success — guard the dereference so a
		// successful install + successful pin doesn't segfault on the
		// Stdout += assignment below. Audit F056(a).
		if params.Pin {
			pinOutput, pinErr := runSudoCmd(ctx, "flatpak", "mask", systemFlag, params.AppId)
			if output == nil {
				output = &pb.CommandOutput{}
			}
			if pinErr != nil {
				output.Stdout += "\nWarning: failed to pin application: " + pinErr.Error()
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

		// Remove pin first if it exists. The mask may not have been
		// set, so a non-zero exit is expected and benign — but log
		// at Debug so the operator can correlate if uninstall later
		// fails. Audit F056(b).
		if _, err := runSudoCmd(ctx, "flatpak", "mask", "--remove", systemFlag, params.AppId); err != nil {
			e.logger.Debug("flatpak ABSENT: unmask before uninstall failed (often expected if not pinned)",
				"app_id", params.AppId, "error", err)
		}

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
