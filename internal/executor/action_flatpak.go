// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"strings"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/pkg"
	"github.com/manchtools/power-manage-sdk/sys/desktop"
)

func (e *Executor) executeFlatpak(ctx context.Context, params *pb.FlatpakParams, state pb.DesiredState) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("flatpak params required")
	}

	// Validate app-id and remote BEFORE the flatpak lookup or any
	// dispatch (WS8 finding 7). Both reach `flatpak install` as operands,
	// so a flag-shaped value (`--system`, `--from=…`) must be rejected up
	// front. Validating before the lookup also means a malformed action
	// is rejected on every host, not silently skipped on one without
	// flatpak.
	if params.AppId == "" {
		return nil, false, fmt.Errorf("flatpak app_id is required")
	}
	if err := pkg.ValidatePackageName(params.AppId); err != nil {
		return nil, false, fmt.Errorf("invalid flatpak app_id: %w", err)
	}

	// Default to flathub if no remote specified
	remote := params.Remote
	if remote == "" {
		remote = "flathub"
	}
	if err := pkg.ValidateRemoteName(remote); err != nil {
		return nil, false, fmt.Errorf("invalid flatpak remote: %w", err)
	}

	// Skip on systems without flatpak. flatpak is a first-class pkg.Backend
	// that the SDK's pkg.Detect enumerates, so this honors the SDK's PATH
	// resolution instead of hard-coding the "flatpak" binary name.
	if !slices.Contains(pkg.Detect(ctx), pkg.Flatpak) {
		return &pb.CommandOutput{Stdout: "skipped: flatpak not available on this system"}, false, nil
	}

	if params.SystemWide {
		return e.executeFlatpakSystem(ctx, params, state, remote)
	}
	return e.executeFlatpakPerUser(ctx, params, state, remote)
}

// newPerUserFlatpak builds a per-user flatpak Manager that runs AS the given
// session's user: a desktop.RunAsRunner wraps the escalating base runner so the
// flatpak --user operations execute under that user's uid/HOME, and WithUserScope
// selects the per-user installation. This composes desktop.RunAsRunner +
// pkg.Flatpak so the agent no longer hand-builds `runuser … flatpak --user`
// command lines (SDK gap 7).
func newPerUserFlatpak(s desktop.Session) (pkg.Manager, error) {
	ru, err := desktop.RunAsRunner(executorRunner, s)
	if err != nil {
		return nil, fmt.Errorf("build run-as runner for %s: %w", s.Username, err)
	}
	return pkg.New(pkg.Flatpak, ru, pkg.WithUserScope())
}

// executeFlatpakSystem implements the system-wide install/uninstall path,
// delegating to the SDK's system-scoped flatpak Manager (escalates via the
// configured runner). The explicit remote is honored through InstallOptions
// (SDK gap 6), and pin/unpin go through Pin/IsPinned/Unpin.
func (e *Executor) executeFlatpakSystem(ctx context.Context, params *pb.FlatpakParams, state pb.DesiredState, remote string) (*pb.CommandOutput, bool, error) {
	mgr, err := pkg.New(pkg.Flatpak, executorRunner)
	if err != nil {
		return nil, false, fmt.Errorf("build flatpak manager: %w", err)
	}
	// The system path fails closed on a failed install-state probe: it is a
	// single operation with no fan-out to stay resilient for, so surfacing the
	// flatpak failure beats blindly attempting an install or falsely reporting
	// "already absent". (The per-user path below instead treats a probe error as
	// "not installed", so one user's failure doesn't abort the whole fan-out.)
	installed, err := mgr.IsInstalled(ctx, params.AppId)
	if err != nil {
		return nil, false, fmt.Errorf("check flatpak %s installed: %w", params.AppId, err)
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		if installed {
			out := &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("flatpak %s is already installed", params.AppId),
			}
			// Converge the pin even when already installed — a pin requested
			// after install, or lost out-of-band, must still be applied. A pin
			// failure is a real failure.
			if params.Pin {
				changed, pinErr := ensureFlatpakPinned(ctx, mgr, params.AppId)
				if pinErr != nil {
					out.ExitCode = 1
					out.Stderr = pinErr.Error()
					return out, false, pinErr
				}
				if changed {
					out.Stdout += "\npinned"
				}
				return out, changed, nil
			}
			return out, false, nil
		}

		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		out, _, instErr := packageResult(mgr.Install(ctx, pkg.InstallOptions{Remote: remote}, params.AppId))
		if instErr != nil {
			return out, false, fmt.Errorf("flatpak install failed: %w", instErr)
		}

		// Pin if requested (mask prevents updates). Pinning is part of the
		// requested state, so a pin failure surfaces as a real error — the
		// install is durable but the action did not reach the desired state
		// (mirrors action_package.go).
		if params.Pin {
			if _, pinErr := ensureFlatpakPinned(ctx, mgr, params.AppId); pinErr != nil {
				if out == nil {
					out = &pb.CommandOutput{}
				}
				out.Stderr += "\n" + pinErr.Error()
				return out, true, fmt.Errorf("flatpak installed but pin failed: %w", pinErr)
			}
		}
		return out, true, nil

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		if !installed {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("flatpak %s is already not installed", params.AppId),
			}, false, nil
		}

		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		// Unmask before uninstall — best-effort; can fail benignly if the app
		// was never pinned, so log at Debug for correlation only.
		if _, err := mgr.Unpin(ctx, params.AppId); err != nil {
			e.logger.Debug("flatpak ABSENT: unmask before uninstall failed (often expected if not pinned)",
				"app_id", params.AppId, "error", err)
		}

		return packageResult(mgr.Remove(ctx, pkg.RemoveOptions{}, params.AppId))
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// executeFlatpakPerUser implements the per-user install/uninstall path (#79).
// The PRESENT branch installs for every currently signed-in graphical session;
// the ABSENT branch uninstalls from every account on the box that has the app
// under ~/.local/share/flatpak/. The asymmetry is deliberate: install requires a
// live session (we want the new app visible immediately to a user at the
// keyboard), uninstall must reach dormant accounts to actually converge the
// policy.
//
// Each session/user gets its own flatpak Manager built via newPerUserFlatpak, so
// the --user operations run AS that user through the SDK rather than the agent
// hand-assembling runuser command lines.
//
// Empty-set policy (no signed-in users for PRESENT, no installs to remove for
// ABSENT) is "log Warn, return success no-op" rather than fail — pre-fix the
// action would have silently installed into /root/.local/share/flatpak, so
// success-no-op is strictly better and keeps the action retry-friendly until a
// session appears.
func (e *Executor) executeFlatpakPerUser(ctx context.Context, params *pb.FlatpakParams, state pb.DesiredState, remote string) (*pb.CommandOutput, bool, error) {
	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		sessions, err := desktopMgr.ActiveSessions(ctx)
		if err != nil {
			return nil, false, fmt.Errorf("enumerate active desktop sessions: %w", err)
		}
		if len(sessions) == 0 {
			e.logger.Warn("flatpak PRESENT: no active desktop sessions; per-user install deferred until a user signs in",
				"app_id", params.AppId)
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("skipped: no signed-in desktop users to install %s for; will run again on next reconciliation", params.AppId),
			}, false, nil
		}

		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		var (
			anyChanged   bool
			perUserOut   = &strings.Builder{}
			firstFailure error
		)
		for _, s := range sessions {
			line := func(body string) {
				perUserOut.WriteString("user=")
				perUserOut.WriteString(s.Username)
				perUserOut.WriteString(": ")
				perUserOut.WriteString(body)
				perUserOut.WriteString("\n")
			}

			umgr, mkErr := newPerUserFlatpak(s)
			if mkErr != nil {
				if firstFailure == nil {
					firstFailure = fmt.Errorf("user %s: %w", s.Username, mkErr)
				}
				e.logger.Warn("flatpak PRESENT: per-user manager setup failed",
					"user", s.Username, "app_id", params.AppId, "error", mkErr)
				line("setup failed: " + mkErr.Error())
				continue
			}

			// An IsInstalled probe error is treated as "not installed" (mirrors
			// the prior `flatpak info` check, which collapsed to a bool): proceed
			// to install, which surfaces any real failure per-user below.
			if installed, _ := umgr.IsInstalled(ctx, params.AppId); installed {
				line(fmt.Sprintf("flatpak %s already installed; skipped", params.AppId))
				// Converge the pin even when already installed.
				if params.Pin {
					changed, pinErr := ensureFlatpakPinned(ctx, umgr, params.AppId)
					if pinErr != nil {
						if firstFailure == nil {
							firstFailure = fmt.Errorf("user %s: %w", s.Username, pinErr)
						}
						e.logger.Warn("flatpak PRESENT: per-user pin (mask) failed",
							"user", s.Username, "app_id", params.AppId, "error", pinErr)
						line("pin failed: " + pinErr.Error())
					} else if changed {
						anyChanged = true
						line("pinned " + params.AppId)
					}
				}
				continue
			}

			if _, runErr := umgr.Install(ctx, pkg.InstallOptions{Remote: remote}, params.AppId); runErr != nil {
				if firstFailure == nil {
					firstFailure = fmt.Errorf("user %s: install failed: %w", s.Username, runErr)
				}
				e.logger.Warn("flatpak PRESENT: per-user install failed",
					"user", s.Username, "app_id", params.AppId, "error", runErr)
				line(runErr.Error())
				continue
			}
			anyChanged = true
			line(fmt.Sprintf("installed %s", params.AppId))

			if params.Pin {
				if _, pinErr := ensureFlatpakPinned(ctx, umgr, params.AppId); pinErr != nil {
					// Pin is part of the requested state: record it as a failure
					// (firstFailure) so the action reports FAILED, not a silent
					// success with the app left unpinned.
					if firstFailure == nil {
						firstFailure = fmt.Errorf("user %s: install succeeded but %w", s.Username, pinErr)
					}
					e.logger.Warn("flatpak PRESENT: per-user pin (mask) failed (install succeeded)",
						"user", s.Username, "app_id", params.AppId, "error", pinErr)
					line("pin failed: " + pinErr.Error())
				}
			}
		}

		return &pb.CommandOutput{Stdout: perUserOut.String()}, anyChanged, firstFailure

	case pb.DesiredState_DESIRED_STATE_ABSENT:
		users, err := desktopMgr.UsersWithFlatpakInstall(ctx, params.AppId)
		if err != nil {
			return nil, false, fmt.Errorf("enumerate per-user flatpak installs: %w", err)
		}
		if len(users) == 0 {
			return &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("flatpak %s is already not installed for any user", params.AppId),
			}, false, nil
		}

		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		var (
			anyChanged   bool
			perUserOut   = &strings.Builder{}
			firstFailure error
		)
		for _, u := range users {
			perUserOut.WriteString("user=")
			perUserOut.WriteString(u.Username)
			perUserOut.WriteString(": ")

			umgr, mkErr := newPerUserFlatpak(u)
			if mkErr != nil {
				if firstFailure == nil {
					firstFailure = fmt.Errorf("user %s: %w", u.Username, mkErr)
				}
				e.logger.Warn("flatpak ABSENT: per-user manager setup failed",
					"user", u.Username, "app_id", params.AppId, "error", mkErr)
				perUserOut.WriteString("setup failed: " + mkErr.Error() + "\n")
				continue
			}

			// Mask removal is best-effort, same rationale as the system-wide
			// path. Log only if loud.
			if _, err := umgr.Unpin(ctx, params.AppId); err != nil {
				e.logger.Debug("flatpak ABSENT: per-user unmask before uninstall failed (often expected if not pinned)",
					"user", u.Username, "app_id", params.AppId, "error", err)
			}

			if _, runErr := umgr.Remove(ctx, pkg.RemoveOptions{}, params.AppId); runErr != nil {
				if firstFailure == nil {
					firstFailure = fmt.Errorf("user %s: uninstall failed: %w", u.Username, runErr)
				}
				e.logger.Warn("flatpak ABSENT: per-user uninstall failed",
					"user", u.Username, "app_id", params.AppId, "error", runErr)
				perUserOut.WriteString(runErr.Error() + "\n")
				continue
			}
			anyChanged = true
			perUserOut.WriteString("uninstalled\n")
		}

		return &pb.CommandOutput{Stdout: perUserOut.String()}, anyChanged, firstFailure
	}
	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// ensureFlatpakPinned converges the pin (mask) state for appID through the given
// flatpak Manager: it pins the app if it isn't already pinned and reports whether
// it changed anything. A pin failure is returned as a real error — pinning is
// part of the requested desired state (mirrors action_package.go's
// ensurePackagePinned contract), so a failed pin must NOT be reported as success.
// IsPinned makes the pin converge on an already-installed-but-unpinned app.
func ensureFlatpakPinned(ctx context.Context, mgr pkg.Manager, appID string) (bool, error) {
	pinned, err := mgr.IsPinned(ctx, appID)
	if err != nil {
		return false, fmt.Errorf("check pin %s: %w", appID, err)
	}
	if pinned {
		return false, nil // already pinned, nothing to do
	}
	if _, err := mgr.Pin(ctx, appID); err != nil {
		return false, fmt.Errorf("pin (mask) %s: %w", appID, err)
	}
	return true, nil
}

// repairFlatpak fixes common Flatpak issues (broken/orphaned refs, stale
// appstream metadata) via the system-scoped flatpak Manager: Repair restores a
// consistent installation state and Update refreshes appstream metadata
// (flatpak update --appstream).
func (e *Executor) repairFlatpak(ctx context.Context) {
	mgr, err := pkg.New(pkg.Flatpak, executorRunner)
	if err != nil {
		slog.Warn("repairFlatpak: build flatpak manager failed", "error", err)
		return
	}
	if _, err := mgr.Repair(ctx); err != nil {
		slog.Warn("repairFlatpak: repair failed", "error", err)
	}
	if _, err := mgr.Update(ctx); err != nil {
		slog.Warn("repairFlatpak: appstream update failed", "error", err)
	}
}
