// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/pkg"
	"github.com/manchtools/power-manage-sdk/sys/desktop"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
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

	// Skip on systems without flatpak
	if _, err := exec.LookPath("flatpak"); err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return &pb.CommandOutput{Stdout: "skipped: flatpak not available on this system"}, false, nil
		}
		return nil, false, fmt.Errorf("flatpak lookup: %w", err)
	}

	if params.SystemWide {
		return e.executeFlatpakSystem(ctx, params, state, remote)
	}
	return e.executeFlatpakPerUser(ctx, params, state, remote)
}

// flatpakInstallArgs builds `flatpak install -y --noninteractive <scope>
// -- <remote> <appId>` so the remote and app-id sit after the `--`
// end-of-options separator and can never be reparsed as flatpak options
// (`--from=…`, `--sideload-repo=…`, …).
func flatpakInstallArgs(scopeFlag, remote, appId string) []string {
	return sysexec.SeparatePositionals([]string{"install", "-y", "--noninteractive", scopeFlag}, remote, appId)
}

// flatpakUninstallArgs is the install counterpart: `flatpak uninstall -y
// --noninteractive <scope> -- <appId>`. The app-id is already
// grammar-validated at executeFlatpak's entry, but passing it after `--`
// keeps the install/uninstall argv discipline symmetric.
func flatpakUninstallArgs(scopeFlag, appId string) []string {
	return sysexec.SeparatePositionals([]string{"uninstall", "-y", "--noninteractive", scopeFlag}, appId)
}

// executeFlatpakSystem implements the system-wide install/uninstall
// path. Behavior matches the pre-#79 codepath verbatim — only the
// SystemWide=true case routes here, so existing assignments are
// untouched.
func (e *Executor) executeFlatpakSystem(ctx context.Context, params *pb.FlatpakParams, state pb.DesiredState, remote string) (*pb.CommandOutput, bool, error) {
	const systemFlag = "--system"
	isInstalled := e.isFlatpakInstalled(params.AppId, systemFlag)

	// Pin (mask) runner for this scope; closes over sudo + --system.
	sysMaskRun := func(args ...string) (*pb.CommandOutput, error) {
		return runSudoCmd(ctx, "flatpak", append([]string{"mask", systemFlag}, args...)...)
	}

	switch state {
	case pb.DesiredState_DESIRED_STATE_PRESENT:
		if isInstalled {
			out := &pb.CommandOutput{
				ExitCode: 0,
				Stdout:   fmt.Sprintf("flatpak %s is already installed", params.AppId),
			}
			// Converge the pin even when already installed — a pin
			// requested after install, or lost out-of-band, must still
			// be applied. A pin failure is a real failure.
			if params.Pin {
				changed, pinErr := ensureFlatpakMasked(params.AppId, sysMaskRun)
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

		output, err := runSudoCmd(ctx, "flatpak", flatpakInstallArgs(systemFlag, remote, params.AppId)...)
		if err != nil {
			return output, false, fmt.Errorf("flatpak install failed: %w", err)
		}

		// Pin if requested (mask prevents updates). Pinning is part of
		// the requested state, so a pin failure surfaces as a real error
		// — the install is durable but the action did not reach the
		// desired state (mirrors action_package.go).
		if params.Pin {
			if _, pinErr := ensureFlatpakMasked(params.AppId, sysMaskRun); pinErr != nil {
				if output == nil {
					output = &pb.CommandOutput{}
				}
				output.Stderr += "\n" + pinErr.Error()
				return output, true, fmt.Errorf("flatpak installed but pin failed: %w", pinErr)
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

		if out, err := e.requireWritableFS(ctx); err != nil {
			return out, false, err
		}

		// Audit F056(b) — mask removal can fail benignly if the app
		// was never pinned; log at Debug so the operator can correlate
		// if uninstall later fails.
		if _, err := runSudoCmd(ctx, "flatpak", "mask", "--remove", systemFlag, params.AppId); err != nil {
			e.logger.Debug("flatpak ABSENT: unmask before uninstall failed (often expected if not pinned)",
				"app_id", params.AppId, "error", err)
		}

		output, err := runSudoCmd(ctx, "flatpak", flatpakUninstallArgs(systemFlag, params.AppId)...)
		return output, true, err
	}

	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// executeFlatpakPerUser implements the per-user install/uninstall
// path (#79). The PRESENT branch installs for every currently
// signed-in graphical session; the ABSENT branch uninstalls from
// every account on the box that has the app under
// ~/.local/share/flatpak/. The asymmetry is deliberate: install
// requires a live session (we want the new app visible immediately
// to a user who's at the keyboard), uninstall must reach dormant
// accounts to actually converge the policy.
//
// Empty-set policy (no signed-in users for PRESENT, no installs to
// remove for ABSENT) is "log Warn, return success no-op" rather
// than fail — pre-fix the action would have silently installed into
// /root/.local/share/flatpak, so success-no-op is strictly better
// and keeps the action retry-friendly until a session appears.
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
			line := func(prefix, body string) {
				perUserOut.WriteString(prefix)
				perUserOut.WriteString(s.Username)
				perUserOut.WriteString(": ")
				perUserOut.WriteString(body)
				perUserOut.WriteString("\n")
			}

			userMaskRun := func(args ...string) (*pb.CommandOutput, error) {
				return runAsUserCmd(ctx, s, nil, "flatpak", append([]string{"mask", "--user"}, args...)...)
			}

			if runAsUserCheck(ctx, s, "flatpak", "info", "--user", params.AppId) {
				line("user=", fmt.Sprintf("flatpak %s already installed; skipped", params.AppId))
				// Converge the pin even when already installed.
				if params.Pin {
					changed, pinErr := ensureFlatpakMasked(params.AppId, userMaskRun)
					if pinErr != nil {
						if firstFailure == nil {
							firstFailure = fmt.Errorf("user %s: %w", s.Username, pinErr)
						}
						e.logger.Warn("flatpak PRESENT: per-user pin (mask) failed",
							"user", s.Username, "app_id", params.AppId, "error", pinErr)
						line("user=", "pin failed: "+pinErr.Error())
					} else if changed {
						anyChanged = true
						line("user=", "pinned "+params.AppId)
					}
				}
				continue
			}

			out, runErr := runAsUserCmd(ctx, s, nil, "flatpak", flatpakInstallArgs("--user", remote, params.AppId)...)
			if runErr != nil {
				if firstFailure == nil {
					firstFailure = fmt.Errorf("user %s: install failed: %w", s.Username, runErr)
				}
				e.logger.Warn("flatpak PRESENT: per-user install failed",
					"user", s.Username, "app_id", params.AppId, "error", runErr)
				if out != nil {
					line("user=", strings.TrimSpace(out.Stderr))
				}
				continue
			}
			anyChanged = true
			line("user=", fmt.Sprintf("installed %s", params.AppId))

			if params.Pin {
				if _, pinErr := ensureFlatpakMasked(params.AppId, userMaskRun); pinErr != nil {
					// Pin is part of the requested state: record it as a
					// failure (firstFailure) so the action reports FAILED,
					// not a silent success with the app left unpinned.
					if firstFailure == nil {
						firstFailure = fmt.Errorf("user %s: install succeeded but %w", s.Username, pinErr)
					}
					e.logger.Warn("flatpak PRESENT: per-user pin (mask) failed (install succeeded)",
						"user", s.Username, "app_id", params.AppId, "error", pinErr)
					line("user=", "pin failed: "+pinErr.Error())
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
			// Mask removal is best-effort, same rationale as the
			// system-wide path. Log only if loud.
			if _, err := runAsUserCmd(ctx, u, nil, "flatpak", "mask", "--remove", "--user", params.AppId); err != nil {
				e.logger.Debug("flatpak ABSENT: per-user unmask before uninstall failed (often expected if not pinned)",
					"user", u.Username, "app_id", params.AppId, "error", err)
			}

			out, runErr := runAsUserCmd(ctx, u, nil, "flatpak", flatpakUninstallArgs("--user", params.AppId)...)
			perUserOut.WriteString("user=")
			perUserOut.WriteString(u.Username)
			perUserOut.WriteString(": ")
			if runErr != nil {
				if firstFailure == nil {
					firstFailure = fmt.Errorf("user %s: uninstall failed: %w", u.Username, runErr)
				}
				e.logger.Warn("flatpak ABSENT: per-user uninstall failed",
					"user", u.Username, "app_id", params.AppId, "error", runErr)
				if out != nil {
					perUserOut.WriteString(strings.TrimSpace(out.Stderr))
				} else {
					perUserOut.WriteString(runErr.Error())
				}
				perUserOut.WriteString("\n")
				continue
			}
			anyChanged = true
			perUserOut.WriteString("uninstalled\n")
		}

		return &pb.CommandOutput{Stdout: perUserOut.String()}, anyChanged, firstFailure
	}
	return nil, false, fmt.Errorf("unknown desired state: %v", state)
}

// isFlatpakInstalled checks if a flatpak app is installed.
func (e *Executor) isFlatpakInstalled(appId, systemFlag string) bool {
	return checkCmdSuccess("flatpak", "info", systemFlag, appId)
}

// flatpakRunner executes `flatpak mask <scope> <args...>` and returns
// its output. The scope flag (--system / --user) and exec context
// (sudo vs runuser) are captured by the closure, so ensureFlatpakMasked
// works identically for the system-wide and per-user paths.
type flatpakRunner func(args ...string) (*pb.CommandOutput, error)

// flatpakMaskListed reports whether appID appears as an exact entry in
// the `flatpak mask` listing output.
func flatpakMaskListed(maskListStdout, appID string) bool {
	for _, line := range strings.Split(maskListStdout, "\n") {
		if strings.TrimSpace(line) == appID {
			return true
		}
	}
	return false
}

// ensureFlatpakMasked converges the pin (mask) state for appID: it masks
// the app if it isn't already masked, and reports whether it changed
// anything. A mask failure is returned as a real error — pinning is part
// of the requested desired state (mirrors action_package.go's
// ensurePackagePinned contract), so a failed pin must NOT be reported as
// a success. This also makes the pin converge on an
// already-installed-but-unpinned app, which the early-return paths
// previously skipped entirely.
func ensureFlatpakMasked(appID string, run flatpakRunner) (bool, error) {
	if listOut, err := run(); err == nil && listOut != nil && flatpakMaskListed(listOut.Stdout, appID) {
		return false, nil // already pinned, nothing to do
	}
	if _, err := run(appID); err != nil {
		return false, fmt.Errorf("pin (mask) %s: %w", appID, err)
	}
	return true, nil
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
