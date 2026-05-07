// Package executor provides implementations for action executors.
package executor

import (
	"context"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
	sysservice "github.com/manchtools/power-manage/sdk/go/sys/service"
)

func (e *Executor) executeService(ctx context.Context, params *pb.ServiceParams) (*pb.CommandOutput, bool, error) {
	if params == nil {
		return nil, false, fmt.Errorf("service params required")
	}

	// Reject the unit name up front via the backend's own naming rules
	// (systemd: <name>.<type>; future backends define their own). This
	// replaces the ad-hoc path-traversal check below — WriteUnit owns
	// the path and validates the name through the same helper, so a
	// bad name can never reach the filesystem.
	if err := sysservice.ValidateUnitName(params.UnitName); err != nil {
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   err.Error() + "\n",
		}, false, err
	}

	// Never allow managing the agent's own service
	if params.UnitName == "power-manage-agent.service" || params.UnitName == "power-manage-agent" {
		return &pb.CommandOutput{
			ExitCode: 1,
			Stderr:   "refusing to manage the power-manage-agent service\n",
		}, false, fmt.Errorf("cannot manage protected service: power-manage-agent")
	}

	var output strings.Builder
	changed := false

	// Check and update unit file content if provided
	if params.UnitContent != "" {
		// Skip-if-unchanged — hashes are cheap and saves the atomic
		// write + daemon-reload cycle on every assign-on-connect run.
		// The systemd unit path is an implementation detail of the
		// backend, but reading it directly is fine here because a
		// mismatch / missing file just falls through to the write path.
		unitPath := filepath.Join("/etc/systemd/system", params.UnitName)
		needsUpdate := true
		if existingContent, err := os.ReadFile(unitPath); err == nil {
			existingHash := sha256.Sum256(existingContent)
			desiredHash := sha256.Sum256([]byte(params.UnitContent))
			if existingHash == desiredHash {
				needsUpdate = false
				output.WriteString(fmt.Sprintf("unit file %s is already up to date\n", params.UnitName))
			}
		}

		if needsUpdate {
			// Repair filesystem if mounted read-only
			if out, err := e.requireWritableFS(ctx); err != nil {
				return out, false, err
			}

			// Delegate the write to the SDK so the active service
			// backend (systemd today; openrc/runit/s6 when implemented)
			// owns the unit-file location and validation. This keeps
			// the agent backend-agnostic — a POWER_MANAGE_SERVICE_BACKEND
			// change no longer silently writes systemd files on a host
			// that doesn't use systemd.
			if err := sysservice.WriteUnit(ctx, params.UnitName, params.UnitContent); err != nil {
				return nil, false, fmt.Errorf("write unit %s: %w", params.UnitName, err)
			}
			output.WriteString(fmt.Sprintf("updated unit file %s\n", params.UnitName))
			changed = true

			// Reload the service manager so it picks up the new unit.
			// DaemonReload is a no-op for backends that don't need it
			// (the SDK dispatches per-backend).
			if err := sysservice.DaemonReload(ctx); err != nil {
				return nil, changed, fmt.Errorf("daemon-reload failed: %w", err)
			}
			output.WriteString("reloaded service manager\n")
		}
	}

	// Check and update enable/disable status
	isEnabled := e.isUnitEnabled(params.UnitName)
	if params.Enable && !isEnabled {
		// Check if unit is masked - provide helpful error
		if e.isUnitMasked(params.UnitName) {
			return nil, changed, fmt.Errorf("enable: unit %s is masked (run 'systemctl unmask %s' first)", params.UnitName, params.UnitName)
		}
		if err := sysservice.Enable(ctx, params.UnitName); err != nil {
			return nil, changed, fmt.Errorf("enable: %w", err)
		}
		output.WriteString("enabled unit\n")
		changed = true
	} else if !params.Enable && isEnabled {
		if err := sysservice.Disable(ctx, params.UnitName); err != nil {
			// Don't swallow real disable failures. The earlier
			// shape blanket-suppressed every error with "unit may
			// not exist" — but isEnabled was just true, so a
			// missing-unit explanation contradicts the precondition.
			// A real failure here (permissions, masked, systemd
			// not responding) means the unit stays enabled
			// against the operator's intent; surface it so the
			// caller sees a failed action and can investigate.
			return nil, false, fmt.Errorf("disable %s: %w", params.UnitName, err)
		}
		output.WriteString("disabled unit\n")
		changed = true
	}

	// Handle running state
	isActive := e.isUnitActive(params.UnitName)
	switch params.DesiredState {
	case pb.ServiceUnitState_SERVICE_UNIT_STATE_STARTED:
		if !isActive {
			if err := sysservice.Start(ctx, params.UnitName); err != nil {
				return nil, changed, fmt.Errorf("start: %w", err)
			}
			output.WriteString("started unit\n")
			changed = true
		} else {
			output.WriteString("unit is already running\n")
		}
	case pb.ServiceUnitState_SERVICE_UNIT_STATE_STOPPED:
		if isActive {
			if err := sysservice.Stop(ctx, params.UnitName); err != nil {
				return nil, changed, fmt.Errorf("stop: %w", err)
			}
			output.WriteString("stopped unit\n")
			changed = true
		} else {
			output.WriteString("unit is already stopped\n")
		}
	case pb.ServiceUnitState_SERVICE_UNIT_STATE_RESTARTED:
		// Restart always runs (not idempotent by design)
		if err := sysservice.Restart(ctx, params.UnitName); err != nil {
			return nil, changed, fmt.Errorf("restart: %w", err)
		}
		output.WriteString("restarted unit\n")
		changed = true
	default:
		if !changed {
			output.WriteString("unit is already in desired state\n")
		}
	}

	return &pb.CommandOutput{ExitCode: 0, Stdout: output.String()}, changed, nil
}

// isUnitEnabled checks if a service unit is enabled. The SDK's
// sysservice.IsEnabled returns (bool, error); callers of this agent
// helper just want the bool. A transient failure (dbus timeout,
// systemctl missing on a non-systemd host, etc.) is treated as "not
// enabled" to keep the previous behaviour, but logged at debug so
// operators have the context when troubleshooting why a unit wasn't
// marked enabled.
func (e *Executor) isUnitEnabled(unitName string) bool {
	enabled, err := sysservice.IsEnabled(unitName)
	if err != nil {
		e.logger.Debug("sysservice.IsEnabled failed; treating as not enabled",
			"unit", unitName, "error", err)
	}
	return enabled
}

// isUnitMasked checks if a service unit is masked. Errors are logged
// at warn — the masked/unmasked distinction drives whether we reject
// an Enable attempt with a "run systemctl unmask" hint, so a false
// negative here is a confusing user-visible failure worth surfacing.
func (e *Executor) isUnitMasked(unitName string) bool {
	masked, err := sysservice.IsMasked(unitName)
	if err != nil {
		e.logger.Warn("sysservice.IsMasked failed; treating as not masked",
			"unit", unitName, "error", err)
	}
	return masked
}

// isUnitActive checks if a service unit is currently active (running).
func (e *Executor) isUnitActive(unitName string) bool {
	active, err := sysservice.IsActive(unitName)
	if err != nil {
		e.logger.Debug("sysservice.IsActive failed; treating as not active",
			"unit", unitName, "error", err)
	}
	return active
}
