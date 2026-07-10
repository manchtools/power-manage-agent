// Package unit owns the agent's systemd unit (spec 27): the unit file
// ships INSIDE the binary as the single source of truth, is installed
// by the `install-unit` subcommand (invoked once by install.sh and by
// the self-updater between binary swap and respawn), and is reconciled
// against the on-disk copy at every daemon startup — so a binary update
// updates the unit and capability drift like agent#187 (pre-#96 units
// missing CAP_SETFCAP wedging apt postinsts) cannot recur.
//
// The reconciler never restarts the service (user decision 2026-07-10):
// a rewritten unit takes effect at the next restart — reboot, a manual
// systemctl restart, or the respawn the next self-update performs.
// Operator customizations belong in drop-ins
// (power-manage-agent.service.d/*.conf), which win per systemd
// semantics and which this package never reads or writes.
//
// All system operations go through sdk/sys/service.Manager — the same
// validated, atomic WriteUnit path operator SERVICE actions use; this
// package contains no systemctl or filesystem plumbing of its own.
package unit

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"text/template"
)

// ServiceName is the agent's systemd service name (sans unit suffix).
const ServiceName = "power-manage-agent"

// UnitName is the full unit-file name WriteUnit/ReadUnit operate on.
const UnitName = ServiceName + ".service"

// restrictRealtimeMinVersion is the first systemd version where
// RestrictRealtime does not set no_new_privs via its seccomp filter
// (which would break sudo children); see the former install.sh probe.
const restrictRealtimeMinVersion = 257

//go:embed power-manage-agent.service.tmpl
var unitTemplate string

var tmpl = template.Must(template.New(UnitName).Parse(unitTemplate))

// Manager is the slice of sdk/sys/service.Manager this package uses.
// Narrow on purpose: the reconcile may read, write, probe, and
// daemon-reload — never enable, restart, or stop anything.
type Manager interface {
	Version(ctx context.Context) (int, error)
	ReadUnit(ctx context.Context, unit string) (string, error)
	WriteUnit(ctx context.Context, unit, content string) error
	DaemonReload(ctx context.Context) error
}

// Params are the render inputs. BinaryPath and DataDir come from the
// running process (os.Executable, -data-dir) so the render is a fixed
// point: the values the unit started the daemon with are the values
// the daemon renders back. RestrictRealtime is resolved from the
// version probe by the sync paths; Render takes the decided boolean.
type Params struct {
	BinaryPath       string
	DataDir          string
	RestrictRealtime bool
}

// Render produces the unit-file content for p.
func Render(p Params) (string, error) {
	if p.BinaryPath == "" || p.DataDir == "" {
		return "", fmt.Errorf("unit render: BinaryPath and DataDir are required")
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, p); err != nil {
		return "", fmt.Errorf("unit render: %w", err)
	}
	return buf.String(), nil
}

// Reconcile is the daemon-startup path: compare the on-disk unit with
// the render and rewrite + daemon-reload on drift. An ABSENT unit is a
// deliberate no-op (container/dev runs are not installations). Returns
// whether a rewrite happened; the caller is fail-open and owns the
// ERROR logging contract for returned errors.
func Reconcile(ctx context.Context, mgr Manager, logger *slog.Logger, p Params) (bool, error) {
	return sync(ctx, mgr, logger, p, false)
}

// EnsureInstalled is the install path (`install-unit`, install.sh, the
// self-updater hook): like Reconcile, but an absent unit is written
// rather than skipped. Idempotent — an identical on-disk unit is a
// no-op, so repeated invocations never churn the file or reload.
func EnsureInstalled(ctx context.Context, mgr Manager, logger *slog.Logger, p Params) error {
	_, err := sync(ctx, mgr, logger, p, true)
	return err
}

func sync(ctx context.Context, mgr Manager, logger *slog.Logger, p Params, createIfMissing bool) (bool, error) {
	// Version probe failure fails SAFE, not closed: render with
	// RestrictRealtime=false (the same precaution install.sh took) —
	// a broken probe must not leave a stale bounding set in place.
	if ver, err := mgr.Version(ctx); err != nil {
		logger.Warn("systemd version probe failed; rendering RestrictRealtime=false as a precaution", "error", err)
		p.RestrictRealtime = false
	} else {
		p.RestrictRealtime = ver >= restrictRealtimeMinVersion
	}

	rendered, err := Render(p)
	if err != nil {
		return false, err
	}

	onDisk, err := mgr.ReadUnit(ctx, UnitName)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !createIfMissing {
			logger.Debug("no unit file on disk; skipping unit reconcile", "unit", UnitName)
			return false, nil
		}
		onDisk = ""
	case err != nil:
		return false, fmt.Errorf("read unit %s: %w", UnitName, err)
	}

	if onDisk == rendered {
		logger.Debug("unit file matches the embedded template", "unit", UnitName)
		return false, nil
	}

	if err := mgr.WriteUnit(ctx, UnitName, rendered); err != nil {
		return false, fmt.Errorf("write unit %s: %w", UnitName, err)
	}
	if err := mgr.DaemonReload(ctx); err != nil {
		return true, fmt.Errorf("daemon-reload after writing %s (unit IS updated on disk): %w", UnitName, err)
	}
	return true, nil
}
