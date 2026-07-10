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
	"strings"
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
	NeedsReload(ctx context.Context, unit string) (bool, error)
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
	if err := validateUnitPath("BinaryPath", p.BinaryPath); err != nil {
		return "", err
	}
	if err := validateUnitPath("DataDir", p.DataDir); err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, p); err != nil {
		return "", fmt.Errorf("unit render: %w", err)
	}
	return buf.String(), nil
}

// validateUnitPath rejects render inputs that would corrupt the unit:
// the values land verbatim in ExecStart= (systemd word-splits on
// whitespace and interprets quotes/backslashes) and Environment=
// (systemd expands %-specifiers), so whitespace, quotes, backslashes,
// '%', control characters, and relative paths are refused. These are
// operator-supplied install flags, not attacker input — the point is a
// loud install-time failure instead of a silently mangled root unit.
func validateUnitPath(field, value string) error {
	if !strings.HasPrefix(value, "/") {
		return fmt.Errorf("unit render: %s %q must be an absolute path", field, value)
	}
	for _, r := range value {
		switch {
		case r <= 0x20 || r == 0x7f: // control chars incl. space/tab/newline
			return fmt.Errorf("unit render: %s %q contains whitespace or a control character", field, value)
		case r == '"' || r == '\'' || r == '\\' || r == '%' || r == '$':
			// '%' = specifier expansion; '$' = environment-variable
			// expansion in ExecStart — both would silently rewrite the
			// path at unit load time instead of failing at install time.
			return fmt.Errorf("unit render: %s %q contains %q, which systemd unit syntax interprets", field, value, string(r))
		}
	}
	return nil
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
	// Read FIRST: an absent unit (container/dev run) must skip before
	// anything touches systemctl — no version probe, no warnings.
	absent := false
	onDisk, err := mgr.ReadUnit(ctx, UnitName)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		if !createIfMissing {
			logger.Debug("no unit file on disk; skipping unit reconcile", "unit", UnitName)
			return false, nil
		}
		absent = true
	case err != nil:
		return false, fmt.Errorf("read unit %s: %w", UnitName, err)
	}

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

	if !absent && onDisk == rendered {
		// The file is current, but a PREVIOUS run may have written it
		// and then failed its daemon-reload — in which case systemd is
		// still running the stale loaded config and a byte compare
		// alone would never retry. NeedDaemonReload is the stateless
		// truth for that; complete the pending reload here.
		pending, nrErr := mgr.NeedsReload(ctx, UnitName)
		if nrErr != nil {
			logger.Warn("could not check for a pending daemon-reload; continuing", "unit", UnitName, "error", nrErr)
			return false, nil
		}
		if pending {
			logger.Warn("unit file is current but systemd's loaded config is stale (an earlier daemon-reload failed?); completing the reload", "unit", UnitName)
			if err := mgr.DaemonReload(ctx); err != nil {
				return false, fmt.Errorf("retry daemon-reload for %s: %w", UnitName, err)
			}
		}
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
