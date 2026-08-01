// Package main is the entry point for the power-manage agent.
package main

import (
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	osexec "os/exec"
	"time"

	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// geteuidFn is a seam over os.Geteuid so the empty-default privilege branch
// (root vs sudo) can be exercised deterministically in a normal non-root test
// run instead of depending on the runner's real uid.
var geteuidFn = os.Geteuid

// randomBackoff returns a random duration between minInitialBackoff and
// maxInitialBackoff. Guarded against a degenerate span (#174):
// rand.Int64N panics on n <= 0, so a future constants edit that makes
// min >= max would crash the reconnect path instead of just losing the
// jitter.
func randomBackoff() time.Duration {
	span := int64(maxInitialBackoff - minInitialBackoff)
	if span <= 0 {
		return minInitialBackoff
	}
	return minInitialBackoff + time.Duration(rand.Int64N(span))
}

// applyBackendOverrides maps the backend strings resolved by
// parseFlags() onto the SDK's pluggable backend selectors. Called once
// at startup before any privileged helper runs. Unknown or empty
// values fail at startup rather than selecting a different privilege model.
//
// Returns an error if the selected backend's required binary isn't on
// PATH (e.g. POWER_MANAGE_PRIVILEGE_BACKEND=doas on a host with no
// doas installed). Fail-fast at startup is cheaper than debugging a
// "permission denied" on the first privileged call hours later.
func applyBackendOverrides(cfg *Config, logger *slog.Logger) (sysexec.PrivilegeBackend, error) {
	resolved, err := setPrivilegeBackend(cfg.PrivilegeBackend, logger)
	if err != nil {
		return resolved, err
	}
	// SERVICE actions use systemd. Refuse startup when its control utility is
	// absent rather than carrying a runtime selector with no alternative.
	if _, err := osexec.LookPath("systemctl"); err != nil {
		return resolved, fmt.Errorf("service actions require systemctl on PATH: %w", err)
	}
	logger.Info("service manager ready", "manager", "systemd")

	// LUKS is optional: its missing host utility must not prevent unrelated
	// capabilities from running.
	if _, err := osexec.LookPath("cryptsetup"); err != nil {
		logger.Warn("cryptsetup not found; encryption actions are unavailable", "error", err)
	}
	return resolved, nil
}

// setPrivilegeBackend resolves and installs the SDK privilege backend.
// The agent now runs as root by default (systemd User=root). When the
// backend string is empty and we detect uid 0, pick the no-escalation
// root backend so privileged calls dispatch directly without forking
// sudo (and without depending on per-distro quirks like openSUSE's
// default sudoers excluding root). Returns an error if the selected
// backend's binary isn't on PATH.
func setPrivilegeBackend(backend string, logger *slog.Logger) (sysexec.PrivilegeBackend, error) {
	var (
		privilegeTool string
		resolved      sysexec.PrivilegeBackend
	)
	switch backend {
	case "root":
		// Refuse the no-escalation root backend unless the process is actually
		// root. Otherwise an explicit POWER_MANAGE_PRIVILEGE_BACKEND=root on a
		// non-root agent would build a usable Direct runner, bypassing the
		// fail-closed path and running privileged commands unescalated (e.g. a
		// desktop reboot via logind/polkit). Fail fast at startup instead.
		if euid := geteuidFn(); euid != 0 {
			return sysexec.Direct, fmt.Errorf("privilege backend %q selected but process euid is %d; run as root, or use the sudo/doas backend", backend, euid)
		}
		resolved = sysexec.Direct
		privilegeTool = ""
	case "doas":
		resolved = sysexec.Doas
		privilegeTool = "doas"
	case "sudo":
		resolved = sysexec.Sudo
		privilegeTool = "sudo"
	case "":
		if geteuidFn() == 0 {
			resolved = sysexec.Direct
			privilegeTool = ""
		} else {
			resolved = sysexec.Sudo
			privilegeTool = "sudo"
		}
	default:
		return sysexec.Direct, fmt.Errorf("unknown privilege backend %q", backend)
	}
	// The resolved backend is returned to the caller, which builds the one
	// process-wide exec.Runner from it (sysexec.NewRunner) and injects that into
	// every capability Manager — there is no global privilege state anymore.
	if privilegeTool == "" {
		// Root backend has no external tool to look up — Privileged*
		// dispatchers exec the resolved command directly.
		logger.Info("privilege backend set", "backend", "root")
		return resolved, nil
	}
	if _, err := osexec.LookPath(privilegeTool); err != nil {
		return resolved, fmt.Errorf("privilege backend %q selected but %q is not on PATH: %w",
			privilegeTool, privilegeTool, err)
	}
	logger.Info("privilege backend set", "backend", privilegeTool)
	return resolved, nil
}
