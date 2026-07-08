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
// values fall through to the default (sudo / systemd / luks) and the
// function pins the SDK explicitly rather than relying on zero-value
// state, so an unknown value is still deterministic.
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
	// Service manager. The reworked SDK implements only systemd
	// (service.New(service.Systemd, runner)); the OpenRC/Runit/S6 scaffolds and
	// the global SetServiceBackend selector were removed. Warn loudly if a
	// non-systemd backend was requested — the first SERVICE action will fail, but
	// the warning explains why before that happens — and require systemctl since
	// the Manager always drives systemd.
	if sb := normalizedServiceBackend(cfg.ServiceBackend); sb != "systemd" {
		logger.Warn("only the systemd service backend is implemented; SERVICE actions will fail on this host",
			"requested", sb)
	}
	if _, err := osexec.LookPath("systemctl"); err != nil {
		return resolved, fmt.Errorf("systemd service backend requires systemctl on PATH: %w", err)
	}
	logger.Info("service backend set", "backend", "systemd")

	setEncryptionBackend(cfg.EncryptionBackend, logger)
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
		logger.Warn("unknown POWER_MANAGE_PRIVILEGE_BACKEND, staying on sudo", "value", backend)
		resolved = sysexec.Sudo
		privilegeTool = "sudo"
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

// setEncryptionBackend validates the configured encryption backend. The reworked
// SDK implements only LUKS (encryption.New(encryption.LUKS, runner)) and the
// global backend selector was removed, so this only warns on a non-luks request
// and checks that cryptsetup is on PATH.
func setEncryptionBackend(backend string, logger *slog.Logger) {
	encName := backend
	switch backend {
	case "luks", "":
		encName = "luks"
	default:
		logger.Warn("only the luks encryption backend is implemented; ENCRYPTION actions will fail on this host", "requested", backend)
		encName = "luks"
	}
	if encName == "luks" {
		if _, err := osexec.LookPath("cryptsetup"); err != nil {
			logger.Warn("luks backend selected but cryptsetup not on PATH; encryption actions will fail", "error", err)
		}
	}
	logger.Info("encryption backend set", "backend", encName)
}

// normalizedServiceBackend returns the canonical name for logging so
// the empty-string default case doesn't log "service backend set
// backend=" with a blank value.
func normalizedServiceBackend(s string) string {
	if s == "" {
		return "systemd"
	}
	return s
}
