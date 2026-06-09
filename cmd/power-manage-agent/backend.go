// Package main is the entry point for the power-manage agent.
package main

import (
	"fmt"
	"log/slog"
	"math/rand/v2"
	"os"
	osexec "os/exec"
	"strings"
	"time"

	sysenc "github.com/manchtools/power-manage/sdk/go/sys/encryption"
	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
	sysservice "github.com/manchtools/power-manage/sdk/go/sys/service"
)

// randomBackoff returns a random duration between minInitialBackoff and maxInitialBackoff.
func randomBackoff() time.Duration {
	jitter := rand.Int64N(int64(maxInitialBackoff - minInitialBackoff))
	return minInitialBackoff + time.Duration(jitter)
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
func applyBackendOverrides(cfg *Config, logger *slog.Logger) error {
	if err := setPrivilegeBackend(cfg.PrivilegeBackend, logger); err != nil {
		return err
	}

	// Service manager. Only systemd has a concrete implementation
	// today; the other backends are scaffolded in the SDK so the
	// proto enum + agent wiring stay stable, but WriteUnit / Enable /
	// Start return sysservice.unsupported(...) until implementations
	// land. Warn loudly so operators who select a scaffold backend
	// don't think the agent silently succeeded — the first action
	// will fail, but the warning explains why before that happens.
	var serviceTool string
	scaffoldOnly := false
	switch cfg.ServiceBackend {
	case "openrc":
		sysservice.SetServiceBackend(sysservice.ServiceBackendOpenRC)
		serviceTool = "rc-service"
		scaffoldOnly = true
	case "runit":
		sysservice.SetServiceBackend(sysservice.ServiceBackendRunit)
		serviceTool = "sv"
		scaffoldOnly = true
	case "s6":
		sysservice.SetServiceBackend(sysservice.ServiceBackendS6)
		serviceTool = "s6-svc"
		scaffoldOnly = true
	case "systemd", "":
		sysservice.SetServiceBackend(sysservice.ServiceBackendSystemd)
		serviceTool = "systemctl"
	default:
		logger.Warn("unknown POWER_MANAGE_SERVICE_BACKEND, staying on systemd",
			"value", cfg.ServiceBackend)
		sysservice.SetServiceBackend(sysservice.ServiceBackendSystemd)
		serviceTool = "systemctl"
	}
	if scaffoldOnly {
		logger.Warn("service backend has no SDK implementation yet; SERVICE actions will fail until support lands",
			"backend", cfg.ServiceBackend)
	}
	if _, err := osexec.LookPath(serviceTool); err != nil {
		return fmt.Errorf("service backend %q selected but %q is not on PATH: %w",
			normalizedServiceBackend(cfg.ServiceBackend), serviceTool, err)
	}
	logger.Info("service backend set", "backend", normalizedServiceBackend(cfg.ServiceBackend))

	setEncryptionBackend(cfg.EncryptionBackend, logger)
	return nil
}

// setPrivilegeBackend resolves and installs the SDK privilege backend.
// The agent now runs as root by default (systemd User=root). When the
// backend string is empty and we detect uid 0, pick the no-escalation
// root backend so privileged calls dispatch directly without forking
// sudo (and without depending on per-distro quirks like openSUSE's
// default sudoers excluding root). Returns an error if the selected
// backend's binary isn't on PATH.
func setPrivilegeBackend(backend string, logger *slog.Logger) error {
	var privilegeTool string
	switch backend {
	case "root":
		sysexec.SetPrivilegeBackend(sysexec.PrivilegeBackendRoot)
		privilegeTool = ""
	case "doas":
		sysexec.SetPrivilegeBackend(sysexec.PrivilegeBackendDoas)
		privilegeTool = "doas"
	case "sudo":
		sysexec.SetPrivilegeBackend(sysexec.PrivilegeBackendSudo)
		privilegeTool = "sudo"
	case "":
		if os.Geteuid() == 0 {
			sysexec.SetPrivilegeBackend(sysexec.PrivilegeBackendRoot)
			privilegeTool = ""
		} else {
			sysexec.SetPrivilegeBackend(sysexec.PrivilegeBackendSudo)
			privilegeTool = "sudo"
		}
	default:
		logger.Warn("unknown POWER_MANAGE_PRIVILEGE_BACKEND, staying on sudo", "value", backend)
		sysexec.SetPrivilegeBackend(sysexec.PrivilegeBackendSudo)
		privilegeTool = "sudo"
	}
	if privilegeTool == "" {
		// Root backend has no external tool to look up — Privileged*
		// dispatchers exec the resolved command directly.
		logger.Info("privilege backend set", "backend", "root")
		return nil
	}
	if _, err := osexec.LookPath(privilegeTool); err != nil {
		return fmt.Errorf("privilege backend %q selected but %q is not on PATH: %w",
			privilegeTool, privilegeTool, err)
	}
	logger.Info("privilege backend set", "backend", privilegeTool)
	return nil
}

// setEncryptionBackend resolves and installs the SDK encryption backend.
// Only LUKS is implemented today. GELI/CGD live on BSD where we don't
// probe for a specific CLI binary.
func setEncryptionBackend(backend string, logger *slog.Logger) {
	var encName string
	switch backend {
	case "geli":
		sysenc.SetBackend(sysenc.BackendGELI)
		encName = "geli"
	case "cgd":
		sysenc.SetBackend(sysenc.BackendCGD)
		encName = "cgd"
	case "luks", "":
		sysenc.SetBackend(sysenc.BackendLUKS)
		encName = "luks"
	default:
		logger.Warn("unknown POWER_MANAGE_ENCRYPTION_BACKEND, staying on luks", "value", backend)
		sysenc.SetBackend(sysenc.BackendLUKS)
		encName = "luks"
	}
	if encName == "luks" {
		if _, err := osexec.LookPath("cryptsetup"); err != nil {
			logger.Warn("luks backend selected but cryptsetup not on PATH; encryption actions will fail", "error", err)
		}
	}
	logger.Info("encryption backend set", "backend", encName)
}

// applyCLIBackends installs the privilege + encryption backends for the
// standalone CLI subcommands (e.g. `luks set-passphrase`). Those run
// without parseFlags + applyBackendOverrides, so without this they stay
// on the SDK default sudo backend and the cryptsetup helpers fail on
// hosts where root can't `sudo -n` (openSUSE Defaults targetpw) — the
// exact quirk the root backend exists to avoid. The service backend is
// not needed by these subcommands, so it is intentionally not set here.
func applyCLIBackends(logger *slog.Logger) error {
	if err := setPrivilegeBackend(strings.ToLower(os.Getenv("POWER_MANAGE_PRIVILEGE_BACKEND")), logger); err != nil {
		return err
	}
	setEncryptionBackend(strings.ToLower(os.Getenv("POWER_MANAGE_ENCRYPTION_BACKEND")), logger)
	return nil
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
