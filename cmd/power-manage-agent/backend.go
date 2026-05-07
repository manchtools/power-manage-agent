// Package main is the entry point for the power-manage agent.
package main

import (
	"fmt"
	"log/slog"
	"math/rand/v2"
	osexec "os/exec"
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
	// Privilege-escalation tool. sudo remains the default because
	// every mainstream Linux distro ships it; doas is for OpenBSD-
	// style setups and some BSD-influenced Linux deployments.
	var privilegeTool string
	switch cfg.PrivilegeBackend {
	case "doas":
		sysexec.SetPrivilegeBackend(sysexec.PrivilegeBackendDoas)
		privilegeTool = "doas"
	case "sudo", "":
		sysexec.SetPrivilegeBackend(sysexec.PrivilegeBackendSudo)
		privilegeTool = "sudo"
	default:
		logger.Warn("unknown POWER_MANAGE_PRIVILEGE_BACKEND, staying on sudo",
			"value", cfg.PrivilegeBackend)
		sysexec.SetPrivilegeBackend(sysexec.PrivilegeBackendSudo)
		privilegeTool = "sudo"
	}
	if _, err := osexec.LookPath(privilegeTool); err != nil {
		return fmt.Errorf("privilege backend %q selected but %q is not on PATH: %w",
			privilegeTool, privilegeTool, err)
	}
	logger.Info("privilege backend set", "backend", privilegeTool)

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

	// Disk-encryption tooling. Only LUKS is implemented today.
	// GELI/CGD live on BSD where we don't probe for a specific CLI
	// binary — the SDK's encryption package handles detection there.
	var encName string
	switch cfg.EncryptionBackend {
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
		logger.Warn("unknown POWER_MANAGE_ENCRYPTION_BACKEND, staying on luks",
			"value", cfg.EncryptionBackend)
		sysenc.SetBackend(sysenc.BackendLUKS)
		encName = "luks"
	}
	if encName == "luks" {
		if _, err := osexec.LookPath("cryptsetup"); err != nil {
			// Not fatal — devices without encryption actions assigned
			// don't need cryptsetup. Warn so operators troubleshooting
			// a failed encryption action have the context.
			logger.Warn("luks backend selected but cryptsetup not on PATH; encryption actions will fail",
				"error", err)
		}
	}
	logger.Info("encryption backend set", "backend", encName)

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
