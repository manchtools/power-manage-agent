package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// applyBackendOverrides is the single point where operator-supplied backend
// strings become the resolved privilege backend that main builds the one
// process-wide exec.Runner from. The reworked SDK has no global backend state,
// so the resolved backend is RETURNED (not installed into a global) and these
// tests assert on the return value. Every branch still matters:
//
//   - A valid known value must resolve to the matching backend and succeed.
//   - An unknown value must fall through to the safe default AND succeed (we
//     don't want the agent to refuse to start because someone set
//     POWER_MANAGE_PRIVILEGE_BACKEND=typo).
//   - A known value whose binary is missing must fail fast at startup, not
//     paper over the error until first privileged call.
func TestApplyBackendOverrides_PrivilegeBackend(t *testing.T) {
	// Force a non-root euid so "empty defaults to sudo" is deterministic even
	// when this runs under root (e.g. the privileged CI job) — the empty
	// default is euid-coupled and would otherwise resolve to the root backend.
	origEuid := geteuidFn
	t.Cleanup(func() { geteuidFn = origEuid })
	geteuidFn = func() int { return 1000 }

	// Build a PATH where every backend binary we care about exists as an empty
	// executable, so LookPath succeeds without actually running any of them.
	fakeBin := fakePathWith(t, "sudo", "doas", "systemctl", "cryptsetup")

	cases := []struct {
		name    string
		cfg     *Config
		wantErr bool
		want    sysexec.PrivilegeBackend
	}{
		{name: "empty defaults to sudo", cfg: &Config{}, want: sysexec.Sudo},
		{name: "explicit sudo", cfg: &Config{PrivilegeBackend: "sudo"}, want: sysexec.Sudo},
		{name: "explicit doas", cfg: &Config{PrivilegeBackend: "doas"}, want: sysexec.Doas},
		{name: "unknown value warns and falls back to sudo", cfg: &Config{PrivilegeBackend: "typo"}, want: sysexec.Sudo},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PATH", fakeBin)
			got, err := applyBackendOverrides(tc.cfg, discardLogger())
			if err != nil {
				if !tc.wantErr {
					t.Fatalf("applyBackendOverrides: %v", err)
				}
				return
			}
			if tc.wantErr {
				t.Fatal("expected error, got nil")
			}
			if got != tc.want {
				t.Errorf("privilege backend = %v, want %v", got, tc.want)
			}
		})
	}
}

// The agent must refuse to start when the selected privilege backend has no
// binary on PATH. Running forward past this check would surface as a cryptic
// "command not found" on the first privileged call, long after the cause.
func TestApplyBackendOverrides_MissingPrivilegeBinaryIsFatal(t *testing.T) {
	// PATH that contains everything EXCEPT doas. systemctl is present so the
	// service-backend check passes; we're isolating the privilege-backend failure.
	fakeBin := fakePathWith(t, "sudo", "systemctl", "cryptsetup")
	t.Setenv("PATH", fakeBin)

	_, err := applyBackendOverrides(&Config{PrivilegeBackend: "doas"}, discardLogger())
	if err == nil {
		t.Fatal("expected error when doas binary is missing, got nil")
	}
	if !strings.Contains(err.Error(), "doas") {
		t.Errorf("error should mention doas, got: %v", err)
	}
}

// The empty-string privilege default is security-relevant: it must pick the
// no-escalation root backend when the agent runs as root (uid 0) and sudo
// otherwise. Drive both branches deterministically via the geteuidFn seam so a
// normal non-root CI run still proves the root default. setPrivilegeBackend now
// returns the resolved backend (no global to read back).
func TestSetPrivilegeBackend_EmptyDefault_BranchesOnEuid(t *testing.T) {
	origEuid := geteuidFn
	t.Cleanup(func() { geteuidFn = origEuid })

	// fake sudo so the non-root branch's LookPath("sudo") succeeds regardless of
	// the host PATH.
	t.Setenv("PATH", fakePathWith(t, "sudo"))

	t.Run("euid 0 selects the root backend (no escalation tool)", func(t *testing.T) {
		geteuidFn = func() int { return 0 }
		got, err := setPrivilegeBackend("", discardLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != sysexec.Direct {
			t.Errorf("empty default at euid 0 = %v, want Direct (root)", got)
		}
	})

	t.Run("euid 1000 selects the sudo backend", func(t *testing.T) {
		geteuidFn = func() int { return 1000 }
		got, err := setPrivilegeBackend("", discardLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != sysexec.Sudo {
			t.Errorf("empty default at euid 1000 = %v, want Sudo", got)
		}
	})
}

// An EXPLICIT root backend must be refused on a non-root process. Otherwise it
// would build a usable Direct runner under a non-root agent, bypassing the
// fail-closed path and running privileged commands unescalated (e.g. a
// logind/polkit reboot). At euid 0 it is accepted (no escalation tool).
func TestSetPrivilegeBackend_RootBackend_RequiresRootEuid(t *testing.T) {
	origEuid := geteuidFn
	t.Cleanup(func() { geteuidFn = origEuid })

	t.Run("euid 1000 refuses the explicit root backend", func(t *testing.T) {
		geteuidFn = func() int { return 1000 }
		if _, err := setPrivilegeBackend("root", discardLogger()); err == nil {
			t.Fatal("root backend on a non-root process must error, not build a Direct runner")
		}
	})

	t.Run("euid 0 accepts the explicit root backend", func(t *testing.T) {
		geteuidFn = func() int { return 0 }
		got, err := setPrivilegeBackend("root", discardLogger())
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got != sysexec.Direct {
			t.Errorf("root backend at euid 0 = %v, want Direct", got)
		}
	})
}

// The reworked SDK implements only the systemd service backend (the OpenRC/
// Runit/S6 scaffolds and the global SetServiceBackend selector were removed).
// The contract is now: systemctl must be on PATH (fatal otherwise); a non-systemd
// request warns but is NOT fatal (systemd is still used); empty/systemd succeed.
func TestApplyBackendOverrides_ServiceBackend(t *testing.T) {
	// Non-root so the empty privilege default lands on sudo (present in PATH).
	origEuid := geteuidFn
	t.Cleanup(func() { geteuidFn = origEuid })
	geteuidFn = func() int { return 1000 }

	t.Run("missing systemctl is fatal", func(t *testing.T) {
		t.Setenv("PATH", fakePathWith(t, "sudo", "cryptsetup")) // no systemctl
		_, err := applyBackendOverrides(&Config{}, discardLogger())
		if err == nil {
			t.Fatal("expected a fatal error when systemctl is missing")
		}
		if !strings.Contains(err.Error(), "systemctl") {
			t.Errorf("error should mention systemctl, got: %v", err)
		}
	})

	t.Run("non-systemd value warns but is not fatal", func(t *testing.T) {
		t.Setenv("PATH", fakePathWith(t, "sudo", "cryptsetup", "systemctl"))
		if _, err := applyBackendOverrides(&Config{ServiceBackend: "openrc"}, discardLogger()); err != nil {
			t.Fatalf("a non-systemd service backend must warn, not error: %v", err)
		}
	})

	t.Run("empty defaults to systemd", func(t *testing.T) {
		t.Setenv("PATH", fakePathWith(t, "sudo", "cryptsetup", "systemctl"))
		if _, err := applyBackendOverrides(&Config{ServiceBackend: ""}, discardLogger()); err != nil {
			t.Fatalf("empty service backend must not error: %v", err)
		}
	})
}

// fakePathWith creates empty executables for each named tool in a temp dir and
// returns the tempdir so callers can set PATH to it. The files are mode 0o755 so
// exec.LookPath accepts them. Cleaned up automatically via t.TempDir().
func fakePathWith(t *testing.T, tools ...string) string {
	t.Helper()
	dir := t.TempDir()
	for _, tool := range tools {
		path := filepath.Join(dir, tool)
		if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("write fake %s: %v", tool, err)
		}
	}
	return dir
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}
