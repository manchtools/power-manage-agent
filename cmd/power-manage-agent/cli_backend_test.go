package main

import (
	"os"
	"testing"

	sysenc "github.com/manchtools/power-manage/sdk/go/sys/encryption"
	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
)

// applyCLIBackends is what the `luks set-passphrase` CLI uses instead of
// the daemon's applyBackendOverrides. It must install the same root/sudo
// resolution so the cryptsetup helpers don't fall back to the SDK
// default sudo backend (which fails on root-can't-sudo hosts).
func TestApplyCLIBackends_HonorsEnvAndRootDefault(t *testing.T) {
	defer sysexec.SetPrivilegeBackend(sysexec.PrivilegeBackendSudo)
	defer sysenc.SetBackend(sysenc.BackendLUKS)
	t.Setenv("PATH", fakePathWith(t, "sudo", "doas", "cryptsetup"))

	t.Run("explicit root", func(t *testing.T) {
		t.Setenv("POWER_MANAGE_PRIVILEGE_BACKEND", "root")
		if err := applyCLIBackends(discardLogger()); err != nil {
			t.Fatalf("applyCLIBackends: %v", err)
		}
		if got := sysexec.CurrentPrivilegeBackend(); got != sysexec.PrivilegeBackendRoot {
			t.Errorf("privilege backend = %v, want root", got)
		}
	})

	t.Run("explicit doas", func(t *testing.T) {
		t.Setenv("POWER_MANAGE_PRIVILEGE_BACKEND", "doas")
		if err := applyCLIBackends(discardLogger()); err != nil {
			t.Fatalf("applyCLIBackends: %v", err)
		}
		if got := sysexec.CurrentPrivilegeBackend(); got != sysexec.PrivilegeBackendDoas {
			t.Errorf("privilege backend = %v, want doas", got)
		}
	})

	t.Run("empty env resolves to root when running as uid 0", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("requires root to exercise the uid-0 default branch")
		}
		t.Setenv("POWER_MANAGE_PRIVILEGE_BACKEND", "")
		if err := applyCLIBackends(discardLogger()); err != nil {
			t.Fatalf("applyCLIBackends: %v", err)
		}
		if got := sysexec.CurrentPrivilegeBackend(); got != sysexec.PrivilegeBackendRoot {
			t.Errorf("privilege backend = %v, want root (uid 0 default)", got)
		}
	})
}
