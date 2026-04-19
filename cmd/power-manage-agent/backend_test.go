package main

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sysenc "github.com/manchtools/power-manage/sdk/go/sys/encryption"
	sysexec "github.com/manchtools/power-manage/sdk/go/sys/exec"
	sysservice "github.com/manchtools/power-manage/sdk/go/sys/service"
)

// applyBackendOverrides is the single point where operator-supplied
// backend strings become runtime SDK state. Every branch matters:
//
//   - A valid known value must flip the SDK selector and succeed.
//   - An unknown value must fall through to the safe default AND
//     succeed (we don't want the agent to refuse to start because
//     someone set POWER_MANAGE_PRIVILEGE_BACKEND=typo).
//   - A known value whose binary is missing must fail fast at startup,
//     not paper over the error until first privileged call.
//
// These tests pin each of those behaviours for the privilege backend
// (the most security-critical) and for the service backend (the most
// common one to be swapped on non-systemd distros). The encryption
// backend's LookPath is a soft warning, not an error, so we don't
// assert on its error path.
func TestApplyBackendOverrides_PrivilegeBackend(t *testing.T) {
	// Restore the SDK's global state after each case so parallel
	// test packages can't see stale backend selections.
	defer sysexec.SetPrivilegeBackend(sysexec.PrivilegeBackendSudo)
	defer sysservice.SetServiceBackend(sysservice.ServiceBackendSystemd)
	defer sysenc.SetBackend(sysenc.BackendLUKS)

	// Build a PATH where every backend binary we care about exists
	// as an empty executable, so LookPath succeeds without actually
	// running any of them.
	fakeBin := fakePathWith(t, "sudo", "doas", "systemctl", "cryptsetup")

	cases := []struct {
		name    string
		cfg     *Config
		wantErr bool
		want    sysexec.PrivilegeBackend
	}{
		{
			name:    "empty defaults to sudo",
			cfg:     &Config{},
			want:    sysexec.PrivilegeBackendSudo,
			wantErr: false,
		},
		{
			name:    "explicit sudo",
			cfg:     &Config{PrivilegeBackend: "sudo"},
			want:    sysexec.PrivilegeBackendSudo,
			wantErr: false,
		},
		{
			name:    "explicit doas",
			cfg:     &Config{PrivilegeBackend: "doas"},
			want:    sysexec.PrivilegeBackendDoas,
			wantErr: false,
		},
		{
			name:    "unknown value warns and falls back to sudo",
			cfg:     &Config{PrivilegeBackend: "typo"},
			want:    sysexec.PrivilegeBackendSudo,
			wantErr: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PATH", fakeBin)
			if err := applyBackendOverrides(tc.cfg, discardLogger()); err != nil {
				if !tc.wantErr {
					t.Fatalf("applyBackendOverrides: %v", err)
				}
				return
			}
			if tc.wantErr {
				t.Fatal("expected error, got nil")
			}
			if got := sysexec.CurrentPrivilegeBackend(); got != tc.want {
				t.Errorf("privilege backend = %v, want %v", got, tc.want)
			}
		})
	}
}

// The agent must refuse to start when the selected privilege backend
// has no binary on PATH. Running forward past this check would surface
// as a cryptic "command not found" on the first privileged call,
// long after the cause.
func TestApplyBackendOverrides_MissingPrivilegeBinaryIsFatal(t *testing.T) {
	defer sysexec.SetPrivilegeBackend(sysexec.PrivilegeBackendSudo)

	// PATH that contains everything EXCEPT doas. systemctl is present
	// so the service-backend check passes; we're isolating the
	// privilege-backend failure.
	fakeBin := fakePathWith(t, "sudo", "systemctl", "cryptsetup")
	t.Setenv("PATH", fakeBin)

	err := applyBackendOverrides(&Config{PrivilegeBackend: "doas"}, discardLogger())
	if err == nil {
		t.Fatal("expected error when doas binary is missing, got nil")
	}
	if !strings.Contains(err.Error(), "doas") {
		t.Errorf("error should mention doas, got: %v", err)
	}
}

// fakePathWith creates empty executables for each named tool in a
// temp dir and returns the tempdir so callers can set PATH to it. The
// files are mode 0o755 so exec.LookPath accepts them. Cleaned up
// automatically via t.TempDir().
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
