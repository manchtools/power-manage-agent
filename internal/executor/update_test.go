package executor

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/manchtools/power-manage-sdk/pkg"
	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
)

// updateTestExecutor builds an Executor over a real Direct runner so the
// package-manager Manager is detected and built (NewExecutor with a nil runner
// builds no Manager). The detected backend is exposed via e.pkgBackend, which the
// per-manager integration tests below use as their skip guard — replacing the
// removed package-global pkg.IsApt/IsDnf/... detectors.
func updateTestExecutor(t *testing.T) *Executor {
	t.Helper()
	r, err := sysexec.NewRunner(sysexec.Direct)
	if err != nil {
		t.Fatalf("build direct runner: %v", err)
	}
	return NewExecutor(nil, r)
}

// TestHasUpdatesAvailable_Dnf tests the dnf check-update path on Fedora systems.
func TestHasUpdatesAvailable_Dnf(t *testing.T) {
	e := updateTestExecutor(t)
	if e.pkgBackend != pkg.Dnf {
		t.Skip("not a dnf-based system")
	}
	result := e.hasUpdatesAvailable(context.Background(), false)
	t.Logf("hasUpdatesAvailable (dnf) = %v", result)

	// Cross-check with dnf check-update exit code (language-agnostic)
	// Exit 0 = no updates, 100 = updates available, anything else = error
	_, exitCode, err := queryCmdOutput("dnf", "check-update")
	if err != nil && exitCode != 100 {
		t.Skipf("dnf check-update failed with exit %d: %v", exitCode, err)
	}
	expected := exitCode == 100

	if result != expected {
		t.Errorf("hasUpdatesAvailable() = %v, but dnf check-update exit code = %d (expected updates=%v)", result, exitCode, expected)
	}
}

// TestHasUpdatesAvailable_Apt tests the apt-get -s upgrade path on Debian systems.
func TestHasUpdatesAvailable_Apt(t *testing.T) {
	e := updateTestExecutor(t)
	if e.pkgBackend != pkg.Apt {
		t.Skip("not an apt-based system")
	}
	result := e.hasUpdatesAvailable(context.Background(), false)
	t.Logf("hasUpdatesAvailable (apt) = %v", result)

	// Cross-check: apt/apt-get -s upgrade "Inst " prefix is language-agnostic
	aptCmd := "apt-get"
	if _, err := exec.LookPath("apt"); err == nil {
		aptCmd = "apt"
	}
	out, exitCode, err := queryCmdOutput(aptCmd, "-s", "upgrade")
	if err != nil && exitCode != 0 {
		t.Fatalf("%s -s upgrade failed with exit %d: %v", aptCmd, exitCode, err)
	}
	expected := strings.Contains(out, "Inst ")

	if result != expected {
		t.Errorf("hasUpdatesAvailable() = %v, but %s -s upgrade says updates=%v", result, aptCmd, expected)
	}
}

// TestHasUpdatesAvailable_Pacman tests the pacman -Qu path on Arch systems.
func TestHasUpdatesAvailable_Pacman(t *testing.T) {
	e := updateTestExecutor(t)
	if e.pkgBackend != pkg.Pacman {
		t.Skip("not a pacman-based system")
	}
	result := e.hasUpdatesAvailable(context.Background(), false)
	t.Logf("hasUpdatesAvailable (pacman) = %v", result)

	_, exitCode, _ := queryCmdOutput("pacman", "-Qu")
	expected := exitCode == 0

	if result != expected {
		t.Errorf("hasUpdatesAvailable() = %v, but pacman -Qu exit code = %d (expected updates=%v)", result, exitCode, expected)
	}
}

// TestHasUpdatesAvailable_Zypper tests the zypper list-updates path on openSUSE systems.
func TestHasUpdatesAvailable_Zypper(t *testing.T) {
	e := updateTestExecutor(t)
	if e.pkgBackend != pkg.Zypper {
		t.Skip("not a zypper-based system")
	}
	result := e.hasUpdatesAvailable(context.Background(), false)
	t.Logf("hasUpdatesAvailable (zypper) = %v", result)
}

// TestInstalledPackageCount verifies the package count function works on the current system.
func TestInstalledPackageCount(t *testing.T) {
	e := updateTestExecutor(t)
	count := e.installedPackageCount()
	if count <= 0 {
		t.Skipf("installedPackageCount() = %d (no supported package manager or error)", count)
	}
	t.Logf("installedPackageCount() = %d", count)
}

// TestInstalledPackageCount_Stable verifies that two consecutive calls return the same count.
func TestInstalledPackageCount_Stable(t *testing.T) {
	e := updateTestExecutor(t)
	a := e.installedPackageCount()
	if a <= 0 {
		t.Skip("no supported package manager")
	}
	b := e.installedPackageCount()
	if a != b {
		t.Errorf("package count not stable: %d vs %d", a, b)
	}
}
