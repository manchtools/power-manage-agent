package executor

import (
	"context"
	"os/exec"
	"strings"
	"testing"
)

// TestHasUpdatesAvailable_Dnf tests the dnf check-update path on Fedora systems.
func TestHasUpdatesAvailable_Dnf(t *testing.T) {
	if _, err := exec.LookPath("dnf"); err != nil {
		t.Skip("dnf not available on this system")
	}

	e := NewExecutor(nil)
	// Just verify it doesn't panic/crash — the actual result depends on system state
	result := e.hasUpdatesAvailable(context.Background(), false)
	t.Logf("hasUpdatesAvailable (dnf) = %v", result)

	// Cross-check with dnf check-update exit code
	cmd := exec.Command("dnf", "check-update")
	cmd.Run()
	exitCode := cmd.ProcessState.ExitCode()
	expected := exitCode == 100

	if result != expected {
		t.Errorf("hasUpdatesAvailable() = %v, but dnf check-update exit code = %d (expected updates=%v)", result, exitCode, expected)
	}
}

// TestHasUpdatesAvailable_Apt tests the apt list --upgradable path on Debian systems.
func TestHasUpdatesAvailable_Apt(t *testing.T) {
	if _, err := exec.LookPath("apt"); err != nil {
		t.Skip("apt not available on this system")
	}
	// Only run on actual apt-based systems (Fedora has apt but it's not the primary PM)
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("not a dpkg-based system")
	}

	e := NewExecutor(nil)
	result := e.hasUpdatesAvailable(context.Background(), false)
	t.Logf("hasUpdatesAvailable (apt) = %v", result)
}

// TestAutoremoveChangedDetection_Dnf tests parsing of dnf autoremove output.
func TestAutoremoveChangedDetection_Dnf(t *testing.T) {
	tests := []struct {
		name    string
		stdout  string
		changed bool
	}{
		{
			name:    "nothing to do",
			stdout:  "Dependencies resolved.\nNothing to do.\nComplete!\n",
			changed: false,
		},
		{
			name:    "packages removed",
			stdout:  "Dependencies resolved.\nRemoving:\n maliit-keyboard  x86_64  2.3.1  @System  1.2M\nRemoved:\n maliit-keyboard-2.3.1\nComplete!\n",
			changed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := !strings.Contains(tt.stdout, "Nothing to do")
			if changed != tt.changed {
				t.Errorf("expected changed=%v for output %q", tt.changed, tt.stdout)
			}
		})
	}
}

// TestAutoremoveChangedDetection_Apt tests parsing of apt autoremove output.
func TestAutoremoveChangedDetection_Apt(t *testing.T) {
	tests := []struct {
		name    string
		stdout  string
		changed bool
	}{
		{
			name:    "nothing to remove",
			stdout:  "Reading package lists... Done\nBuilding dependency tree... Done\n0 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n",
			changed: false,
		},
		{
			name:    "packages removed",
			stdout:  "Reading package lists... Done\nBuilding dependency tree... Done\nThe following packages will be REMOVED:\n  libfoo libbar\n0 upgraded, 0 newly installed, 2 to remove and 0 not upgraded.\nRemoving libfoo...\n",
			changed: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			changed := !strings.Contains(tt.stdout, "0 upgraded, 0 newly installed, 0 to remove")
			if changed != tt.changed {
				t.Errorf("expected changed=%v for output %q", tt.changed, tt.stdout)
			}
		})
	}
}
