package executor

import (
	"context"
	"strings"
	"testing"

	"github.com/manchtools/power-manage/sdk/go/pkg"
)

// TestHasUpdatesAvailable_Dnf tests the dnf check-update path on Fedora systems.
func TestHasUpdatesAvailable_Dnf(t *testing.T) {
	if !pkg.IsDnf() {
		t.Skip("not a dnf-based system")
	}

	e := NewExecutor(nil)
	result := e.hasUpdatesAvailable(context.Background(), false)
	t.Logf("hasUpdatesAvailable (dnf) = %v", result)

	// Cross-check with dnf check-update exit code
	_, exitCode, _ := queryCmdOutput("dnf", "check-update")
	expected := exitCode == 100

	if result != expected {
		t.Errorf("hasUpdatesAvailable() = %v, but dnf check-update exit code = %d (expected updates=%v)", result, exitCode, expected)
	}
}

// TestHasUpdatesAvailable_Apt tests the apt list --upgradable path on Debian systems.
func TestHasUpdatesAvailable_Apt(t *testing.T) {
	if !pkg.IsApt() {
		t.Skip("not an apt-based system")
	}

	e := NewExecutor(nil)
	result := e.hasUpdatesAvailable(context.Background(), false)
	t.Logf("hasUpdatesAvailable (apt) = %v", result)

	// Cross-check with apt list --upgradable
	out, _, _ := queryCmdOutput("apt", "list", "--upgradable")
	expected := false
	for _, line := range splitLines(out) {
		if line != "" && line != "Listing..." {
			expected = true
			break
		}
	}

	if result != expected {
		t.Errorf("hasUpdatesAvailable() = %v, but apt list --upgradable says updates=%v", result, expected)
	}
}

func splitLines(s string) []string {
	var lines []string
	for _, l := range strings.Split(s, "\n") {
		lines = append(lines, strings.TrimSpace(l))
	}
	return lines
}

// TestDnfAutoremoveChanged tests parsing of dnf autoremove output.
func TestDnfAutoremoveChanged(t *testing.T) {
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
			if dnfAutoremoveChanged(tt.stdout) != tt.changed {
				t.Errorf("dnfAutoremoveChanged() = %v, want %v", !tt.changed, tt.changed)
			}
		})
	}
}

// TestAptAutoremoveChanged tests parsing of apt autoremove output.
func TestAptAutoremoveChanged(t *testing.T) {
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
			if aptAutoremoveChanged(tt.stdout) != tt.changed {
				t.Errorf("aptAutoremoveChanged() = %v, want %v", !tt.changed, tt.changed)
			}
		})
	}
}
