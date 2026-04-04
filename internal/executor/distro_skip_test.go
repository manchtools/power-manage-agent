package executor

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// TestExecuteDeb_SkipsWhenDpkgMissing verifies that the DEB executor
// returns a skip message when dpkg is not available.
func TestExecuteDeb_SkipsWhenDpkgMissing(t *testing.T) {
	if _, err := exec.LookPath("dpkg"); err == nil {
		t.Skip("dpkg is available on this system — test requires a system without dpkg")
	}

	e := NewExecutor(nil)
	output, changed, err := e.executeDeb(context.Background(), &pb.AppInstallParams{
		Url: "https://example.com/test.deb",
	}, pb.DesiredState_DESIRED_STATE_PRESENT)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if changed {
		t.Error("expected changed=false for skipped action")
	}
	if output == nil || !strings.Contains(output.Stdout, "skipped") {
		t.Errorf("expected skip message, got: %v", output)
	}
}

// TestExecuteRpm_SkipsWhenRpmMissing verifies that the RPM executor
// returns a skip message when rpm is not available.
func TestExecuteRpm_SkipsWhenRpmMissing(t *testing.T) {
	if _, err := exec.LookPath("rpm"); err == nil {
		t.Skip("rpm is available on this system — test requires a system without rpm")
	}

	e := NewExecutor(nil)
	output, changed, err := e.executeRpm(context.Background(), &pb.AppInstallParams{
		Url: "https://example.com/test.rpm",
	}, pb.DesiredState_DESIRED_STATE_PRESENT)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if changed {
		t.Error("expected changed=false for skipped action")
	}
	if output == nil || !strings.Contains(output.Stdout, "skipped") {
		t.Errorf("expected skip message, got: %v", output)
	}
}

// TestExecuteFlatpak_SkipsWhenFlatpakMissing verifies that the Flatpak executor
// returns a skip message when flatpak is not available.
func TestExecuteFlatpak_SkipsWhenFlatpakMissing(t *testing.T) {
	if _, err := exec.LookPath("flatpak"); err == nil {
		t.Skip("flatpak is available on this system — test requires a system without flatpak")
	}

	e := NewExecutor(nil)
	output, changed, err := e.executeFlatpak(context.Background(), &pb.FlatpakParams{
		AppId: "org.example.Test",
	}, pb.DesiredState_DESIRED_STATE_PRESENT)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if changed {
		t.Error("expected changed=false for skipped action")
	}
	if output == nil || !strings.Contains(output.Stdout, "skipped") {
		t.Errorf("expected skip message, got: %v", output)
	}
}

// TestExecuteDeb_DoesNotSkipWhenDpkgPresent verifies that the DEB executor
// proceeds (doesn't skip) when dpkg is available.
func TestExecuteDeb_DoesNotSkipWhenDpkgPresent(t *testing.T) {
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("dpkg is not available on this system")
	}

	e := NewExecutor(nil)
	// Use an invalid URL so it fails after the tool check (proving it didn't skip)
	output, _, err := e.executeDeb(context.Background(), &pb.AppInstallParams{
		Url: "https://invalid.example.com/nonexistent.deb",
	}, pb.DesiredState_DESIRED_STATE_PRESENT)

	// Should NOT contain "skipped" — it should proceed and fail on download/install
	if output != nil && strings.Contains(output.Stdout, "skipped") {
		t.Error("DEB executor should not skip when dpkg is available")
	}
	if err == nil {
		t.Error("expected error from download/install of invalid URL, got nil")
	}
}

// TestExecuteRpm_DoesNotSkipWhenRpmPresent verifies that the RPM executor
// proceeds (doesn't skip) when rpm is available.
func TestExecuteRpm_DoesNotSkipWhenRpmPresent(t *testing.T) {
	if _, err := exec.LookPath("rpm"); err != nil {
		t.Skip("rpm is not available on this system")
	}

	e := NewExecutor(nil)
	output, _, err := e.executeRpm(context.Background(), &pb.AppInstallParams{
		Url: "https://invalid.example.com/nonexistent.rpm",
	}, pb.DesiredState_DESIRED_STATE_PRESENT)

	if output != nil && strings.Contains(output.Stdout, "skipped") {
		t.Error("RPM executor should not skip when rpm is available")
	}
	if err == nil {
		t.Error("expected error from download/install of invalid URL, got nil")
	}
}

// TestExecuteFlatpak_DoesNotSkipWhenFlatpakPresent verifies that the Flatpak executor
// proceeds (doesn't skip) when flatpak is available.
func TestExecuteFlatpak_DoesNotSkipWhenFlatpakPresent(t *testing.T) {
	if _, err := exec.LookPath("flatpak"); err != nil {
		t.Skip("flatpak is not available on this system")
	}

	e := NewExecutor(nil)
	output, _, err := e.executeFlatpak(context.Background(), &pb.FlatpakParams{
		AppId: "org.nonexistent.surely_does_not_exist_12345",
	}, pb.DesiredState_DESIRED_STATE_PRESENT)

	if output != nil && strings.Contains(output.Stdout, "skipped") {
		t.Error("Flatpak executor should not skip when flatpak is available")
	}
	if err == nil {
		t.Error("expected error from install of nonexistent app, got nil")
	}
}
