package executor

import (
	"context"
	"slices"
	"strings"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/pkg"
)

// These skip-gates mirror the production detection exactly: the executors now
// decide "is this a deb/rpm/flatpak-capable host?" via the SDK's pkg.Detect
// (Apt / Dnf|Zypper / Flatpak), not a raw LookPath of dpkg/rpm/flatpak. Gating
// the tests on the same predicate keeps them honest on any host — e.g. a dnf
// box with a stray dpkg binary is NOT deb-capable and the DEB action skips.
func debCapable() bool { return slices.Contains(pkg.Detect(context.Background()), pkg.Apt) }
func rpmCapable() bool {
	d := pkg.Detect(context.Background())
	return slices.Contains(d, pkg.Dnf) || slices.Contains(d, pkg.Zypper)
}
func flatpakCapable() bool { return slices.Contains(pkg.Detect(context.Background()), pkg.Flatpak) }

// TestExecuteDeb_SkipsWhenDpkgMissing verifies that the DEB executor
// returns a skip message when dpkg is not available.
func TestExecuteDeb_SkipsWhenDpkgMissing(t *testing.T) {
	if debCapable() {
		t.Skip("apt (deb backend) detected — test requires a non-deb host")
	}

	e := NewExecutor(nil, nil)
	// A well-formed action (https + checksum): the executor-boundary
	// requireVerifiedArtifact guard runs before the dpkg lookup, so a
	// checksum-less action would be rejected rather than skipped on a non-deb
	// host (WS16 #2). Use a valid action so this test exercises the skip path.
	output, changed, err := e.executeDeb(context.Background(), &pb.AppInstallParams{
		Url:            "https://example.com/test.deb",
		ChecksumSha256: strings.Repeat("a", 64),
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
	if rpmCapable() {
		t.Skip("dnf/zypper (rpm backend) detected — test requires a non-rpm host")
	}

	e := NewExecutor(nil, nil)
	// Well-formed action so requireVerifiedArtifact (which runs before the rpm
	// lookup) passes and the test reaches the skip path on a non-rpm host.
	output, changed, err := e.executeRpm(context.Background(), &pb.AppInstallParams{
		Url:            "https://example.com/test.rpm",
		ChecksumSha256: strings.Repeat("a", 64),
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
	if flatpakCapable() {
		t.Skip("flatpak detected — test requires a host without flatpak")
	}

	e := NewExecutor(nil, nil)
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
	if !debCapable() {
		t.Skip("apt (deb backend) not detected on this host")
	}

	e := NewExecutor(nil, nil)
	// A well-formed action (https + valid checksum) so it passes the
	// requireVerifiedArtifact guard and proceeds past the tool check; the
	// unresolvable host then fails the download (proving it didn't skip).
	output, _, err := e.executeDeb(context.Background(), &pb.AppInstallParams{
		Url:            "https://invalid.example.com/nonexistent.deb",
		ChecksumSha256: strings.Repeat("a", 64),
	}, pb.DesiredState_DESIRED_STATE_PRESENT)

	// Should NOT contain "skipped" — it should proceed and fail on download/install
	if output != nil && strings.Contains(output.Stdout, "skipped") {
		t.Error("DEB executor should not skip when dpkg is available")
	}
	if err == nil {
		t.Error("expected error from download/install of invalid URL, got nil")
	}
	// And it must NOT be rejected at the artifact guard (that would mean it
	// failed before the tool check, not after).
	if err != nil && strings.Contains(err.Error(), "artifact rejected") {
		t.Errorf("valid action wrongly rejected at the artifact guard: %v", err)
	}
}

// TestExecuteRpm_DoesNotSkipWhenRpmPresent verifies that the RPM executor
// proceeds (doesn't skip) when rpm is available.
func TestExecuteRpm_DoesNotSkipWhenRpmPresent(t *testing.T) {
	if !rpmCapable() {
		t.Skip("dnf/zypper (rpm backend) not detected on this host")
	}

	e := NewExecutor(nil, nil)
	// A well-formed action (https + valid checksum) so it passes the
	// requireVerifiedArtifact guard and proceeds past the rpm check; the
	// unresolvable host then fails the download (proving it didn't skip).
	output, _, err := e.executeRpm(context.Background(), &pb.AppInstallParams{
		Url:            "https://invalid.example.com/nonexistent.rpm",
		ChecksumSha256: strings.Repeat("a", 64),
	}, pb.DesiredState_DESIRED_STATE_PRESENT)

	if output != nil && strings.Contains(output.Stdout, "skipped") {
		t.Error("RPM executor should not skip when rpm is available")
	}
	if err == nil {
		t.Error("expected error from download/install of invalid URL, got nil")
	}
	// And it must NOT be rejected at the artifact guard (that would mean it
	// failed before the tool check, not after).
	if err != nil && strings.Contains(err.Error(), "artifact rejected") {
		t.Errorf("valid action wrongly rejected at the artifact guard: %v", err)
	}
}

// TestExecuteFlatpak_DoesNotSkipWhenFlatpakPresent verifies that the Flatpak executor
// proceeds (doesn't skip) when flatpak is available.
func TestExecuteFlatpak_DoesNotSkipWhenFlatpakPresent(t *testing.T) {
	if !flatpakCapable() {
		t.Skip("flatpak not detected on this host")
	}

	e := NewExecutor(nil, nil)
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
