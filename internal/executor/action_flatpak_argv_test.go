package executor

import (
	"context"
	"log/slog"
	"slices"
	"strings"
	"testing"
	"time"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// TestFlatpakInstallArgs_AfterEndOfOptions pins that the remote and
// app-id reach `flatpak install` after a "--" so neither can be reparsed
// as a flatpak option (`--from=…`, `--sideload-repo=…`, …).
func TestFlatpakInstallArgs_AfterEndOfOptions(t *testing.T) {
	if got, want := flatpakInstallArgs("--system", "flathub", "org.videolan.VLC"),
		[]string{"install", "-y", "--noninteractive", "--system", "--", "flathub", "org.videolan.VLC"}; !slices.Equal(got, want) {
		t.Errorf("flatpakInstallArgs(system) = %v, want %v", got, want)
	}
	if got, want := flatpakInstallArgs("--user", "flathub", "org.gnome.Calculator"),
		[]string{"install", "-y", "--noninteractive", "--user", "--", "flathub", "org.gnome.Calculator"}; !slices.Equal(got, want) {
		t.Errorf("flatpakInstallArgs(user) = %v, want %v", got, want)
	}
	// install/uninstall argv discipline is symmetric.
	if got, want := flatpakUninstallArgs("--system", "org.videolan.VLC"),
		[]string{"uninstall", "-y", "--noninteractive", "--system", "--", "org.videolan.VLC"}; !slices.Equal(got, want) {
		t.Errorf("flatpakUninstallArgs(system) = %v, want %v", got, want)
	}
}

// TestExecuteFlatpak_ValidatesAppIdAndRemote pins finding 7: app-id and
// remote are validated BEFORE any dispatch, so a flag-shaped value can
// never reach `flatpak`. Hermetic: validation runs before the flatpak
// binary lookup, so no flatpak install is required.
func TestExecuteFlatpak_ValidatesAppIdAndRemote(t *testing.T) {
	e := &Executor{logger: slog.Default(), now: time.Now}
	ctx := context.Background()

	reject := []*pb.FlatpakParams{
		{AppId: "--system"}, // flag-shaped app id
		{AppId: "-y"},       // flag-shaped app id
		{AppId: "a b"},      // embedded space → argv confusion
		{AppId: "org.ok.App", Remote: "--from=evil"}, // flag-shaped remote
		{AppId: "org.ok.App", Remote: "-x"},          // flag-shaped remote
		{AppId: ""},                                  // ABSENT — existing required error preserved
	}
	// The rejection must be a VALIDATION error — not an incidental
	// downstream failure (e.g. desktop-session enumeration) that would
	// mask a missing validation gate.
	isValidationErr := func(err error) bool {
		if err == nil {
			return false
		}
		m := err.Error()
		return strings.Contains(m, "invalid") || strings.Contains(m, "is required") || strings.Contains(m, "is empty")
	}
	for i, p := range reject {
		_, _, err := e.executeFlatpak(ctx, p, pb.DesiredState_DESIRED_STATE_PRESENT)
		if !isValidationErr(err) {
			t.Errorf("reject case %d (%+v): want a validation error, got %v", i, p, err)
		}
	}

	// correct app-id + remote must pass validation. On a host without
	// flatpak this returns the skip no-op (nil err); on a host with
	// flatpak it may fail the real install — assert only that it is NOT a
	// validation rejection.
	if _, _, err := e.executeFlatpak(ctx, &pb.FlatpakParams{AppId: "org.videolan.VLC", Remote: "flathub"}, pb.DesiredState_DESIRED_STATE_PRESENT); err != nil {
		if strings.Contains(err.Error(), "invalid") || strings.Contains(err.Error(), "is required") {
			t.Errorf("valid app-id/remote produced a validation error: %v", err)
		}
	}
}
