package executor

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// TestExecuteAppImage_RejectsBeforeWriteAndRemount pins WS7/WS8 parity with
// rpm/deb: installing an AppImage with a non-https URL or an empty/whitespace
// checksum is refused BEFORE any privileged filesystem remount or download — an
// unverified binary is never fetched. The recording repairFS seam proves no
// remount ran. (ABSENT removal needs no checksum — see the sibling test.)
func TestExecuteAppImage_RejectsBeforeWriteAndRemount(t *testing.T) {
	validHex := strings.Repeat("a", 64)
	cases := []struct {
		name string
		p    *pb.AppInstallParams
	}{
		{"http url", &pb.AppInstallParams{Url: "http://mirror/x.AppImage", ChecksumSha256: validHex}},
		{"empty checksum", &pb.AppInstallParams{Url: "https://x/x.AppImage", ChecksumSha256: ""}},
		{"whitespace checksum", &pb.AppInstallParams{Url: "https://x/x.AppImage", ChecksumSha256: "   "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// A resolvable install dir so it is the verification guard — not a
			// path-resolution failure — that rejects the install.
			tc.p.InstallPath = t.TempDir()
			var remountCalls int
			e := &Executor{logger: slog.Default(), now: time.Now, repairFS: func(context.Context) bool {
				remountCalls++
				return true
			}}
			out, changed, err := e.executeAppImage(context.Background(), tc.p, pb.DesiredState_DESIRED_STATE_PRESENT)
			if err == nil {
				t.Fatalf("expected rejection, got out=%v changed=%v", out, changed)
			}
			if remountCalls != 0 {
				t.Errorf("privileged remount ran %d times before artifact verification; want 0", remountCalls)
			}
		})
	}
}

// TestExecuteAppImage_AbsentDoesNotRequireChecksum pins that the checksum guard
// is PRESENT-only: removing an AppImage needs no checksum (parity with the
// DEB guard, which is also install-only).
func TestExecuteAppImage_AbsentDoesNotRequireChecksum(t *testing.T) {
	e := &Executor{logger: slog.Default(), now: time.Now}
	out, changed, err := e.executeAppImage(context.Background(),
		&pb.AppInstallParams{Url: "https://x/x.AppImage", InstallPath: t.TempDir(), ChecksumSha256: ""},
		pb.DesiredState_DESIRED_STATE_ABSENT)
	if err != nil {
		t.Fatalf("ABSENT removal must not require a checksum: %v", err)
	}
	if changed {
		t.Errorf("removing a non-existent appimage should report no change")
	}
	_ = out
}
