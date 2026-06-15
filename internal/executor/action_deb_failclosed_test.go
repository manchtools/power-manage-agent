package executor

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// WS16 #2: executeDeb relied solely on downloadFile, which SKIPS checksum
// verification when checksum_sha256 is empty. RPM/AppImage already guard at the
// executor boundary; DEB now does too (requireVerifiedArtifact). Pin that a
// non-https URL or an absent/malformed checksum is rejected BEFORE any
// privileged filesystem remount — hermetic, since the guard runs before the
// dpkg lookup.
func TestExecuteDeb_RejectsBeforeRemount(t *testing.T) {
	validHex := strings.Repeat("a", 64)
	cases := []struct {
		name string
		p    *pb.AppInstallParams
	}{
		{"http url", &pb.AppInstallParams{Url: "http://mirror/x.deb", ChecksumSha256: validHex}},
		{"ftp url", &pb.AppInstallParams{Url: "ftp://mirror/x.deb", ChecksumSha256: validHex}},
		{"empty checksum", &pb.AppInstallParams{Url: "https://x/x.deb", ChecksumSha256: ""}},
		{"whitespace checksum", &pb.AppInstallParams{Url: "https://x/x.deb", ChecksumSha256: "   "}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var remountCalls int
			e := &Executor{logger: slog.Default(), now: time.Now, repairFS: func(context.Context) bool {
				remountCalls++
				return true
			}}
			out, changed, err := e.executeDeb(context.Background(), tc.p, pb.DesiredState_DESIRED_STATE_PRESENT)
			if err == nil {
				t.Fatalf("expected rejection, got out=%v changed=%v", out, changed)
			}
			if remountCalls != 0 {
				t.Errorf("privileged remount ran %d times before validation; want 0", remountCalls)
			}
		})
	}
}
