package executor

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/sys/remote"
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

// #173 review finding (SECURITY): with no verifiable checksum the ABSENT
// path must NEVER fetch the artifact — an unverified origin-served .deb's
// Package field would otherwise choose what gets removed. The name must
// come from the CA-signed URL's filename instead.
func TestDebAbsentPackageName_NoChecksumNeverFetches(t *testing.T) {
	fetchCalls := 0
	orig := fetchArtifact
	fetchArtifact = func(_ context.Context, _, _, _, _ string, _ remote.RedirectPolicy) error {
		fetchCalls++
		return nil
	}
	t.Cleanup(func() { fetchArtifact = orig })

	e := &Executor{logger: slog.Default(), now: time.Now}
	name, err := e.debAbsentPackageName(context.Background(), nil,
		&pb.AppInstallParams{Url: "https://mirror/pool/foo-agent_1.2.3_amd64.deb", ChecksumSha256: ""})
	if err != nil {
		t.Fatalf("URL-filename fallback must succeed: %v", err)
	}
	if name != "foo-agent" {
		t.Fatalf("name = %q, want %q (from the signed URL, not the artifact)", name, "foo-agent")
	}
	if fetchCalls != 0 {
		t.Fatalf("fetchArtifact was called %d times with an unverifiable checksum — the origin must never choose the removal target", fetchCalls)
	}
}

// Complementary positive path: with a well-formed checksum the ABSENT
// path DOES attempt the verified fetch (and still falls back to the URL
// name when the artifact is gone upstream).
func TestDebAbsentPackageName_WithChecksumFetchesVerified(t *testing.T) {
	var gotChecksum string
	fetchCalls := 0
	orig := fetchArtifact
	fetchArtifact = func(_ context.Context, _, _ string, checksum, _ string, _ remote.RedirectPolicy) error {
		fetchCalls++
		gotChecksum = checksum
		return fmt.Errorf("404: artifact deleted upstream")
	}
	t.Cleanup(func() { fetchArtifact = orig })

	validHex := strings.Repeat("a", 64)
	e := &Executor{logger: slog.Default(), now: time.Now}
	name, err := e.debAbsentPackageName(context.Background(), nil,
		&pb.AppInstallParams{Url: "https://mirror/pool/foo-agent_1.2.3_amd64.deb", ChecksumSha256: validHex})
	if err != nil {
		t.Fatalf("stale-URL fallback must succeed: %v", err)
	}
	if name != "foo-agent" {
		t.Fatalf("name = %q, want %q", name, "foo-agent")
	}
	if fetchCalls != 1 {
		t.Fatalf("fetchArtifact calls = %d, want 1", fetchCalls)
	}
	if gotChecksum != validHex {
		t.Fatalf("fetch ran without the action's checksum (got %q)", gotChecksum)
	}
}
