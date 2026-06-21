package executor

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
)

// TestExecuteRepository_RejectsBeforePrivilegedRemount pins finding 5:
// a malformed repository action (bad name, oversized name, non-https
// base URL) is rejected BEFORE any privileged filesystem
// remount/repair. The repairFS seam records zero invocations.
func TestExecuteRepository_RejectsBeforePrivilegedRemount(t *testing.T) {
	var remountCalls int
	e := &Executor{logger: slog.Default(), now: time.Now, repairFS: func(context.Context) bool {
		remountCalls++
		return true
	}}
	bad := []*pb.RepositoryParams{
		{Name: "r", Dnf: &pb.DnfRepository{Baseurl: "http://evil", Gpgcheck: true}}, // non-https base URL
		{Name: "../etc"},                 // path-traversing name
		{Name: strings.Repeat("a", 200)}, // oversized name
	}
	for i, p := range bad {
		out, changed, err := e.executeRepository(context.Background(), p, pb.DesiredState_DESIRED_STATE_PRESENT)
		if err == nil {
			t.Errorf("case %d: malformed repo action accepted: out=%v changed=%v", i, out, changed)
		}
	}
	if remountCalls != 0 {
		t.Errorf("privileged remount ran %d times for rejected actions; want 0", remountCalls)
	}
}

// TestDownloadAptKey_RejectsNonHTTPS pins WS7 #2 at the agent boundary: the apt
// signing-key download — the one repository responsibility the SDK Manager
// cannot own, because it takes raw key bytes, not a URL — refuses any non-https
// scheme before performing network I/O. The SDK validator never sees
// gpg_key_url, so this guard lives only here; a regression would let an action
// pull a signing key over an unauthenticated transport.
func TestDownloadAptKey_RejectsNonHTTPS(t *testing.T) {
	e := &Executor{}
	// Genuinely non-https URLs must be rejected before any network round-trip.
	// "HTTPS://m/k" (uppercase) is intentionally NOT here: a URL scheme is
	// case-insensitive (RFC 3986), so it is valid https — the old strict
	// HasPrefix("https://") falsely rejected it; sdk.ValidateHTTPSURL (the single
	// https-trust boundary, used here now) correctly accepts it. "https:m/k" IS
	// rejected: it is an opaque URL with no host.
	for _, u := range []string{"http://m/key.asc", "ftp://m/key", "file:///etc/x", "//m/key", "https:m/k"} {
		if _, err := e.downloadAptKey(context.Background(), u); err == nil {
			t.Errorf("non-https GPG key URL accepted: %q", u)
		}
	}
}
