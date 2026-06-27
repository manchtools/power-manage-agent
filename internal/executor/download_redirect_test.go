package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	pb "github.com/manchtools/power-manage-sdk/gen/go/pm/v1"
	"github.com/manchtools/power-manage-sdk/sys/remote"
)

// crossOriginFixture serves payload from B and 302s A -> B/file. A and B listen
// on different ports, so A -> B is a genuine cross-origin redirect (the exact
// shape of GitHub's github.com -> release-assets.githubusercontent.com bounce).
func crossOriginFixture(t *testing.T, payload []byte) string {
	t.Helper()
	srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srvB.Close)
	srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srvB.URL+"/file", http.StatusFound)
	}))
	t.Cleanup(srvA.Close)
	return srvA.URL + "/file"
}

// TestFetchArtifact_RedirectPolicy is the regression test for the self-update
// cross-origin failure: a download whose URL bounces to another host is refused
// under RedirectSameOrigin and followed under RedirectCrossOrigin. remoteHTTPClient
// is forced nil so the SDK's default client — and thus the policy under test — is
// actually exercised (an injected client would own its own redirect policy).
func TestFetchArtifact_RedirectPolicy(t *testing.T) {
	prev := remoteHTTPClient
	remoteHTTPClient = nil
	t.Cleanup(func() { remoteHTTPClient = prev })

	payload := []byte("agent binary bytes behind a cross-origin redirect")
	sum := sha256.Sum256(payload)
	checksum := hex.EncodeToString(sum[:])
	url := crossOriginFixture(t, payload)

	// Same-origin policy refuses the host-changing hop (the buggy default).
	dest := filepath.Join(t.TempDir(), "bin")
	if err := fetchArtifact(context.Background(), url, dest, checksum, "0755", remote.RedirectSameOrigin); err == nil {
		t.Fatal("RedirectSameOrigin must refuse the cross-origin redirect, got nil")
	}

	// Cross-origin policy follows it and the pin still verifies the bytes.
	dest2 := filepath.Join(t.TempDir(), "bin")
	if err := fetchArtifact(context.Background(), url, dest2, checksum, "0755", remote.RedirectCrossOrigin); err != nil {
		t.Fatalf("RedirectCrossOrigin must follow the redirect: %v", err)
	}
	got, err := os.ReadFile(dest2)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != string(payload) {
		t.Fatalf("dest = %q; want %q", got, payload)
	}
}

// TestUpdateRedirectPolicy pins the operator-facing mapping: the self-update
// action's allow_redirect flag selects cross-origin, and the default (false)
// keeps the strict same-origin guard.
func TestUpdateRedirectPolicy(t *testing.T) {
	if got := updateRedirectPolicy(&pb.AgentUpdateParams{AllowRedirect: true}); got != remote.RedirectCrossOrigin {
		t.Fatalf("AllowRedirect=true -> %v; want RedirectCrossOrigin", got)
	}
	if got := updateRedirectPolicy(&pb.AgentUpdateParams{AllowRedirect: false}); got != remote.RedirectSameOrigin {
		t.Fatalf("AllowRedirect=false -> %v; want RedirectSameOrigin", got)
	}
	if got := updateRedirectPolicy(&pb.AgentUpdateParams{}); got != remote.RedirectSameOrigin {
		t.Fatalf("default -> %v; want RedirectSameOrigin", got)
	}
}

// TestRedirectForArtifact pins the package-download default: cross-origin only
// when the artifact is sha256-pinned (the pin makes a host-changing hop safe).
func TestRedirectForArtifact(t *testing.T) {
	if got := redirectForArtifact("abc123"); got != remote.RedirectCrossOrigin {
		t.Fatalf("pinned -> %v; want RedirectCrossOrigin", got)
	}
	if got := redirectForArtifact(""); got != remote.RedirectSameOrigin {
		t.Fatalf("unpinned -> %v; want RedirectSameOrigin", got)
	}
}
