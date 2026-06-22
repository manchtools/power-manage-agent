package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestFetchArtifact_TrimsWhitespacePaddedURL pins the divergence fix between the
// agent's URL validation and its fetch. sdk.ValidateHTTPSURL (used by
// requireVerifiedArtifact for appimage/deb/rpm) trims the URL internally before
// checking scheme/host, so a whitespace-padded-but-otherwise-valid URL PASSES
// validation. remote.NewHTTP's parser does NOT trim, so without fetchArtifact
// trimming the padded URL reaches the fetch and is rejected ("not absolute" /
// "control characters") — an artifact that validated cleanly then fails to
// download. fetchArtifact must trim so the fetched URL matches the form
// validation blessed.
func TestFetchArtifact_TrimsWhitespacePaddedURL(t *testing.T) {
	const body = "artifact-bytes"
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/app" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()
	withRemoteTestClient(t, srv)

	dest := filepath.Join(t.TempDir(), "app")
	padded := "  " + srv.URL + "/app\n" // leading spaces + trailing newline
	if err := fetchArtifact(context.Background(), padded, dest, "", "0644"); err != nil {
		t.Fatalf("fetchArtifact on a whitespace-padded URL: %v", err)
	}
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read dest: %v", err)
	}
	if string(got) != body {
		t.Errorf("dest content = %q, want %q", got, body)
	}
}
