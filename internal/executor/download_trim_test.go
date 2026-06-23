package executor

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestFetchArtifact_AcceptsWhitespacePaddedURL pins that a URL which passes the
// agent's validation also fetches. sdk.ValidateHTTPSURL (used by
// requireVerifiedArtifact for appimage/deb/rpm) trims the URL before checking
// scheme/host, so a whitespace-padded-but-otherwise-valid URL PASSES validation;
// remote.NewHTTP likewise trims its URL internally, so the padded URL fetches
// rather than being rejected as "not absolute". This guards that the two trim
// behaviours stay aligned end to end — fetchArtifact no longer pre-trims.
func TestFetchArtifact_AcceptsWhitespacePaddedURL(t *testing.T) {
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
