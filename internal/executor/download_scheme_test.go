package executor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	pb "github.com/manchtools/power-manage/sdk/gen/go/pm/v1"
)

// WS7 #2: downloadFile is the single chokepoint for deb/rpm/appimage
// downloads. It must reject any non-https scheme AND an empty checksum
// (mandatory integrity) BEFORE any network request.
func TestDownloadFile_RejectsNonHTTPS(t *testing.T) {
	e := &Executor{logger: slog.Default(), now: time.Now}
	dest := filepath.Join(t.TempDir(), "out")
	const anyChecksum = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

	for _, u := range []string{
		"http://example.com/app.deb",
		"file:///etc/passwd",
		"ftp://example.com/app.deb",
		"//example.com/app.deb", // scheme-relative
		"example.com/app.deb",   // no scheme
	} {
		if err := e.downloadFile(context.Background(), u, dest, anyChecksum); err == nil {
			t.Errorf("downloadFile(%q) = nil, want rejection (non-https)", u)
		}
		if _, err := os.Stat(dest); err == nil {
			t.Errorf("downloadFile(%q) created the destination despite rejection", u)
		}
	}
}

// The https + correct-checksum path succeeds (proves the guard does not
// over-reject and the chokepoint still works).
func TestDownloadFile_AcceptsHTTPSWithChecksum(t *testing.T) {
	body := []byte("agent binary bytes")
	sum := sha256.Sum256(body)
	checksum := hex.EncodeToString(sum[:])

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()

	e := &Executor{logger: slog.Default(), now: time.Now}
	e.httpClient = srv.Client()
	dest := filepath.Join(t.TempDir(), "out")

	if err := e.downloadFile(context.Background(), srv.URL+"/app.deb", dest, checksum); err != nil {
		t.Fatalf("https + correct checksum should succeed: %v", err)
	}
	got, _ := os.ReadFile(dest)
	if string(got) != string(body) {
		t.Errorf("downloaded content = %q, want %q", got, body)
	}
}

// WS7 #2: the appimage executor must reject a non-https URL at the URL
// parse, before any download (the prior code allowed http://).
func TestExecuteAppImage_RejectsHTTP(t *testing.T) {
	e := &Executor{logger: slog.Default(), now: time.Now}
	_, changed, err := e.executeAppImage(context.Background(),
		&pb.AppInstallParams{
			Url:            "http://example.com/app.AppImage",
			ChecksumSha256: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		}, pb.DesiredState_DESIRED_STATE_PRESENT)
	if err == nil {
		t.Fatal("appimage with an http url must be rejected")
	}
	if changed {
		t.Error("changed must be false")
	}
}
