// Package executor: artifact download adapter over the SDK remote source.
package executor

import (
	"context"
	"net/http"
	"strings"

	"github.com/manchtools/power-manage-sdk/sys/remote"
)

// remoteHTTPClient is the HTTP client the artifact fetcher uses. It is nil in
// production — remote.NewHTTP then uses its own default client — and is
// overridden by tests to point Fetch at an httptest TLS server
// (remote.HTTPConfig.Client is the SDK's injectable transport seam). Never set
// it in production code.
var remoteHTTPClient *http.Client

// fetchArtifact downloads url to dest through the SDK's remote.HTTP source, which
// validates the scheme, enforces the size cap, optionally verifies the sha256,
// fsyncs, and atomically renames onto dest (applying mode when set). It replaces
// the agent's former hand-rolled downloadFile/downloadToFile, which reimplemented
// exactly this. checksum "" skips verification; mode "" leaves the temp's default
// mode. Callers that need https-only must still gate the URL up front
// (requireVerifiedArtifact) — remote accepts http too.
func fetchArtifact(ctx context.Context, url, dest, checksum, mode string) error {
	// Trim the URL before use: the agent's URL validators (sdk.ValidateHTTPSURL
	// via requireVerifiedArtifact) trim internally before checking scheme/host,
	// but remote.NewHTTP's parser does NOT trim, so a whitespace-padded URL would
	// pass validation and then fail the fetch as "not absolute". Trimming here
	// keeps the fetched URL identical to the form validation blessed, for every
	// fetchArtifact call site (appimage/deb/rpm/agent_update).
	src, err := remote.NewHTTP(remote.HTTPConfig{
		URL:            strings.TrimSpace(url),
		ChecksumSHA256: checksum,
		Mode:           mode,
		Client:         remoteHTTPClient,
	})
	if err != nil {
		return err
	}
	_, err = src.Fetch(ctx, dest)
	return err
}
