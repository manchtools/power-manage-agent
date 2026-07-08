// Package executor: artifact download adapter over the SDK remote source.
package executor

import (
	"context"
	"net/http"

	"github.com/manchtools/power-manage-sdk/sys/remote"
)

// remoteHTTPClient is the HTTP client the artifact fetcher uses. It is nil in
// production — remote.NewHTTP then uses its own default client — and is
// overridden by tests to point Fetch at an httptest TLS server
// (remote.HTTPConfig.Client is the SDK's injectable transport seam). Never set
// it in production code.
var remoteHTTPClient *http.Client

// fetchArtifact downloads url to dest through the SDK's remote.HTTP source, which
// validates the scheme, normalizes (trims) the URL, enforces the size cap,
// optionally verifies the sha256, fsyncs, and atomically renames onto dest
// (applying mode when set). It replaces the agent's former hand-rolled
// downloadFile/downloadToFile, which reimplemented exactly this. checksum ""
// skips verification; mode "" leaves the temp's default mode. Callers that need
// https-only must still gate the URL up front (requireVerifiedArtifact) — remote
// accepts http too.
//
// redirect selects the SDK redirect policy for this download (see
// redirectForArtifact for the pin-aware default, or updateRedirectPolicy for the
// operator-driven self-update choice). A cross-origin policy lets operator-chosen
// URLs that are CDN-redirected resolve (e.g. GitHub releases bounce github.com ->
// release-assets.githubusercontent.com); the sha256 pin keeps the bytes honest
// across the hop, and an https->http downgrade stays refused by the SDK.
// Package-var seam so tests can pin WHETHER a fetch happens (the deb
// ABSENT path must never fetch without a verifiable checksum) without
// standing up an HTTP origin.
var fetchArtifact = func(ctx context.Context, url, dest, checksum, mode string, redirect remote.RedirectPolicy) error {
	// No pre-trim: remote.NewHTTP trims the URL internally, matching
	// sdk.ValidateHTTPSURL (used by requireVerifiedArtifact), so a whitespace-padded
	// URL that passes validation still fetches rather than failing as "not absolute".
	src, err := remote.NewHTTP(remote.HTTPConfig{
		URL:            url,
		ChecksumSHA256: checksum,
		Mode:           mode,
		Redirect:       redirect,
		Client:         remoteHTTPClient,
	})
	if err != nil {
		return err
	}
	_, err = src.Fetch(ctx, dest)
	return err
}

// redirectForArtifact picks the redirect policy for an artifact download from
// whether it is sha256-pinned. A pinned download may follow a cross-origin
// redirect safely — the pin catches any substituted bytes — so CDN-backed URLs
// (e.g. GitHub releases bouncing to release-assets.githubusercontent.com) work.
// An unpinned download stays same-origin: with no pin, a host-changing redirect
// could swap the bytes undetected.
func redirectForArtifact(checksum string) remote.RedirectPolicy {
	if checksum != "" {
		return remote.RedirectCrossOrigin
	}
	return remote.RedirectSameOrigin
}
