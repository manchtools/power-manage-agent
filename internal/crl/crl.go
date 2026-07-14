// Package crl holds the agent's view of the gateway certificate revocation list
// (spec 31 Part D). It fetches the list from control, caches the last good
// snapshot, and answers the per-connection revocation check the SDK runs during
// every gateway TLS handshake.
//
// Fail-closed posture (AC 12): with no list yet loaded, or with a loaded list
// past its not_after, Check refuses ALL gateways rather than trusting nothing or
// trusting a stale list. A loaded, fresh list refuses only the revoked
// fingerprints (AC 11). A transient fetch failure keeps the last good snapshot
// so a brief control blip does not immediately sever the data plane — staleness
// is bounded by control's not_after.
package crl

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	sdk "github.com/manchtools/power-manage-sdk"
)

// FetchFunc retrieves a fresh CRL snapshot from control. Injected so the cache
// is testable without a live control server and so the agent owns the transport
// (system-roots mTLS to creds.ControlAddr, AC 13).
type FetchFunc func(ctx context.Context) (*sdk.GatewayCRL, error)

// Option configures a Cache.
type Option func(*Cache)

// WithClock overrides the time source (tests inject a fixed clock to exercise
// the not_after staleness boundary deterministically).
func WithClock(now func() time.Time) Option { return func(c *Cache) { c.now = now } }

// Cache holds the last successfully-fetched gateway CRL and answers Check.
type Cache struct {
	fetch  FetchFunc
	logger *slog.Logger
	now    func() time.Time

	mu       sync.RWMutex
	revoked  map[string]struct{}
	notAfter time.Time
	loaded   bool
}

// New builds a Cache. A nil logger is replaced with the default logger; a nil
// fetch is a programming error and makes Refresh fail loudly rather than
// silently never loading (which would fail every gateway closed forever).
func New(fetch FetchFunc, logger *slog.Logger, opts ...Option) *Cache {
	if logger == nil {
		logger = slog.Default()
	}
	c := &Cache{fetch: fetch, logger: logger, now: time.Now}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// Check is the gate handed to sdk.WithMTLSFromPEMAndRevocationCheck; it runs on
// every gateway TLS handshake with the gateway's hex SHA-256 leaf fingerprint.
// A non-nil return fails the handshake.
func (c *Cache) Check(fingerprint string) error {
	c.mu.RLock()
	defer c.mu.RUnlock()

	if !c.loaded {
		return errors.New("gateway CRL not yet loaded — refusing until the first list is fetched")
	}
	if !c.now().Before(c.notAfter) {
		return fmt.Errorf("gateway CRL expired at %s — refusing fail-closed until refreshed", c.notAfter.Format(time.RFC3339))
	}
	if _, ok := c.revoked[fingerprint]; ok {
		return fmt.Errorf("gateway certificate %s is revoked", fingerprint)
	}
	return nil
}

// Refresh fetches a new snapshot and atomically swaps it in. On fetch failure
// the previous snapshot is retained — still bounded by its not_after, after
// which Check fails closed — so a brief control blip does not immediately sever
// the data plane. The error is returned so callers can log it.
func (c *Cache) Refresh(ctx context.Context) error {
	if c.fetch == nil {
		return errors.New("gateway CRL: nil fetch func")
	}
	snap, err := c.fetch(ctx)
	if err != nil {
		return fmt.Errorf("refresh gateway CRL: %w", err)
	}
	if snap == nil {
		return errors.New("refresh gateway CRL: control returned a nil snapshot")
	}

	set := make(map[string]struct{}, len(snap.RevokedFingerprints))
	for _, fp := range snap.RevokedFingerprints {
		set[fp] = struct{}{}
	}

	c.mu.Lock()
	c.revoked = set
	c.notAfter = snap.NotAfter
	c.loaded = true
	c.mu.Unlock()
	return nil
}

// Run refreshes on a ticker until ctx is cancelled. interval should be well
// below control's not_after window so the list renews before it can expire; a
// persistent fetch failure eventually lets the snapshot age past not_after and
// Check fails closed (AC 12).
func (c *Cache) Run(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := c.Refresh(ctx); err != nil {
				c.logger.Warn("gateway CRL refresh failed; using last snapshot until not_after", "error", err)
			}
		}
	}
}
