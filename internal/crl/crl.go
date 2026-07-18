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

	// Live-session revocation (AC 11): the leaf fingerprint the currently
	// connected gateway authenticated with (recorded by CheckSession on a
	// successful handshake) and the canceler that tears that session down. A
	// later refresh that newly revokes watchedFP, or the cached list ageing past
	// notAfter while the session is still up, cancels the session so it
	// re-handshakes through the (now-failing) check — handshake-only revocation
	// would otherwise let an in-flight stream to a revoked gateway run until
	// natural disconnect. sessionID tokens the registration: a torn-down
	// client's transport can still complete an in-flight dial handshake after
	// the next session registered, and without the token that stale handshake
	// would overwrite the live session's fingerprint (missing its later
	// revocation) or its teardown would clear the live canceler.
	sessionID     uint64
	watchedFP     string
	cancelSession context.CancelFunc
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
	return c.checkLocked(fingerprint)
}

// checkLocked is the CRL policy; callers hold c.mu (read or write).
func (c *Cache) checkLocked(fingerprint string) error {
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

// CheckSession is the per-handshake gate for the session registered as id: the
// same policy as Check, plus — while id is still the active registration —
// recording the approved fingerprint as the watched session peer so a later
// refresh/expiry that condemns it can cancel the session (AC 11). A stale
// client's late handshake (its registration already replaced) still gets the
// policy verdict but must NOT overwrite the live session's fingerprint.
func (c *Cache) CheckSession(id uint64, fingerprint string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.checkLocked(fingerprint); err != nil {
		return err
	}
	if c.sessionID == id {
		c.watchedFP = fingerprint
	}
	return nil
}

// WatchSession registers the active gateway session's context canceler so a
// later CRL refresh that revokes the connected gateway — or the cached list
// expiring while the session is still up — can tear the session down (AC 11).
// runAgent calls this for each new connection; the peer fingerprint is filled
// in by CheckSession when that connection's handshake completes. The returned
// token binds CheckSession/UnwatchSession to THIS registration so a torn-down
// session's lingering handshake or teardown cannot touch a newer session's
// state. A new registration forgets the prior peer.
func (c *Cache) WatchSession(cancel context.CancelFunc) uint64 {
	c.mu.Lock()
	c.sessionID++
	id := c.sessionID
	c.cancelSession = cancel
	c.watchedFP = ""
	c.mu.Unlock()
	return id
}

// UnwatchSession unregisters the session registered as id; a no-op when a
// newer session has already replaced the registration.
func (c *Cache) UnwatchSession(id uint64) {
	c.mu.Lock()
	if c.sessionID == id {
		c.cancelSession = nil
		c.watchedFP = ""
	}
	c.mu.Unlock()
}

// enforceSessionRevocation cancels the live gateway session when its
// authenticated peer is now revoked, or the cached CRL has aged past not_after
// while the session is still up (AC 11 — fail closed for the in-flight session,
// not only at the next handshake). Called after every refresh attempt and on the
// staleness ticker; a no-op until a session is registered and its handshake has
// recorded a peer fingerprint. Cancels at most once per registration — the
// session tears down and re-registers on reconnect.
func (c *Cache) enforceSessionRevocation() {
	c.mu.Lock()
	cancel := c.cancelSession
	fp := c.watchedFP
	reason := ""
	if cancel != nil && fp != "" {
		_, revoked := c.revoked[fp]
		switch {
		case c.loaded && !c.now().Before(c.notAfter):
			reason = "cached gateway CRL expired while the session was live"
		case revoked:
			reason = "connected gateway certificate was revoked"
		}
	}
	if reason != "" {
		c.cancelSession = nil
		c.watchedFP = ""
	}
	c.mu.Unlock()

	if reason != "" {
		c.logger.Warn("cancelling live gateway session (spec 31 AC 11): "+reason, "fingerprint", fp)
		cancel()
	}
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

	// A refresh that newly revokes the connected gateway must cancel the live
	// session, not wait for its next handshake (AC 11).
	c.enforceSessionRevocation()
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
				// A failed refresh may have let the cached list age past not_after
				// while a session is live; enforce staleness here too (AC 11/12).
				// Refresh already enforced on its success path.
				c.enforceSessionRevocation()
			}
		}
	}
}
