package crl

import (
	"context"
	"errors"
	"testing"
	"time"

	sdk "github.com/manchtools/power-manage-sdk"
)

func fixedClock(t time.Time) func() time.Time { return func() time.Time { return t } }

// TestCheck_FailsClosedBeforeFirstLoad pins the AC 12 boot posture: with no CRL
// yet fetched the cache has nothing to trust, so every gateway is refused.
func TestCheck_FailsClosedBeforeFirstLoad(t *testing.T) {
	c := New(func(context.Context) (*sdk.GatewayCRL, error) { return nil, nil }, nil)
	if err := c.Check("anyfingerprint"); err == nil {
		t.Fatal("Check must fail closed before the first successful CRL load")
	}
}

// TestCheck_RevokedRejected_UnrevokedAllowed pins AC 11: a loaded, fresh list
// rejects exactly the revoked fingerprints and allows the rest.
func TestCheck_RevokedRejected_UnrevokedAllowed(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	snap := &sdk.GatewayCRL{
		RevokedFingerprints: []string{"deadbeef"},
		NotAfter:            now.Add(time.Hour),
		RefreshedAt:         now,
	}
	c := New(func(context.Context) (*sdk.GatewayCRL, error) { return snap, nil }, nil, WithClock(fixedClock(now)))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if err := c.Check("deadbeef"); err == nil {
		t.Error("revoked fingerprint must be rejected (AC 11)")
	}
	if err := c.Check("cafef00d"); err != nil {
		t.Errorf("unrevoked fingerprint must be allowed: %v", err)
	}
}

// TestCheck_FailsClosedWhenStale pins AC 12: a loaded list past its not_after is
// no longer trusted — refuse rather than trust a stale list, even for an
// unrevoked fingerprint.
func TestCheck_FailsClosedWhenStale(t *testing.T) {
	loadTime := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	snap := &sdk.GatewayCRL{
		NotAfter:    loadTime.Add(time.Hour),
		RefreshedAt: loadTime,
	}
	clk := loadTime
	c := New(func(context.Context) (*sdk.GatewayCRL, error) { return snap, nil }, nil, WithClock(func() time.Time { return clk }))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("Refresh: %v", err)
	}
	if err := c.Check("x"); err != nil {
		t.Fatalf("fresh CRL should allow an unrevoked fingerprint: %v", err)
	}
	clk = loadTime.Add(2 * time.Hour) // past not_after
	if err := c.Check("x"); err == nil {
		t.Error("a CRL past not_after must fail closed even for an unrevoked fingerprint")
	}
}

// TestRefresh_RetainsLastSnapshotOnError pins that a transient fetch failure does
// NOT immediately fail closed: the previous snapshot rides until its not_after
// (bounded staleness), so a brief control blip doesn't sever the whole fleet.
func TestRefresh_RetainsLastSnapshotOnError(t *testing.T) {
	now := time.Date(2026, 7, 14, 12, 0, 0, 0, time.UTC)
	good := &sdk.GatewayCRL{RevokedFingerprints: []string{"bad"}, NotAfter: now.Add(time.Hour), RefreshedAt: now}
	calls := 0
	fetch := func(context.Context) (*sdk.GatewayCRL, error) {
		calls++
		if calls == 1 {
			return good, nil
		}
		return nil, errors.New("control unreachable")
	}
	c := New(fetch, nil, WithClock(fixedClock(now)))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("first Refresh: %v", err)
	}
	if err := c.Refresh(context.Background()); err == nil {
		t.Fatal("second Refresh should surface the fetch error")
	}
	if err := c.Check("bad"); err == nil {
		t.Error("last-good revoked entry must still be enforced after a failed refresh")
	}
	if err := c.Check("ok"); err != nil {
		t.Errorf("last-good snapshot should still allow an unrevoked fingerprint: %v", err)
	}
}

// TestRefresh_CancelsLiveSessionWhenPeerRevoked pins AC 11: after a gateway
// handshake records the connected peer's fingerprint, a later refresh that newly
// revokes that fingerprint cancels the live session — handshake-only revocation
// would let the in-flight stream run to a revoked gateway until natural
// disconnect.
func TestRefresh_CancelsLiveSessionWhenPeerRevoked(t *testing.T) {
	now := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	snaps := []*sdk.GatewayCRL{
		{NotAfter: now.Add(time.Hour), RefreshedAt: now},                                          // fresh, nothing revoked
		{RevokedFingerprints: []string{"peerfp"}, NotAfter: now.Add(time.Hour), RefreshedAt: now}, // revokes the peer
	}
	call := 0
	fetch := func(context.Context) (*sdk.GatewayCRL, error) {
		s := snaps[call]
		if call < len(snaps)-1 {
			call++
		}
		return s, nil
	}
	c := New(fetch, nil, WithClock(fixedClock(now)))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("first refresh: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.WatchSession(cancel)
	// Simulate the gateway handshake: Check approves and records the peer.
	if err := c.Check("peerfp"); err != nil {
		t.Fatalf("handshake check should pass for an unrevoked peer: %v", err)
	}

	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("second refresh: %v", err)
	}
	select {
	case <-ctx.Done():
	default:
		t.Fatal("live session was not cancelled after its gateway was revoked (AC 11)")
	}
}

// TestEnforce_CancelsLiveSessionWhenCRLExpires pins the other AC 11 trigger: a
// cached CRL ageing past not_after while a session is still up fails closed for
// the in-flight session too, not only at the next handshake. Mirrors what Run
// does on the failed-refresh path.
func TestEnforce_CancelsLiveSessionWhenCRLExpires(t *testing.T) {
	load := time.Date(2026, 7, 18, 12, 0, 0, 0, time.UTC)
	clk := load
	snap := &sdk.GatewayCRL{NotAfter: load.Add(time.Hour), RefreshedAt: load}
	c := New(func(context.Context) (*sdk.GatewayCRL, error) { return snap, nil }, nil, WithClock(func() time.Time { return clk }))
	if err := c.Refresh(context.Background()); err != nil {
		t.Fatalf("refresh: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c.WatchSession(cancel)
	if err := c.Check("peerfp"); err != nil {
		t.Fatalf("handshake check: %v", err)
	}

	// Still fresh: enforcing must NOT cancel a healthy live session.
	c.enforceSessionRevocation()
	select {
	case <-ctx.Done():
		t.Fatal("session cancelled while the CRL was still fresh")
	default:
	}

	// Past not_after: a live session on a now-stale CRL fails closed.
	clk = load.Add(2 * time.Hour)
	c.enforceSessionRevocation()
	select {
	case <-ctx.Done():
	default:
		t.Fatal("live session was not cancelled when the cached CRL expired (AC 11/12)")
	}
}
