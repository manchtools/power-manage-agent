package archtest

import (
	"go/ast"
	"go/token"
	"strings"
	"testing"
)

// TestNoUnabstractedTimeNow enforces that production runtime code never
// CALLS time.Now() directly. Time-dependent logic (token/cert/session
// expiry, rate-limit windows, timestamps, even latency measurement) must
// read the current time through an injected `now func() time.Time` seam
// (defaulting to the bare time.Now value), so every time-dependent path
// is deterministically testable with a fixed clock. This extends the
// existing seam already used by internal/crl, internal/terminal,
// internal/compliance and internal/gateway/registry to the whole module.
//
// The bare `time.Now` *value* (the injection default, e.g. `now: time.Now`)
// is not a call and is therefore allowed — it is the single sanctioned
// reference to the wall clock.
//
// One structural exception: time.Now() passed as the timestamp argument to
// ulid.Timestamp(...) is ID generation, where the wall clock seeds the
// ULID's time component rather than driving a decision; injecting a clock
// there buys no testability and threads a parameter through every ID
// helper. This is a category rule, not a per-site blessing — any ULID
// generator is covered, and nothing else is.
//
// Scope: production runtime only. _test.go, the generated sqlc package,
// the archtest package itself, and internal/testutil (test scaffolding,
// imported only by tests) are out of scope.
func TestNoUnabstractedTimeNow(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(rel string) bool {
		if strings.HasPrefix(rel, "internal/store/generated/") {
			return false
		}
		if strings.HasPrefix(rel, "internal/testutil/") {
			return false
		}
		return true
	})
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero production Go files — detector is mis-scoped")
	}

	// sawTimeNowRef counts every reference to the `time.Now` selector,
	// whether a call (`time.Now()`) or the bare injection-default value
	// (`now: time.Now`). It is the detector's liveness signal: the agent
	// has already been fully migrated to the clock seam, so in steady
	// state there are ZERO direct `time.Now()` CALLS — the matches-zero
	// guard therefore cannot key off call count (that would fail-closed
	// on a clean module and pressure someone to keep a violation alive
	// just to satisfy the detector). It keys off the `time.Now` selector
	// instead, which every seam default still carries, so the guard stays
	// non-vacuous (it fails if zero files are scanned or the `time.Now`
	// recognition machinery dies) without demanding a violation exist.
	// The server's copy keys off call count because its ULID path keeps
	// at least one allowed `time.Now()` call present; the agent has no
	// ULID generator, hence this divergence.
	sawTimeNowRef := 0
	for _, gf := range files {
		exempt := map[token.Pos]bool{}
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			if isTimeNowSelector(n) {
				sawTimeNowRef++
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			// Mark a time.Now() that seeds ulid.Timestamp(...) as exempt.
			// Inspect is top-down, so the ulid.Timestamp parent is seen
			// before its time.Now child and the exemption is in place by
			// the time the child is visited.
			if isULIDTimestampCall(call) {
				if inner, ok := call.Args[0].(*ast.CallExpr); ok && isTimeNowCall(inner) {
					exempt[inner.Pos()] = true
				}
			}
			if isTimeNowCall(call) {
				if exempt[call.Pos()] {
					return true
				}
				t.Errorf("unabstracted time.Now() at %s:%d — read the clock through an injected `now func() time.Time` seam (default `time.Now`) and call it, e.g. s.now(); never call time.Now() directly in runtime code.",
					gf.rel, gf.line(call))
			}
			return true
		})
	}
	if sawTimeNowRef == 0 {
		t.Fatal("matches-zero guard: found no reference to the time.Now selector anywhere (not even a seam default) — the detector is dead, the guard would pass vacuously")
	}
}

// isTimeNowSelector reports whether n is the selector expression
// `time.Now` itself — matching both the call `time.Now()` (whose Fun is
// this selector) and the bare value `time.Now` used as an injection
// default. It is the liveness probe for the matches-zero guard.
func isTimeNowSelector(n ast.Node) bool {
	sel, ok := n.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Now" {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "time"
}

// isTimeNowCall reports whether call is exactly time.Now().
func isTimeNowCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Now" || len(call.Args) != 0 {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "time"
}

// isULIDTimestampCall reports whether call is ulid.Timestamp(<one arg>).
func isULIDTimestampCall(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "Timestamp" || len(call.Args) != 1 {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == "ulid"
}
