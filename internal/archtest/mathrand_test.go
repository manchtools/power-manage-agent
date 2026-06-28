package archtest

import (
	"testing"
)

// TestNoMathRandForCrypto enforces the NIS2 / CLAUDE rule: never use math/rand
// (or math/rand/v2) for security-sensitive values — nonces, keys, challenges,
// IDs. math/rand is a deterministic PRNG seeded from a predictable source; an
// attacker who recovers its state can predict every subsequent value. IDs use
// ulidx (crypto-seeded) and secret material uses crypto/rand.
//
// The rule is about INTENT, but the honest enforceable proxy is the import:
// math/rand legitimately appears only for non-cryptographic jitter/backoff/
// load-balancing. Forbid the import everywhere and allowlist those few
// non-crypto uses by file, with a justification. A NEW math/rand import — the
// most likely vector for "I'll just roll an ID with rand" — fails the build.
//
// The single allowlist entry doubles as the liveness probe: assertNoStale
// fails if the detector ever stops finding math/rand at all (a broken scan or
// the jitter use being removed), so the guard cannot pass vacuously.
func TestNoMathRandForCrypto(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(string) bool { return true })
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero production Go files — detector is mis-scoped")
	}

	allow := newAllowlist(map[string]string{
		"cmd/power-manage-agent/backend.go :: math/rand/v2": "connection backoff jitter (rand.Int64N) — non-cryptographic; IDs use ulidx and secret material uses crypto/rand",
	})

	for _, gf := range files {
		for _, imp := range gf.ast.Imports {
			p := unquoteLit(imp.Path)
			if p != "math/rand" && p != "math/rand/v2" {
				continue
			}
			if allow.exempt(gf.rel + " :: " + p) {
				continue
			}
			t.Errorf("%s imports %s at %s:%d — math/rand is not cryptographically secure; use crypto/rand for nonces/keys/challenges and ulidx for IDs. If this is a non-crypto use (jitter/backoff/load-balancing), allowlist the file with a justification.",
				gf.rel, p, gf.rel, gf.line(imp))
		}
	}
	allow.assertNoStale(t)
}
