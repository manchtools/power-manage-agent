package archtest

import (
	"go/ast"
	"go/token"
	"testing"
)

// secretCompareAllowlist lists comparisons that match the secret-name
// heuristic but are NOT timing-sensitive secret-value compares (typically
// enum/metadata fields the suffix filter didn't catch). Each entry is
// justified; assertNoStale fails the build if one stops matching.
// Keyed by "<module-rel path> :: <rendered expression>".
var secretCompareAllowlist = map[string]string{
	`internal/executor/lps.go :: params.Complexity == pb.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_UNSPECIFIED`: "Enum-mode compare, not secret bytes. The secret-name regex matches because the LPS (Local Password Solution) complexity enum's constant name contains \"PASSWORD\"; params.Complexity is a policy-complexity mode (UNSPECIFIED/COMPLEX/ALPHANUMERIC), carrying no secret material and no timing oracle. The generated password itself is never compared with ==/!=.",
	`internal/executor/lps.go :: params.Complexity == pb.LpsPasswordComplexity_LPS_PASSWORD_COMPLEXITY_COMPLEX`:     "Enum-mode compare, not secret bytes. Same as above: selects whether the rotated password includes special characters. params.Complexity is a configuration enum, not timing-sensitive secret material.",
}

// TestSecretComparesAreConstantTime forbids comparing secret material
// (tokens, MACs, signatures, fingerprints, password/digest bytes) with
// == / != / bytes.Equal — all of which short-circuit and leak length and
// content through timing. The correct primitives are
// subtle.ConstantTimeCompare and hmac.Equal. Presence checks (`tok == ""`,
// `sig == nil`) and metadata fields (TokenType, KeyID, SessionVersion)
// are excluded; everything else that names secret material and is
// compared with a non-constant-time operator is a finding.
func TestSecretComparesAreConstantTime(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(string) bool { return true })
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero production Go files — detector is mis-scoped")
	}

	allow := newAllowlist(secretCompareAllowlist)
	sawComparison := false
	sawSecretName := false

	for _, gf := range files {
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.BinaryExpr:
				if x.Op == token.EQL || x.Op == token.NEQ {
					sawComparison = true
					checkSecretCompare(t, gf, x, x.X, x.Y, allow, &sawSecretName)
				}
			case *ast.CallExpr:
				// bytes.Equal(a, b) is non-constant-time for secrets.
				if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
					if id, ok := sel.X.(*ast.Ident); ok && id.Name == "bytes" && sel.Sel.Name == "Equal" && len(x.Args) == 2 {
						sawComparison = true
						checkSecretCompare(t, gf, x, x.Args[0], x.Args[1], allow, &sawSecretName)
					}
				}
			}
			return true
		})
	}

	if !sawComparison {
		t.Fatal("matches-zero guard: found no equality comparisons in the module — the AST walk is not reaching real code")
	}
	if !sawSecretName {
		t.Fatal("matches-zero guard: the secret-name detector matched no identifier anywhere in the module — the regex/scoping is dead, the guard would pass vacuously")
	}
	allow.assertNoStale(t)
}

// checkSecretCompare flags node if either operand names secret material
// and neither operand is a presence comparand (nil/empty/zero).
func checkSecretCompare(t *testing.T, gf *goFile, node ast.Node, lhs, rhs ast.Expr, allow *allowlist, sawSecretName *bool) {
	t.Helper()
	lSecret := looksLikeSecretOperand(lhs)
	rSecret := looksLikeSecretOperand(rhs)
	if lSecret || rSecret {
		*sawSecretName = true
	}
	if !lSecret && !rSecret {
		return
	}
	if isPresenceComparand(lhs) || isPresenceComparand(rhs) {
		return // presence/absence check, not a secret-value compare
	}
	key := gf.rel + " :: " + render(gf.fset, node)
	if allow.exempt(key) {
		return
	}
	t.Errorf("non-constant-time secret compare at %s:%d — %s\n  compares secret material with ==/!=/bytes.Equal, which leaks length and content via timing. Use subtle.ConstantTimeCompare or hmac.Equal. If this is metadata (not secret bytes), add a justified, guarded entry to secretCompareAllowlist.",
		gf.rel, gf.line(node), render(gf.fset, node))
}
