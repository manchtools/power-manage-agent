package archtest

import (
	"go/ast"
	"go/token"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// identName returns the most specific name an expression is known by:
// the identifier for a bare ident, or the trailing selector field
// (foo.Bar -> "Bar"). Anything else yields "".
func identName(e ast.Expr) string {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name
	case *ast.SelectorExpr:
		return x.Sel.Name
	case *ast.StarExpr:
		return identName(x.X)
	case *ast.ParenExpr:
		return identName(x.X)
	}
	return ""
}

// isContextArg reports whether an argument is (very likely) a
// context.Context, so SQL-method scanning can locate the SQL string at
// the correct argument index for both the database/sql shape
// (sql first) and the pgx shape (ctx first).
func isContextArg(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name == "ctx"
	case *ast.SelectorExpr:
		return x.Sel.Name == "ctx" || x.Sel.Name == "Ctx" || x.Sel.Name == "Context"
	case *ast.CallExpr:
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok {
			if sel.Sel.Name == "Context" || sel.Sel.Name == "Background" || sel.Sel.Name == "TODO" {
				return true
			}
			if id, ok := sel.X.(*ast.Ident); ok && id.Name == "context" {
				return true
			}
		}
	}
	return false
}

// isPresenceComparand reports whether an operand is a nil / empty-string
// / zero literal — i.e. the comparison is a presence/absence check, not a
// secret-value comparison. Constant-time compares only matter when both
// sides carry real secret material.
func isPresenceComparand(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return x.Name == "nil"
	case *ast.BasicLit:
		switch x.Kind {
		case token.STRING:
			// `""` (or `` `` ``) — empty string literal.
			if s, err := strconv.Unquote(x.Value); err == nil {
				return s == ""
			}
		case token.INT, token.FLOAT:
			return x.Value == "0" || x.Value == "0.0"
		}
	case *ast.CallExpr:
		// []byte(nil), []byte("") — presence checks on byte slices.
		if len(x.Args) == 1 {
			return isPresenceComparand(x.Args[0])
		}
	}
	return false
}

// stringConstNames returns the set of every package-level identifier in
// the module bound to a string-literal constant. A query whose SQL
// argument is one of these names is a literal query (e.g. an
// sqlc-generated query const), not dynamically-built SQL.
func stringConstNames(t *testing.T, root string) map[string]bool {
	t.Helper()
	out := make(map[string]bool)
	files := walkGoFiles(t, root, func(string) bool { return true })
	for _, gf := range files {
		for _, decl := range gf.ast.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, name := range vs.Names {
					if i < len(vs.Values) && isStringLiteralExpr(vs.Values[i]) {
						out[name.Name] = true
					}
				}
			}
		}
	}
	return out
}

// isStringLiteralExpr reports whether e is a string literal or a
// concatenation of string literals (`"a" + "b"`).
func isStringLiteralExpr(e ast.Expr) bool {
	switch x := e.(type) {
	case *ast.BasicLit:
		return x.Kind == token.STRING
	case *ast.BinaryExpr:
		return x.Op == token.ADD && isStringLiteralExpr(x.X) && isStringLiteralExpr(x.Y)
	case *ast.ParenExpr:
		return isStringLiteralExpr(x.X)
	}
	return false
}

// unquoteLit returns the string value of a STRING BasicLit, or "".
func unquoteLit(lit *ast.BasicLit) string {
	if lit == nil || lit.Kind != token.STRING {
		return ""
	}
	if s, err := strconv.Unquote(lit.Value); err == nil {
		return s
	}
	return ""
}

// secretNameRe matches identifiers that hold secret material. Bare "sig"
// and "mac" from the original sweep regex are intentionally dropped:
// "sig" collides with "assign", and "mac" is too short to be specific;
// the full "signature" / "hmac" forms are kept instead. A match is only a
// violation when it is NOT metadata about the secret (see
// secretMetaSuffixes) and NOT a presence check.
var secretNameRe = regexp.MustCompile(`(?i)(token|secret|hmac|signature|fingerprint|password|passwd|digest|apikey)`)

// secretMetaSuffixes name fields that describe a secret rather than carry
// its bytes (TokenType, SessionVersion, KeyID, ...). Comparing these with
// == is fine — they are not timing-sensitive secret material.
var secretMetaSuffixes = []string{
	"type", "kind", "id", "name", "len", "length", "count", "version",
	"expiry", "expiresat", "at", "format", "algorithm", "algo", "method",
	"status", "enabled", "disabled", "index", "idx", "field", "size",
}

// looksLikeSecretOperand reports whether an operand names secret material
// that must be compared in constant time (matches the secret regex and is
// not a metadata field).
func looksLikeSecretOperand(e ast.Expr) bool {
	name := identName(e)
	if name == "" || !secretNameRe.MatchString(name) {
		return false
	}
	lower := strings.ToLower(name)
	for _, suf := range secretMetaSuffixes {
		if strings.HasSuffix(lower, suf) {
			return false
		}
	}
	return true
}
