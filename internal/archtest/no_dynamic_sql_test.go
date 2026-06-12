package archtest

import (
	"go/ast"
	"go/token"
	"testing"
)

// sqlMethodNames are the database driver methods (database/sql and pgx)
// whose query/statement argument MUST be a string literal or named
// string constant. A non-literal argument means the SQL text was built
// at runtime — the raw/concatenated-SQL smell this guard forbids.
var sqlMethodNames = map[string]bool{
	"Exec": true, "ExecContext": true,
	"Query": true, "QueryContext": true,
	"QueryRow": true, "QueryRowContext": true,
	"Prepare": true, "PrepareContext": true,
}

// sqlHandleReceivers are the identifiers the agent binds its
// database/sql handles to: the store's `db *sql.DB` field (accessed as
// `s.db` or copied to a local `db`) and the `tx` locals from
// `s.db.Begin()`. The method-name set above is necessary but not
// sufficient in this module: `Query` collides with the osquery client
// (`oq.Query`, `registry.Query` — a *pb.OSQuery proto arg), the system
// command runner (`sysexec.Query(name, ...)` — a binary name), and
// `*url.URL.Query()`. None of those touch SQL. Gating on the receiver
// being a real sql handle keeps the guard pointed only at hand-written
// sqlite, which must stay parameterized. SkipObjectResolution parsing
// cannot resolve receiver *types*, so this matches by the conventional
// handle name; isSQLHandleReceiver is the single point that decides, and
// the matches-zero guard fails the build if it ever stops matching the
// real DB calls (e.g. the handle gets renamed without updating this set).
var sqlHandleReceivers = map[string]bool{
	"db": true,
	"tx": true,
}

// dynamicSQLAllowlist lists the only sites permitted to pass a
// non-literal SQL string to a database method, each with the reason it is
// safe. Keyed by "<module-rel path> :: <rendered call>" so it survives
// line moves. assertNoStale fails the build if any entry stops matching.
//
// The agent's SQL is entirely hand-written, literal, parameterized
// sqlite — there are no exceptions, so this allowlist is empty.
var dynamicSQLAllowlist = map[string]string{}

// TestNoDynamicSQL pins the parameterized-SQL discipline: every call to a
// database query/exec method must receive a string-literal or
// named-string-const SQL argument. This makes "build a query string with
// fmt.Sprintf / string concatenation" fail the build — the canonical
// SQL-injection footgun — and locks the good state for the agent's
// hand-written sqlite queries (all literal/parameterized today).
func TestNoDynamicSQL(t *testing.T) {
	root := moduleRoot(t)

	// A query whose SQL arg is a named string const (e.g. a query const)
	// is still a literal query.
	consts := stringConstNames(t, root)

	// Scan all production Go. The agent has no generated SQL package.
	files := walkGoFiles(t, root, func(rel string) bool { return true })
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero production Go files — detector is mis-scoped")
	}

	allow := newAllowlist(dynamicSQLAllowlist)
	candidates := 0
	for _, gf := range files {
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || !sqlMethodNames[sel.Sel.Name] {
				return true
			}
			if !isSQLHandleReceiver(sel.X) {
				return true
			}
			sqlArg, ok := sqlArgOf(call)
			if !ok {
				return true
			}
			candidates++
			if isLiteralSQL(sqlArg, consts) {
				return true
			}
			key := gf.rel + " :: " + render(gf.fset, call)
			if allow.exempt(key) {
				return true
			}
			t.Errorf("dynamic SQL at %s:%d — %s\n  passes a non-literal SQL string. Use a parameterized literal; never build SQL with fmt.Sprintf/concatenation. If genuinely unavoidable, add a justified, guarded entry to dynamicSQLAllowlist.",
				gf.rel, gf.line(call), render(gf.fset, call))
			return true
		})
	}
	if candidates == 0 {
		t.Fatal("matches-zero guard: found no database query/exec call sites at all — the SQL-method set is mis-scoped, the guard would pass vacuously")
	}
	allow.assertNoStale(t)
}

// isSQLHandleReceiver reports whether the receiver expression of a
// method call is one of the database/sql handles (sqlHandleReceivers).
// It matches both a bare local (`tx.Exec(...)`, `db.Exec(...)`) and a
// field access (`s.db.Exec(...)`), taking the most specific name via
// identName so `s.db` resolves to "db".
func isSQLHandleReceiver(recv ast.Expr) bool {
	return sqlHandleReceivers[identName(recv)]
}

// sqlArgOf returns the SQL-text argument of a database method call,
// accounting for the pgx shape (ctx, sql, args...) vs the database/sql
// shape (sql, args...).
func sqlArgOf(call *ast.CallExpr) (ast.Expr, bool) {
	if len(call.Args) == 0 {
		return nil, false
	}
	idx := 0
	if isContextArg(call.Args[0]) {
		idx = 1
	}
	if idx >= len(call.Args) {
		return nil, false
	}
	return call.Args[idx], true
}

// isLiteralSQL reports whether the SQL argument is a string literal or a
// named string constant (both safe), as opposed to a runtime-built value.
func isLiteralSQL(e ast.Expr, consts map[string]bool) bool {
	switch x := e.(type) {
	case *ast.BasicLit:
		return x.Kind == token.STRING
	case *ast.Ident:
		return consts[x.Name]
	case *ast.SelectorExpr:
		return consts[x.Sel.Name]
	case *ast.ParenExpr:
		return isLiteralSQL(x.X, consts)
	}
	return false
}
