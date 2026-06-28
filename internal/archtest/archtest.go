// Package archtest holds architectural fitness functions for the
// agent module: self-discovering, repo-wide invariant tests that fail
// the build when a known code smell is reintroduced or an established
// good pattern is broken.
//
// # Why these exist
//
// The 2026-06 security + architecture sweeps fixed a set of smells
// (raw/concatenated SQL, non-constant-time secret comparisons) and
// pinned a set of good patterns (parameterized queries,
// subtle.ConstantTimeCompare/hmac.Equal, an injected clock seam). A
// one-off fix does not stop the next contributor from reintroducing the
// smell. These tests turn each invariant into a permanent, build-failing
// guard.
//
// # Design constraints
//
//   - Standard library only (go/parser, go/ast, go/token, go/printer).
//     No golang.org/x/tools dependency, so the guards stay hermetic,
//     fast, and identical in shape across the sdk/agent/server archtest
//     packages. Syntactic invariants do not need full type resolution;
//     where a guard relies on a naming/structure heuristic it documents
//     the heuristic and ships a guarded allowlist for true exceptions.
//   - Self-discovering: every guard walks the module tree and asserts it
//     inspected a non-empty set, so it can never pass vacuously (the
//     classic stale-allowlist failure that fails open).
//   - Every allowlist is itself guarded: a no-stale-entry check fails the
//     build if an allowlisted exception no longer exists, so the
//     allowlist cannot rot into a silent escape hatch.
//
// # Coverage map (what lives where)
//
//   - TestNoDynamicSQL .................... no_dynamic_sql_test.go
//   - TestSecretComparesAreConstantTime ... secret_compare_test.go
//   - TestNoUnabstractedTimeNow ........... time_now_test.go
//   - TestNoStdlibJSONOfProtoMessage ...... proto_json_test.go
//   - TestNoContextBackgroundInRequestPaths ... context_background_test.go
package archtest

import (
	"go/ast"
	"go/parser"
	"go/printer"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// goFile is a parsed Go source file with its module-relative path.
type goFile struct {
	abs  string
	rel  string // slash-separated, relative to the module root
	fset *token.FileSet
	ast  *ast.File
}

// moduleRoot walks up from the test's working directory until it finds
// the directory containing go.mod. go test sets the working directory to
// the package under test, so this reliably locates the agent module
// root regardless of where the archtest package sits.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("could not locate go.mod above %s", dir)
		}
		dir = parent
	}
}

// walkGoFiles parses every .go file under root whose module-relative,
// slash-separated path satisfies keep. Test files, the archtest package
// itself, and anything under a vendor/ directory are never returned —
// keep only narrows further. Parsing is syntactic (no type checking) and
// skips object resolution for speed.
func walkGoFiles(t *testing.T, root string, keep func(rel string) bool) []*goFile {
	t.Helper()
	var out []*goFile
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == "testdata" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if strings.HasSuffix(rel, "_test.go") {
			return nil
		}
		if strings.HasPrefix(rel, "internal/archtest/") {
			return nil
		}
		if !keep(rel) {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if perr != nil {
			t.Fatalf("parse %s: %v", rel, perr)
		}
		out = append(out, &goFile{abs: path, rel: rel, fset: fset, ast: f})
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// render returns the gofmt-style source text of an AST node. Used to
// build stable, line-independent allowlist keys and human-readable
// failure messages.
func render(fset *token.FileSet, n ast.Node) string {
	var b strings.Builder
	if err := printer.Fprint(&b, fset, n); err != nil {
		return "<unprintable node>"
	}
	// Collapse internal newlines so multi-line call expressions render as
	// a single stable key.
	return strings.Join(strings.Fields(b.String()), " ")
}

// line returns the 1-based source line of a node within its file.
func (gf *goFile) line(n ast.Node) int {
	return gf.fset.Position(n.Pos()).Line
}

// allowlist couples a set of intentionally-exempt sites with their
// documented justifications and tracks which entries were actually hit,
// so a stale entry (an exemption whose site no longer exists) fails the
// build instead of silently widening the guard.
type allowlist struct {
	reason map[string]string // key -> why it is exempt
	used   map[string]bool
}

func newAllowlist(reasons map[string]string) *allowlist {
	return &allowlist{reason: reasons, used: make(map[string]bool)}
}

// exempt reports whether key is allowlisted, marking it used.
func (a *allowlist) exempt(key string) bool {
	if _, ok := a.reason[key]; ok {
		a.used[key] = true
		return true
	}
	return false
}

// assertNoStale fails the test for every allowlist entry that was never
// matched during the scan — a stale exemption is itself a finding,
// because it means the guard's surface drifted out from under it.
func (a *allowlist) assertNoStale(t *testing.T) {
	t.Helper()
	for key := range a.reason {
		if !a.used[key] {
			t.Errorf("stale allowlist entry never matched any site (remove it or fix the key): %q", key)
		}
	}
}
