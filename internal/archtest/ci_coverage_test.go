package archtest

import (
	"bufio"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCIRunsEveryIntegrationTest guards the hand-wired integration lanes in
// .github/workflows/integration-test.yml against failing open (audit A-06,
// issue #171 — the agent port of server#482's self-discovering guard).
//
// The agent's split differs from the server's: the unit workflow runs a
// plain `go test ./...`, so PACKAGE-level coverage is complete by
// construction. The dormant-test trap here is TAG- and NAME-level:
//
//   - a `//go:build integration` file in a package the workflow never
//     passes to `go test -tags=integration` silently never compiles in CI;
//   - an integration-tagged Test function whose name matches none of the
//     workflow's `-run` selectors (the distro matrix runs `-run
//     Integration`; the privileged lane's last `-run` wins, selecting
//     `EdgeCase`) silently never executes anywhere.
//
// This guard discovers every integration-tagged test file, then asserts
// (a) its package appears as a ./agent/<pkg>/ argument in the workflow and
// (b) every Test function in it matches at least one -run selector.
// TestMain is exempt: it is the per-package harness, not a selected test.
func TestCIRunsEveryIntegrationTest(t *testing.T) {
	root := moduleRoot(t)

	files := discoverIntegrationTaggedFiles(t, root)
	if len(files) == 0 {
		t.Fatal("matches-zero guard: discovered no //go:build integration test files; the walk is broken (internal/executor has them today)")
	}

	workflow := filepath.Join(root, ".github", "workflows", "integration-test.yml")
	raw, err := os.ReadFile(workflow)
	if err != nil {
		t.Fatalf("read %s: %v", workflow, err)
	}
	pkgs := extractWorkflowPackages(string(raw))
	if len(pkgs) == 0 {
		t.Fatal("matches-zero guard: extracted no ./agent/<pkg>/ package arguments from integration-test.yml; the parser is broken")
	}
	selectors := extractRunSelectors(string(raw))
	if len(selectors) == 0 {
		t.Fatal("matches-zero guard: extracted no -run selectors from integration-test.yml; the parser is broken")
	}

	// Stale-list direction: a workflow package argument whose directory no
	// longer exists is the same rot in reverse.
	for _, p := range pkgs {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(p))); err != nil {
			t.Errorf("integration-test.yml references ./agent/%s/ but that directory does not exist (stale lane entry)", p)
		}
	}

	for file, fns := range files {
		pkg := filepath.ToSlash(filepath.Dir(file))
		if !workflowCovers(pkg, pkgs) {
			t.Errorf("%s carries //go:build integration but package %s is passed to no `go test -tags=integration` invocation in integration-test.yml — it never even compiles in CI", file, pkg)
			continue
		}
		for _, fn := range fns {
			if fn == "TestMain" {
				continue
			}
			if !matchesAnySelector(fn, selectors) {
				t.Errorf("%s: %s matches none of the workflow's -run selectors %v — it never executes in any CI lane; rename it (TestIntegration_* / TestEdgeCase_*) or add a lane", file, fn, selectors)
			}
		}
	}
}

// discoverIntegrationTaggedFiles maps module-relative _test.go files that
// carry the `integration` build tag to their declared Test function names.
// vendor/, testdata/, and hidden directories are skipped.
func discoverIntegrationTaggedFiles(t *testing.T, root string) map[string][]string {
	t.Helper()
	testFn := regexp.MustCompile(`^func (Test[A-Za-z0-9_]*)\(`)
	out := map[string][]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			name := d.Name()
			if name == "vendor" || name == "testdata" || (strings.HasPrefix(name, ".") && path != root) {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), "_test.go") {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()
		tagged := false
		var fns []string
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1024*1024), 1024*1024)
		for sc.Scan() {
			line := sc.Text()
			if strings.HasPrefix(line, "//go:build") && buildTagHasIntegration(line) {
				tagged = true
			}
			if m := testFn.FindStringSubmatch(line); m != nil {
				fns = append(fns, m[1])
			}
		}
		if err := sc.Err(); err != nil {
			return err
		}
		if tagged {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			out[filepath.ToSlash(rel)] = fns
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// buildTagHasIntegration reports whether a //go:build line references the
// integration tag as a positive term (not `!integration`).
func buildTagHasIntegration(line string) bool {
	expr := strings.TrimSpace(strings.TrimPrefix(line, "//go:build"))
	for _, tok := range strings.FieldsFunc(expr, func(r rune) bool {
		return r == '&' || r == '|' || r == '(' || r == ')' || r == ' '
	}) {
		if tok == "integration" {
			return true
		}
	}
	return false
}

// workflowPkgPattern matches the `./agent/internal/executor/` style package
// arguments the workflow passes to `go test` (the repo is checked out into
// the `agent/` sub-directory).
var workflowPkgPattern = regexp.MustCompile(`\./agent/([A-Za-z0-9_/-]+?)/?(\s|\\|$|\.\.\.)`)

func extractWorkflowPackages(workflow string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range workflowPkgPattern.FindAllStringSubmatch(workflow, -1) {
		p := strings.TrimSuffix(m[1], "/")
		if !seen[p] {
			seen[p] = true
			out = append(out, p)
		}
	}
	return out
}

// runSelectorPattern matches `-run <regex>` occurrences. Multiple -run flags
// on one go test command mean the LAST wins, so treating every occurrence as
// an active selector is the permissive union across lanes — still strict
// enough to catch the real failure mode (a test matching NO selector).
var runSelectorPattern = regexp.MustCompile(`-run[= ]([^\s\\]+)`)

func extractRunSelectors(workflow string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range runSelectorPattern.FindAllStringSubmatch(workflow, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	return out
}

func workflowCovers(pkg string, pkgs []string) bool {
	for _, p := range pkgs {
		if pkg == p || strings.HasPrefix(pkg, p+"/") {
			return true
		}
	}
	return false
}

func matchesAnySelector(fn string, selectors []string) bool {
	for _, s := range selectors {
		re, err := regexp.Compile(s)
		if err != nil {
			continue // an uncompilable selector can't select anything
		}
		if re.MatchString(fn) {
			return true
		}
	}
	return false
}
