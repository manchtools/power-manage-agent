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
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(p.dir))); err != nil {
			t.Errorf("integration-test.yml references ./agent/%s/ but that directory does not exist (stale lane entry)", p.dir)
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

// sdkModulePath is the SDK module whose version pin integration CI must
// build against. A replace directive naming it silently defeats that pin.
const sdkModulePath = "github.com/manchtools/power-manage-sdk"

func TestIntegrationCIUsesPinnedSDK(t *testing.T) {
	root := moduleRoot(t)
	goMod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^\s*` + regexp.QuoteMeta(sdkModulePath) + `\s+v0\.5\.4\s*$`).Match(goMod) {
		t.Error("go.mod must require " + sdkModulePath + " at exactly v0.5.4")
	}
	// go.mod's replace directives are PARSED rather than substring-scanned by
	// the marker loop below: Go's parenthesised block form puts the `replace`
	// keyword and the module path on different lines, so a same-line marker
	// never sees it while the override is fully in effect (issue #204).
	if overrides := sdkReplaceDirectives(string(goMod)); len(overrides) > 0 {
		t.Errorf("go.mod replaces %s with %q; integration CI must build against the reviewed pin", sdkModulePath, overrides)
	}

	files := []string{
		filepath.Join(root, "go.mod"),
		filepath.Join(root, ".github", "workflows", "integration-test.yml"),
	}
	dockerfiles, err := filepath.Glob(filepath.Join(root, "test", "Dockerfile.integration*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(dockerfiles) == 0 {
		t.Fatal("matches-zero guard: discovered no test/Dockerfile.integration* files")
	}
	files = append(files, dockerfiles...)

	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		for _, override := range []string{"SDK_MODE", "Resolve SDK branch override", "power-manage-sdk.git", "replace github.com/manchtools/power-manage-sdk"} {
			if strings.Contains(string(raw), override) {
				t.Errorf("integration CI must use the reviewed SDK pin, found override path %q in %s", override, file)
			}
		}
	}
}

// sdkReplaceDirectives returns the replacement target of every `replace`
// directive in goMod whose left-hand module path is exactly sdkModulePath.
//
// It parses the directive structure rather than scanning for the substring
// "replace <path>", because the go command accepts BOTH
//
//	replace github.com/manchtools/power-manage-sdk v0.5.4 => ../sdk
//
// and the parenthesised block form
//
//	replace (
//	    github.com/manchtools/power-manage-sdk v0.5.4 => ../sdk
//	)
//
// which override the pin identically while a same-line substring scan sees
// only the first (issue #204). Comments are stripped first, so a
// commented-out directive — which the build ignores — is not reported.
func sdkReplaceDirectives(goMod string) []string {
	var out []string
	inBlock := false
	for _, raw := range strings.Split(goMod, "\n") {
		line := strings.TrimSpace(stripGoModComment(raw))
		if line == "" {
			continue
		}
		if inBlock {
			if strings.HasPrefix(line, ")") {
				inBlock = false
				continue
			}
		} else {
			rest, ok := afterGoModKeyword(line, "replace")
			if !ok {
				continue
			}
			if strings.HasPrefix(rest, "(") {
				inBlock = true
				line = strings.TrimSpace(strings.TrimPrefix(rest, "("))
				if line == "" || strings.HasPrefix(line, ")") {
					continue
				}
			} else {
				line = rest
			}
		}
		if target, ok := sdkReplaceTarget(line); ok {
			out = append(out, target)
		}
	}
	return out
}

// stripGoModComment removes a `//` line comment. go.mod has no block
// comments, so a line comment is the only form to handle.
func stripGoModComment(line string) string {
	if i := strings.Index(line, "//"); i >= 0 {
		return line[:i]
	}
	return line
}

// afterGoModKeyword reports whether line opens with keyword as a whole token
// and returns the remainder. It rejects a merely-prefixed identifier such as
// `replacements`, and accepts `replace(` because go.mod's lexer treats the
// parenthesis as its own token.
func afterGoModKeyword(line, keyword string) (string, bool) {
	rest, ok := strings.CutPrefix(line, keyword)
	if !ok || rest == "" {
		return "", false
	}
	if c := rest[0]; c != ' ' && c != '\t' && c != '(' {
		return "", false
	}
	return strings.TrimSpace(rest), true
}

// sdkReplaceTarget parses one `<old> [version] => <new> [version]` entry and
// returns the replacement target when the old side names sdkModulePath. The
// old-side version is optional, and the path may be quoted.
func sdkReplaceTarget(entry string) (string, bool) {
	oldSide, newSide, ok := strings.Cut(entry, "=>")
	if !ok {
		return "", false
	}
	fields := strings.Fields(oldSide)
	if len(fields) == 0 {
		return "", false
	}
	if strings.Trim(fields[0], "\"`") != sdkModulePath {
		return "", false
	}
	return strings.TrimSpace(newSide), true
}

// TestSDKReplaceDirectivesSeesEveryReplaceForm pins the detector against the
// forms the go command actually accepts. The block-form rows are the
// regression: a same-line substring scan reports a clean go.mod while the pin
// is fully overridden (issue #204).
//
// The `replace (` / module-path / version split across three lines is
// deliberately absent — the go command rejects it as a parse error, so it is
// not a bypass this guard has to cover.
func TestSDKReplaceDirectivesSeesEveryReplaceForm(t *testing.T) {
	const header = "module github.com/manchtools/power-manage/agent\n\ngo 1.25.12\n\nrequire " + sdkModulePath + " v0.5.4\n\n"

	for _, tc := range []struct {
		name   string
		goMod  string
		want   []string
		reason string
	}{
		{
			name:   "clean go.mod with no replace at all",
			goMod:  header,
			want:   nil,
			reason: "the pinned baseline must not be reported as overridden",
		},
		{
			name:   "single-line replace with a version",
			goMod:  header + "replace " + sdkModulePath + " v0.5.4 => ../sdk\n",
			want:   []string{"../sdk"},
			reason: "the form the original marker scan already caught",
		},
		{
			name:   "single-line replace without a version",
			goMod:  header + "replace " + sdkModulePath + " => ../sdk\n",
			want:   []string{"../sdk"},
			reason: "the version on the left is optional",
		},
		{
			name:   "block-form replace with a version",
			goMod:  header + "replace (\n\t" + sdkModulePath + " v0.5.4 => ../sdk\n)\n",
			want:   []string{"../sdk"},
			reason: "issue #204: the keyword and the module path sit on different lines",
		},
		{
			name:   "block-form replace with the module path alone on its line",
			goMod:  header + "replace (\n\t" + sdkModulePath + " => ../sdk\n)\n",
			want:   []string{"../sdk"},
			reason: "issue #204: versionless block entry, still a full override",
		},
		{
			name:   "block-form replace hidden among unrelated entries",
			goMod:  header + "replace (\n\tgithub.com/other/thing v1.2.3 => ../thing\n\t" + sdkModulePath + " v0.5.4 => github.com/attacker/sdk v0.0.1\n\tgithub.com/third/thing => ../third\n)\n",
			want:   []string{"github.com/attacker/sdk v0.0.1"},
			reason: "the SDK entry must be found regardless of its position in the block",
		},
		{
			name:   "block-form replacing only other modules",
			goMod:  header + "replace (\n\tgithub.com/other/thing v1.2.3 => ../thing\n)\n",
			want:   nil,
			reason: "replacing an unrelated module is not an SDK pin override",
		},
		{
			name:   "module whose path merely starts with the SDK path",
			goMod:  header + "replace " + sdkModulePath + "-extras v1.0.0 => ../extras\n",
			want:   nil,
			reason: "the left-hand path must match exactly, not by prefix",
		},
		{
			name:   "commented-out replace directives",
			goMod:  header + "// replace " + sdkModulePath + " => ../sdk\nreplace (\n\t// " + sdkModulePath + " v0.5.4 => ../sdk\n)\n",
			want:   nil,
			reason: "a commented directive has no effect on the build",
		},
		{
			name:   "block-form replace closed and followed by a require block",
			goMod:  header + "replace (\n\t" + sdkModulePath + " => ../sdk\n)\n\nrequire (\n\tgithub.com/other/thing v1.2.3 // indirect\n)\n",
			want:   []string{"../sdk"},
			reason: "the scanner must leave the block at `)` and not swallow later directives",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := sdkReplaceDirectives(tc.goMod)
			if len(got) != len(tc.want) {
				t.Fatalf("sdkReplaceDirectives() = %q, want %q (%s)", got, tc.want, tc.reason)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("sdkReplaceDirectives()[%d] = %q, want %q (%s)", i, got[i], tc.want[i], tc.reason)
				}
			}
		})
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

// workflowPkg is one `./agent/<dir>/` package argument from the workflow.
// Recursive records whether it carried the `/...` suffix — a non-recursive
// argument tests ONLY that directory, so it must not count as covering
// subpackages (CR catch: prefix-matching a non-recursive entry would
// reintroduce the exact silent-gap this guard exists to close).
type workflowPkg struct {
	dir       string
	recursive bool
}

// workflowPkgPattern matches the `./agent/internal/executor/` and
// `./agent/internal/executor/...` style package arguments the workflow
// passes to `go test` (the repo is checked out into the `agent/`
// sub-directory).
var workflowPkgPattern = regexp.MustCompile(`\./agent/([A-Za-z0-9_/-]+?)/?(\.\.\.)?(\s|\\|$)`)

func extractWorkflowPackages(workflow string) []workflowPkg {
	seen := map[workflowPkg]bool{}
	var out []workflowPkg
	for _, m := range workflowPkgPattern.FindAllStringSubmatch(workflow, -1) {
		p := workflowPkg{dir: strings.TrimSuffix(m[1], "/"), recursive: m[2] == "..."}
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

func workflowCovers(pkg string, pkgs []workflowPkg) bool {
	for _, p := range pkgs {
		if pkg == p.dir {
			return true
		}
		if p.recursive && strings.HasPrefix(pkg, p.dir+"/") {
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
