package archtest

import (
	"go/ast"
	"go/token"
	"strings"
	"testing"
)

// TestNoRedundantPackageManagerLookPath enforces that the agent does NOT call
// exec.LookPath or osexec.LookPath for package-manager binaries (flatpak, dpkg,
// rpm) that the SDK's pkg.Detect() already enumerates. The SDK runs Detect at
// startup (executor.go:155), stores the result in e.pkgBackend, and the
// executor's per-format action files can check pkg.Detect(ctx) for sibling
// backends instead of hard-coding binary names and bypassing the SDK's PATH
// resolution.
//
// Allowed LookPath calls:
//   - backend.go privilegeTool (sudo/doas) — the agent's own privilege config
//   - backend.go systemctl/cryptsetup — startup validation of the operator's
//     configured backends; these binaries must be on PATH before the SDK
//     Manager can be built.
func TestNoRedundantPackageManagerLookPath(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(rel string) bool {
		return strings.HasPrefix(rel, "internal/executor/")
	})
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero executor Go files")
	}

	// Package manager binaries whose presence the SDK pkg.Detect already checks.
	sdkDetectedBinaries := map[string]string{
		"flatpak": "pkg.Detect(ctx) already checks for flatpak; check pkg.Flatpak membership or use the executor's pkgBackend",
		"dpkg":    "pkg.Detect(ctx) already checks for apt which requires dpkg; use the executor's pkgBackend or check pkg.Apt membership",
		"rpm":     "pkg.Detect(ctx) already checks for dnf/zypper which require rpm; use the executor's pkgBackend or check pkg.Dnf/pacman list membership",
	}

	findings := 0
	for _, gf := range files {
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			// Match exec.LookPath("...") or osexec.LookPath("...")
			fnName, literal, isLookPath := lookPathCall(call)
			if !isLookPath {
				return true
			}
			if reason, found := sdkDetectedBinaries[literal]; found {
				t.Errorf("%s:%d: %s(%q) — %s", gf.rel, gf.line(call), fnName, literal, reason)
				findings++
			}
			return true
		})
	}
	if findings > 0 {
		t.Logf("Found %d redundant exec.LookPath calls for package-manager binaries the SDK already detects", findings)
	}
}

// lookPathCall returns the fully-qualified name and the string literal argument
// when the call is exec.LookPath("...") or osexec.LookPath("...").
func lookPathCall(call *ast.CallExpr) (string, string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != "LookPath" {
		return "", "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok {
		return "", "", false
	}
	if id.Name != "exec" && id.Name != "osexec" {
		return "", "", false
	}
	if len(call.Args) != 1 {
		return "", "", false
	}
	lit, ok := call.Args[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", "", false
	}
	val := strings.Trim(lit.Value, `"`)
	return id.Name + ".LookPath", val, true
}
