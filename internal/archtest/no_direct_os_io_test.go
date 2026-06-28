package archtest

import (
	"go/ast"
	"strings"
	"testing"
)

// TestNoDirectOSIOInSensitivePaths enforces that the executor and credentials
// packages do not call os.ReadFile, os.Stat, os.WriteFile, os.Open,
// os.CreateTemp, os.MkdirAll, or os.Remove directly. All filesystem I/O must
// route through the SDK fs Manager (fsMgr) so the privilege backend is
// honored, reads are testable via fake managers, and a future non-root agent
// does not silently lose access to privileged files.
//
// Coverage: internal/executor/ + internal/credentials/
//
// Wrappers that ARE the SDK routing path (exempt):
//   readFileWithSudo, fileExistsWithSudo, atomicWriteFile, removeFileStrict,
//   createDirectory, createDirectoryWithPermissions, removeDirectory.
func TestNoDirectOSIOInSensitivePaths(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(rel string) bool {
		return strings.HasPrefix(rel, "internal/executor/") ||
			strings.HasPrefix(rel, "internal/credentials/")
	})
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero sensitive-path Go files — detector mis-scoped")
	}

	directIO := map[string]bool{
		"Open":       true,
		"Create":     true,
		"CreateTemp": true,
		"ReadFile":   true,
		"WriteFile":  true,
		"Stat":       true,
		"Lstat":      true,
		"Remove":     true,
		"RemoveAll":  true,
		"Rename":     true,
		"Chmod":      true,
		"Chown":      true,
		"Mkdir":      true,
		"MkdirAll":   true,
		"Symlink":    true,
		"Link":       true,
	}

	wrapperFuncs := map[string]bool{
		"readFileWithSudo":               true,
		"fileExistsWithSudo":             true,
		"atomicWriteFile":                true,
		"removeFileStrict":               true,
		"createDirectory":                true,
		"createDirectoryWithPermissions": true,
		"removeDirectory":                true,
	}

	// os calls that inspect errno or return metadata — no filesystem touch
	allowedOSCalls := map[string]bool{
		"IsNotExist":      true,
		"IsExist":         true,
		"IsPermission":    true,
		"IsTimeout":       true,
		"Getpid":          true,
		"Geteuid":         true,
		"Getegid":         true,
		"Getuid":          true,
		"Getgid":          true,
		"Getenv":          true,
		"Setenv":          true,
		"Unsetenv":        true,
		"Environ":         true,
		"ExpandEnv":       true,
		"Getwd":           true,
		"Hostname":        true,
		"UserHomeDir":     true,
		"UserCacheDir":    true,
		"UserConfigDir":   true,
		"TempDir":         true,
		"Executable":      true,
		"ReadDir":         true,
		"SameFile":        true,
		"Truncate":        true,
		"Chtimes":         true,
		"Pipe":            true,
		"NewFile":         true,
		"NewSyscallError": true,
		"FileMode":        true,
	}

	findings := 0
	for _, gf := range files {
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			fnName, isOS := osCallName(call)
			if !isOS {
				return true
			}

			if !directIO[fnName] {
				if allowedOSCalls[fnName] {
					return true
				}
				// Unknown os call — suspicious, flag it
				t.Errorf("%s:%d: os.%s() — unknown os call, add to allowedOSCalls or directIO in no_direct_os_io_test.go",
					gf.rel, gf.line(call), fnName)
				findings++
				return true
			}

			enclosing := enclosingFuncName(gf.ast, call.Pos())
			if wrapperFuncs[enclosing] {
				return true
			}

			// FINDING: direct os I/O bypassing SDK fs Manager
			t.Errorf("%s:%d: os.%s() in enclosing func %q — bypasses SDK fs Manager; use readFileWithSudo/fileExistsWithSudo/atomicWriteFile/removeFileStrict wrappers that route through fsMgr",
				gf.rel, gf.line(call), fnName, enclosing)
			findings++
			return true
		})
	}

	if findings > 0 {
		t.Logf("Found %d direct os.* filesystem calls in sensitive paths that bypass the SDK fs Manager", findings)
	}
}

func osCallName(call *ast.CallExpr) (string, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != "os" {
		return "", false
	}
	return sel.Sel.Name, true
}
