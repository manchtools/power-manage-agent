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
//
//	readFileWithSudo, fileExistsWithSudo, atomicWriteFile, removeFileStrict,
//	createDirectory, createDirectoryWithPermissions, removeDirectory.
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
		// Sanctioned raw chokepoints: the SDK fs Manager exposes neither a
		// metadata stat nor a streaming reader, so these two single-purpose
		// helpers own the only raw os.* the executor needs. statFile backs the
		// file/dir idempotency checks (mode/type); sha256File streams a large
		// installed artifact through sha256 (fsMgr.ReadFile would buffer the
		// whole AppImage). Both are documented at their definitions.
		"statFile":   true,
		"sha256File": true,
	}

	// os calls that inspect errno or return metadata — no filesystem touch
	allowedOSCalls := map[string]bool{
		"IsNotExist":    true,
		"IsExist":       true,
		"IsPermission":  true,
		"IsTimeout":     true,
		"Getpid":        true,
		"Geteuid":       true,
		"Getegid":       true,
		"Getuid":        true,
		"Getgid":        true,
		"Getenv":        true,
		"Setenv":        true,
		"Unsetenv":      true,
		"Environ":       true,
		"ExpandEnv":     true,
		"Getwd":         true,
		"Hostname":      true,
		"UserHomeDir":   true,
		"UserCacheDir":  true,
		"UserConfigDir": true,
		"TempDir":       true,
		"Executable":    true,
		"ReadDir":       true,
		"SameFile":      true,
		// os.Truncate and os.Chtimes were removed from this list (#173
		// review finding): both MUTATE filesystem state (size, mtime/
		// atime) and were sitting under the "no filesystem touch"
		// comment — the arch test would have silently permitted them in
		// privilege-routed packages.
		"Pipe":            true,
		"NewFile":         true,
		"NewSyscallError": true,
		"FileMode":        true,
	}

	// agentPrivate enumerates the direct os.* sites that are legitimately NOT
	// privilege-routed because they touch AGENT-OWNED files, not operator
	// targets. Each key is "<rel> :: <rendered call>" so it is line-independent
	// and self-documenting; the allowlist's assertNoStale guard fails the build
	// if any entry stops matching (a moved/removed site), so it cannot rot into
	// a fail-open escape hatch. A newly-introduced direct os.* on an OPERATOR
	// path renders to a key that is absent here and is therefore flagged.
	agentPrivate := newAllowlist(map[string]string{
		// Local credential store: operates on the agent's own data dir with
		// owner-only perms (0700/0600), machine-id-bound. The perms guard reads
		// raw FileMode bits (fsMgr discards them), so routing through the fs
		// Manager would DELETE the WS10 forgeable-store defense. The ciphertext
		// write itself already routes through s.fs.WriteFile.
		"internal/credentials/credentials.go :: os.Stat(filepath.Join(s.dataDir, credentialsFile))": "cred store: existence of the agent's own credentials file",
		"internal/credentials/credentials.go :: os.Stat(dir)":                                       "cred store: owner-only-writable perms guard (raw FileMode, WS10 #1/#2)",
		"internal/credentials/credentials.go :: os.MkdirAll(s.dataDir, 0700)":                       "cred store: create the agent's own 0700 data dir",
		"internal/credentials/credentials.go :: os.Chmod(s.dataDir, 0700)":                          "cred store: tighten the agent's own data dir to 0700",
		"internal/credentials/credentials.go :: os.ReadFile(saltPath)":                              "cred store: read the agent's own KDF salt",
		"internal/credentials/credentials.go :: os.ReadFile(credPath)":                              "cred store: read the agent's own ciphertext",
		"internal/credentials/credentials.go :: os.Remove(credPath)":                                "cred store: delete the agent's own ciphertext",
		"internal/credentials/credentials.go :: os.Remove(saltPath)":                                "cred store: delete the agent's own salt",
		"internal/credentials/credentials.go :: os.ReadFile(\"/etc/machine-id\")":                   "cred store: machine-id binding (read-only identity probe)",
		"internal/credentials/credentials.go :: os.ReadFile(\"/var/lib/dbus/machine-id\")":          "cred store: machine-id binding fallback",

		// Package artifact staging: an agent-private mkstemp in the agent's tmp,
		// downloaded into (checksum-verified) and handed to the escalated
		// dpkg/rpm install. The security boundary is the checksum + the
		// escalated install, not the private temp create.
		"internal/executor/action_deb.go :: os.CreateTemp(\"\", \"*.deb\")": "deb staging: agent-private temp for a checksum-verified download",
		"internal/executor/action_deb.go :: os.Remove(tmpFile.Name())":      "deb staging: clean up the agent's own temp",
		"internal/executor/action_rpm.go :: os.CreateTemp(\"\", \"*.rpm\")": "rpm staging: agent-private temp for a checksum-verified download",
		"internal/executor/action_rpm.go :: os.Remove(tmpFile.Name())":      "rpm staging: clean up the agent's own temp",

		// Agent self-update: all under cfg.DataDir/update (agent-owned). The
		// download is verified against the operator-or-CA-pinned sha256 (WS7);
		// the root-owned install uses escalated `cp`, not a direct os.* here.
		"internal/executor/agent_update.go :: os.MkdirAll(updateDir, 0755)":                                    "self-update: create the agent's own update dir",
		"internal/executor/agent_update.go :: os.CreateTemp(updateDir, \"agent-update-*.tmp\")":                "self-update: agent-private staging for the new binary",
		"internal/executor/agent_update.go :: os.Remove(tmpPath)":                                              "self-update: clean up the agent's own staged binary",
		"internal/executor/agent_update.go :: os.ReadFile(tmpPath)":                                            "self-update: read the agent's own staged binary",
		"internal/executor/agent_update.go :: os.ReadFile(filepath.Join(dataDir, \"update\", \"state.json\"))": "self-update: read the agent's own state marker",
		"internal/executor/agent_update.go :: os.Remove(filepath.Join(dataDir, \"update\", \"state.json\"))":   "self-update: clear the agent's own state marker",
		"internal/executor/agent_update.go :: os.Remove(path)":                                                 "self-update: prune the agent's own stale temp files",
	})

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

			// Agent-private, non-operator path: exempt by enumerated, stale-guarded key.
			if agentPrivate.exempt(gf.rel + " :: " + render(gf.fset, call)) {
				return true
			}

			// FINDING: direct os I/O bypassing SDK fs Manager
			t.Errorf("%s:%d: os.%s() in enclosing func %q — bypasses SDK fs Manager; use readFileWithSudo/fileExistsWithSudo/atomicWriteFile/removeFileStrict wrappers that route through fsMgr (or, for an agent-private path, add a justified entry to agentPrivate)",
				gf.rel, gf.line(call), fnName, enclosing)
			findings++
			return true
		})
	}

	agentPrivate.assertNoStale(t)

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
