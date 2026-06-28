package archtest

import (
	"go/ast"
	"go/token"
	"strings"
	"testing"
)

// TestNoContextBackgroundInRequestPaths enforces the NIS2 / spec-12 / CLAUDE
// rule on the agent: request-path code (the signed On* stream-RPC handlers and
// everything they call) MUST propagate the caller's context and MUST NOT root a
// fresh context.Background()/context.TODO(). A fresh root silently drops the
// RPC's deadline and cancellation — the bug this guard pins was
// supplementWithOsquery dropping the RequestInventory ctx so a cancelled
// inventory RPC kept running osquery. Mirrors the server archtest guard and the
// TestNoUnabstractedTimeNow shape.
//
// Two CATEGORY exemptions, deliberately not per-site blessings:
//
//   - package main under cmd/ — the agent CLI / bootstrap legitimately ROOTs
//     the process lifecycle context; there is no caller context to inherit.
//     cmd/ files are still walked (only the error is skipped) so their roots
//     keep the matches-zero liveness probe alive.
//
//   - daemon-lifecycle work that is NOT an RPC request path: per-session
//     terminal goroutines that must outlive the start RPC, background sweep/
//     heartbeat tickers, startup backend detection, shutdown cleanup, and
//     local credential-file writes. Each is allowlisted by enclosing function
//     with a justification and is bounded by its own timeout or by the callee
//     (osquery applies its own defaultTimeout). assertNoStale fails the build
//     if one of these functions stops rooting a context, so the escape hatch
//     cannot rot open.
//
// The allowlist is keyed by enclosing function (not file, not line): every
// context.Background() renders identically, so a file-level key would fail open
// and silently bless a future root anywhere in that file.
func TestNoContextBackgroundInRequestPaths(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(rel string) bool {
		if strings.HasPrefix(rel, "internal/store/generated/") {
			return false
		}
		if strings.HasPrefix(rel, "internal/testutil/") {
			return false
		}
		return true
	})
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero production Go files — detector is mis-scoped")
	}

	allow := newAllowlist(map[string]string{
		"internal/credentials/credentials.go :: writeFile":      "local credential-file write on the enrollment/cert-rotation path, not an RPC request; fs write is synchronous",
		"internal/deviceauth/enroll_server.go :: Shutdown":      "enrollment-socket shutdown path; no caller context to inherit; bounded 5s",
		"internal/executor/agent_update.go :: getBinaryVersion": "bounded 10s subprocess version probe during self-update verification",
		"internal/executor/executor.go :: NewExecutor":          "constructor-time package-backend detection at startup; callee-bounded, no request",
		"internal/handler/handler.go :: BuildHeartbeat":         "best-effort periodic heartbeat metrics; no RPC caller; osquery bounds each call (defaultTimeout)",
		"internal/handler/terminal.go :: OnTerminalStart":       "terminal session must outlive the start RPC; sessionCtx roots its own lifecycle and teardown must run even when the start ctx is gone",
		"internal/handler/terminal.go :: pumpTerminalOutput":    "detached per-session output pump; owns sessionCtx; its sends/cleanup are bounded by their own timeouts",
		"internal/handler/terminal.go :: sweepIdleTerminals":    "background idle-terminal sweep ticker; no RPC caller; bounded cleanup",
	})

	// Liveness probe: every context.Background()/context.TODO() seen anywhere
	// (cmd/ included). Keying matches-zero off this — not off non-cmd
	// violations — keeps the guard non-vacuous even once every request path is
	// clean, because cmd/ bootstrap always roots a context.
	sawCtxRoot := 0
	for _, gf := range files {
		underCmd := strings.HasPrefix(gf.rel, "cmd/")
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, ok := contextRootCall(call)
			if !ok {
				return true
			}
			sawCtxRoot++
			if underCmd {
				return true // category exemption: process lifecycle root
			}
			fn := enclosingFuncName(gf.ast, call.Pos())
			if allow.exempt(gf.rel + " :: " + fn) {
				return true
			}
			t.Errorf("context.%s() rooted in a request path at %s:%d (enclosing func %q) — propagate the caller's context.Context instead; a fresh root drops the request deadline and cancellation. If this is detached daemon-lifecycle work, allowlist it by enclosing function with a justification.",
				name, gf.rel, gf.line(call), fn)
			return true
		})
	}
	if sawCtxRoot == 0 {
		t.Fatal("matches-zero guard: found no context.Background()/context.TODO() anywhere (not even in cmd/ bootstrap) — the detector is dead, the guard would pass vacuously")
	}
	allow.assertNoStale(t)
}

// contextRootCall reports whether call is exactly context.Background() or
// context.TODO() (zero args), returning the bare method name.
func contextRootCall(call *ast.CallExpr) (string, bool) {
	if len(call.Args) != 0 {
		return "", false
	}
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	if sel.Sel.Name != "Background" && sel.Sel.Name != "TODO" {
		return "", false
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != "context" {
		return "", false
	}
	return sel.Sel.Name, true
}

// enclosingFuncName returns the name of the top-level FuncDecl whose source
// range contains pos (covering calls nested inside closures), or "<file-scope>"
// when pos sits outside any function.
func enclosingFuncName(file *ast.File, pos token.Pos) string {
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if pos >= fd.Pos() && pos <= fd.End() {
			return fd.Name.Name
		}
	}
	return "<file-scope>"
}
