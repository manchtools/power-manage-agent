package archtest

import (
	"go/ast"
	"strconv"
	"testing"
)

// sdkImportPath is the import path of the Power Manage SDK root package,
// which owns the mTLS ClientOption constructors.
const sdkImportPath = "github.com/manchtools/power-manage-sdk"

// strictTrustOption is the SDK option whose server-verification RootCAs
// pool is EXACTLY the CA PEM handed to it (the CA this device enrolled
// with), at TLS 1.3, with the host's system roots deliberately absent.
const strictTrustOption = "WithMTLSFromPEM"

// widenedTrustOption is the SDK option that unions the enrollment CA with
// x509.SystemCertPool(). Legitimate for a public-CA-fronted endpoint, fatal
// for the agent's control stream.
const widenedTrustOption = "WithMTLSFromPEMAndSystemRoots"

// streamClientCtor is the SDK constructor for the bidirectional
// AgentService stream client.
const streamClientCtor = "NewClient"

// agentAddrField is the credentials field naming the control-stream
// endpoint; a function that both constructs an SDK client and names this
// field is a stream dial site.
const agentAddrField = "AgentAddr"

// TestStreamDialPinsEnrollmentCA pins the TLS trust posture of the agent's
// control-stream dial.
//
// The stream is the agent's standing, fully-privileged channel: it carries
// action dispatch, terminal I/O, LUKS passphrases and LPS passwords. Its
// server-verification trust must therefore be the enrollment CA ALONE —
// sdk.WithMTLSFromPEM sets RootCAs to exactly that CA, so no publicly
// trusted certificate can impersonate control however the agent's DNS or
// routing is subverted.
//
// The failure this guard exists to catch is a one-identifier edit.
// sdk.WithMTLSFromPEMAndSystemRoots is a legitimate, in-tree call
// (cert_rotation.go reaches RenewCertificate at the public,
// Traefik/Let's-Encrypt-fronted ControlAddr), so the wrong option is always
// within autocomplete reach of the stream dial. Swapping it compiles, runs,
// connects, and passes every behavioural test — the widened trust is
// invisible until someone with any public CA's signature answers for
// control's hostname. Nothing in this module noticed before this guard; only
// the server repo's deployment smoke lane would have, in a different repo
// and a different CI lane.
//
// Discovery is self-locating: the whole module is walked and a dial site is
// any function that both calls <sdk>.NewClient and references .AgentAddr,
// so the guard follows the code when it moves between files or functions
// (it covers runAgent and runSelfTest today). Finding no site at all is a
// FATAL matches-zero failure, not a pass — an unlocatable dial site means
// the guard pins nothing.
//
// The required option is asserted by exact selector name, not by substring:
// strictTrustOption is a prefix of widenedTrustOption, so a textual
// "contains WithMTLSFromPEM" check would happily accept the swap it is
// supposed to reject.
func TestStreamDialPinsEnrollmentCA(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(string) bool { return true })
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero production Go files — the detector is mis-scoped")
	}

	sites := 0
	for _, gf := range files {
		sdkName, ok := sdkLocalName(gf.ast)
		if !ok {
			continue
		}
		for _, decl := range gf.ast.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Body == nil {
				continue
			}
			if !buildsStreamClient(fd, sdkName) {
				continue
			}
			sites++
			opts := sdkCallNames(fd, sdkName)
			if opts[widenedTrustOption] {
				t.Errorf("%s :: %s builds the control-stream client but configures mTLS with sdk.%s — the stream's server trust must be the enrollment CA ALONE (sdk.%s). Unioning the host's system roots lets any publicly-trusted certificate answering for control's hostname terminate the agent's privileged stream.",
					gf.rel, fd.Name.Name, widenedTrustOption, strictTrustOption)
			}
			if !opts[strictTrustOption] {
				t.Errorf("%s :: %s builds the control-stream client but calls no sdk.%s in the same function — this guard can no longer see which trust anchor the stream dial uses. Keep the option construction at the dial site, or re-point this guard at wherever it moved.",
					gf.rel, fd.Name.Name, strictTrustOption)
			}
		}
	}
	if sites == 0 {
		t.Fatalf("matches-zero guard: no function in the module both calls sdk.%s and references .%s — the stream dial site moved or was renamed, so this guard now pins nothing. Re-point it at the new construction site.",
			streamClientCtor, agentAddrField)
	}
}

// TestSystemRootsTrustIsConfinedToThePublicCAEndpoint is the positive
// control for TestStreamDialPinsEnrollmentCA's negative assertion, and a
// containment guard in its own right.
//
// A "the dial site does not call sdk.WithMTLSFromPEMAndSystemRoots"
// assertion is only evidence if the detector behind it can actually match
// that call. This test runs the same selector matcher across the module and
// FAILS FATALLY when it matches nothing: the module does contain a
// deliberate widened-trust call, so a zero result means the matcher is dead
// and the stream guard is passing vacuously.
//
// The complementary half is containment: every widened-trust site must be
// allowlisted with a justification, so the option cannot spread to a third
// call site unnoticed. assertNoStale closes the loop in the other direction
// — if the allowlisted site disappears, the stale entry fails the build
// rather than silently becoming the escape hatch for some future call.
func TestSystemRootsTrustIsConfinedToThePublicCAEndpoint(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(string) bool { return true })
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero production Go files — the detector is mis-scoped")
	}

	allow := newAllowlist(map[string]string{
		"cmd/power-manage-agent/cert_rotation.go :: startCertRotation": "ControlService.RenewCertificate is dialled at creds.ControlAddr, the public HTTPS host (Traefik + Let's Encrypt in the reference deployment), so server verification legitimately needs the host's system roots. The agent's own identity on that call is proven at the application layer by the current certificate carried in the request body, not by the transport's root pool.",
	})

	seen := 0
	for _, gf := range files {
		sdkName, ok := sdkLocalName(gf.ast)
		if !ok {
			continue
		}
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if sdkCallName(call, sdkName) != widenedTrustOption {
				return true
			}
			seen++
			if allow.exempt(gf.rel + " :: " + enclosingFuncName(gf.ast, call.Pos())) {
				return true
			}
			t.Errorf("%s:%d: sdk.%s widens server trust to every public CA — allowlist this site with a justification only if it dials a genuinely public-CA-fronted endpoint; anything on the enrollment CA's own network must use sdk.%s.",
				gf.rel, gf.line(call), widenedTrustOption, strictTrustOption)
			return true
		})
	}
	if seen == 0 {
		t.Fatalf("matches-zero guard: the sdk.%s matcher found no call anywhere in the module, yet the certificate-renewal path is supposed to make one. The matcher is dead, which also makes TestStreamDialPinsEnrollmentCA's \"the dial site does not use %s\" assertion vacuous.",
			widenedTrustOption, widenedTrustOption)
	}
	allow.assertNoStale(t)
}

// sdkLocalName returns the identifier under which file refers to the SDK
// root package, and whether the file imports it in a usable form. Blank and
// dot imports yield false: neither can produce a <sdk>.Foo selector, so
// there is nothing for the matchers to key on.
func sdkLocalName(file *ast.File) (string, bool) {
	for _, imp := range file.Imports {
		path, err := strconv.Unquote(imp.Path.Value)
		if err != nil || path != sdkImportPath {
			continue
		}
		if imp.Name == nil {
			return "sdk", true // the SDK root is `package sdk`
		}
		if imp.Name.Name == "_" || imp.Name.Name == "." {
			return "", false
		}
		return imp.Name.Name, true
	}
	return "", false
}

// sdkCallName returns the SDK function name for a call of the form
// <sdkName>.Foo(...), or "" for anything else. Matching is on the exact
// selector identifier, so WithMTLSFromPEM and WithMTLSFromPEMAndSystemRoots
// never alias each other.
func sdkCallName(call *ast.CallExpr, sdkName string) string {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return ""
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || id.Name != sdkName {
		return ""
	}
	return sel.Sel.Name
}

// sdkCallNames returns the set of SDK package functions called anywhere in
// fd's body, closures included.
func sdkCallNames(fd *ast.FuncDecl, sdkName string) map[string]bool {
	out := make(map[string]bool)
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if name := sdkCallName(call, sdkName); name != "" {
				out[name] = true
			}
		}
		return true
	})
	return out
}

// buildsStreamClient reports whether fd is a control-stream dial site: it
// constructs an SDK client and names the credentials' stream endpoint in
// the same function. Requiring both keeps out the log statements that
// mention creds.AgentAddr without dialling anything.
func buildsStreamClient(fd *ast.FuncDecl, sdkName string) bool {
	var ctor, streamAddr bool
	ast.Inspect(fd.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.CallExpr:
			if sdkCallName(x, sdkName) == streamClientCtor {
				ctor = true
			}
		case *ast.SelectorExpr:
			if x.Sel.Name == agentAddrField {
				streamAddr = true
			}
		}
		return true
	})
	return ctor && streamAddr
}
