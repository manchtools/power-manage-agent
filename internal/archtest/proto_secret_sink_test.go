package archtest

import (
	"go/ast"
	"strings"
	"testing"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	_ "github.com/manchtools/power-manage-sdk/gen/go/powermanage/v1" // registers the descriptors this guard reads
)

// secretLogSinkAllowlist lists the ONLY places a secret-named field may be
// handed to a logging or formatting call. Keyed by "<module-rel path> :: <rendered call>".
//
// Empty on purpose: no such site is legitimate today. assertNoStale means an
// entry added later cannot rot silently — if the site it names stops matching,
// the build fails rather than leaving an exemption nobody notices.
var secretLogSinkAllowlist = map[string]string{}

// TestProtoSecretFieldSinks: a credential must never reach a log.
//
// LUKS passphrases and LPS passwords are sealed on the wire, but the agent must
// still handle plaintext at the narrow operating-system sink. A field selector
// handed to formatting or logging can therefore disclose a live credential.
//
// The agent is where these values ORIGINATE — it generates the password, sets
// it on the account, and reports it — so it holds the plaintext longest and
// logs the most around it (per-user rotation progress, LUKS slot operations).
//
// The protobuf option that exists for this does not work in Go.
// `debug_redact = true` is defined in protobuf-go's descriptor types and
// consulted by NO encoder in the module — it is implemented for C++ and Java.
// Annotating the fields and trusting String() would assert a protection that
// does not exist.
//
// So the annotation is used as a MARKER instead, and this test is the
// enforcement: the secret field names are derived from the descriptors at run
// time (never a hardcoded list — a new debug_redact field is covered the moment
// it is added), and any of them appearing as an argument to a logging or
// formatting call fails the build.
//
// Scope, stated plainly: this matches on the field NAME, so it also covers the
// decrypted store values that share it — `key.Passphrase` off a database row is
// exactly as secret as `req.Passphrase` off the wire, and neither belongs in a
// log. What it does NOT catch is `%v` on a whole message: that needs type
// resolution the archtest suite deliberately does not carry. Reading a secret
// in order to encrypt, compare or store it stays legal; only the sinks are
// closed.
func TestProtoSecretFieldSinks(t *testing.T) {
	secrets := secretFieldNamesFromDescriptors(t)
	if len(secrets) == 0 {
		t.Fatal("matches-zero guard: no debug_redact fields found in the contract — either the markers were " +
			"dropped (the fields are now unguarded) or this discovery is broken")
	}

	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(rel string) bool {
		if strings.HasPrefix(rel, "internal/archtest/") {
			return false
		}
		return !strings.HasSuffix(rel, "_test.go")
	})
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero Go files — the detector is mis-scoped")
	}

	allow := newAllowlist(secretLogSinkAllowlist)
	sawSink := false

	for _, gf := range files {
		ast.Inspect(gf.ast, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || !isLogOrFormatSink(call) {
				return true
			}
			sawSink = true
			for _, arg := range call.Args {
				name, found := findSecretSelector(arg, secrets)
				if !found {
					continue
				}
				key := gf.rel + " :: " + render(gf.fset, call)
				if allow.exempt(key) {
					continue
				}
				t.Errorf("%s:%d: secret field %q reaches a log/format sink — a credential written to a log "+
					"outlives the request and the operator never sees it happen:\n\t%s",
					gf.rel, gf.line(call), name, render(gf.fset, call))
			}
			return true
		})
	}

	if !sawSink {
		t.Fatal("matches-zero guard: no logging or formatting call matched anywhere in the tree — " +
			"isLogOrFormatSink is broken and this test proves nothing")
	}
	allow.assertNoStale(t)
}

// secretFieldNamesFromDescriptors returns the Go field names of every contract
// field marked debug_redact. Derived from the registered descriptors so the set
// tracks the proto, not a copy of it that drifts.
func secretFieldNamesFromDescriptors(t *testing.T) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if !strings.HasPrefix(string(fd.Package()), "powermanage.") {
			return true
		}
		msgs := fd.Messages()
		for i := 0; i < msgs.Len(); i++ {
			collectRedactedFields(msgs.Get(i), out)
		}
		return true
	})
	return out
}

func collectRedactedFields(md protoreflect.MessageDescriptor, out map[string]bool) {
	fields := md.Fields()
	for i := 0; i < fields.Len(); i++ {
		f := fields.Get(i)
		if opts, ok := f.Options().(*descriptorpb.FieldOptions); ok && opts.GetDebugRedact() {
			out[goFieldName(string(f.Name()))] = true
		}
	}
	nested := md.Messages()
	for i := 0; i < nested.Len(); i++ {
		collectRedactedFields(nested.Get(i), out)
	}
}

// goFieldName converts a proto field name to the Go struct field protoc-gen-go
// emits: snake_case becomes CamelCase.
func goFieldName(protoName string) string {
	parts := strings.Split(protoName, "_")
	var b strings.Builder
	for _, p := range parts {
		if p == "" {
			continue
		}
		b.WriteString(strings.ToUpper(p[:1]))
		b.WriteString(p[1:])
	}
	return b.String()
}

// isLogOrFormatSink reports whether call renders its arguments into text that
// escapes the process — a log line, an error string, formatted output.
func isLogOrFormatSink(call *ast.CallExpr) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	switch sel.Sel.Name {
	// slog on any receiver (h.logger.Warn, slog.Default().Error, …).
	case "Debug", "Info", "Warn", "Error",
		"DebugContext", "InfoContext", "WarnContext", "ErrorContext":
		return true
	// fmt / errors text builders.
	case "Sprintf", "Printf", "Sprint", "Sprintln", "Println", "Print", "Fprintf", "Fprintln", "Errorf":
		return true
	}
	return false
}

// findSecretSelector reports the first secret-named field selector inside e,
// descending through nested calls so fmt.Sprintf(...) wrapped in a log argument
// is still caught.
func findSecretSelector(e ast.Expr, secrets map[string]bool) (string, bool) {
	var name string
	ast.Inspect(e, func(n ast.Node) bool {
		if name != "" {
			return false
		}
		sel, ok := n.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		// Getter form too: msg.GetPassphrase().
		field := strings.TrimPrefix(sel.Sel.Name, "Get")
		if secrets[sel.Sel.Name] || secrets[field] {
			name = sel.Sel.Name
			return false
		}
		return true
	})
	return name, name != ""
}
