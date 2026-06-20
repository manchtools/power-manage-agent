package archtest

import (
	"go/ast"
	"go/token"
	"strings"
	"testing"
)

// protoJSONAllowlist lists stdlib-encoding/json call sites whose operand is
// proto-package-typed but is NOT a wire-format proto message marshalling
// concern (typically a proto ENUM, which is a plain int32 and encodes
// identically under stdlib json and protojson). Each entry is justified;
// assertNoStale fails the build if one stops matching.
// Keyed by "<module-rel path> :: <rendered call expression>".
var protoJSONAllowlist = map[string]string{}

// protoPkgPathSuffix identifies the generated protobuf package regardless of
// the import alias a file chooses (conventionally "pm").
const protoPkgPathSuffix = "-sdk/gen/go/pm/v1"

// TestNoStdlibJSONOfProtoMessage forbids passing a generated protobuf type to
// the standard library encoding/json (Marshal / MarshalIndent / Unmarshal, and
// the inline json.NewEncoder(w).Encode / json.NewDecoder(r).Decode forms).
// Proto messages MUST be (de)serialised with google.golang.org/protobuf's
// protojson: stdlib json only works by snake-case-struct-tag luck and silently
// corrupts oneofs, well-known types (Timestamp/Duration), int64 (string in
// protojson), and enums (name vs number) on any future field. WS1b#5 closed the
// pm.CommandOutput sites; this guard stops the smell from returning.
//
// Heuristic (documented per the archtest design constraints): a value is
// "proto-typed" when it is a composite literal of a proto type (pm.Foo{} /
// &pm.Foo{}) or a local variable declared with a proto type (var v pm.Foo /
// v := pm.Foo{} / v := &pm.Foo{}), possibly addressed (&v). The proto import
// alias is self-discovered from the import path, not hardcoded. The
// field-selector shape (json.Marshal(x.ProtoField)) and indirection through a
// helper are not resolvable without type information and are a documented blind
// spot; the common message-(de)serialisation shapes are covered. Benign cases
// (e.g. marshalling a proto enum) go in the guarded protoJSONAllowlist.
func TestNoStdlibJSONOfProtoMessage(t *testing.T) {
	root := moduleRoot(t)
	files := walkGoFiles(t, root, func(string) bool { return true })
	if len(files) == 0 {
		t.Fatal("matches-zero guard: walked zero production Go files — detector is mis-scoped")
	}

	allow := newAllowlist(protoJSONAllowlist)
	sawProtoImport := false
	sawJSONCall := false

	for _, gf := range files {
		protoAliases := protoImportAliases(gf.ast)
		if len(protoAliases) > 0 {
			sawProtoImport = true
		}
		jsonAlias := importAliasFor(gf.ast, "encoding/json")
		if jsonAlias == "" {
			continue // file never touches encoding/json
		}
		for _, decl := range gf.ast.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			protoLocals := protoTypedLocals(fn, protoAliases)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				target, isJSON := jsonSerdeTarget(call, jsonAlias)
				if !isJSON {
					return true
				}
				sawJSONCall = true
				if target == nil || !exprIsProtoTyped(target, protoAliases, protoLocals) {
					return true
				}
				key := gf.rel + " :: " + render(gf.fset, call)
				if allow.exempt(key) {
					return true
				}
				t.Errorf("stdlib encoding/json applied to a proto message at %s:%d — %s\n  proto messages must use protojson (google.golang.org/protobuf/encoding/protojson); stdlib json silently corrupts oneofs/enums/int64/well-known types. If this operand is a proto ENUM (a plain int32, safe under stdlib json), add a justified, guarded entry to protoJSONAllowlist.",
					gf.rel, gf.line(call), render(gf.fset, call))
				return true
			})
		}
	}

	if !sawProtoImport {
		t.Fatal("matches-zero guard: no file imports the generated proto package — the proto-type detector is dead, the guard would pass vacuously")
	}
	if !sawJSONCall {
		t.Fatal("matches-zero guard: detected no encoding/json calls in the module — the json-call detector is dead, the guard would pass vacuously")
	}
	allow.assertNoStale(t)
}

// protoImportAliases returns the set of local names by which f imports the
// generated protobuf package (path suffix /sdk/gen/go/pm/v1). Self-discovered
// from the import block so the guard is not tied to the conventional "pm".
func protoImportAliases(f *ast.File) map[string]bool {
	out := map[string]bool{}
	for _, imp := range f.Imports {
		path := unquoteLit(imp.Path)
		if !strings.HasSuffix(path, protoPkgPathSuffix) {
			continue
		}
		if imp.Name != nil {
			out[imp.Name.Name] = true
		} else {
			// Unaliased import: pure-AST parsing can't resolve the package's
			// declared name. The generated protobuf package is `package pmv1`,
			// but register the last path segment `v1` too so neither possible
			// identifier bypasses the guard. Both are scoped to this exact
			// import path, so there is no collision with other /v1 packages.
			out["pmv1"] = true
			out["v1"] = true
		}
	}
	return out
}

// importAliasFor returns the local name f imports path under, or "" if not
// imported. An unaliased import resolves to the last path segment (correct for
// encoding/json -> "json").
func importAliasFor(f *ast.File, path string) string {
	for _, imp := range f.Imports {
		if unquoteLit(imp.Path) != path {
			continue
		}
		if imp.Name != nil {
			return imp.Name.Name
		}
		if i := strings.LastIndex(path, "/"); i >= 0 {
			return path[i+1:]
		}
		return path
	}
	return ""
}

// jsonSerdeTarget reports whether call is a stdlib encoding/json
// (de)serialisation and returns the operand whose type matters:
//   - json.Marshal(x) / json.MarshalIndent(x, ...) -> x
//   - json.Unmarshal(b, x)                         -> x
//   - json.NewEncoder(w).Encode(x)                 -> x
//   - json.NewDecoder(r).Decode(x)                 -> x
func jsonSerdeTarget(call *ast.CallExpr, jsonAlias string) (ast.Expr, bool) {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return nil, false
	}
	// Package-qualified json.Func(...) forms.
	if id, ok := sel.X.(*ast.Ident); ok && id.Name == jsonAlias {
		switch sel.Sel.Name {
		case "Marshal", "MarshalIndent":
			if len(call.Args) >= 1 {
				return call.Args[0], true
			}
		case "Unmarshal":
			if len(call.Args) >= 2 {
				return call.Args[1], true
			}
		}
		return nil, false
	}
	// Chained json.NewEncoder(w).Encode(x) / json.NewDecoder(r).Decode(x).
	if (sel.Sel.Name == "Encode" || sel.Sel.Name == "Decode") && len(call.Args) >= 1 {
		if inner, ok := sel.X.(*ast.CallExpr); ok {
			if innerSel, ok := inner.Fun.(*ast.SelectorExpr); ok {
				if id, ok := innerSel.X.(*ast.Ident); ok && id.Name == jsonAlias &&
					(innerSel.Sel.Name == "NewEncoder" || innerSel.Sel.Name == "NewDecoder") {
					return call.Args[0], true
				}
			}
		}
	}
	return nil, false
}

// protoTypedLocals returns the set of local variable names in fn whose declared
// type is a proto message — via an explicit type (var v pm.Foo / var v *pm.Foo)
// or a composite-literal initialiser (v := pm.Foo{} / v := &pm.Foo{}).
func protoTypedLocals(fn *ast.FuncDecl, aliases map[string]bool) map[string]bool {
	out := map[string]bool{}
	if len(aliases) == 0 {
		return out
	}
	ast.Inspect(fn.Body, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.DeclStmt:
			gd, ok := x.Decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.VAR {
				return true
			}
			for _, spec := range gd.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok || vs.Type == nil {
					continue
				}
				if isProtoTypeExpr(vs.Type, aliases) {
					for _, name := range vs.Names {
						out[name.Name] = true
					}
				}
			}
		case *ast.AssignStmt:
			if x.Tok != token.DEFINE || len(x.Lhs) != len(x.Rhs) {
				return true
			}
			for i, rhs := range x.Rhs {
				if exprIsProtoComposite(rhs, aliases) {
					if id, ok := x.Lhs[i].(*ast.Ident); ok {
						out[id.Name] = true
					}
				}
			}
		}
		return true
	})
	return out
}

// isProtoTypeExpr reports whether a TYPE expression denotes a proto type
// (pm.Foo) or pointer to one (*pm.Foo), qualified by a proto import alias.
func isProtoTypeExpr(e ast.Expr, aliases map[string]bool) bool {
	switch x := e.(type) {
	case *ast.StarExpr:
		return isProtoTypeExpr(x.X, aliases)
	case *ast.SelectorExpr:
		id, ok := x.X.(*ast.Ident)
		return ok && aliases[id.Name]
	}
	return false
}

// exprIsProtoComposite reports whether a VALUE expression is a proto composite
// literal pm.Foo{...} or &pm.Foo{...}.
func exprIsProtoComposite(e ast.Expr, aliases map[string]bool) bool {
	switch x := e.(type) {
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return exprIsProtoComposite(x.X, aliases)
		}
	case *ast.ParenExpr:
		return exprIsProtoComposite(x.X, aliases)
	case *ast.CompositeLit:
		return x.Type != nil && isProtoTypeExpr(x.Type, aliases)
	}
	return false
}

// exprIsProtoTyped reports whether a VALUE expression handed to encoding/json is
// proto-typed: a proto composite literal, or a (possibly &-addressed) local
// variable recorded as proto-typed.
func exprIsProtoTyped(e ast.Expr, aliases, protoLocals map[string]bool) bool {
	switch x := e.(type) {
	case *ast.UnaryExpr:
		if x.Op == token.AND {
			return exprIsProtoTyped(x.X, aliases, protoLocals)
		}
	case *ast.ParenExpr:
		return exprIsProtoTyped(x.X, aliases, protoLocals)
	case *ast.CompositeLit:
		return x.Type != nil && isProtoTypeExpr(x.Type, aliases)
	case *ast.Ident:
		return protoLocals[x.Name]
	}
	return false
}
