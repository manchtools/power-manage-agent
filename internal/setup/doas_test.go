package setup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"text/template"
)

// The doas template has to render a real `permit` rule for the given
// user and must not leak the template syntax into the output — a stray
// `{{.User}}` in /etc/doas.d/*.conf would make doas(1) fail to parse
// the whole file, taking every other drop-in down with it.
func TestDoasTemplate_RendersPermitRule(t *testing.T) {
	tmpl, err := template.New("doas").Parse(doasTmpl)
	if err != nil {
		t.Fatalf("parse doas template: %v", err)
	}

	var sb strings.Builder
	if err := tmpl.Execute(&sb, DoasData{User: "power-manage"}); err != nil {
		t.Fatalf("execute template: %v", err)
	}
	out := sb.String()

	if !strings.Contains(out, "permit nopass power-manage as root") {
		t.Errorf("rendered doas fragment missing permit rule; got:\n%s", out)
	}
	if strings.Contains(out, "{{") || strings.Contains(out, "}}") {
		t.Errorf("rendered doas fragment still contains unexpanded template syntax:\n%s", out)
	}
}

// verifyDoasIncludeIn is the gate that refuses to install a drop-in
// when /etc/doas.conf isn't configured to load it — without this,
// doas silently ignores the agent's rules and the agent fails at
// first escalation with no actionable signal. Pin every relevant
// case (missing file, no include, glob include, direct include,
// whitespace tolerance) so a future change can't re-break any of them.
func TestVerifyDoasIncludeIn(t *testing.T) {
	dir := t.TempDir()
	fragment := "/etc/doas.d/power-manage.conf"

	cases := []struct {
		name    string
		content *string // nil => file does not exist
		wantErr bool
	}{
		{"missing main conf", nil, true},
		{"empty main conf", ptr(""), true},
		{"only comment line", ptr("# commented include\n"), true},
		{"unrelated includes", ptr(`include "/etc/other.d/foo.conf"` + "\n"), true},
		{"direct include of fragment", ptr(`include "` + fragment + `"` + "\n"), false},
		{"glob include of drop-in dir", ptr(`include "/etc/doas.d/*.conf"` + "\n"), false},
		{"include with extra whitespace", ptr("   include \"" + fragment + "\"\n"), false},
		{"include after other rules", ptr("permit nopass admin as root\ninclude \"/etc/doas.d/*.conf\"\n"), false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var confPath string
			if tc.content != nil {
				confPath = filepath.Join(dir, strings.ReplaceAll(tc.name, " ", "_")+".conf")
				if err := os.WriteFile(confPath, []byte(*tc.content), 0o644); err != nil {
					t.Fatalf("write fixture: %v", err)
				}
			} else {
				confPath = filepath.Join(dir, "does-not-exist.conf")
			}
			err := verifyDoasIncludeIn(confPath, fragment)
			if tc.wantErr && err == nil {
				t.Errorf("expected error, got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("expected no error, got %v", err)
			}
		})
	}
}

func ptr(s string) *string { return &s }
