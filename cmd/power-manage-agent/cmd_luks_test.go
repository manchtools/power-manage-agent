package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// F2: process arguments are world-readable through /proc/<pid>/cmdline, and
// the LUKS client reads the passphrase BEFORE it dials the daemon — so a token
// on argv sits in /proc for the entire interactive typing window, and the token
// is the sole authorization for a root daemon that writes LUKS keyslots.
// Nothing the client ships may advertise or accept that form.
func TestLuksCLI_NeverAcceptsTheTokenOnArgv(t *testing.T) {
	source, err := os.ReadFile("cmd_luks.go")
	if err != nil {
		t.Fatalf("read cmd_luks.go: %v", err)
	}
	src := string(source)

	for _, banned := range []string{
		`fs.String("token"`,
		`--token <token>`,
		`--token XXX`,
	} {
		if strings.Contains(src, banned) {
			t.Errorf("cmd_luks.go still carries the argv token form %q; the token must arrive by file, environment, or prompt", banned)
		}
	}
	// Literals, not the package's own constants: the guard must fail if the
	// route is renamed away, not follow the rename.
	for _, required := range []string{"token-file", "PM_LUKS_TOKEN"} {
		if !strings.Contains(src, required) {
			t.Errorf("cmd_luks.go must offer %q as a token route that keeps the token off argv", required)
		}
	}
}

// resolveLuksToken must prefer the routes that keep the token out of
// /proc/<pid>/cmdline, and must fail closed when none of them supplied one.
func TestResolveLuksToken_Ladder(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "token")
	if err := os.WriteFile(file, []byte("  file-token\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("token file wins and is trimmed", func(t *testing.T) {
		got, err := resolveLuksToken(file, "env-token", nil, func() (string, error) {
			t.Fatal("prompt must not run when a token file was given")
			return "", nil
		})
		if err != nil || got != "file-token" {
			t.Fatalf("resolveLuksToken = (%q, %v), want file-token", got, err)
		}
	})

	t.Run("stdin via -", func(t *testing.T) {
		got, err := resolveLuksToken("-", "", strings.NewReader("stdin-token\n"), nil)
		if err != nil || got != "stdin-token" {
			t.Fatalf("resolveLuksToken = (%q, %v), want stdin-token", got, err)
		}
	})

	t.Run("environment before prompt", func(t *testing.T) {
		got, err := resolveLuksToken("", " env-token ", nil, func() (string, error) {
			t.Fatal("prompt must not run when the environment supplied a token")
			return "", nil
		})
		if err != nil || got != "env-token" {
			t.Fatalf("resolveLuksToken = (%q, %v), want env-token", got, err)
		}
	})

	t.Run("prompt is the last resort", func(t *testing.T) {
		got, err := resolveLuksToken("", "", nil, func() (string, error) { return "prompt-token", nil })
		if err != nil || got != "prompt-token" {
			t.Fatalf("resolveLuksToken = (%q, %v), want prompt-token", got, err)
		}
	})

	t.Run("no source fails closed", func(t *testing.T) {
		if got, err := resolveLuksToken("", "", nil, func() (string, error) { return "", nil }); err == nil {
			t.Fatalf("resolveLuksToken = (%q, nil), want an error when nothing supplied a token", got)
		}
	})
}

// A token file other local users can read is the same leak as argv by another
// route, so it is refused rather than warned about.
func TestResolveLuksToken_RefusesReadableTokenFile(t *testing.T) {
	dir := t.TempDir()
	for _, mode := range []os.FileMode{0o644, 0o640, 0o604} {
		file := filepath.Join(dir, "token")
		if err := os.WriteFile(file, []byte("tok"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(file, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := resolveLuksToken(file, "", nil, nil); err == nil {
			t.Errorf("resolveLuksToken accepted a token file at mode %o readable beyond its owner", mode)
		}
	}

	// Positive control: 0600 is accepted, so the check above is not vacuous.
	file := filepath.Join(dir, "private")
	if err := os.WriteFile(file, []byte("tok"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got, err := resolveLuksToken(file, "", nil, nil); err != nil || got != "tok" {
		t.Fatalf("resolveLuksToken(0600 file) = (%q, %v), want the token", got, err)
	}
}

func TestResolveLuksToken_BoundsStreamAndFileInputs(t *testing.T) {
	oversized := strings.Repeat("x", maxLuksTokenBytes+1)
	if _, err := resolveLuksToken("-", "", strings.NewReader(oversized), nil); err == nil {
		t.Fatal("oversized stdin token was accepted")
	}
	file := filepath.Join(t.TempDir(), "oversized-token")
	if err := os.WriteFile(file, []byte(oversized), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := resolveLuksToken(file, "", nil, nil); err == nil {
		t.Fatal("oversized token file was accepted")
	}
}
