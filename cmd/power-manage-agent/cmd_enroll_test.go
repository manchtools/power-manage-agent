package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestParseRegistrationURI pins URI parsing (#19): token required, the
// optional pin is carried, the host always normalizes to https, and any
// tls=/skip-verify= query params are ignored (no TLS-bypass path).
func TestParseRegistrationURI(t *testing.T) {
	t.Run("well-formed with pin", func(t *testing.T) {
		u, err := parseRegistrationURI("power-manage://host:8081?token=abc123&pin=DEADBEEF")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if u.ServerURL != "https://host:8081" {
			t.Errorf("ServerURL = %q, want https://host:8081", u.ServerURL)
		}
		if u.Token != "abc123" {
			t.Errorf("Token = %q, want abc123", u.Token)
		}
		if u.Pin != "DEADBEEF" {
			t.Errorf("Pin = %q, want DEADBEEF", u.Pin)
		}
	})
	t.Run("token required", func(t *testing.T) {
		if _, err := parseRegistrationURI("power-manage://host"); err == nil {
			t.Error("expected error for missing token")
		}
		if _, err := parseRegistrationURI("power-manage://host?token="); err == nil {
			t.Error("expected error for empty token")
		}
	})
	t.Run("tls-bypass params ignored", func(t *testing.T) {
		u, err := parseRegistrationURI("power-manage://host?token=t&tls=false&skip-verify=true")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if u.ServerURL != "https://host" {
			t.Errorf("ServerURL = %q, want https://host (no bypass)", u.ServerURL)
		}
	})
}

// TestResolveEnrollToken pins the secure token-delivery precedence (#3):
// file > env > argv flag; missing file errors; whitespace is trimmed.
func TestResolveEnrollToken(t *testing.T) {
	tokenFile := filepath.Join(t.TempDir(), "tok")
	if err := os.WriteFile(tokenFile, []byte("  filetok\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name            string
		flag, file, env string
		want            string
		wantErr         bool
	}{
		{"file wins over env and flag", "flagtok", tokenFile, "envtok", "filetok", false},
		{"env wins over flag", "flagtok", "", "envtok", "envtok", false},
		{"flag last resort", "flagtok", "", "", "flagtok", false},
		{"flag whitespace trimmed", "  flagtok  ", "", "", "flagtok", false},
		{"none", "", "", "", "", false},
		{"missing file errors", "", "/nonexistent/path/tok", "", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveEnrollToken(tc.flag, tc.file, tc.env)
			if tc.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Errorf("resolveEnrollToken(%q,%q,%q) = %q, want %q", tc.flag, tc.file, tc.env, got, tc.want)
			}
		})
	}
}
