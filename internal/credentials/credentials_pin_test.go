package credentials

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// COMPAT PIN (#173): the machine-id KDF password is the RAW file bytes,
// trailing newline included. If a refactor ever trims or normalizes the
// bytes, every deployed credentials.enc stops decrypting. This test
// freezes the contract: two machine IDs that differ only in a trailing
// newline must derive DIFFERENT keys (i.e., the newline is significant).
func TestMachineID_RawBytesAreTheKDFContract(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)

	orig := getMachineID
	t.Cleanup(func() { getMachineID = orig })

	getMachineID = func() ([]byte, error) { return []byte("abc123\n"), nil }
	if err := s.Save(sampleCreds()); err != nil {
		t.Fatalf("Save: %v", err)
	}

	// Same ID without the newline must NOT decrypt — proving the raw
	// bytes (newline included) are what the key is derived from.
	getMachineID = func() ([]byte, error) { return []byte("abc123"), nil }
	if _, err := s.Load(); err == nil {
		t.Fatal("credentials decrypted after the machine-id bytes changed by only a trailing newline — the raw-bytes KDF contract is broken")
	}

	// The original raw bytes still decrypt.
	getMachineID = func() ([]byte, error) { return []byte("abc123\n"), nil }
	if _, err := s.Load(); err != nil {
		t.Fatalf("original raw machine-id bytes must keep decrypting: %v", err)
	}
}

// #173: a present-but-corrupt salt file must fail loudly, never be
// silently regenerated (which destroys the forensic signal and
// permanently orphans the paired credentials.enc).
func TestLoadOrCreateSalt_CorruptSaltFailsClosed(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	if err := os.WriteFile(filepath.Join(dir, saltFile), []byte("short"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err := s.loadOrCreateSalt()
	if err == nil {
		t.Fatal("corrupt salt must fail closed, not regenerate")
	}
	if !strings.Contains(err.Error(), "corrupt") {
		t.Fatalf("error must name the corruption, got: %v", err)
	}
	// The corrupt file must be left in place for forensics.
	got, rerr := os.ReadFile(filepath.Join(dir, saltFile))
	if rerr != nil || string(got) != "short" {
		t.Fatalf("corrupt salt file must be preserved, got %q err=%v", got, rerr)
	}
}
