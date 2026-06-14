package credentials

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSavePermissions pins WS10 #2: the secret-bearing files are 0600 and
// the store directory is 0700 after Save.
func TestSavePermissions(t *testing.T) {
	requireMachineID(t)
	dir := t.TempDir()
	store := NewStore(dir)
	if err := store.Save(sampleCreds()); err != nil {
		t.Fatalf("Save: %v", err)
	}

	for _, f := range []string{credentialsFile, saltFile} {
		info, err := os.Stat(filepath.Join(dir, f))
		if err != nil {
			t.Fatalf("stat %s: %v", f, err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Errorf("%s mode = %v, want 0600", f, info.Mode().Perm())
		}
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("store dir mode = %v, want 0700", di.Mode().Perm())
	}
}

// TestLoadSubstitutedSaltFails pins WS10 #6: replacing the salt yields a
// different derived key, so Load fails (GCM auth). Distinct from the
// missing-salt and tag-flip cases.
func TestLoadSubstitutedSaltFails(t *testing.T) {
	requireMachineID(t)
	dir := t.TempDir()
	store := NewStore(dir)
	if err := store.Save(sampleCreds()); err != nil {
		t.Fatalf("Save: %v", err)
	}

	subst := make([]byte, saltLen)
	for i := range subst {
		subst[i] = 0xAB
	}
	if err := os.WriteFile(filepath.Join(dir, saltFile), subst, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(); err == nil {
		t.Fatal("expected Load to fail with a substituted salt (different derived key)")
	}
}

// TestLoadCrossMachineFails pins WS10 #1's machine-binding intent: creds
// saved under one machine ID do not decrypt under another.
func TestLoadCrossMachineFails(t *testing.T) {
	dir := t.TempDir()
	store := NewStore(dir)

	prev := getMachineID
	t.Cleanup(func() { getMachineID = prev })

	getMachineID = func() ([]byte, error) { return []byte("machine-id-AAAAAAAAAAAA"), nil }
	if err := store.Save(sampleCreds()); err != nil {
		t.Fatalf("Save (machine A): %v", err)
	}

	getMachineID = func() ([]byte, error) { return []byte("machine-id-BBBBBBBBBBBB"), nil }
	if _, err := store.Load(); err == nil {
		t.Fatal("expected Load to fail under a different machine ID")
	}
}

// TestLoadTruncatedCiphertextTooShort pins WS10 #6: a credentials.enc
// whose post-magic body is shorter than the nonce surfaces the explicit
// "ciphertext too short" rejection, not an opaque GCM error.
func TestLoadTruncatedCiphertextTooShort(t *testing.T) {
	requireMachineID(t)
	dir := t.TempDir()
	store := NewStore(dir)
	if err := store.Save(sampleCreds()); err != nil { // creates a valid salt
		t.Fatalf("Save: %v", err)
	}

	short := append([]byte(credentialsMagicV1), []byte("xx")...) // 2 bytes < nonceLen
	if err := os.WriteFile(filepath.Join(dir, credentialsFile), short, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := store.Load()
	if err == nil || !strings.Contains(err.Error(), "too short") {
		t.Fatalf("expected 'ciphertext too short', got: %v", err)
	}
}

// TestRefusesWritableStoreDir pins WS10 #1/#2 fail-closed guard: a
// group/world-writable store directory (forgeable by a non-owner) is
// refused on Load.
func TestRefusesWritableStoreDir(t *testing.T) {
	requireMachineID(t)
	dir := t.TempDir()
	store := NewStore(dir)
	if err := store.Save(sampleCreds()); err != nil {
		t.Fatalf("Save: %v", err)
	}

	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) }) // let t.TempDir clean up

	_, err := store.Load()
	if err == nil || !strings.Contains(err.Error(), "writable") {
		t.Fatalf("expected refusal of a world-writable store dir, got: %v", err)
	}
}

// TestSaveTightensLooseDir pins that Save narrows a pre-existing loose
// directory to 0700 (self-heal) rather than failing.
func TestSaveTightensLooseDir(t *testing.T) {
	requireMachineID(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o775); err != nil { // group-writable
		t.Fatal(err)
	}
	store := NewStore(dir)
	if err := store.Save(sampleCreds()); err != nil {
		t.Fatalf("Save should tighten and succeed, got: %v", err)
	}
	di, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("Save did not tighten the dir to 0700, got %v", di.Mode().Perm())
	}
}
