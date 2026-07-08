// Package credentials provides secure storage for agent credentials.
// Credentials are encrypted at rest using AES-256-GCM with a key derived
// from the machine ID (Argon2id) and a per-store random salt, written
// 0600 in a 0700 owner-only directory.
//
// At-rest threat model (WS10): the agent runs as root, so the
// credentials.enc + salt files are 0600 in a 0700 root-owned directory —
// no unprivileged local user can read them. The machine-id KDF binds the
// ciphertext to the host (it will not decrypt if copied to another
// machine). It is NOT, however, protection against OFFLINE theft of the
// disk/backup: the machine-id lives on the same disk, so an attacker with
// raw disk access has both. **Full-disk encryption is the at-rest
// protection for that threat** — a same-disk key file would add no real
// defense, so it is intentionally not used (accepted residual). The
// fail-closed guards below ensure the store cannot be FORGED by a
// non-owner (a group/world-writable directory is refused).
package credentials

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"

	sysexec "github.com/manchtools/power-manage-sdk/sys/exec"
	sdkfs "github.com/manchtools/power-manage-sdk/sys/fs"
)

const (
	// Argon2id parameters (RFC 9106 recommendations)
	argonTime    = 1
	argonMemory  = 64 * 1024 // 64 MB
	argonThreads = 4
	argonKeyLen  = 32 // AES-256

	saltLen  = 32
	nonceLen = 12 // GCM standard nonce size

	credentialsFile = "credentials.enc"
	saltFile        = "salt"

	// Default data directory
	DefaultDataDir = "/var/lib/power-manage"

	// credentialsMagicV1 is the magic prefix for the v1 on-disk
	// credential format (Argon2id-derived AES-256-GCM, nonce
	// prepended to the GCM ciphertext). The prefix lets future
	// format migrations (e.g. TPM-sealed key, different KDF
	// parameters, alternate cipher) be detected at Load() time
	// instead of requiring a flag-day migration. Pre-versioning
	// installs have no magic prefix; Load() detects the absence
	// and falls back to the legacy parser.
	credentialsMagicV1 = "pmcred:v1:"
)

// Credentials holds the agent's identity and certificates.
type Credentials struct {
	DeviceID    string `json:"device_id"`
	CACert      []byte `json:"ca_cert"`
	Certificate []byte `json:"certificate"`
	PrivateKey  []byte `json:"private_key"`
	GatewayAddr string `json:"gateway_addr"`
	ControlAddr string `json:"control_addr,omitempty"` // Control Server URL for device auth proxy
}

// Store manages encrypted credential storage.
type Store struct {
	dataDir string
	fs      sdkfs.Manager
	fsErr   error // deferred fs-manager construction error, surfaced fail-closed on write
}

// NewStore creates a new credential store. Writes go through the SDK fs Manager
// over a Direct runner: the agent runs as root and owns its data directory, so
// no privilege escalation is needed; WriteFile is atomic (temp + rename).
func NewStore(dataDir string) *Store {
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	s := &Store{dataDir: dataDir}
	r, err := sysexec.NewRunner(sysexec.Direct)
	if err != nil {
		s.fsErr = fmt.Errorf("credentials: build direct runner: %w", err)
		return s
	}
	m, err := sdkfs.New(r)
	if err != nil {
		s.fsErr = fmt.Errorf("credentials: build fs manager: %w", err)
		return s
	}
	s.fs = m
	return s
}

// writeFile atomically writes data at 0600 through the Direct fs Manager,
// surfacing any deferred construction error fail-closed.
func (s *Store) writeFile(path string, data []byte) error {
	if s.fsErr != nil {
		return s.fsErr
	}
	return s.fs.WriteFile(context.Background(), path, data, sdkfs.WriteOptions{Mode: 0600})
}

// Exists checks if credentials exist.
func (s *Store) Exists() bool {
	_, err := os.Stat(filepath.Join(s.dataDir, credentialsFile))
	return err == nil
}

// requireOwnerOnlyDir fails closed if the credential-store directory is
// group- or world-writable: a writable store dir lets a non-owner forge
// the salt/ciphertext (and thus the agent's identity). World-readable is
// tolerated — the secret files themselves are 0600 — but writable is
// not. WS10 #1/#2 (the honest forgeable-store guard; the KDF itself is
// machine-id + FDE per the package doc).
func requireOwnerOnlyDir(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("stat store directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return fmt.Errorf("store path %s is not a directory", dir)
	}
	if info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("store directory %s is group/world-writable (%#o); it must be owner-only-writable (0700)", dir, info.Mode().Perm())
	}
	return nil
}

// Save encrypts and saves credentials to disk.
func (s *Store) Save(creds *Credentials) error {
	// Ensure data directory exists with secure permissions
	if err := os.MkdirAll(s.dataDir, 0700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
	}
	// Tighten an existing dir to 0700 (MkdirAll does not narrow an
	// already-present directory), then fail closed if it is still
	// group/world-writable (e.g. someone re-loosened it).
	if err := os.Chmod(s.dataDir, 0700); err != nil {
		return fmt.Errorf("secure data directory: %w", err)
	}
	if err := requireOwnerOnlyDir(s.dataDir); err != nil {
		return err
	}

	// Generate or load salt
	salt, err := s.loadOrCreateSalt()
	if err != nil {
		return fmt.Errorf("load/create salt: %w", err)
	}

	// Derive encryption key
	key, err := s.deriveKey(salt)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}

	// Serialize credentials
	plaintext, err := json.Marshal(creds)
	if err != nil {
		return fmt.Errorf("marshal credentials: %w", err)
	}

	// Encrypt and prepend the format-version magic. New writes
	// always use v1; Load() recognises both v1 (magic-prefixed) and
	// the original unprefixed layout for backward compatibility with
	// agents enrolled before the format was versioned. Future
	// migrations (e.g. TPM-sealed key, different KDF parameters)
	// bump the magic and Load() picks the matching path.
	ciphertext, err := encrypt(key, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt credentials: %w", err)
	}
	ciphertext = append([]byte(credentialsMagicV1), ciphertext...)

	// Write encrypted credentials atomically. A direct os.WriteFile
	// leaves a partially written file on crash / full disk / power
	// loss, which corrupts the agent's enrollment and forces a
	// re-enroll. Temp-file + fsync + rename is the standard
	// cure — rename is atomic within a single filesystem, the
	// fsync before rename ensures the new contents are on disk
	// before the directory entry is swapped, and the parent-dir
	// fsync afterwards flushes the directory entry itself.
	credPath := filepath.Join(s.dataDir, credentialsFile)
	if err := s.writeFile(credPath, ciphertext); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}

	return nil
}

// Load decrypts and loads credentials from disk.
func (s *Store) Load() (*Credentials, error) {
	// Fail closed if the store directory is forgeable (group/world-
	// writable) — a non-owner could have swapped the salt/ciphertext.
	if err := requireOwnerOnlyDir(s.dataDir); err != nil {
		return nil, err
	}

	// Load salt
	saltPath := filepath.Join(s.dataDir, saltFile)
	salt, err := os.ReadFile(saltPath)
	if err != nil {
		return nil, fmt.Errorf("read salt: %w", err)
	}

	// Derive decryption key
	key, err := s.deriveKey(salt)
	if err != nil {
		return nil, fmt.Errorf("derive key: %w", err)
	}

	// Read encrypted credentials
	credPath := filepath.Join(s.dataDir, credentialsFile)
	ciphertext, err := os.ReadFile(credPath)
	if err != nil {
		return nil, fmt.Errorf("read credentials: %w", err)
	}

	// Strip the format-version magic if present. New writes always
	// include the v1 prefix; pre-versioning installs have raw
	// nonce+ciphertext with no prefix. The decrypt path is identical
	// either way once the prefix is removed — the version difference
	// is purely about future-proofing format migrations, not about
	// the cipher in use today.
	//
	// Audit F038: reject any future "pmcred:vN:" prefix that isn't
	// the v1 we know about. Without this guard a v2 blob would fall
	// through to decrypt and surface as an opaque AES-GCM auth-tag
	// error, which is hard to diagnose. Tell the operator they need
	// to re-enroll instead.
	if bytes.HasPrefix(ciphertext, []byte(credentialsMagicV1)) {
		ciphertext = ciphertext[len(credentialsMagicV1):]
	} else if bytes.HasPrefix(ciphertext, []byte("pmcred:")) {
		return nil, errors.New("unsupported credentials format version, please re-enroll the agent (delete credentials.enc and re-run with a fresh registration token)")
	}

	// Decrypt
	plaintext, err := decrypt(key, ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decrypt credentials: %w", err)
	}

	// Deserialize
	var creds Credentials
	if err := json.Unmarshal(plaintext, &creds); err != nil {
		return nil, fmt.Errorf("unmarshal credentials: %w", err)
	}

	return &creds, nil
}

// Delete removes stored credentials.
func (s *Store) Delete() error {
	credPath := filepath.Join(s.dataDir, credentialsFile)
	saltPath := filepath.Join(s.dataDir, saltFile)

	if err := os.Remove(credPath); err != nil && !os.IsNotExist(err) {
		slog.Warn("failed to remove credentials file", "path", credPath, "error", err)
	}
	if err := os.Remove(saltPath); err != nil && !os.IsNotExist(err) {
		slog.Warn("failed to remove salt file", "path", saltPath, "error", err)
	}

	return nil
}

// DataDir returns the data directory path.
func (s *Store) DataDir() string {
	return s.dataDir
}

// loadOrCreateSalt loads existing salt or creates a new one.
func (s *Store) loadOrCreateSalt() ([]byte, error) {
	saltPath := filepath.Join(s.dataDir, saltFile)

	// Try to load existing salt
	salt, err := os.ReadFile(saltPath)
	if err == nil && len(salt) == saltLen {
		return salt, nil
	}
	// A PRESENT salt file with the wrong length is corruption, not
	// first-boot (#173): silently regenerating destroyed the forensic
	// signal AND guaranteed the paired credentials.enc could never
	// decrypt again — fail loudly so the operator sees the corruption
	// and re-enrolls deliberately.
	if err == nil {
		return nil, fmt.Errorf("salt file %s is corrupt (%d bytes, want %d) — refusing to regenerate; delete it together with %s to re-enroll", saltPath, len(salt), saltLen, credentialsFile)
	}
	if !os.IsNotExist(err) {
		return nil, fmt.Errorf("read salt: %w", err)
	}

	// Generate new salt
	salt = make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	// Save salt atomically — the salt is paired with the encrypted
	// credentials and a corrupt salt is just as fatal as a corrupt
	// credentials.enc.
	if err := s.writeFile(saltPath, salt); err != nil {
		return nil, fmt.Errorf("write salt: %w", err)
	}

	return salt, nil
}

// deriveKey derives an encryption key from the machine ID and salt.
func (s *Store) deriveKey(salt []byte) ([]byte, error) {
	machineID, err := getMachineID()
	if err != nil {
		return nil, fmt.Errorf("get machine ID: %w", err)
	}

	// Derive key using Argon2id
	key := argon2.IDKey(machineID, salt, argonTime, argonMemory, argonThreads, argonKeyLen)
	return key, nil
}

// getMachineID reads the machine ID from the system. It is a package var
// (not a plain func) so tests can inject a synthetic machine ID to prove
// the cross-machine binding (credentials saved under one machine ID do
// not decrypt under another).
var getMachineID = func() ([]byte, error) {
	// COMPAT PIN (#173): the RAW file bytes — including the trailing
	// newline — are the Argon2id password. Trimming, normalizing, or
	// re-encoding here would silently change the derived key and brick
	// decryption of every credentials.enc in the fleet. Never "clean
	// this up"; a format change requires a versioned migration
	// (credentialsMagicV1 exists for exactly that).
	// Try /etc/machine-id first (systemd)
	id, err := os.ReadFile("/etc/machine-id")
	if err == nil && len(id) > 0 {
		return id, nil
	}

	// Fallback to /var/lib/dbus/machine-id
	id, err = os.ReadFile("/var/lib/dbus/machine-id")
	if err == nil && len(id) > 0 {
		return id, nil
	}

	return nil, errors.New("machine ID not found")
}

// MachineIDAvailable reports whether a machine ID can be read on this host.
// Credential save/load (and cert rotation, which round-trips through the
// credential store) need it for the KDF binding, so cmd-level tests use this to
// skip cleanly on machine-id-less hosts rather than hard-failing.
func MachineIDAvailable() bool {
	_, err := getMachineID()
	return err == nil
}

// encrypt encrypts plaintext using AES-256-GCM.
func encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	// Prepend nonce to ciphertext
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt decrypts ciphertext using AES-256-GCM.
func decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < nonceLen {
		return nil, errors.New("ciphertext too short")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := ciphertext[:nonceLen]
	ciphertext = ciphertext[nonceLen:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
