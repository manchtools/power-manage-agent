// Package credentials provides secure storage for agent credentials.
// Credentials are encrypted at rest using AES-256-GCM with a key derived
// from the machine ID using Argon2id.
package credentials

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
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
}

// NewStore creates a new credential store.
func NewStore(dataDir string) *Store {
	if dataDir == "" {
		dataDir = DefaultDataDir
	}
	return &Store{dataDir: dataDir}
}

// Exists checks if credentials exist.
func (s *Store) Exists() bool {
	_, err := os.Stat(filepath.Join(s.dataDir, credentialsFile))
	return err == nil
}

// Save encrypts and saves credentials to disk.
func (s *Store) Save(creds *Credentials) error {
	// Ensure data directory exists with secure permissions
	if err := os.MkdirAll(s.dataDir, 0700); err != nil {
		return fmt.Errorf("create data directory: %w", err)
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

	// Encrypt
	ciphertext, err := encrypt(key, plaintext)
	if err != nil {
		return fmt.Errorf("encrypt credentials: %w", err)
	}

	// Write encrypted credentials with secure permissions
	credPath := filepath.Join(s.dataDir, credentialsFile)
	if err := os.WriteFile(credPath, ciphertext, 0600); err != nil {
		return fmt.Errorf("write credentials: %w", err)
	}

	return nil
}

// Load decrypts and loads credentials from disk.
func (s *Store) Load() (*Credentials, error) {
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

	os.Remove(credPath)
	os.Remove(saltPath)

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

	// Generate new salt
	salt = make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, fmt.Errorf("generate salt: %w", err)
	}

	// Save salt with secure permissions
	if err := os.WriteFile(saltPath, salt, 0600); err != nil {
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

// getMachineID reads the machine ID from the system.
func getMachineID() ([]byte, error) {
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

// GenerateCSR creates a new ECDSA P-256 key pair and returns the CSR (PEM)
// and private key (PEM). The private key never leaves the agent.
func GenerateCSR(hostname string) (csrPEM, keyPEM []byte, err error) {
	// Generate ECDSA P-256 key pair
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate key pair: %w", err)
	}

	// Create CSR template
	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: hostname,
		},
		DNSNames: []string{hostname},
	}

	// Generate CSR
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create CSR: %w", err)
	}

	// Encode CSR to PEM
	csrPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	// Encode private key to PEM
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal private key: %w", err)
	}

	keyPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
	})

	return csrPEM, keyPEM, nil
}

// GenerateCSRFromKey creates a CSR using an existing private key (PEM-encoded).
// This is used for certificate renewal where the key pair is reused.
func GenerateCSRFromKey(hostname string, keyPEM []byte) (csrPEM []byte, err error) {
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("failed to decode key PEM")
	}

	privateKey, err := x509.ParseECPrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse private key: %w", err)
	}

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName: hostname,
		},
		DNSNames: []string{hostname},
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, privateKey)
	if err != nil {
		return nil, fmt.Errorf("create CSR: %w", err)
	}

	csrPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})

	return csrPEM, nil
}
