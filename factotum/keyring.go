// keyring.go handles key storage and retrieval.
// It dials VFS via 9P to read/write public keys at /priv/factotum/<user>/pubkey.
package factotum

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Keyring manages public keys and the signing key.
// For v1, we use local filesystem. In production, this dials VFS via 9P.
type Keyring struct {
	basePath   string // e.g., "/priv/factotum"
	signingKey ed25519.PrivateKey
	publicKey  ed25519.PublicKey
}

// NewKeyring creates a new keyring with the given base path.
func NewKeyring(basePath string) (*Keyring, error) {
	kr := &Keyring{basePath: basePath}

	// Load or generate signing key
	if err := kr.loadOrGenerateSigningKey(); err != nil {
		return nil, err
	}

	return kr, nil
}

// SigningKey returns the private signing key.
func (kr *Keyring) SigningKey() ed25519.PrivateKey {
	return kr.signingKey
}

// PublicKey returns the public signing key.
func (kr *Keyring) PublicKey() ed25519.PublicKey {
	return kr.publicKey
}

// LoadUserKey loads a user's public key.
func (kr *Keyring) LoadUserKey(user string) ([]byte, error) {
	path := filepath.Join(kr.basePath, user, "pubkey")
	return os.ReadFile(path)
}

// SaveUserKey saves a user's public key.
func (kr *Keyring) SaveUserKey(user string, key []byte) error {
	dir := filepath.Join(kr.basePath, user)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, "pubkey")
	return os.WriteFile(path, key, 0600)
}

// DeleteUserKey removes a user's public key.
func (kr *Keyring) DeleteUserKey(user string) error {
	path := filepath.Join(kr.basePath, user, "pubkey")
	return os.Remove(path)
}

// loadOrGenerateSigningKey loads signing.key or creates a new one.
func (kr *Keyring) loadOrGenerateSigningKey() error {
	keyPath := filepath.Join(kr.basePath, "signing.key")

	data, err := os.ReadFile(keyPath)
	if err == nil {
		// Parse existing key
		decoded, err := base64.StdEncoding.DecodeString(string(data))
		if err != nil {
			return fmt.Errorf("invalid signing key: %w", err)
		}
		if len(decoded) != ed25519.PrivateKeySize {
			return errors.New("invalid signing key size")
		}
		kr.signingKey = ed25519.PrivateKey(decoded)
		kr.publicKey = kr.signingKey.Public().(ed25519.PublicKey)
		return nil
	}

	// Generate new key
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	kr.signingKey = priv
	kr.publicKey = pub

	// Save to disk
	if err := os.MkdirAll(kr.basePath, 0700); err != nil {
		return err
	}
	encoded := base64.StdEncoding.EncodeToString(priv)
	return os.WriteFile(keyPath, []byte(encoded), 0600)
}

// RotateSigningKey generates a new signing key and saves it.
// The old key is archived with a timestamp suffix.
func (kr *Keyring) RotateSigningKey() error {
	keyPath := filepath.Join(kr.basePath, "signing.key")

	// Archive old key
	if data, err := os.ReadFile(keyPath); err == nil {
		archivePath := keyPath + "." + fmt.Sprintf("%d", time.Now().Unix())
		os.WriteFile(archivePath, data, 0600)
	}

	// Generate new key
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	kr.signingKey = priv
	kr.publicKey = pub

	// Save new key
	encoded := base64.StdEncoding.EncodeToString(priv)
	return os.WriteFile(keyPath, []byte(encoded), 0600)
}
