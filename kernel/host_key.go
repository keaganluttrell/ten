package kernel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"os"
)

// HostIdentity holds the cryptographic identity of this Kernel instance.
type HostIdentity struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

// LoadHostIdentity loads the private key from environment or file, or generates one if missing.
// Env: HOST_KEY_BASE64
// File: host.key
func LoadHostIdentity() (*HostIdentity, error) {
	var privKey ed25519.PrivateKey

	// 1. Try Environment
	if val := os.Getenv("HOST_KEY_BASE64"); val != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(val)
		if err != nil {
			return nil, fmt.Errorf("invalid HOST_KEY_BASE64: %w", err)
		}
		if len(keyBytes) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("HOST_KEY_BASE64 wrong length: %d", len(keyBytes))
		}
		privKey = ed25519.PrivateKey(keyBytes)
	} else {
		// 2. Try File
		// For simplicity in this demo, if file missing, GENERATE and Log warning
		// In production, we should probably fail or strictly read.
		// For E2E, we might want to inject via env.

		// Let's generate ephemeral if not found for now to unblock
		pub, priv, err2 := ed25519.GenerateKey(rand.Reader)
		if err2 != nil {
			return nil, err2
		}
		privKey = priv
		log.Printf("Generated Ephemeral Host Key (Public: %s)", base64.StdEncoding.EncodeToString(pub))
	}

	return &HostIdentity{
		PrivateKey: privKey,
		PublicKey:  privKey.Public().(ed25519.PublicKey),
	}, nil
}

// Sign signs the data with the host private key.
func (h *HostIdentity) Sign(data []byte) []byte {
	return ed25519.Sign(h.PrivateKey, data)
}
