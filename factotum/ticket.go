// Package factotum is the authentication agent for Project Ten.
// It provides WebAuthn ceremonies and ticket-based session management.
package factotum

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Ticket represents a session token stored in VFS.
// Format: <user> <expiry> <nonce> <sig>
type Ticket struct {
	User   string
	Expiry time.Time
	Nonce  string
	Sig    string // base64(ed25519.Sign(user+expiry+nonce))
}

// DefaultTTL is the default ticket lifetime.
const DefaultTTL = 7 * 24 * time.Hour

// ParseTicket parses a space-delimited ticket string.
func ParseTicket(line string) (Ticket, error) {
	fields := strings.Fields(line)
	if len(fields) != 4 {
		return Ticket{}, errors.New("invalid ticket format")
	}
	expiry, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return Ticket{}, fmt.Errorf("invalid expiry: %w", err)
	}
	return Ticket{
		User:   fields[0],
		Expiry: time.Unix(expiry, 0),
		Nonce:  fields[2],
		Sig:    fields[3],
	}, nil
}

// String returns the space-delimited ticket format.
func (t Ticket) String() string {
	return fmt.Sprintf("%s %d %s %s", t.User, t.Expiry.Unix(), t.Nonce, t.Sig)
}

// IsExpired returns true if the ticket has expired.
func (t Ticket) IsExpired() bool {
	return time.Now().After(t.Expiry)
}

// Generate creates a new ticket for the given user.
func Generate(user string, key ed25519.PrivateKey) Ticket {
	nonce := generateNonce()
	expiry := time.Now().Add(DefaultTTL)

	// Sign: user + expiry + nonce
	message := fmt.Sprintf("%s%d%s", user, expiry.Unix(), nonce)
	sig := ed25519.Sign(key, []byte(message))

	return Ticket{
		User:   user,
		Expiry: expiry,
		Nonce:  nonce,
		Sig:    base64.StdEncoding.EncodeToString(sig),
	}
}

// Verify checks the ticket signature against the public key.
func (t Ticket) Verify(pub ed25519.PublicKey) bool {
	message := fmt.Sprintf("%s%d%s", t.User, t.Expiry.Unix(), t.Nonce)
	sig, err := base64.StdEncoding.DecodeString(t.Sig)
	if err != nil {
		return false
	}
	return ed25519.Verify(pub, []byte(message), sig)
}

// generateNonce creates a random 16-byte hex string.
func generateNonce() string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("%x", b)
}
