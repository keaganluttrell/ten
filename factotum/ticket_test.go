package factotum

import (
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestGenerateAndVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	user := "alice"
	ticket := Generate(user, priv)

	assert.Equal(t, user, ticket.User)
	assert.NotEmpty(t, ticket.Nonce)
	assert.NotEmpty(t, ticket.Sig)
	assert.False(t, ticket.IsExpired())

	// Verify signature
	assert.True(t, ticket.Verify(pub))

	// Verify with wrong key
	wrongPub, _, _ := ed25519.GenerateKey(rand.Reader)
	assert.False(t, ticket.Verify(wrongPub))
}

func TestTicketExpiry(t *testing.T) {
	user := "bob"
	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Create a ticket manually with past expiry
	ticket := Generate(user, priv)
	ticket.Expiry = time.Now().Add(-1 * time.Hour)

	assert.True(t, ticket.IsExpired())
}

func TestParseTicket(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	ticket := Generate("charlie", priv)
	ticketStr := ticket.String()

	// 1. Valid parse
	parsed, err := ParseTicket(ticketStr)
	assert.NoError(t, err)
	assert.Equal(t, ticket.User, parsed.User)
	assert.Equal(t, ticket.Nonce, parsed.Nonce)
	// Time comparison can be tricky due to precision, check unix timestamp
	assert.Equal(t, ticket.Expiry.Unix(), parsed.Expiry.Unix())
	assert.Equal(t, ticket.Sig, parsed.Sig)
	assert.True(t, parsed.Verify(pub))

	// 2. Invalid format (too few fields)
	_, err = ParseTicket("alice 123456 abc")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid ticket format")

	// 3. Invalid expiry
	parts := strings.Fields(ticketStr)
	parts[1] = "not-a-number"
	badExpiry := strings.Join(parts, " ")
	_, err = ParseTicket(badExpiry)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid expiry")
}
