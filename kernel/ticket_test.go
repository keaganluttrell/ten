package kernel

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
	"github.com/stretchr/testify/assert"
)

func TestValidateTicket(t *testing.T) {
	// Generate Keypair
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Create valid ticket
	user := "alice"
	expiryStr := fmt.Sprintf("%d", time.Now().Add(1*time.Hour).Unix())
	nonce := "12345"
	msg := user + expiryStr + nonce
	sig := ed25519.Sign(priv, []byte(msg))
	sigB64 := base64.StdEncoding.EncodeToString(sig)

	ticketContent := fmt.Sprintf("%s %s %s %s", user, expiryStr, nonce, sigB64)

	// Setup Mock VFS
	md := NewMockDialer()
	md.Handlers["vfs:9002"] = SimpleServerHandler(t, func(req *p9.Fcall) *p9.Fcall {
		if req.Type == p9.Tread {
			return &p9.Fcall{
				Type: p9.Rread,
				Data: []byte(ticketContent),
			}
		}
		if req.Type == p9.Tattach || req.Type == p9.Twalk || req.Type == p9.Topen || req.Type == p9.Tclunk {
			return &p9.Fcall{Type: req.Type + 1}
		}
		return &p9.Fcall{Type: p9.Rerror, Ename: "unexpected"}
	})

	// Test
	ticket, err := ValidateTicket("/priv/sessions/alice/ticket", "vfs:9002", pub, nil, md)
	assert.NoError(t, err)
	assert.Equal(t, "alice", ticket.User)
	assert.Equal(t, nonce, ticket.Nonce)
}

func TestValidateTicket_Expired(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Expired Ticket
	user := "bob"
	expiryStr := fmt.Sprintf("%d", time.Now().Add(-1*time.Hour).Unix())
	nonce := "12345"
	msg := user + expiryStr + nonce
	sig := ed25519.Sign(priv, []byte(msg))
	sigB64 := base64.StdEncoding.EncodeToString(sig)
	ticketContent := fmt.Sprintf("%s %s %s %s", user, expiryStr, nonce, sigB64)

	md := NewMockDialer()
	md.Handlers["vfs:9002"] = SimpleServerHandler(t, func(req *p9.Fcall) *p9.Fcall {
		if req.Type == p9.Tread {
			return &p9.Fcall{Type: p9.Rread, Data: []byte(ticketContent)}
		}
		return &p9.Fcall{Type: req.Type + 1}
	})

	_, err := ValidateTicket("/abc", "vfs:9002", pub, nil, md)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ticket_expired")
}
