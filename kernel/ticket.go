package kernel

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// Ticket represents a verified session token.
type Ticket struct {
	User   string
	Expiry time.Time
	Nonce  string
}

// ValidateTicket fetches a ticket from VFS and verifies its signature.
func ValidateTicket(path string, vfsAddr string, pubKey ed25519.PublicKey, host *HostIdentity, d Dialer) (*Ticket, error) {
	// 1. Dial VFS (Bootstrap connection)
	client, err := d.Dial(vfsAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial vfs: %w", err)
	}
	defer client.Close()

	// 2. Host Auth (Required by VFS for "kernel" user)
	afid, err := HostAuthHandshake(client, host)
	if err != nil {
		// Log but proceed? Failure usually blocks attach.
		fmt.Printf("Warning: Host Auth failed during ticket validation: %v\n", err)
		afid = p9.NOFID
	}

	// Helper for RPC error checking
	rpcCheck := func(req *p9.Fcall) (*p9.Fcall, error) {
		resp, err := client.RPC(req)
		if err != nil {
			return nil, err
		}
		if resp.Type == p9.Rerror {
			return nil, fmt.Errorf("9p error: %s", resp.Ename)
		}
		return resp, nil
	}

	// 3. Attach (as 'none' or 'adm' - kernel needs to read the ticket)
	// In Plan 9, kernel has special access. Here we just attach as "kernel".
	rootFid := uint32(0)
	req := &p9.Fcall{
		Type:  p9.Tattach,
		Fid:   rootFid,
		Afid:  afid,
		Uname: "kernel",
		Aname: "/",
	}
	if _, err := rpcCheck(req); err != nil {
		return nil, fmt.Errorf("vfs attach failed: %w", err)
	}

	// 3. Walk to ticket file
	// path is like "/priv/sessions/alice/abc..."
	// We need to walk to it.
	// Since path is absolute, we should strip leading /.
	cleanPath := strings.TrimPrefix(path, "/")
	parts := strings.Split(cleanPath, "/")

	fileFid := uint32(1)
	walkReq := &p9.Fcall{
		Type:   p9.Twalk,
		Fid:    rootFid,
		Newfid: fileFid,
		Wname:  parts,
	}
	if _, err := rpcCheck(walkReq); err != nil {
		return nil, fmt.Errorf("ticket lookup failed: %w", err)
	}
	defer client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: fileFid}) // Cleanup logic

	// 4. Open
	openReq := &p9.Fcall{
		Type: p9.Topen,
		Fid:  fileFid,
		Mode: 0, // Read
	}
	if _, err := rpcCheck(openReq); err != nil {
		return nil, fmt.Errorf("ticket open failed: %w", err)
	}

	// 5. Read content
	// Tickets are small (< 200 bytes)
	readReq := &p9.Fcall{
		Type:   p9.Tread,
		Fid:    fileFid,
		Offset: 0,
		Count:  1024,
	}
	resp, err := rpcCheck(readReq)
	if err != nil {
		return nil, fmt.Errorf("ticket read failed: %w", err)
	}

	// 6. Parse and Verify
	return parseAndVerify(string(resp.Data), pubKey)
}

func parseAndVerify(content string, pubKey ed25519.PublicKey) (*Ticket, error) {
	// Format: <user> <expiry> <nonce> <sig>
	fields := strings.Fields(content)
	if len(fields) != 4 {
		return nil, errors.New("invalid ticket format")
	}

	user := fields[0]
	expiryStr := fields[1]
	nonce := fields[2]
	sigB64 := fields[3]

	// Check Expiry
	expiryInt, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil {
		return nil, errors.New("invalid expiry format")
	}
	expiry := time.Unix(expiryInt, 0)
	if time.Now().After(expiry) {
		return nil, errors.New("ticket_expired")
	}

	// Check Signature
	// Message = user + expiry + nonce
	message := fmt.Sprintf("%s%s%s", user, expiryStr, nonce)
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, errors.New("invalid signature encoding")
	}

	if !ed25519.Verify(pubKey, []byte(message), sig) {
		return nil, errors.New("invalid_signature")
	}

	return &Ticket{
		User:   user,
		Expiry: expiry,
		Nonce:  nonce,
	}, nil
}
