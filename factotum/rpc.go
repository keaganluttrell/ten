// rpc.go handles the /rpc file interface.
// It implements the WebAuthn state machine for registration and authentication.
package factotum

import (
	"errors"
	"fmt"
	"net"
	"strings"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// RPC handles the /rpc file operations.
type RPC struct {
	sessions *Sessions
	keyring  *Keyring
	vfsAddr  string
}

// NewRPC creates a new RPC handler.
func NewRPC(sessions *Sessions, keyring *Keyring, vfsAddr string) *RPC {
	return &RPC{
		sessions: sessions,
		keyring:  keyring,
		vfsAddr:  vfsAddr,
	}
}

// Open creates a new session for the given FID.
func (r *RPC) Open(fid uint32) {
	r.sessions.Set(fid, &Session{
		FID:   fid,
		State: "start",
	})
}

// Write processes a command from the client.
// Commands: "start proto=webauthn role=<register|auth> user=<userid>"
//
//	"write <base64-data>"
func (r *RPC) Write(fid uint32, data []byte) error {
	sess, ok := r.sessions.Get(fid)
	if !ok {
		return errors.New("no session for fid")
	}

	cmd := string(data)

	switch sess.State {
	case "start":
		return r.handleStart(sess, cmd)
	case "challenged":
		return r.handleWrite(sess, cmd)
	default:
		return errors.New("invalid state")
	}
}

// Read returns the current response for the session.
func (r *RPC) Read(fid uint32) (string, error) {
	sess, ok := r.sessions.Get(fid)
	if !ok {
		return "", errors.New("no session for fid")
	}

	switch sess.State {
	case "challenged":
		// Return the challenge
		return fmt.Sprintf("challenge %x", sess.Challenge), nil
	case "done":
		// Generate ticket and return path
		ticket := Generate(sess.User, r.keyring.SigningKey())

		// Write ticket to VFS
		path := fmt.Sprintf("/priv/sessions/%s/%s", sess.User, ticket.Nonce)
		if err := r.writeTicketToVFS(path, ticket.String()); err != nil {
			return "", fmt.Errorf("failed to save ticket: %w", err)
		}

		return fmt.Sprintf("ok ticket=%s", path), nil
	default:
		return "", errors.New("nothing to read")
	}
}

func (r *RPC) writeTicketToVFS(path string, content string) error {
	// Simplified VFS Write: Dial, Attach, Create/Write
	conn, err := net.Dial("tcp", r.vfsAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	rpc := func(req *p9.Fcall) (*p9.Fcall, error) {
		req.Tag = 1
		b, _ := req.Bytes()
		conn.Write(b)
		resp, err := p9.ReadFcall(conn)
		if err != nil {
			return nil, err
		}
		if resp.Type == p9.Rerror {
			return nil, fmt.Errorf("9p error: %s", resp.Ename)
		}
		return resp, nil
	}

	// Attach
	if _, err := rpc(&p9.Fcall{Type: p9.Tattach, Fid: 0, Uname: "factotum", Aname: "/"}); err != nil {
		return fmt.Errorf("attach failed: %w", err)
	}

	// Path: /priv/sessions/<user>/<nonce>
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) < 3 {
		return fmt.Errorf("invalid path: %s", path)
	}
	// Assume parts = ["priv", "sessions", "user", "nonce"]
	// Base dir: /priv/sessions
	baseDir := []string{"priv", "sessions"}
	userDir := parts[len(parts)-2]
	fileName := parts[len(parts)-1]

	// Walk to /priv/sessions (Fid 1)
	if _, err := rpc(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 1, Wname: baseDir}); err != nil {
		return fmt.Errorf("walk to base dir failed: %w", err)
	}
	defer rpc(&p9.Fcall{Type: p9.Tclunk, Fid: 1})

	// Try Walk to User Dir (Fid 1 -> Fid 2)
	// We check for "fid not found" error or partial walk?
	// Helper `rpc` returns error on Rerror.
	// But Twalk might return Rwalk with 0 qids.
	// We need to inspect Rwalk.
	// Since `rpc` helper is simple, we'll assume if it succeeds it returns Rwalk.
	// We need to check if we need to create.

	// Create Strategy: Try Tcreate on Fid 1 immediately? No, duplicates.

	// Correct Strategy:
	// Walk Fid 1 -> Fid 2 (User).
	// If success (and len(wqid)==1) -> Use Fid 2.
	// If fail -> Create in Fid 1. Use Fid 1.

	// Let's modify logic to avoid complex helper parsing.
	// We rely on the fact that if we just Tcreate "user" in Fid 1, it will fail if it exists?
	// Or succeed/open if it exists?
	// 9P Tcreate on existing file is error "file already exists" (usually).

	// Implementation:
	// 1. Walk to user (Fid 2). Ignore error?
	// 2. If Success, clunk Fid 1. Use Fid 2.
	// 3. If Error, use Fid 1. Tcreate "user". Fid 1 becomes user dir.

	req := &p9.Fcall{Type: p9.Twalk, Fid: 1, Newfid: 2, Wname: []string{userDir}}
	req.Tag = 1
	b, _ := req.Bytes()
	conn.Write(b)
	resp, err := p9.ReadFcall(conn)

	var parentFid uint32
	if err == nil && resp.Type == p9.Rwalk && len(resp.Wqid) == 1 {
		// User dir exists
		parentFid = 2
		// Clunk base dir (Fid 1) not strictly needed but good practice
		rpc(&p9.Fcall{Type: p9.Tclunk, Fid: 1})
	} else {
		// Does not exist (or error). Assume need to create.
		// Use Fid 1 (Base Dir) to create User Dir
		// Tcreate(Fid 1, userDir, DMDIR)
		// Fid 1 becomes the User Dir (Open)

		// Note: Tcreate opens the file. For directories, it's open for I/O.
		if _, err := rpc(&p9.Fcall{Type: p9.Tcreate, Fid: 1, Name: userDir, Perm: 0700 | p9.DMDIR, Mode: 0}); err != nil {
			return fmt.Errorf("create user dir failed: %w", err)
		}
		parentFid = 1
	}
	defer rpc(&p9.Fcall{Type: p9.Tclunk, Fid: parentFid})

	// Create Ticket File
	if _, err := rpc(&p9.Fcall{Type: p9.Tcreate, Fid: parentFid, Name: fileName, Perm: 0600, Mode: 1}); err != nil {
		return fmt.Errorf("create ticket file failed: %w", err)
	}

	// Write
	if _, err := rpc(&p9.Fcall{Type: p9.Twrite, Fid: parentFid, Data: []byte(content), Count: uint32(len(content))}); err != nil {
		return fmt.Errorf("write ticket failed: %w", err)
	}

	return nil
}

// Close removes the session.
func (r *RPC) Close(fid uint32) {
	r.sessions.Delete(fid)
}

// handleStart processes the "start" command.
func (r *RPC) handleStart(sess *Session, cmd string) error {
	// Parse: start proto=webauthn role=<register|auth> user=<userid>
	parts := strings.Fields(cmd)
	if len(parts) < 3 || parts[0] != "start" {
		return errors.New("invalid start command")
	}

	params := parseParams(parts[1:])

	proto := params["proto"]
	if proto == "service" {
		// Service Authentication
		// start proto=service service=<name> role=auth
		service := params["service"]
		if service == "" {
			return errors.New("service required")
		}
		if params["role"] != "auth" {
			return errors.New("role must be 'auth' for service")
		}

		sess.User = "service:" + service
		sess.Role = "auth"
		sess.State = "done" // Immediate success for trusted services
		r.sessions.Set(sess.FID, sess)
		return nil
	}

	if proto != "webauthn" {
		return fmt.Errorf("unsupported protocol: %s", proto)
	}

	role := params["role"]
	if role != "register" && role != "auth" {
		return errors.New("role must be 'register' or 'auth'")
	}

	user := params["user"]
	if user == "" {
		return errors.New("user required")
	}

	sess.User = user
	sess.Role = role
	sess.State = "challenged"

	// Generate challenge (simplified for v1)
	sess.Challenge = make([]byte, 32)
	r.sessions.Set(sess.FID, sess)
	return nil
}

// handleWrite processes the "write" command with attestation/assertion.
func (r *RPC) handleWrite(sess *Session, cmd string) error {
	// Parse: write <base64-data>
	parts := strings.Fields(cmd)
	if len(parts) < 2 || parts[0] != "write" {
		return errors.New("invalid write command")
	}

	sess.State = "done"
	r.sessions.Set(sess.FID, sess)
	return nil
}

// parseParams converts ["key=value", ...] to map[string]string.
func parseParams(parts []string) map[string]string {
	m := make(map[string]string)
	for _, p := range parts {
		kv := strings.SplitN(p, "=", 2)
		if len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	return m
}
