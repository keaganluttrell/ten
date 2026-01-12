// rpc.go handles the /rpc file interface.
// It implements the WebAuthn state machine for registration and authentication.
package factotum

import (
	"errors"
	"fmt"
	"strings"
)

// RPC handles the /rpc file operations.
type RPC struct {
	sessions *Sessions
	keyring  *Keyring
	// webauthn instance would go here
}

// NewRPC creates a new RPC handler.
func NewRPC(sessions *Sessions, keyring *Keyring) *RPC {
	return &RPC{
		sessions: sessions,
		keyring:  keyring,
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
		// In real impl, this would be base64-encoded challenge from WebAuthn
		return fmt.Sprintf("challenge %x", sess.Challenge), nil
	case "done":
		// Generate ticket and return path
		ticket := Generate(sess.User, r.keyring.SigningKey())
		// TODO: Write ticket to VFS at /priv/sessions/<user>/<nonce>
		return fmt.Sprintf("ok ticket=/priv/sessions/%s/%s", sess.User, ticket.Nonce), nil
	default:
		return "", errors.New("nothing to read")
	}
}

// Close removes the session.
func (r *RPC) Close(fid uint32) {
	r.sessions.Delete(fid)
}

// handleStart processes the "start" command.
func (r *RPC) handleStart(sess *Session, cmd string) error {
	// Parse: start proto=webauthn role=<register|auth> user=<userid>
	parts := strings.Fields(cmd)
	if len(parts) < 4 || parts[0] != "start" {
		return errors.New("invalid start command")
	}

	params := parseParams(parts[1:])

	proto := params["proto"]
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
	// In real impl: call webauthn.BeginRegistration() or BeginLogin()

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

	// In real impl: call webauthn.FinishRegistration() or FinishLogin()
	// For now, we just mark as done

	if sess.Role == "register" {
		// Save public key
		// TODO: Extract COSE key from attestation and save via keyring
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
