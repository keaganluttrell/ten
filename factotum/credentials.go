package factotum

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/go-webauthn/webauthn/webauthn"
	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// CredentialStore manages WebAuthn credentials stored in VFS.
type CredentialStore struct {
	vfsAddr string
}

// NewCredentialStore creates a new credential store.
func NewCredentialStore(vfsAddr string) *CredentialStore {
	return &CredentialStore{vfsAddr: vfsAddr}
}

// User represents a WebAuthn user with their credentials.
type User struct {
	ID          []byte                `json:"id"`
	Name        string                `json:"name"`
	DisplayName string                `json:"display_name"`
	Credentials []webauthn.Credential `json:"credentials"`
}

// WebAuthnID returns the user's ID for WebAuthn.
func (u *User) WebAuthnID() []byte {
	return u.ID
}

// WebAuthnName returns the user's name.
func (u *User) WebAuthnName() string {
	return u.Name
}

// WebAuthnDisplayName returns the user's display name.
func (u *User) WebAuthnDisplayName() string {
	return u.DisplayName
}

// WebAuthnCredentials returns the user's credentials.
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	return u.Credentials
}

// LoadUser loads a user's credentials from VFS.
func (cs *CredentialStore) LoadUser(username string) (*User, error) {
	path := fmt.Sprintf("/priv/factotum/%s/cred", username)
	data, err := cs.readFromVFS(path)
	if err != nil {
		return nil, err
	}

	// Parse space-delimited text: <credid-b64> <pubkey-b64> <signcount>
	fields := strings.Fields(string(data))
	if len(fields) < 3 {
		return nil, errors.New("invalid credential format")
	}

	credID, err := base64.StdEncoding.DecodeString(fields[0])
	if err != nil {
		return nil, fmt.Errorf("decode credid: %w", err)
	}

	pubKey, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, fmt.Errorf("decode pubkey: %w", err)
	}

	signCount, err := strconv.ParseUint(fields[2], 10, 32)
	if err != nil {
		return nil, fmt.Errorf("parse signcount: %w", err)
	}

	return &User{
		ID:          []byte(username),
		Name:        username,
		DisplayName: username,
		Credentials: []webauthn.Credential{{
			ID:        credID,
			PublicKey: pubKey,
			Authenticator: webauthn.Authenticator{
				SignCount: uint32(signCount),
			},
		}},
	}, nil
}

// SaveCredential saves a credential to VFS as space-delimited text.
func (cs *CredentialStore) SaveCredential(username string, cred webauthn.Credential) error {
	// Format: <credid-b64> <pubkey-b64> <signcount>
	credID := base64.StdEncoding.EncodeToString(cred.ID)
	pubKey := base64.StdEncoding.EncodeToString(cred.PublicKey)
	signCount := fmt.Sprintf("%d", cred.Authenticator.SignCount)

	line := fmt.Sprintf("%s %s %s", credID, pubKey, signCount)
	path := fmt.Sprintf("/priv/factotum/%s/cred", username)
	return cs.writeToVFS(path, []byte(line))
}

// AddCredential adds a new credential to a user.
func (cs *CredentialStore) AddCredential(username string, cred webauthn.Credential) error {
	// For V1: single credential per user (overwrite)
	return cs.SaveCredential(username, cred)
}

// readFromVFS reads a file from VFS.
func (cs *CredentialStore) readFromVFS(path string) ([]byte, error) {
	conn, err := net.Dial("tcp", cs.vfsAddr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	rpc := makeRPCFunc(conn)

	// Attach
	if _, err := rpc(&p9.Fcall{Type: p9.Tattach, Fid: 0, Uname: "factotum", Aname: "/"}); err != nil {
		return nil, fmt.Errorf("attach: %w", err)
	}
	defer rpc(&p9.Fcall{Type: p9.Tclunk, Fid: 0})

	// Walk to file
	parts := splitPath(path)
	if _, err := rpc(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 1, Wname: parts}); err != nil {
		return nil, fmt.Errorf("walk: %w", err)
	}
	defer rpc(&p9.Fcall{Type: p9.Tclunk, Fid: 1})

	// Open
	if _, err := rpc(&p9.Fcall{Type: p9.Topen, Fid: 1, Mode: 0}); err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}

	// Read
	resp, err := rpc(&p9.Fcall{Type: p9.Tread, Fid: 1, Count: 65536})
	if err != nil {
		return nil, fmt.Errorf("read: %w", err)
	}

	return resp.Data, nil
}

// writeToVFS writes a file to VFS.
func (cs *CredentialStore) writeToVFS(path string, data []byte) error {
	conn, err := net.Dial("tcp", cs.vfsAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	rpc := makeRPCFunc(conn)

	// Attach
	if _, err := rpc(&p9.Fcall{Type: p9.Tattach, Fid: 0, Uname: "factotum", Aname: "/"}); err != nil {
		return fmt.Errorf("attach: %w", err)
	}

	// Create directories and file
	parts := splitPath(path)
	fileName := parts[len(parts)-1]
	dirParts := parts[:len(parts)-1]

	currentFid := uint32(0)
	for i, part := range dirParts {
		nextFid := uint32(i + 1)
		// Try to walk
		resp, err := rpc(&p9.Fcall{Type: p9.Twalk, Fid: currentFid, Newfid: nextFid, Wname: []string{part}})
		if err != nil || len(resp.Wqid) == 0 {
			// Directory doesn't exist, create it
			if _, err := rpc(&p9.Fcall{Type: p9.Tcreate, Fid: currentFid, Name: part, Perm: 0700 | p9.DMDIR, Mode: 0}); err != nil {
				return fmt.Errorf("create dir %s: %w", part, err)
			}
		}
		currentFid = nextFid
	}

	// Create file
	if _, err := rpc(&p9.Fcall{Type: p9.Tcreate, Fid: currentFid, Name: fileName, Perm: 0600, Mode: 1}); err != nil {
		return fmt.Errorf("create file: %w", err)
	}

	// Write
	if _, err := rpc(&p9.Fcall{Type: p9.Twrite, Fid: currentFid, Data: data, Count: uint32(len(data))}); err != nil {
		return fmt.Errorf("write: %w", err)
	}

	rpc(&p9.Fcall{Type: p9.Tclunk, Fid: currentFid})
	return nil
}

// Helper functions

func makeRPCFunc(conn net.Conn) func(*p9.Fcall) (*p9.Fcall, error) {
	return func(req *p9.Fcall) (*p9.Fcall, error) {
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
}

func splitPath(path string) []string {
	var parts []string
	current := ""
	for _, ch := range path {
		if ch == '/' {
			if current != "" {
				parts = append(parts, current)
				current = ""
			}
		} else {
			current += string(ch)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}
