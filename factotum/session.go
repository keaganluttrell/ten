// session.go manages per-FID authentication sessions.
// Sessions are stored in RAM only. Challenges never touch disk.
package factotum

import (
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Sessions holds all active auth sessions, protected by mutex.
type Sessions struct {
	mu   sync.Mutex
	data map[uint32]*Session
}

// Session represents one authentication dialogue.
type Session struct {
	FID       uint32
	User      string
	Role      string // "register" | "auth"
	State     string // "start" | "challenged" | "done"
	Challenge []byte // ephemeral, never persisted
	WebAuthn  *webauthn.SessionData
}

// NewSessions creates a new session store.
func NewSessions() *Sessions {
	return &Sessions{
		data: make(map[uint32]*Session),
	}
}

// Get retrieves a session by FID.
func (s *Sessions) Get(fid uint32) (*Session, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.data[fid]
	return sess, ok
}

// Set stores a session by FID.
func (s *Sessions) Set(fid uint32, sess *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.data[fid] = sess
}

// Delete removes a session by FID.
func (s *Sessions) Delete(fid uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.data, fid)
}
