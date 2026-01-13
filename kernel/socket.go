package kernel

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// Socket wraps a WebSocket connection.
type Socket struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

// Upgrade upgrades the HTTP request to a WebSocket connection.
func Upgrade(w http.ResponseWriter, r *http.Request) (*Socket, error) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // Allow all origins for now
	})
	if err != nil {
		return nil, err
	}
	return &Socket{conn: c}, nil
}

// Close closes the connection.
func (s *Socket) Close() error {
	return s.conn.Close(websocket.StatusNormalClosure, "")
}

// ReadMsg reads a 9P message from a WebSocket binary frame.
// Framing: [4-byte size][9P Message]
func (s *Socket) ReadMsg(ctx context.Context) (*p9.Fcall, error) {
	_, data, err := s.conn.Read(ctx)
	if err != nil {
		return nil, err
	}

	// Validate size prefix
	if len(data) < 4 {
		return nil, fmt.Errorf("frame too short")
	}
	size := binary.LittleEndian.Uint32(data[0:4])
	if uint32(len(data)) != size {
		return nil, fmt.Errorf("frame size mismatch: header says %d, got %d", size, len(data))
	}

	// Unmarshal 9P message (skipping 4 byte size header, p9.Unmarshal expects type at index 0)
	// Wait, our fcall.Bytes() includes 4-byte size.
	// Our p9.Unmarshal expects [type][tag][...] ??
	// Let's check p9.Unmarshal in decode.go.
	// It parses `f.Type = buf[0]`.
	// If the wire format is [Size][Type][Tag]...
	// p9.ReadFcall reads size first, then passes the rest to Unmarshal.
	// So Unmarshal expects [Type][Tag]...

	// The buffer `data` contains [Size][Type][Tag]...
	// We should pass `data[4:]` to Unmarshal, along with `size`.

	return p9.Unmarshal(data[4:], size)
}

// WriteMsg writes a 9P message to a WebSocket binary frame.
func (s *Socket) WriteMsg(ctx context.Context, f *p9.Fcall) error {
	buf, err := f.Bytes() // Includes [Size][Type]...
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Timeout for writes
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return s.conn.Write(ctx, websocket.MessageBinary, buf)
}
