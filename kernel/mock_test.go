package kernel

import (
	"fmt"
	"net"
	"testing"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// MockDialer simulates network connections using net.Pipe.
type MockDialer struct {
	Handlers map[string]func(net.Conn)
}

func NewMockDialer() *MockDialer {
	return &MockDialer{
		Handlers: make(map[string]func(net.Conn)),
	}
}

func (m *MockDialer) Dial(addr string) (*Client, error) {
	handler, ok := m.Handlers[addr]
	if !ok {
		return nil, fmt.Errorf("connection refused: %s", addr)
	}

	c1, c2 := net.Pipe()
	go handler(c2)

	return &Client{
		addr: addr,
		conn: c1,
		tag:  1,
	}, nil
}

// SimpleServerHandler creates a handler that processes one request at a time using a callback.
func SimpleServerHandler(t *testing.T, handlerFunc func(req *p9.Fcall) *p9.Fcall) func(net.Conn) {
	return func(c net.Conn) {
		defer c.Close()
		for {
			req, err := p9.ReadFcall(c)
			if err != nil {
				return // Client closed or error
			}

			resp := handlerFunc(req)
			resp.Tag = req.Tag // Ensure tag matches

			buf, err := resp.Bytes()
			if err != nil {
				t.Errorf("mock server encode error: %v", err)
				return
			}
			if _, err := c.Write(buf); err != nil {
				return
			}
		}
	}
}

// MockKeyring generates a temporary signing key for tests.
// (Placeholder if we needed crypto util)
