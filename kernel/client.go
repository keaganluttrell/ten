package kernel

import (
	"fmt"
	"net"
	"sync"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// Client represents a connection to a backend 9P service.
type Client struct {
	addr string
	conn net.Conn
	mu   sync.Mutex
	tag  uint16
}

// Dialer abstracts the connection creation for testing.
type Dialer interface {
	Dial(addr string) (*Client, error)
}

// NetworkDialer implements Dialer using net.Dial.
type NetworkDialer struct{}

// Dial connects to a backend service.
func (d NetworkDialer) Dial(addr string) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Client{
		addr: addr,
		conn: conn,
		tag:  1, // Start tags at 1, 0 is NOTAG
	}, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// RPC sends a request and waits for a response.
// For v1 Kernel (Synchronous), we just lock, send, read, unlock.
// In a real async kernel, this would need a tag map.
func (c *Client) RPC(req *p9.Fcall) (*p9.Fcall, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Assign tag
	c.tag++
	if c.tag == 0xFFFF { // Wrap around
		c.tag = 1
	}
	req.Tag = c.tag

	// Encode
	buf, err := req.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode failed: %w", err)
	}

	// Write
	if _, err := c.conn.Write(buf); err != nil {
		return nil, fmt.Errorf("write failed: %w", err)
	}

	// Read Response
	resp, err := p9.ReadFcall(c.conn)
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}

	// Check tag match
	if resp.Tag != req.Tag {
		return nil, fmt.Errorf("tag mismatch: sent %d got %d", req.Tag, resp.Tag)
	}

	return resp, nil
}
