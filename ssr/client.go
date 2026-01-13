package ssr

import (
	"fmt"
	"net"
	"sync"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// Client wraps a network connection to VFS.
// Reuses logic similar to kernel/client but simplified here.
type Client struct {
	conn net.Conn
	mu   sync.Mutex
	tag  uint16
}

func Dial(addr string) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, tag: 1}, nil
}

func (c *Client) Close() error {
	return c.conn.Close()
}

// RPC sends a request and waits for a response (Synchronous).
func (c *Client) RPC(req *p9.Fcall) (*p9.Fcall, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.tag++
	if c.tag == 0xFFFF {
		c.tag = 1
	}
	req.Tag = c.tag

	b, err := req.Bytes()
	if err != nil {
		return nil, fmt.Errorf("encode failed: %w", err)
	}

	if _, err := c.conn.Write(b); err != nil {
		return nil, fmt.Errorf("write failed: %w", err)
	}

	resp, err := p9.ReadFcall(c.conn)
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}

	if resp.Tag != req.Tag {
		return nil, fmt.Errorf("tag mismatch")
	}

	return resp, nil
}
