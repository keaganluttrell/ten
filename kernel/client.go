package kernel

import (
	"crypto/ed25519"
	"fmt"
	"net"
	"sync"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
	"github.com/keaganluttrell/ten/pkg/resilience"
)

// Client represents a connection to a backend 9P service.
type Client struct {
	addr    string
	conn    net.Conn
	mu      sync.Mutex
	tag     uint16
	lastFid uint32
}

// Dialer abstracts the connection creation for testing.
type Dialer interface {
	Dial(addr string) (*Client, error)
}

// NetworkDialer implements Dialer using net.Dial with retry.
type NetworkDialer struct {
	RetryConfig resilience.RetryConfig
}

// NewNetworkDialer creates a NetworkDialer with default retry settings.
func NewNetworkDialer() *NetworkDialer {
	return &NetworkDialer{
		RetryConfig: resilience.DefaultRetryConfig(),
	}
}

// Dial connects to a backend service with retry logic.
func (d *NetworkDialer) Dial(addr string) (*Client, error) {
	var client *Client
	cleanAddr := convertAddr(addr) // Strip tcp!

	err := resilience.Retry(d.RetryConfig, func() error {
		conn, err := net.Dial("tcp", cleanAddr)
		if err != nil {
			return err
		}
		client = &Client{
			addr: addr,
			conn: conn,
			tag:  1, // Start tags at 1, 0 is NOTAG
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return client, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Authenticate performs the Host Challenge Protocol.
// It returns the afid on success, or NOFID on failure/error.
func (c *Client) Authenticate(user string, key ed25519.PrivateKey) (uint32, error) {
	// 1. Tauth
	afid := c.NextFid()
	tAuth := &p9.Fcall{Type: p9.Tauth, Afid: afid, Uname: user, Aname: ""}
	resp, err := c.RPC(tAuth)
	if err != nil {
		return p9.NOFID, err
	}
	if resp.Type == p9.Rerror {
		return p9.NOFID, fmt.Errorf("auth error: %s", resp.Ename)
	}

	// 2. Read Nonce (Tread afid)
	// We need IOUnit from Somewhere? Assume 8192 or use Msize?
	// Tauth result accepts Qid. Tread requires Open?
	// VFS implementation allows Tread on QTAUTH without Topen.
	// But let's check VFS implementation again.
	// VFS Topen handler handles QTAUTH.
	// We might need to Topen(afid) first?
	// VFS Tauth returns Qid.
	// VFS Tread checks "fid not found".
	// Yes, Tauth creates the fid. So allowed to read.

	tRead := &p9.Fcall{Type: p9.Tread, Fid: afid, Offset: 0, Count: 8192}
	resp, err = c.RPC(tRead)
	if err != nil {
		return p9.NOFID, err
	}
	if resp.Type == p9.Rerror {
		return p9.NOFID, fmt.Errorf("read nonce failed: %s", resp.Ename)
	}
	nonce := resp.Data

	// 3. Sign Nonce
	sig := ed25519.Sign(key, nonce)

	// 4. Write Signature (Twrite afid)
	tWrite := &p9.Fcall{Type: p9.Twrite, Fid: afid, Offset: 0, Data: sig, Count: uint32(len(sig))}
	resp, err = c.RPC(tWrite)
	if err != nil {
		return p9.NOFID, err
	}
	if resp.Type == p9.Rerror {
		return p9.NOFID, fmt.Errorf("write signature failed: %s", resp.Ename)
	}

	return afid, nil
}

func (c *Client) NextFid() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastFid++
	// Skip 0 (NOFID)
	if c.lastFid == 0 {
		c.lastFid = 1
	}
	return c.lastFid
}

// RPC sends a request and waits for a response.
// For v1 Kernel (Synchronous), we just lock, send, read, unlock.
// In a real async kernel, this would need a tag map.
func (c *Client) RPC(req *p9.Fcall) (*p9.Fcall, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Alloc Tag
	if req.Tag == p9.NOTAG {
		req.Tag = c.nextTag()
	}

	if err := c.writeFcall(req); err != nil {
		return nil, err
	}
	resp, err := c.readFcall()
	if err != nil {
		return nil, err
	}

	if resp.Tag != req.Tag {
		return nil, fmt.Errorf("tag mismatch: expected %d, got %d", req.Tag, resp.Tag)
	}

	return resp, nil
}

// nextTag increments and returns the next available tag, handling wrap-around.
func (c *Client) nextTag() uint16 {
	c.tag++
	if c.tag == p9.NOTAG { // Wrap around, 0 is NOTAG
		c.tag = 1
	}
	return c.tag
}

// writeFcall encodes and writes an Fcall to the connection.
func (c *Client) writeFcall(req *p9.Fcall) error {
	buf, err := req.Bytes()
	if err != nil {
		return fmt.Errorf("encode failed: %w", err)
	}

	if _, err := c.conn.Write(buf); err != nil {
		return fmt.Errorf("write failed: %w", err)
	}
	return nil
}

// readFcall reads and decodes an Fcall from the connection.
func (c *Client) readFcall() (*p9.Fcall, error) {
	resp, err := p9.ReadFcall(c.conn)
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}
	return resp, nil
}
