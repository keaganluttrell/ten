package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/keaganluttrell/ten/factotum"
	"github.com/keaganluttrell/ten/kernel"
	p9 "github.com/keaganluttrell/ten/pkg/9p"
	"github.com/keaganluttrell/ten/ssr"
	"github.com/keaganluttrell/ten/vfs"
	"github.com/stretchr/testify/assert"
)

func TestE2E_FullFlow(t *testing.T) {
	// 1. Setup Environment
	tmpDir := t.TempDir()
	vfsRoot := filepath.Join(tmpDir, "vfs")
	factotumDir := filepath.Join(tmpDir, "factotum")
	os.MkdirAll(vfsRoot, 0755)
	os.MkdirAll(factotumDir, 0755)

	// 2. Ports
	vfsAddr := getFreeAddr()
	ssrAddr := getFreeAddr()
	factotumAddr := getFreeAddr()
	kernelAddr := getFreeAddr()

	// 3. `/lib/namespace`
	nsParams := fmt.Sprintf(
		"mount / tcp!%s\n"+
			"mount /dev/factotum tcp!%s\n"+
			"mount /view tcp!%s\n",
		vfsAddr, factotumAddr, ssrAddr,
	)
	os.MkdirAll(filepath.Join(vfsRoot, "lib"), 0755)
	os.WriteFile(filepath.Join(vfsRoot, "lib", "namespace"), []byte(nsParams), 0644)

	// Create /priv/sessions for Factotum to write tickets
	os.MkdirAll(filepath.Join(vfsRoot, "priv", "sessions"), 0755)

	// Create dummy data in VFS
	os.WriteFile(filepath.Join(vfsRoot, "hello.txt"), []byte("Hello from VFS!"), 0644)

	// 4. Keys
	// A. Factotum Key (For Ticket Signing)
	// Factotum writes signing.key (seed) to disk.
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	privB64 := base64.StdEncoding.EncodeToString(priv)
	os.WriteFile(filepath.Join(factotumDir, "signing.key"), []byte(privB64), 0600)

	// Kernel needs Factotum Public Key to verify tickets.
	pubB64 := base64.StdEncoding.EncodeToString(pub)
	os.Setenv("SIGNING_KEY_BASE64", pubB64)
	defer os.Unsetenv("SIGNING_KEY_BASE64")

	// B. Host Identity Key (For Kernel-VFS Auth)
	// VFS needs Host Public Key to trust Kernel.
	hostPub, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostPubB64 := base64.StdEncoding.EncodeToString(hostPub)
	hostPrivB64 := base64.StdEncoding.EncodeToString(hostPriv)

	// Kernel needs Host Private Key to sign challenges.
	os.Setenv("HOST_KEY_BASE64", hostPrivB64)
	defer os.Unsetenv("HOST_KEY_BASE64")

	// 5. Start Services
	go func() {
		// VFS trusts the Kernel's Host Key
		if err := vfs.StartServer(vfsAddr, vfsRoot, hostPubB64); err != nil {
			log.Printf("VFS Error: %v", err)
		}
	}()
	go func() {
		// Needs VFS addr to dialect
		if err := ssr.StartServer(ssrAddr, vfsAddr); err != nil {
			log.Printf("SSR Error: %v", err)
		}
	}()
	go func() {
		if err := factotum.StartServer(factotumAddr, factotumDir, vfsAddr); err != nil {
			log.Printf("Factotum Error: %v", err)
		}
	}()
	go func() {
		if err := kernel.StartServer(kernelAddr, vfsAddr, "env"); err != nil {
			log.Printf("Kernel Error: %v", err)
		}
	}()

	time.Sleep(1 * time.Second) // Wait for startup

	// 6. Connect Client (Bootstrap)
	wsURL := fmt.Sprintf("ws://%s/9p", kernelAddr)
	ctx := context.Background()
	c, _, err := websocket.Dial(ctx, wsURL, nil)
	assert.NoError(t, err)
	defer c.Close(websocket.StatusNormalClosure, "")

	rpc := NewWSRpc(c)

	// Tversion
	resp := rpc(&p9.Fcall{Type: p9.Tversion, Msize: 8192, Version: "9P2000"})
	if resp == nil {
		t.Fatal("RPC failed: Tversion")
	}
	assert.Equal(t, uint8(p9.Rversion), resp.Type)

	// Tattach (No Ticket)
	resp = rpc(&p9.Fcall{Type: p9.Tattach, Fid: 0, Uname: "user", Aname: ""})
	if resp == nil {
		t.Fatal("RPC failed: Tattach")
	}
	assert.Equal(t, uint8(p9.Rattach), resp.Type)

	// Check that we can ONLY see /factotum (Actually we mounted at /)
	// Walk to /rpc
	resp = rpc(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 1, Wname: []string{"rpc"}})
	if resp == nil {
		t.Fatal("RPC failed: Twalk /rpc")
	}
	assert.Equal(t, uint8(p9.Rwalk), resp.Type)

	// Walk to /lib/namespace (Should fail or not exist in bootstrap)
	resp = rpc(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 2, Wname: []string{"lib", "namespace"}})
	// Should fail because /lib doesn't exist in Factotum FS
	if resp != nil && resp.Type != p9.Rerror {
		t.Logf("Warning: Walk to /lib/namespace succeeded? Type=%d", resp.Type)
	}

	// 7. Authenticate
	// Open /rpc (Fid 1 is at /rpc)
	resp = rpc(&p9.Fcall{Type: p9.Topen, Fid: 1, Mode: 2}) // RDWR
	if resp == nil {
		t.Fatal("RPC failed: Topen")
	}
	assert.Equal(t, uint8(p9.Ropen), resp.Type)

	// Write Start
	cmd := "start proto=webauthn role=auth user=alice"
	resp = rpc(&p9.Fcall{Type: p9.Twrite, Fid: 1, Data: []byte(cmd), Count: uint32(len(cmd))})
	if resp == nil {
		t.Fatal("RPC failed: Twrite Start")
	}
	assert.Equal(t, uint8(p9.Rwrite), resp.Type)

	// Read Challenge
	resp = rpc(&p9.Fcall{Type: p9.Tread, Fid: 1, Count: 8192})
	if resp == nil {
		t.Fatal("RPC failed: Tread Challenge")
	}
	assert.Contains(t, string(resp.Data), "challenge")

	// Write Assertion
	cmd = "write ZHVtbXk="
	resp = rpc(&p9.Fcall{Type: p9.Twrite, Fid: 1, Data: []byte(cmd), Count: uint32(len(cmd))})
	if resp == nil {
		t.Fatal("RPC failed: Twrite Assertion")
	}
	assert.Equal(t, uint8(p9.Rwrite), resp.Type)

	// Read Ticket
	resp = rpc(&p9.Fcall{Type: p9.Tread, Fid: 1, Count: 8192})
	if resp.Type == p9.Rerror {
		t.Fatalf("Read Ticket failed: %s", resp.Ename)
	}
	authOut := string(resp.Data)
	assert.Contains(t, authOut, "ok ticket=")

	// Extract Ticket Path
	// "ok ticket=/priv/sessions/alice/<nonce>"
	parts := strings.Split(authOut, "=")
	if len(parts) < 2 {
		t.Fatalf("Invalid auth output: %s", authOut)
	}
	ticketPath := strings.TrimSpace(parts[1])
	t.Logf("Got Ticket: %s", ticketPath)

	c.Close(websocket.StatusNormalClosure, "")

	// 8. Re-Connect (Full Session)
	c2, _, err := websocket.Dial(ctx, wsURL, nil)
	assert.NoError(t, err)
	defer c2.Close(websocket.StatusNormalClosure, "")
	rpc2 := NewWSRpc(c2)

	rpc2(&p9.Fcall{Type: p9.Tversion, Msize: 8192, Version: "9P2000"})

	// Attach with Ticket
	resp = rpc2(&p9.Fcall{Type: p9.Tattach, Fid: 0, Uname: "alice", Aname: ticketPath})
	if resp.Type == p9.Rerror {
		t.Fatalf("Attach failed: %s", resp.Ename)
	}
	assert.Equal(t, uint8(p9.Rattach), resp.Type)

	// 9. Verify VFS Access
	// Walk to /hello.txt
	resp = rpc2(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 1, Wname: []string{"hello.txt"}})
	assert.Equal(t, uint8(p9.Rwalk), resp.Type)

	// Read it
	rpc2(&p9.Fcall{Type: p9.Topen, Fid: 1, Mode: 0})
	resp = rpc2(&p9.Fcall{Type: p9.Tread, Fid: 1, Count: 8192})
	assert.Equal(t, "Hello from VFS!", string(resp.Data))

	// 10. Verify SSR Access
	// Walk to /view/hello.txt
	resp = rpc2(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 2, Wname: []string{"view", "hello.txt"}})
	assert.Equal(t, uint8(p9.Rwalk), resp.Type)

	rpc2(&p9.Fcall{Type: p9.Topen, Fid: 2, Mode: 0})
	resp = rpc2(&p9.Fcall{Type: p9.Tread, Fid: 2, Count: 8192})
	if resp.Type == p9.Rerror {
		t.Fatalf("SSR Read failed: %s", resp.Ename)
	}
	html := string(resp.Data)
	assert.Contains(t, html, "<html>")
	assert.Contains(t, html, "<pre>Hello from VFS!</pre>")
}

func getFreeAddr() string {
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	defer l.Close()
	return l.Addr().String()
}

func NewWSRpc(c *websocket.Conn) func(*p9.Fcall) *p9.Fcall {
	return func(req *p9.Fcall) *p9.Fcall {
		req.Tag = 1
		frame, _ := req.Bytes()

		c.Write(context.Background(), websocket.MessageBinary, frame)

		_, r, _ := c.Read(context.Background())
		// Strip size
		if len(r) < 4 {
			return nil
		}

		sizeStr := binary.LittleEndian.Uint32(r[:4])
		msg, _ := p9.Unmarshal(r[4:], sizeStr)
		return msg
	}
}
