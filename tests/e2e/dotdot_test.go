package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keaganluttrell/ten/factotum"
	"github.com/keaganluttrell/ten/kernel"
	p9 "github.com/keaganluttrell/ten/pkg/9p"
	"github.com/keaganluttrell/ten/vfs"
	"github.com/stretchr/testify/assert"
)

// TestDotDot_MountBoundary verifies that walking ".." across a mount boundary
// correctly switches back to the parent mount's client.
func TestDotDot_MountBoundary(t *testing.T) {
	tmpDir := t.TempDir()

	// Three roots: main VFS, external VFS, and factotum
	mainRoot := filepath.Join(tmpDir, "vfs_main")
	extRoot := filepath.Join(tmpDir, "vfs_ext")
	factotumDir := filepath.Join(tmpDir, "factotum")
	os.MkdirAll(mainRoot, 0755)
	os.MkdirAll(extRoot, 0755)
	os.MkdirAll(factotumDir, 0755)

	// Main VFS: create /lib/namespace, /hello.txt, /priv/sessions
	os.MkdirAll(filepath.Join(mainRoot, "lib"), 0755)
	os.MkdirAll(filepath.Join(mainRoot, "priv", "sessions"), 0755)
	os.WriteFile(filepath.Join(mainRoot, "hello.txt"), []byte("main root"), 0644)

	// External VFS: create /external.txt
	os.WriteFile(filepath.Join(extRoot, "external.txt"), []byte("external content"), 0644)

	// Get addresses
	mainAddr := getFreeAddr()
	extAddr := getFreeAddr()
	factotumAddr := getFreeAddr()

	// Write manifest
	manifest := fmt.Sprintf("mount / tcp!%s\nmount /ext tcp!%s\nmount /dev/factotum tcp!%s\n", mainAddr, extAddr, factotumAddr)
	os.WriteFile(filepath.Join(mainRoot, "lib", "namespace"), []byte(manifest), 0644)

	// Host Key (Kernel -> VFS auth)
	hostPub, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	trustKey := base64.StdEncoding.EncodeToString(hostPub)
	hostKey := base64.StdEncoding.EncodeToString(hostPriv)

	// Signing Key (Factotum tickets)
	sigPub, sigPriv, _ := ed25519.GenerateKey(rand.Reader)
	sigPrivB64 := base64.StdEncoding.EncodeToString(sigPriv)
	sigPubB64 := base64.StdEncoding.EncodeToString(sigPub)
	os.WriteFile(filepath.Join(factotumDir, "signing.key"), []byte(sigPrivB64), 0600)
	os.Setenv("SIGNING_KEY_BASE64", sigPubB64)
	defer os.Unsetenv("SIGNING_KEY_BASE64")

	// Start Main VFS
	go vfs.StartServer(mainAddr, mainRoot, trustKey)

	// Start External VFS (no auth needed)
	go vfs.StartServer(extAddr, extRoot, "")

	// Start Factotum
	go factotum.StartServer(factotumAddr, factotumDir, mainAddr)
	time.Sleep(100 * time.Millisecond)

	// Start Kernel
	kernelAddr := getFreeAddr()
	os.Setenv("HOST_KEY_BASE64", hostKey)
	defer os.Unsetenv("HOST_KEY_BASE64")

	go kernel.StartServer(kernelAddr, mainAddr, "env")
	time.Sleep(100 * time.Millisecond)

	// Connect Client for bootstrap
	rpc := dialKernel(t, kernelAddr)

	// Attach (Bootstrap) - mounts Factotum at root
	resp := rpc(&p9.Fcall{Type: p9.Tattach, Fid: 0, Uname: "user", Aname: ""})
	assert.Equal(t, uint8(p9.Rattach), resp.Type)

	// Authenticate to get a ticket
	resp = rpc(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 10, Wname: []string{"rpc"}})
	if resp.Type == p9.Rerror {
		t.Fatalf("Walk to /rpc failed: %s", resp.Ename)
	}

	rpc(&p9.Fcall{Type: p9.Topen, Fid: 10, Mode: 2})
	cmd := "start proto=webauthn role=auth user=testuser"
	rpc(&p9.Fcall{Type: p9.Twrite, Fid: 10, Data: []byte(cmd), Count: uint32(len(cmd))})
	rpc(&p9.Fcall{Type: p9.Tread, Fid: 10, Count: 8192})
	rpc(&p9.Fcall{Type: p9.Twrite, Fid: 10, Data: []byte("write dummy"), Count: 11})
	resp = rpc(&p9.Fcall{Type: p9.Tread, Fid: 10, Count: 8192})
	if resp.Type == p9.Rerror {
		t.Fatalf("Read ticket failed: %s", resp.Ename)
	}
	ticketPath := strings.TrimPrefix(string(resp.Data), "ok ticket=")
	ticketPath = strings.TrimSpace(ticketPath)
	t.Logf("Got ticket: %s", ticketPath)

	// Re-connect with ticket to get full namespace
	rpc2 := dialKernel(t, kernelAddr)
	rpc2(&p9.Fcall{Type: p9.Tversion, Msize: 8192, Version: "9P2000"})
	resp = rpc2(&p9.Fcall{Type: p9.Tattach, Fid: 0, Uname: "testuser", Aname: ticketPath})
	if resp.Type == p9.Rerror {
		t.Fatalf("Attach with ticket failed: %s", resp.Ename)
	}

	// Test 1: Read /hello.txt directly
	resp = rpc2(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 1, Wname: []string{"hello.txt"}})
	if resp.Type == p9.Rerror {
		t.Fatalf("Walk to /hello.txt failed: %s", resp.Ename)
	}
	rpc2(&p9.Fcall{Type: p9.Topen, Fid: 1, Mode: 0})
	resp = rpc2(&p9.Fcall{Type: p9.Tread, Fid: 1, Count: 1024})
	assert.Equal(t, "main root", string(resp.Data))
	t.Logf("Read /hello.txt directly: %s", string(resp.Data))

	// Test 2: Walk into /ext/external.txt
	resp = rpc2(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 2, Wname: []string{"ext", "external.txt"}})
	if resp.Type == p9.Rerror {
		t.Fatalf("Walk to /ext/external.txt failed: %s", resp.Ename)
	}
	assert.Equal(t, 2, len(resp.Wqid))
	rpc2(&p9.Fcall{Type: p9.Topen, Fid: 2, Mode: 0})
	resp = rpc2(&p9.Fcall{Type: p9.Tread, Fid: 2, Count: 1024})
	assert.Equal(t, "external content", string(resp.Data))
	t.Logf("Read /ext/external.txt: %s", string(resp.Data))

	// Test 3: Walk /ext, .., hello.txt - this crosses back to main VFS
	resp = rpc2(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 3, Wname: []string{"ext", "..", "hello.txt"}})
	if resp.Type == p9.Rerror {
		t.Fatalf("Walk /ext/../hello.txt failed: %s", resp.Ename)
	}
	assert.Equal(t, uint8(p9.Rwalk), resp.Type)
	assert.Equal(t, 3, len(resp.Wqid)) // ext, .., hello.txt

	// Read to verify we're at hello.txt in main VFS
	rpc2(&p9.Fcall{Type: p9.Topen, Fid: 3, Mode: 0})
	resp = rpc2(&p9.Fcall{Type: p9.Tread, Fid: 3, Count: 1024})
	assert.Equal(t, "main root", string(resp.Data))
	t.Logf("Read /hello.txt via /ext/../hello.txt: %s", string(resp.Data))

	t.Logf("SUCCESS: .. traversal across mount boundary works!")
}
