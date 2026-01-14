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

func TestDynamicNamespace_Bind(t *testing.T) {
	// 1. Setup Environment
	tmpDir := t.TempDir()
	vfsRoot := filepath.Join(tmpDir, "vfs_bind")
	factotumDir := filepath.Join(tmpDir, "factotum")
	os.MkdirAll(vfsRoot, 0755)
	os.MkdirAll(factotumDir, 0755)

	// Create /lib directory (manifest will be written after we know addresses)
	os.MkdirAll(filepath.Join(vfsRoot, "lib"), 0755)

	// Create /data/hello.txt in VFS
	os.MkdirAll(filepath.Join(vfsRoot, "data"), 0755)
	os.WriteFile(filepath.Join(vfsRoot, "data", "hello.txt"), []byte("Hello via Bind!"), 0644)

	// Create /dev directory for /dev/sys mount point
	os.MkdirAll(filepath.Join(vfsRoot, "dev"), 0755)

	// Create /priv/sessions for Factotum tickets
	os.MkdirAll(filepath.Join(vfsRoot, "priv", "sessions"), 0755)

	// Get addresses
	vfsAddr := getFreeAddr()
	factotumAddr := getFreeAddr()

	// Write manifest with actual addresses
	manifest := fmt.Sprintf("mount / tcp!%s\nmount /dev/factotum tcp!%s\n", vfsAddr, factotumAddr)
	os.WriteFile(filepath.Join(vfsRoot, "lib", "namespace"), []byte(manifest), 0644)

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

	// Start VFS
	go func() {
		if err := vfs.StartServer(vfsAddr, vfsRoot, trustKey); err != nil {
			t.Logf("VFS Error: %v", err)
		}
	}()

	// Start Factotum
	go func() {
		if err := factotum.StartServer(factotumAddr, factotumDir, vfsAddr); err != nil {
			t.Logf("Factotum Error: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	// Start Kernel
	kernelAddr := getFreeAddr()
	os.Setenv("HOST_KEY_BASE64", hostKey)
	defer os.Unsetenv("HOST_KEY_BASE64")

	go func() {
		if err := kernel.StartServer(kernelAddr, vfsAddr, "env"); err != nil {
			t.Logf("Kernel Error: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	// Connect Client
	rpc := dialKernel(t, kernelAddr)

	// 2. Attach (Bootstrap) - mounts Factotum at root
	resp := rpc(&p9.Fcall{Type: p9.Tattach, Fid: 0, Uname: "user", Aname: ""})
	assert.Equal(t, uint8(p9.Rattach), resp.Type)

	// 3. Authenticate to get a ticket
	// Walk to /rpc
	resp = rpc(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 10, Wname: []string{"rpc"}})
	if resp.Type == p9.Rerror {
		t.Fatalf("Walk to /rpc failed: %s", resp.Ename)
	}

	// Open /rpc
	resp = rpc(&p9.Fcall{Type: p9.Topen, Fid: 10, Mode: 2})
	if resp.Type == p9.Rerror {
		t.Fatalf("Open /rpc failed: %s", resp.Ename)
	}

	// Write start command
	cmd := "start proto=webauthn role=auth user=testuser"
	rpc(&p9.Fcall{Type: p9.Twrite, Fid: 10, Data: []byte(cmd), Count: uint32(len(cmd))})

	// Read challenge
	rpc(&p9.Fcall{Type: p9.Tread, Fid: 10, Count: 8192})

	// Write attestation
	rpc(&p9.Fcall{Type: p9.Twrite, Fid: 10, Data: []byte("write dummy"), Count: 11})

	// Read ticket
	resp = rpc(&p9.Fcall{Type: p9.Tread, Fid: 10, Count: 8192})
	if resp.Type == p9.Rerror {
		t.Fatalf("Read ticket failed: %s", resp.Ename)
	}
	ticketPath := strings.TrimPrefix(string(resp.Data), "ok ticket=")
	ticketPath = strings.TrimSpace(ticketPath)
	t.Logf("Got ticket: %s", ticketPath)

	// 4. Re-connect with ticket to get full namespace
	rpc2 := dialKernel(t, kernelAddr)
	rpc2(&p9.Fcall{Type: p9.Tversion, Msize: 8192, Version: "9P2000"})
	resp = rpc2(&p9.Fcall{Type: p9.Tattach, Fid: 0, Uname: "testuser", Aname: ticketPath})
	if resp.Type == p9.Rerror {
		t.Fatalf("Attach with ticket failed: %s", resp.Ename)
	}

	// 5. Walk to /dev/sys/ctl
	resp = rpc2(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 1, Wname: []string{"dev", "sys", "ctl"}})
	if resp.Type == p9.Rerror {
		t.Fatalf("Walk to ctl failed: %s", resp.Ename)
	}
	assert.Equal(t, uint8(p9.Rwalk), resp.Type)

	// 6. Open ctl
	resp = rpc2(&p9.Fcall{Type: p9.Topen, Fid: 1, Mode: 1})
	if resp == nil || resp.Type == p9.Rerror {
		t.Fatalf("Open ctl failed")
	}

	// 7. Write Bind Command: bind /data /alias
	cmd = "bind /data /alias"
	resp = rpc2(&p9.Fcall{Type: p9.Twrite, Fid: 1, Data: []byte(cmd), Count: uint32(len(cmd))})
	if resp == nil || resp.Type == p9.Rerror {
		t.Fatalf("Write bind command failed: %s", resp.Ename)
	}
	t.Logf("Bind command executed: %s", cmd)

	// 8. Verify Access via Alias
	// Walk to /alias/hello.txt
	resp = rpc2(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 2, Wname: []string{"alias", "hello.txt"}})
	if resp.Type == p9.Rerror {
		t.Fatalf("Walk to /alias/hello.txt failed: %s", resp.Ename)
	}
	assert.Equal(t, uint8(p9.Rwalk), resp.Type)
	assert.Equal(t, 2, len(resp.Wqid))

	// Open and Read
	resp = rpc2(&p9.Fcall{Type: p9.Topen, Fid: 2, Mode: 0})
	if resp.Type == p9.Rerror {
		t.Fatalf("Open /alias/hello.txt failed: %s", resp.Ename)
	}

	resp = rpc2(&p9.Fcall{Type: p9.Tread, Fid: 2, Count: 1024})
	if resp.Type == p9.Rerror {
		t.Fatalf("Read /alias/hello.txt failed: %s", resp.Ename)
	}
	assert.Equal(t, "Hello via Bind!", string(resp.Data))

	t.Logf("Successfully read via bind alias: %s", string(resp.Data))
}
