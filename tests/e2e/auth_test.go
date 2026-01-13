package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/keaganluttrell/ten/kernel"
	p9 "github.com/keaganluttrell/ten/pkg/9p"
	"github.com/keaganluttrell/ten/vfs"
	"github.com/stretchr/testify/assert"
)

func TestHostIdentity_Bootstrap(t *testing.T) {
	// 1. Generate Cluster Key Pair
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	trustedKeyB64 := base64.StdEncoding.EncodeToString(pub)
	hostKeyB64 := base64.StdEncoding.EncodeToString(priv)

	// Rogue Key
	_, roguePriv, _ := ed25519.GenerateKey(rand.Reader)
	rogueKeyB64 := base64.StdEncoding.EncodeToString(roguePriv)

	// 2. Setup Shared VFS
	tmpDir := t.TempDir()
	vfsRoot := filepath.Join(tmpDir, "vfs_auth")
	os.MkdirAll(vfsRoot, 0755)
	vfsAddr := getFreeAddr()

	// Write manifest so good boot works
	os.MkdirAll(filepath.Join(vfsRoot, "lib"), 0755)
	os.WriteFile(filepath.Join(vfsRoot, "lib", "namespace"), []byte("mount / tcp!127.0.0.1:9999\n"), 0644)

	// Start VFS with Trusted Key
	go func() {
		if err := vfs.StartServer(vfsAddr, vfsRoot, trustedKeyB64); err != nil {
			t.Logf("VFS Error: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	// Scenario A: Valid Kernel
	t.Run("ValidKernel", func(t *testing.T) {
		kernelAddr := getFreeAddr()
		pubKey := "MCowBQYDK2VwAyEAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=" // Dummy Factotum key

		os.Setenv("HOST_KEY_BASE64", hostKeyB64)
		defer os.Unsetenv("HOST_KEY_BASE64")

		go func() {
			if err := kernel.StartServer(kernelAddr, vfsAddr, pubKey); err != nil {
				t.Logf("Kernel Error: %v", err)
			}
		}()
		time.Sleep(100 * time.Millisecond)

		// Connect and verify we see VFS content (not Rescue Mode)
		rpc := dialKernel(t, kernelAddr)

		// Attach
		resp := rpc(&p9.Fcall{Type: p9.Tattach, Fid: 0, Uname: "user", Aname: ""}) // Bootstrap
		assert.NotNil(t, resp)
		assert.Equal(t, uint8(p9.Rattach), resp.Type)

		// Walk to /lib/namespace
		resp = rpc(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 1, Wname: []string{"lib", "namespace"}})
		if resp.Type == p9.Rerror {
			t.Fatalf("Walk failed (Rescue Mode?): %s", resp.Ename)
		}
		// In Rescue Mode, /lib doesn't exist (only /README)
		// So success here means we are attached to VFS.
		assert.Equal(t, uint8(p9.Rwalk), resp.Type)
	})

	// Scenario B: Rogue Kernel
	t.Run("RogueKernel", func(t *testing.T) {
		kernelAddr := getFreeAddr()
		pubKey := "MCowBQYDK2VwAyEAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa="

		os.Setenv("HOST_KEY_BASE64", rogueKeyB64)
		defer os.Unsetenv("HOST_KEY_BASE64")

		go func() {
			if err := kernel.StartServer(kernelAddr, vfsAddr, pubKey); err != nil {
				t.Logf("Rogue Kernel Error: %v", err)
			}
		}()
		time.Sleep(100 * time.Millisecond)

		// Connect and verify we are in Rescue Mode (because VFS rejected us)
		rpc := dialKernel(t, kernelAddr)

		// Attach
		resp := rpc(&p9.Fcall{Type: p9.Tattach, Fid: 0, Uname: "user", Aname: ""})
		assert.NotNil(t, resp)

		// Walk to README
		resp = rpc(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 1, Wname: []string{"README"}})
		if resp.Type == p9.Rerror {
			t.Fatalf("Expected Rescue Mode (README), but walk failed: %s", resp.Ename)
		}

		// Read content to be sure
		rpc(&p9.Fcall{Type: p9.Topen, Fid: 1, Mode: 0})
		resp = rpc(&p9.Fcall{Type: p9.Tread, Fid: 1, Count: 1024})
		content := string(resp.Data)

		assert.Contains(t, content, "RESCUE MODE", "Rogue Kernel should be in Rescue Mode")
	})
}

func dialKernel(t *testing.T, addr string) func(*p9.Fcall) *p9.Fcall {
	wsURL := fmt.Sprintf("ws://%s/9p", addr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to dial kernel %s: %v", addr, err)
	}
	// We don't close C here easily without blocking, rely on test end or GC.
	// Or wrap RPC.

	return func(req *p9.Fcall) *p9.Fcall {
		req.Tag = 1
		b, _ := req.Bytes()
		c.Write(context.Background(), websocket.MessageBinary, b)

		_, msg, _ := c.Read(context.Background())
		// Strip size
		if len(msg) < 4 {
			return nil
		}
		f, _ := p9.Unmarshal(msg[4:], 8192)
		return f
	}
}
