package e2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/keaganluttrell/ten/kernel"
	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

func TestRescueMode(t *testing.T) {
	// 1. Setup Kernel with DEAD VFS address
	kernelAddr := getFreeAddr()
	deadVFSAddr := getFreeAddr()                                             // Nothing listening here
	pubKey := "MCowBQYDK2VwAyEAaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa=" // Dummy

	go func() {
		if err := kernel.StartServer(kernelAddr, deadVFSAddr, pubKey); err != nil {
			t.Logf("Kernel stopped: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond) // Give it a moment to bind

	// 2. Connect Client
	wsURL := fmt.Sprintf("ws://%s/9p", kernelAddr)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, _, err := websocket.Dial(ctx, wsURL, nil)
	if err != nil {
		t.Fatalf("Failed to dial kernel: %v", err)
	}
	defer c.Close(websocket.StatusNormalClosure, "")

	rpc := NewWSRpc(c)

	// 3. Tversion
	resp := rpc(&p9.Fcall{Type: p9.Tversion, Msize: 8192, Version: "9P2000"})
	if resp == nil {
		t.Fatal("Tversion failed")
	}

	// 4. Tattach (Bootstrap Mode)
	// This usually connects to Factotum. But VFS is dead, so Factotum mounting fails too.
	// Either way, we expect Success (Rescue Mode).
	aresp := rpc(&p9.Fcall{Type: p9.Tattach, Fid: 0, Afid: p9.NOFID, Uname: "user", Aname: ""})
	if aresp == nil {
		t.Fatal("Tattach failed (nil response)")
	}
	if aresp.Type == p9.Rerror {
		t.Fatalf("Tattach failed with error: %s (Expected Rescue Mode)", aresp.Ename)
	}

	// 5. Walk to README
	// Rescue FS has /README
	wresp := rpc(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 1, Wname: []string{"README"}})
	if wresp == nil {
		t.Fatal("Twalk failed")
	}
	if wresp.Type == p9.Rerror {
		t.Fatalf("Twalk failed: %s", wresp.Ename)
	}
	if len(wresp.Wqid) != 1 {
		t.Fatalf("Expected 1 Qid, got %d", len(wresp.Wqid))
	}

	// 6. Open README
	oresp := rpc(&p9.Fcall{Type: p9.Topen, Fid: 1, Mode: 0}) // OREAD = 0
	if oresp == nil || oresp.Type == p9.Rerror {
		t.Fatal("Topen README failed")
	}

	// 7. Read README
	rresp := rpc(&p9.Fcall{Type: p9.Tread, Fid: 1, Offset: 0, Count: 1024})
	if rresp == nil || rresp.Type == p9.Rerror {
		t.Fatal("Tread README failed")
	}

	content := string(rresp.Data)
	t.Logf("README Content: %s", content)

	if !strings.Contains(content, "RESCUE MODE") {
		t.Fatalf("README content does not match expected Rescue Message. Got: %s", content)
	}
}
