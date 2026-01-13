package e2e

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/keaganluttrell/ten/kernel"
	p9 "github.com/keaganluttrell/ten/pkg/9p"
	"github.com/keaganluttrell/ten/vfs"
	"github.com/stretchr/testify/assert"
)

func TestDynamicNamespace_Mount(t *testing.T) {
	// 1. Setup Environment
	tmpDir := t.TempDir()
	vfsRoot := filepath.Join(tmpDir, "vfs_dyn")
	extRoot := filepath.Join(tmpDir, "vfs_ext") // External VFS
	os.MkdirAll(vfsRoot, 0755)
	os.MkdirAll(extRoot, 0755)

	// Create manifest
	os.MkdirAll(filepath.Join(vfsRoot, "lib"), 0755)
	os.WriteFile(filepath.Join(vfsRoot, "lib", "namespace"), []byte("mount / tcp!127.0.0.1:9999\n"), 0644)

	// Create content in External VFS
	os.WriteFile(filepath.Join(extRoot, "extra.txt"), []byte("Extra Content"), 0644)

	vfsAddr := getFreeAddr()
	extAddr := getFreeAddr()

	// Start Main VFS (Trusted)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	trustKey := base64.StdEncoding.EncodeToString(pub)
	hostKey := base64.StdEncoding.EncodeToString(priv)

	go func() {
		if err := vfs.StartServer(vfsAddr, vfsRoot, trustKey); err != nil {
			t.Logf("VFS Error: %v", err)
		}
	}()

	// Start External VFS (No Auth for simplicity, or we can use keys)
	// SysDevice mount implementation currently ignores trusted key for new mounts in code?
	// SysDevice calls dialer.Dial directly. It performs Tversion/Tattach(user).
	// If ExtVFS requires Auth, it will fail unless we handle Tauth.
	// Our SysDevice.execute implementation does NOT handle Tauth yet.
	// So ExtVFS must NOT require Auth (no trusted key).
	go func() {
		if err := vfs.StartServer(extAddr, extRoot, ""); err != nil {
			t.Logf("Ext VFS Error: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	// Start Kernel
	kernelAddr := getFreeAddr()
	os.Setenv("HOST_KEY_BASE64", hostKey)
	defer os.Unsetenv("HOST_KEY_BASE64")

	go func() {
		if err := kernel.StartServer(kernelAddr, vfsAddr, "dummy"); err != nil {
			t.Logf("Kernel Error: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	// Connect Client
	rpc := dialKernel(t, kernelAddr)

	// 2. Attach (Bootstrap)
	resp := rpc(&p9.Fcall{Type: p9.Tattach, Fid: 0, Uname: "user", Aname: ""})
	assert.Equal(t, uint8(p9.Rattach), resp.Type)

	// 3. Walk to /dev/sys/ctl
	// We mounted sys at /dev/sys.
	// Walk 0->1: "dev", "sys", "ctl"
	// Wait, /dev might not exist in VFS?
	// VFS root has /lib.
	// If we Mount /dev/sys, "dev" must exist or be created implicitly by Namespace logic?
	// Namespace.Route prefixes.
	// If I walk "dev", Namespace sees no mount "dev". Best match "/".
	// Route returns VFS client, rel path "dev".
	// VFS client looks for "dev" on disk.
	// If "dev" doesn't exist on VFS, walk fails.
	// So for /dev/sys to work, "/dev" MUST exist in VFS or be a specific mount point.
	// In my setup above, VFS only has /lib.
	// SO "dev" doesn't exist.

	// Create "dev" in VFS.
	os.MkdirAll(filepath.Join(vfsRoot, "dev"), 0755)

	// Also, "sys" must exist in VFS if we mount AT "/dev/sys"?
	// Namespace logic: Route("/dev/sys/ctl") -> Best match "/dev/sys"?
	// Yes.
	// So walking "dev" -> VFS "dev".
	// Walking "sys" -> VFS "sys" (if mount not hit yet).
	// But /dev/sys IS the mount point.
	// If I walk "dev", "sys".
	// Walk "dev" -> VFS.
	// Walk "sys" -> crosses mount point to SysDevice.
	// So "sys" acts as the root of SysDevice.
	// SysDevice root is "/".
	// So Walk "dev" (VFS) -> "sys" (SysDevice Root).

	// Does VFS need "sys" directory?
	// Usually YES, the mount point directory must exist in the underlying FS for the parent to walk to it?
	// OR the Kernel intercepts the walk at the name level.
	// Review `kernel/session.go` Twalk logic:
	// "Check Route" for `nextPath`.
	// If `nextPath` (/dev/sys) maps to a different client than `currPath` (/dev),
	// Then we CLUNK current, switch client, and ATTACH new root.
	// So the "sys" directory does NOT need to exist in VFS, because we switch client BEFORE asking VFS for "sys".
	// Wait.
	// `resolvePath`("/dev", "sys") -> "/dev/sys".
	// `ns.Route("/dev/sys")` -> returns SysClient.
	// `ns.Route("/dev")` -> returns VFSClient.
	// So yes, we switch.

	// However, we need "/dev" to exist in VFS.
	// Done (os.MkdirAll).

	// Walk to /dev/sys/ctl
	resp = rpc(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 1, Wname: []string{"dev", "sys", "ctl"}})
	if resp.Type == p9.Rerror {
		t.Fatalf("Walk to ctl failed: %s", resp.Ename)
	}
	assert.Equal(t, uint8(p9.Rwalk), resp.Type)
	assert.Equal(t, 3, len(resp.Wqid)) // dev, sys, ctl

	// 4. Open ctl
	resp = rpc(&p9.Fcall{Type: p9.Topen, Fid: 1, Mode: 1}) // O_WRONLY
	if resp == nil || resp.Type == p9.Rerror {
		t.Fatalf("Open ctl failed")
	}

	// 5. Write Mount Command
	// mount tcp!127.0.0.1:XXXX /ext
	cmd := fmt.Sprintf("mount tcp!%s /ext", extAddr)
	resp = rpc(&p9.Fcall{Type: p9.Twrite, Fid: 1, Data: []byte(cmd), Count: uint32(len(cmd))})
	if resp == nil || resp.Type == p9.Rerror {
		t.Fatalf("Write mount command failed")
	}
	t.Logf("Mounted external VFS at /ext")

	// 6. Verify Access to New Mount
	// Walk to /ext/extra.txt
	// Need to clunk/use fresh fid, or walk from Root (Fid 0).
	resp = rpc(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 2, Wname: []string{"ext", "extra.txt"}})
	if resp.Type == p9.Rerror {
		t.Fatalf("Walk to /ext/extra.txt failed: %s", resp.Ename)
	}

	// Read it
	rpc(&p9.Fcall{Type: p9.Topen, Fid: 2, Mode: 0})
	resp = rpc(&p9.Fcall{Type: p9.Tread, Fid: 2, Count: 1024})
	assert.Equal(t, "Extra Content", string(resp.Data))
}
