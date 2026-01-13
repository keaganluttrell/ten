package vfs

import (
	"net"
	"os"
	"testing"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
	"github.com/stretchr/testify/assert"
)

func TestVFS_Integration(t *testing.T) {
	// Setup Temp Dir
	tmpDir := t.TempDir()
	backend, err := NewLocalBackend(tmpDir)
	assert.NoError(t, err)

	// Pipe for connection
	c1, c2 := net.Pipe()
	session := NewSession(c1, backend, "")
	go session.Serve()
	defer c2.Close()

	// Helper to send/recv
	rpc := func(req *p9.Fcall) *p9.Fcall {
		req.Tag = 1
		b, err := req.Bytes()
		assert.NoError(t, err)
		_, err = c2.Write(b)
		assert.NoError(t, err)

		resp, err := p9.ReadFcall(c2)
		assert.NoError(t, err)
		return resp
	}

	// 1. Tversion
	resp := rpc(&p9.Fcall{Type: p9.Tversion, Msize: 8192, Version: "9P2000"})
	assert.Equal(t, uint8(p9.Rversion), resp.Type)
	assert.Equal(t, "9P2000", resp.Version)

	// 2. Tattach
	resp = rpc(&p9.Fcall{Type: p9.Tattach, Fid: 0, Uname: "user", Aname: "/"})
	assert.Equal(t, uint8(p9.Rattach), resp.Type)
	assert.True(t, (resp.Qid.Type&p9.QTDIR) != 0)

	// 3. Tcreate File
	// Walk to root (already at root with Fid 0)
	// Open/Create requires walking to strict parent usually, but Tcreate takes name.
	// We create "test.txt" in Fid 0.
	resp = rpc(&p9.Fcall{Type: p9.Tcreate, Fid: 0, Name: "test.txt", Perm: 0644, Mode: 1}) // O_WRONLY
	if resp.Type == p9.Rerror {
		t.Fatalf("create failed: %s", resp.Ename)
	}
	assert.Equal(t, uint8(p9.Rcreate), resp.Type)

	// 4. Twrite
	data := []byte("hello world")
	resp = rpc(&p9.Fcall{Type: p9.Twrite, Fid: 0, Offset: 0, Data: data, Count: uint32(len(data))})
	assert.Equal(t, uint8(p9.Rwrite), resp.Type)
	assert.Equal(t, uint32(len(data)), resp.Count)

	// 5. Tclunk (Close file)
	resp = rpc(&p9.Fcall{Type: p9.Tclunk, Fid: 0})
	assert.Equal(t, uint8(p9.Rclunk), resp.Type)

	// Verify content on disk
	content, err := os.ReadFile(tmpDir + "/test.txt")
	assert.NoError(t, err)
	assert.Equal(t, "hello world", string(content))
}

func TestVFS_DirectoryListing(t *testing.T) {
	tmpDir := t.TempDir()
	backend, _ := NewLocalBackend(tmpDir)

	c1, c2 := net.Pipe()
	session := NewSession(c1, backend, "")
	go session.Serve()
	defer c2.Close()

	rpc := func(req *p9.Fcall) *p9.Fcall {
		req.Tag = 1
		b, _ := req.Bytes()
		c2.Write(b)
		resp, _ := p9.ReadFcall(c2)
		return resp
	}

	// Init
	rpc(&p9.Fcall{Type: p9.Tversion, Msize: 8192, Version: "9P2000"})
	rpc(&p9.Fcall{Type: p9.Tattach, Fid: 0, Uname: "user", Aname: "/"}) // Fid 0 = Root

	// Create Subdir
	// We need to walk to root, clone fid? No, Fid 0 is root.
	// But Tcreate consumes the fid (makes it point to new file).
	// So we should have cloned root first if we wanted to keep it.
	// But let's just use Fid 0.

	// Create "subdir"
	resp := rpc(&p9.Fcall{Type: p9.Tcreate, Fid: 0, Name: "subdir", Perm: 0755 | p9.DMDIR, Mode: 0}) // O_RDONLY
	assert.Equal(t, uint8(p9.Rcreate), resp.Type)
	assert.True(t, (resp.Qid.Type&p9.QTDIR) != 0)

	// Fid 0 is now open on "subdir".
	// Create file inside "subdir"?
	// We need a fresh FID at "subdir". Fid 0 is open.
	// We can Walk to it? No, Tcreate works on open directories?
	// Spec: Tcreate requires FID to represent a directory. It creates file in that directory, optionally making FID represent the new file?
	// Warning: Tcreate(fid, name...) -> "The fid then represents the newly created file".
	// So Fid 0 points to "subdir" now.

	// To create a file inside, we don't start from Fid 0 (which points to subdir and is OPEN).
	// We can't Walk from an OPEN fid in 9P2000?
	// Spec: "The clone request... requires that fid represents a file... The file must not be open."
	// So we need to Clunk Fid 0, then Walk from Root again.

	rpc(&p9.Fcall{Type: p9.Tclunk, Fid: 0})

	// Re-Attach Root -> Fid 0
	rpc(&p9.Fcall{Type: p9.Tattach, Fid: 0, Uname: "user", Aname: "/"})

	// Walk to subdir -> Fid 1
	resp = rpc(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 1, Wname: []string{"subdir"}})
	assert.Equal(t, uint8(p9.Rwalk), resp.Type)

	// Create file in subdir (Fid 1)
	resp = rpc(&p9.Fcall{Type: p9.Tcreate, Fid: 1, Name: "nested.txt", Perm: 0644, Mode: 1})
	assert.Equal(t, uint8(p9.Rcreate), resp.Type)
	// Write
	rpc(&p9.Fcall{Type: p9.Twrite, Fid: 1, Offset: 0, Data: []byte("xyz"), Count: 3})
	rpc(&p9.Fcall{Type: p9.Tclunk, Fid: 1})

	// Read Directory `subdir`
	// Walk Root(0) -> Fid 1
	rpc(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 1, Wname: []string{"subdir"}})
	// Open Fid 1
	rpc(&p9.Fcall{Type: p9.Topen, Fid: 1, Mode: 0})

	// Read
	resp = rpc(&p9.Fcall{Type: p9.Tread, Fid: 1, Offset: 0, Count: 8192})
	assert.Equal(t, uint8(p9.Rread), resp.Type)
	assert.Greater(t, len(resp.Data), 0)

	// Decode Dir entries to verify
	// We just check count for now
}
