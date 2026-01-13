package ssr

import (
	"log"
	"net"
	"testing"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
	"github.com/stretchr/testify/assert"
)

func TestRender(t *testing.T) {
	// Test Layout
	html := string(RenderLayout("Title", "Content"))
	assert.Contains(t, html, "<html>")
	assert.Contains(t, html, "<title>Title</title>")
	assert.Contains(t, html, "Content")

	// Test Dir
	dirs := []p9.Dir{
		{Name: "foo", Qid: p9.Qid{Type: p9.QTFILE}},
		{Name: "bar", Qid: p9.Qid{Type: p9.QTDIR}},
	}
	dirHtml := RenderDir(dirs)
	assert.Contains(t, dirHtml, "href=\"foo\"")
	assert.Contains(t, dirHtml, "href=\"bar/\"")

	// Test File
	fileHtml := RenderFile("hello <world>")
	assert.Contains(t, fileHtml, "<pre>")
	assert.Contains(t, fileHtml, "&lt;world&gt;")
}

func TestSSR_Integration(t *testing.T) {
	// Mock VFS Server
	vfsClient, vfsServer := net.Pipe()

	go func() {
		defer vfsServer.Close()
		for {
			req, err := p9.ReadFcall(vfsServer)
			if err != nil {
				return
			}
			resp := &p9.Fcall{Type: req.Type + 1, Tag: req.Tag}

			switch req.Type {
			case p9.Tversion:
				resp.Version = "9P2000"
				resp.Msize = 8192
			case p9.Tattach:
				resp.Qid = p9.Qid{Type: p9.QTDIR}
			case p9.Twalk:
				resp.Wqid = make([]p9.Qid, len(req.Wname))
				// Simple mock: if name="file", return file qid, else dir qid
				for i, name := range req.Wname {
					if name == "file" {
						resp.Wqid[i] = p9.Qid{Type: p9.QTFILE}
					} else {
						resp.Wqid[i] = p9.Qid{Type: p9.QTDIR}
					}
				}
			case p9.Topen:
				// Return Open Qid
				resp.Qid = p9.Qid{Type: p9.QTDIR} // Match Tattach for root, overridden if file
				if req.Fid == 101 {               // Hack: assume FID 101 is the file walked to
					resp.Qid = p9.Qid{Type: p9.QTFILE}
				}
			case p9.Tread:
				// Return dummy content
				resp.Data = []byte("vfs content")
			case p9.Tclunk:
			case p9.Tstat:
				resp.Stat = []byte{}
			default:
				resp.Type = p9.Rerror
				resp.Ename = "not impl"
				log.Printf("MockVFS: unhandled %v", req)
			}

			b, _ := resp.Bytes()
			vfsServer.Write(b)
		}
	}()

	// Setup SSR Server
	// We need to pass the address. But we have a pipe.
	// SSR `Dial` calls `net.Dial`.
	// To test with pipe, we need to inject the connection or mock Dial.
	// SSR `fs.go` calls `Dial(s.vfsAddr)`. `ssr/client.go` uses `net.Dial`.

	// Refactor needed? Or start a real TCP listener for MockVFS?
	// Real TCP listener is easier for integration test without refactoring `ssr`.

	l, err := net.Listen("tcp", "127.0.0.1:0") // Random port
	assert.NoError(t, err)
	vfsAddr := l.Addr().String()

	// Replace previous pipe logic with real listener loop
	vfsServer.Close() // Close pipe
	vfsClient.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				for {
					req, err := p9.ReadFcall(c)
					if err != nil {
						return
					}

					// Same mock logic
					resp := &p9.Fcall{Type: req.Type + 1, Tag: req.Tag}
					switch req.Type {
					case p9.Tversion:
						resp.Version = "9P2000"
						resp.Msize = 8192
					case p9.Tattach:
						resp.Qid = p9.Qid{Type: p9.QTDIR}
					case p9.Twalk:
						resp.Wqid = make([]p9.Qid, len(req.Wname))
						for i, name := range req.Wname {
							if name == "file.txt" {
								resp.Wqid[i] = p9.Qid{Type: p9.QTFILE}
							} else {
								resp.Wqid[i] = p9.Qid{Type: p9.QTDIR}
							}
						}
					case p9.Topen:
						resp.Qid = p9.Qid{Type: p9.QTDIR}
						if req.Fid == 1 {
							resp.Qid = p9.Qid{Type: p9.QTFILE}
						}
						resp.Iounit = 8192
					case p9.Tread:
						if req.Offset > 0 {
							resp.Data = []byte{}
						} else {
							resp.Data = []byte("vfs_content")
						}
					case p9.Tclunk:
					case p9.Tstat:
						resp.Stat = []byte{}
					default:
						resp.Type = p9.Rerror
					}
					b, _ := resp.Bytes()
					c.Write(b)
				}
			}(conn)
		}
	}()
	defer l.Close()

	// SSR Connection
	ssrClient, ssrServer := net.Pipe()
	session := NewSession(ssrServer, vfsAddr)
	go session.Serve()
	defer ssrClient.Close()

	// Helper
	rpc := func(typeName string, req *p9.Fcall) *p9.Fcall {
		req.Tag = 1
		b, _ := req.Bytes()
		ssrClient.Write(b)
		resp, _ := p9.ReadFcall(ssrClient)
		if resp.Type == p9.Rerror {
			t.Fatalf("%s failed: %s", typeName, resp.Ename)
		}
		return resp
	}

	// 1. Version
	rpc("version", &p9.Fcall{Type: p9.Tversion, Msize: 8192, Version: "9P2000"})

	// 2. Attach
	rpc("attach", &p9.Fcall{Type: p9.Tattach, Fid: 0, Uname: "u", Aname: "/"})

	// 3. Walk to file
	// Note: Our Mock VFS returns QTFILE if name is "file.txt" -> check case p9.Twalk above
	rpc("walk", &p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 1, Wname: []string{"file.txt"}})

	// 4. Open File (Triggers read from VFS -> Render)
	// SSR `Topen` sends `Topen` to VFS, then `Tread` from VFS.
	// Our Mock VFS returns "vfs_content".
	// SSR should wrap it: <pre>vfs_content</pre>...
	rpc("open", &p9.Fcall{Type: p9.Topen, Fid: 1, Mode: 0})

	// 5. Read from SSR
	resp := rpc("read", &p9.Fcall{Type: p9.Tread, Fid: 1, Offset: 0, Count: 8192})

	content := string(resp.Data)
	assert.Contains(t, content, "<pre>vfs_content</pre>")
	assert.Contains(t, content, "<html>")
}
