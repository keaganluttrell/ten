package kernel

import (
	"fmt"
	"net"
	"sync"
	"time"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// BootFS is a minimal in-memory file system for rescue mode.
type BootFS struct {
	files map[string]string // Path -> Content
	dirs  map[string][]p9.Dir
	// Simplified server map
	fids map[uint32]string // Fid -> Path
	mu   sync.Mutex
}

func NewBootFS() *BootFS {
	fs := &BootFS{
		files: make(map[string]string),
		dirs:  make(map[string][]p9.Dir),
		fids:  make(map[uint32]string),
	}
	// Default Content
	fs.addFile("/README", "CRITICAL ERROR: VFS Unreachable.\nSystem is in RESCUE MODE.\n\nCheck your backend connection.")
	return fs
}

func (fs *BootFS) addFile(path string, content string) {
	fs.files[path] = content
	// Add to root dir listing (simplified, no recursion support yet)
	// Assuming path is like /README
	name := path[1:]
	dir := p9.Dir{
		Qid:    p9.Qid{Type: p9.QTFILE, Vers: 1, Path: uint64(len(content))}, // Mock path
		Mode:   0444,
		Name:   name,
		Length: uint64(len(content)),
		Uid:    "sys",
		Gid:    "sys",
		Muid:   "sys",
		Atime:  uint32(time.Now().Unix()),
		Mtime:  uint32(time.Now().Unix()),
	}
	fs.dirs["/"] = append(fs.dirs["/"], dir)
}

// NewBootFSClient creates a pipe, spawns a BootFS server on one end, and returns a Client on the other.
func NewBootFSClient() *Client {
	c1, c2 := net.Pipe()
	fs := NewBootFS()

	// Spawn Server
	go fs.Serve(c2)

	// Return Client
	return &Client{
		addr: "internal!ramfs",
		conn: c1,
		tag:  1,
	}
}

func (fs *BootFS) Serve(conn net.Conn) {
	defer conn.Close()
	for {
		req, err := p9.ReadFcall(conn)
		if err != nil {
			return
		}

		resp := fs.handle(req)
		resp.Tag = req.Tag

		b, _ := resp.Bytes()
		conn.Write(b)
	}
}

func (fs *BootFS) handle(req *p9.Fcall) *p9.Fcall {
	resp := &p9.Fcall{Type: req.Type + 1}
	fs.mu.Lock()
	defer fs.mu.Unlock()

	switch req.Type {
	case p9.Tversion:
		resp.Msize = req.Msize
		resp.Version = "9P2000"

	case p9.Tattach:
		fs.fids[req.Fid] = "/"
		resp.Qid = p9.Qid{Type: p9.QTDIR, Vers: 1, Path: 0}

	case p9.Twalk:
		path, ok := fs.fids[req.Fid]
		if !ok {
			return rError(req, "fid not found")
		}

		wqids := []p9.Qid{}
		newPath := path

		// Only support cloning (0 names) or walking to README or dev
		if len(req.Wname) == 0 {
			fs.fids[req.Newfid] = path
		} else if len(req.Wname) == 1 {
			name := req.Wname[0]
			if name == "README" && path == "/" {
				newPath = "/README"
				wqids = append(wqids, p9.Qid{Type: p9.QTFILE, Vers: 1, Path: 100})
				fs.fids[req.Newfid] = newPath
			} else if name == "dev" && path == "/" {
				newPath = "/dev"
				wqids = append(wqids, p9.Qid{Type: p9.QTDIR, Vers: 1, Path: 200})
				fs.fids[req.Newfid] = newPath
			} else {
				return rError(req, "not found")
			}
		} else {
			return rError(req, "not found")
		}
		resp.Wqid = wqids

	case p9.Topen:
		path, ok := fs.fids[req.Fid]
		if !ok {
			return rError(req, "fid not found")
		}

		if path == "/" || path == "/dev" {
			resp.Qid = p9.Qid{Type: p9.QTDIR, Vers: 1, Path: 0}
			if path == "/dev" {
				resp.Qid.Path = 200
			}
		} else {
			resp.Qid = p9.Qid{Type: p9.QTFILE, Vers: 1, Path: 100}
		}
		resp.Iounit = 8192

	case p9.Tread:
		path, ok := fs.fids[req.Fid]
		if !ok {
			return rError(req, "fid not found")
		}

		content := ""
		if path == "/README" {
			content = fs.files["/README"]
		} else if path == "/" || path == "/dev" {
			// Directory read support if needed (optional for this test if we just walk through)
			resp.Data = []byte{}
			break
		} else {
			// Directory read? Return empty for now or mock dir
			resp.Data = []byte{}
			break
		}

		if req.Offset >= uint64(len(content)) {
			resp.Data = []byte{}
		} else {
			end := int(req.Offset) + int(req.Count)
			if end > len(content) {
				end = len(content)
			}
			resp.Data = []byte(content[req.Offset:end])
		}

	case p9.Tclunk:
		delete(fs.fids, req.Fid)
		resp.Type = p9.Rclunk

	case p9.Tstat:
		resp.Stat = make([]byte, 0) // Dummy

	default:
		return rError(req, fmt.Sprintf("unknown type: %d", req.Type))
	}
	return resp
}
