package kernel

import (
	"fmt"
	"net"
	"sync"
	"time"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

const (
	ORCLOSE = 0x40
	OTRUNC  = 0x10
)

// EnvFS provides a read/write interface to environment variables.
type EnvFS struct {
	vars map[string]string // Variable Name -> Value
	mu   sync.Mutex
}

func NewEnvFS() *EnvFS {
	return &EnvFS{
		vars: make(map[string]string),
	}
}

// NewEnvClient creates a client connection to a new EnvFS instance.
func NewEnvClient() *Client {
	c1, c2 := net.Pipe()
	fs := NewEnvFS()

	// Default variables
	fs.vars["user"] = "glenda" // Default, can be overwritten

	go fs.Serve(c2)

	return &Client{
		addr: "internal!env",
		conn: c1,
		tag:  1,
	}
}

func (fs *EnvFS) Serve(conn net.Conn) {
	defer conn.Close()
	// Track open FIDs
	fids := make(map[uint32]*envFid)

	for {
		req, err := p9.ReadFcall(conn)
		if err != nil {
			return
		}

		resp := fs.handle(req, fids)
		resp.Tag = req.Tag

		b, _ := resp.Bytes()
		conn.Write(b)
	}
}

type envFid struct {
	path   string // "/" or "/VARNAME"
	isOpen bool
	mode   uint8
}

func (fs *EnvFS) handle(req *p9.Fcall, fids map[uint32]*envFid) *p9.Fcall {
	resp := &p9.Fcall{Type: req.Type + 1}
	fs.mu.Lock()
	defer fs.mu.Unlock()

	switch req.Type {
	case p9.Tversion:
		resp.Msize = req.Msize
		resp.Version = "9P2000"

	case p9.Tattach:
		fids[req.Fid] = &envFid{path: "/"}
		resp.Qid = p9.Qid{Type: p9.QTDIR, Vers: 0, Path: 0}

	case p9.Twalk:
		fid, ok := fids[req.Fid]
		if !ok {
			return rError(req, "fid not found")
		}

		wqids := []p9.Qid{}
		currPath := fid.path

		for _, name := range req.Wname {
			if name == ".." {
				currPath = "/"
				wqids = append(wqids, p9.Qid{Type: p9.QTDIR, Vers: 0, Path: 0})
				continue
			}

			// Only 1 level deep
			if currPath != "/" {
				return rError(req, "not found")
			}

			// Variable exists?
			if _, exists := fs.vars[name]; exists {
				// It exists
				wqids = append(wqids, p9.Qid{Type: p9.QTFILE, Vers: 0, Path: hashPath(name)})
				currPath = "/" + name
			} else {
				// We allow walking to non-existent if we are going to create it?
				// No, 9P Walk fails if not found.
				// But Tcreate requires walking to parent first.
				// Wait, to Create /env/foo, we Walk to /env (which we are at), then Tcreate "foo".
				// So we don't need to Walk to "foo" unless it exists.
				return rError(req, "not found")
			}
		}

		if len(wqids) == len(req.Wname) {
			fids[req.Newfid] = &envFid{path: currPath}
			resp.Wqid = wqids
		} else {
			// Partial walk?
			// Since we checked existence, this logic implies complete success or immediate fail.
		}

	case p9.Topen:
		fid, ok := fids[req.Fid]
		if !ok {
			return rError(req, "fid not found")
		}

		if fid.path == "/" {
			if req.Mode&3 != 0 && req.Mode&3 != 3 { // OREAD or OEXEC only
				return rError(req, "permission denied")
			}
			resp.Qid = p9.Qid{Type: p9.QTDIR, Vers: 0, Path: 0}
		} else {
			// File
			name := fid.path[1:]
			if _, exists := fs.vars[name]; !exists {
				// It might have been deleted?
				return rError(req, "not found")
			}
			if req.Mode&ORCLOSE != 0 {
				// ORCLOSE not supported on root, handled in remove?
				// Standard says remove on clunk if ORCLOSE.
				// Ignoring for MVP simple env.
			}
			if req.Mode&OTRUNC != 0 {
				fs.vars[name] = ""
			}
			resp.Qid = p9.Qid{Type: p9.QTFILE, Vers: 0, Path: hashPath(name)}
		}
		fid.isOpen = true
		fid.mode = req.Mode
		resp.Iounit = 8192

	case p9.Tcreate:
		fid, ok := fids[req.Fid]
		if !ok {
			return rError(req, "fid not found")
		}
		if fid.path != "/" {
			return rError(req, "not a directory")
		}

		// Create variable
		name := req.Name
		if name == "" || name == "." || name == ".." {
			return rError(req, "invalid name")
		}
		fs.vars[name] = ""

		// Update FID to point to new file
		fid.path = "/" + name
		fid.isOpen = true
		fid.mode = req.Mode
		resp.Qid = p9.Qid{Type: p9.QTFILE, Vers: 0, Path: hashPath(name)}
		resp.Iounit = 8192

	case p9.Tread:
		fid, ok := fids[req.Fid]
		if !ok {
			return rError(req, "fid not found")
		}
		if !fid.isOpen {
			return rError(req, "file not open")
		}

		var content []byte
		if fid.path == "/" {
			// List directory
			for name := range fs.vars {
				d := p9.Dir{
					Qid:    p9.Qid{Type: p9.QTFILE, Vers: 0, Path: hashPath(name)},
					Mode:   0644,
					Name:   name,
					Length: uint64(len(fs.vars[name])),
					Uid:    "sys",
					Gid:    "sys",
					Muid:   "sys",
					Atime:  uint32(time.Now().Unix()),
					Mtime:  uint32(time.Now().Unix()),
				}
				content = append(content, d.Bytes()...)
			}
		} else {
			name := fid.path[1:]
			val, exists := fs.vars[name]
			if !exists {
				return rError(req, "not found")
			}
			content = []byte(val)
		}

		if req.Offset >= uint64(len(content)) {
			resp.Data = []byte{}
		} else {
			end := int(req.Offset) + int(req.Count)
			if end > len(content) {
				end = len(content)
			}
			resp.Data = content[req.Offset:end]
		}

	case p9.Twrite:
		fid, ok := fids[req.Fid]
		if !ok {
			return rError(req, "fid not found")
		}
		if !fid.isOpen {
			return rError(req, "file not open")
		}
		if fid.path == "/" {
			return rError(req, "is a directory")
		}

		name := fid.path[1:]
		if _, exists := fs.vars[name]; !exists {
			return rError(req, "not found")
		}

		// Simple overwrite or append?
		// Usually environment writes are small and atomic-ish.
		// We'll support append via offsets, but simplest is just replacing string.
		// If Offset == 0, replace? Or just patch?
		// To allow `echo val > file` (truncates) vs `echo val >> file`.

		// The shell handles truncation by opening with OTRUNC.
		// If we are here, we just modify the buffer at offset.

		val := []byte(fs.vars[name])
		off := int(req.Offset)
		data := req.Data

		// Grow if needed
		if off+len(data) > len(val) {
			newVal := make([]byte, off+len(data))
			copy(newVal, val)
			val = newVal
		}
		copy(val[off:], data)
		fs.vars[name] = string(val)
		resp.Count = uint32(len(data))

	case p9.Tremove:
		fid, ok := fids[req.Fid]
		if !ok {
			return rError(req, "fid not found")
		}
		if fid.path != "/" {
			name := fid.path[1:]
			delete(fs.vars, name)
		}
		delete(fids, req.Fid)
		resp.Type = p9.Rremove

	case p9.Tclunk:
		delete(fids, req.Fid)
		resp.Type = p9.Rclunk

	case p9.Tstat:
		fid, ok := fids[req.Fid]
		if !ok {
			return rError(req, "fid not found")
		}

		// Stat logic...
		// Minimal
		name := "env"
		qid := p9.Qid{Type: p9.QTDIR, Vers: 0, Path: 0}
		mode := uint32(p9.DMDIR | 0755)
		length := uint64(0)

		if fid.path != "/" {
			name = fid.path[1:]
			qid = p9.Qid{Type: p9.QTFILE, Vers: 0, Path: hashPath(name)}
			mode = 0644
			if v, ok := fs.vars[name]; ok {
				length = uint64(len(v))
			}
		}

		d := p9.Dir{
			Qid:    qid,
			Mode:   mode,
			Name:   name,
			Length: length,
			Uid:    "sys",
			Gid:    "sys",
			Muid:   "sys",
			Atime:  uint32(time.Now().Unix()),
			Mtime:  uint32(time.Now().Unix()),
		}
		resp.Stat = d.Bytes()

	default:
		return rError(req, fmt.Sprintf("unknown type: %d", req.Type))
	}

	return resp
}

func hashPath(s string) uint64 {
	h := uint64(0)
	for i := 0; i < len(s); i++ {
		h = 31*h + uint64(s[i])
	}
	return h
}
