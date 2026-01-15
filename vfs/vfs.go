// Package vfs implements a 9P file server backed by the local filesystem.
// All VFS logic is consolidated here following Locality of Behavior.
package vfs

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// --- Server ---

// StartServer starts the VFS 9P server on the given address.
func StartServer(addr string, root string, trustedKey string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("VFS listening on %s, root=%s", addr, root)

	backend, err := NewLocalBackend(root)
	if err != nil {
		return err
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}

		session := NewSession(conn, backend, trustedKey)
		go session.Serve()
	}
}

// --- Backend Interface ---

// Backend abstracts the storage layer.
// Since we use FUSE, the main implementation is LocalBackend (os calls).
type Backend interface {
	Stat(path string) (p9.Dir, error)
	List(path string) ([]p9.Dir, error)
	Open(path string, mode uint8) (io.ReadWriteCloser, error)
	Create(path string, perm uint32, mode uint8) (io.ReadWriteCloser, error)
	Remove(path string) error
	Rename(oldPath, newPath string) error
	Chmod(path string, mode uint32) error
	Truncate(path string, size int64) error
}

// --- LocalBackend Implementation ---

// LocalBackend implements Backend using the local filesystem.
type LocalBackend struct {
	Root string
}

func NewLocalBackend(root string) (*LocalBackend, error) {
	abs, err := filepath.Abs(root)
	if err != nil {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0755); err != nil {
		return nil, err
	}
	return &LocalBackend{Root: abs}, nil
}

func (b *LocalBackend) toLocal(path string) string {
	clean := filepath.Clean(path)
	if strings.HasPrefix(clean, "..") {
		return filepath.Join(b.Root, "invalid")
	}
	return filepath.Join(b.Root, clean)
}

func (b *LocalBackend) Stat(path string) (p9.Dir, error) {
	localPath := b.toLocal(path)
	fi, err := os.Stat(localPath)
	if err != nil {
		return p9.Dir{}, err
	}
	return fileInfoToDir(fi), nil
}

func (b *LocalBackend) List(path string) ([]p9.Dir, error) {
	localPath := b.toLocal(path)
	log.Printf("List: path=%s -> localPath=%s", path, localPath)
	entries, err := os.ReadDir(localPath)
	if err != nil {
		log.Printf("List: ReadDir failed: %v", err)
		return nil, err
	}

	log.Printf("List: Found %d entries", len(entries))
	var dirs []p9.Dir
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		log.Printf("  - %s", info.Name())
		dirs = append(dirs, fileInfoToDir(info))
	}
	log.Printf("List: Returning %d dirs", len(dirs))
	return dirs, nil
}

func (b *LocalBackend) Open(path string, mode uint8) (io.ReadWriteCloser, error) {
	localPath := b.toLocal(path)
	flag := os.O_RDWR
	if mode == 0 {
		flag = os.O_RDONLY
	} else if mode == 1 {
		flag = os.O_WRONLY
	}

	f, err := os.OpenFile(localPath, flag, 0)
	if err != nil {
		return nil, err
	}

	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}

	if fi.IsDir() {
		return &DirHandle{f: f}, nil
	}
	return f, nil
}

func (b *LocalBackend) Create(path string, perm uint32, mode uint8) (io.ReadWriteCloser, error) {
	localPath := b.toLocal(path)
	if perm&p9.DMDIR != 0 {
		if err := os.Mkdir(localPath, 0755); err != nil {
			return nil, err
		}
		f, err := os.Open(localPath)
		if err != nil {
			return nil, err
		}
		return &DirHandle{f: f}, nil
	}

	return os.Create(localPath)
}

func (b *LocalBackend) Remove(path string) error {
	return os.Remove(b.toLocal(path))
}

func (b *LocalBackend) Rename(oldPath, newPath string) error {
	return os.Rename(b.toLocal(oldPath), b.toLocal(newPath))
}

func (b *LocalBackend) Chmod(path string, mode uint32) error {
	return os.Chmod(b.toLocal(path), os.FileMode(mode&0777))
}

func (b *LocalBackend) Truncate(path string, size int64) error {
	return os.Truncate(b.toLocal(path), size)
}

func fileInfoToDir(fi os.FileInfo) p9.Dir {
	mode := uint32(fi.Mode() & 0777)
	qidType := uint8(p9.QTFILE)

	if fi.IsDir() {
		mode |= p9.DMDIR
		qidType = p9.QTDIR
	}

	return p9.Dir{
		Type: 0,
		Dev:  0,
		Qid: p9.Qid{
			Type: qidType,
			Vers: 0,
			Path: uint64(fi.ModTime().UnixNano()),
		},
		Mode:   mode,
		Atime:  uint32(fi.ModTime().Unix()),
		Mtime:  uint32(fi.ModTime().Unix()),
		Length: uint64(fi.Size()),
		Name:   fi.Name(),
		Uid:    "user",
		Gid:    "group",
		Muid:   "user",
	}
}

// DirHandle wraps a directory file to provide 9P read semantics
type DirHandle struct {
	f      *os.File
	offset int64
	data   []byte
	loaded bool
}

func (d *DirHandle) Read(p []byte) (n int, err error) {
	if !d.loaded {
		log.Printf("DirHandle: Reading directory %s", d.f.Name())
		dirs, err := d.f.Readdir(-1)
		if err != nil && err != io.EOF {
			log.Printf("DirHandle: Readdir failed: %v", err)
			return 0, err
		}

		log.Printf("DirHandle: Found %d entries", len(dirs))
		for _, fi := range dirs {
			log.Printf("  - %s", fi.Name())
			p9d := fileInfoToDir(fi)
			d.data = append(d.data, p9d.Bytes()...)
		}
		d.loaded = true
	}

	if d.offset >= int64(len(d.data)) {
		return 0, io.EOF
	}

	n = copy(p, d.data[d.offset:])
	d.offset += int64(n)
	log.Printf("DirHandle: Read returning %d bytes (offset %d/%d)", n, d.offset, len(d.data))
	return n, nil
}

func (d *DirHandle) Write(p []byte) (n int, err error) {
	return 0, io.ErrUnexpectedEOF
}

func (d *DirHandle) Close() error {
	return d.f.Close()
}

// --- Session ---

type Session struct {
	conn       net.Conn
	backend    Backend
	trustedKey ed25519.PublicKey
	fids       map[uint32]*Fid
	mu         sync.Mutex
}

type Fid struct {
	Path string
	File io.ReadWriteCloser
	Dir  bool
	// For readdir state
	DirOffset int
	DirList   []p9.Dir

	// Auth State
	IsAuth      bool
	AuthUser    string
	AuthNonce   []byte
	AuthSuccess bool
}

func NewSession(conn net.Conn, backend Backend, trustedKeyB64 string) *Session {
	var key ed25519.PublicKey
	if trustedKeyB64 != "" {
		keyBytes, err := base64.StdEncoding.DecodeString(trustedKeyB64)
		if err == nil && len(keyBytes) == ed25519.PublicKeySize {
			key = ed25519.PublicKey(keyBytes)
		} else {
			log.Printf("Warning: Invalid Trusted Key provided to VFS Session: %v", err)
		}
	}
	return &Session{
		conn:       conn,
		backend:    backend,
		trustedKey: key,
		fids:       make(map[uint32]*Fid),
	}
}

func (s *Session) Serve() {
	defer s.conn.Close()
	defer s.clunkAll()

	for {
		req, err := p9.ReadFcall(s.conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("vfs read error: %v", err)
			}
			return
		}

		resp := s.handle(req)
		resp.Tag = req.Tag

		buf, err := resp.Bytes()
		if err != nil {
			log.Printf("vfs encode error: %v", err)
			return
		}

		if _, err := s.conn.Write(buf); err != nil {
			return
		}
	}
}

func (s *Session) handle(req *p9.Fcall) *p9.Fcall {
	resp := &p9.Fcall{Type: req.Type + 1}

	switch req.Type {
	case p9.Tversion:
		resp.Msize = req.Msize
		resp.Version = "9P2000"

	case p9.Tauth:
		if s.trustedKey == nil {
			return rError(req, "auth_disabled")
		}

		fid := &Fid{
			Path:      "auth",
			IsAuth:    true,
			AuthUser:  req.Uname,
			AuthNonce: make([]byte, 32),
		}
		if _, err := rand.Read(fid.AuthNonce); err != nil {
			return rError(req, "internal error")
		}

		s.putFid(req.Afid, fid)
		resp.Qid = p9.Qid{Type: p9.QTAUTH, Vers: 1, Path: uint64(req.Afid)}

	case p9.Tattach:
		isPrivileged := req.Uname == "kernel" || req.Uname == "host" || req.Uname == "adm"

		if isPrivileged && s.trustedKey != nil {
			if req.Afid == p9.NOFID {
				return rError(req, "auth_required")
			}
			afid, ok := s.getFid(req.Afid)
			if !ok || !afid.IsAuth || !afid.AuthSuccess {
				return rError(req, "auth_failed")
			}
			if afid.AuthUser != req.Uname {
				return rError(req, "auth_user_mismatch")
			}
		}

		attachPath := req.Aname
		if attachPath == "" {
			attachPath = "/"
		}
		if !strings.HasPrefix(attachPath, "/") {
			attachPath = "/" + attachPath
		}

		fid := &Fid{Path: attachPath}
		d, err := s.backend.Stat(attachPath)
		if err != nil {
			return rError(req, err.Error())
		}
		fid.Dir = (d.Qid.Type & p9.QTDIR) != 0
		s.putFid(req.Fid, fid)
		resp.Qid = d.Qid

	case p9.Twalk:
		fid, ok := s.getFid(req.Fid)
		if !ok {
			return rError(req, "fid not found")
		}

		if fid.IsAuth {
			return rError(req, "cannot walk auth fid")
		}

		wqid := make([]p9.Qid, 0, len(req.Wname))
		currPath := fid.Path

		for _, name := range req.Wname {
			if name == ".." {
				currPath = resolveParent(currPath)
			} else {
				currPath = resolveJoin(currPath, name)
			}

			d, err := s.backend.Stat(currPath)
			if err != nil {
				if len(wqid) == 0 {
					return rError(req, "not found")
				}
				break
			}
			wqid = append(wqid, d.Qid)
		}

		if len(wqid) == len(req.Wname) {
			newFid := &Fid{Path: currPath}
			if len(wqid) > 0 {
				newFid.Dir = (wqid[len(wqid)-1].Type & p9.QTDIR) != 0
			} else {
				newFid.Dir = fid.Dir
			}
			s.putFid(req.Newfid, newFid)
		}
		resp.Wqid = wqid

	case p9.Topen:
		fid, ok := s.getFid(req.Fid)
		if !ok {
			return rError(req, "fid not found")
		}

		if fid.IsAuth {
			resp.Qid = p9.Qid{Type: p9.QTAUTH, Vers: 1, Path: uint64(req.Fid)}
			resp.Iounit = 8192
			return resp
		}

		if !fid.Dir {
			f, err := s.backend.Open(fid.Path, req.Mode)
			if err != nil {
				return rError(req, err.Error())
			}
			fid.File = f
		} else {
			list, err := s.backend.List(fid.Path)
			if err != nil {
				return rError(req, err.Error())
			}
			fid.DirList = list
			fid.DirOffset = 0
		}

		d, err := s.backend.Stat(fid.Path)
		if err != nil {
			return rError(req, err.Error())
		}
		resp.Qid = d.Qid
		resp.Iounit = 8192

	case p9.Tcreate:
		fid, ok := s.getFid(req.Fid)
		if !ok {
			return rError(req, "fid not found")
		}
		if fid.IsAuth {
			return rError(req, "permission denied")
		}

		newPath := resolveJoin(fid.Path, req.Name)
		f, err := s.backend.Create(newPath, req.Perm, req.Mode)
		if err != nil {
			return rError(req, err.Error())
		}

		fid.Path = newPath
		fid.File = f
		if req.Perm&p9.DMDIR != 0 {
			fid.Dir = true
			if f != nil {
				f.Close()
			}
			fid.File = nil
			fid.DirList = []p9.Dir{}
			fid.DirOffset = 0
		} else {
			fid.Dir = false
		}

		d, err := s.backend.Stat(newPath)
		if err == nil {
			resp.Qid = d.Qid
		}
		resp.Iounit = 8192

	case p9.Tread:
		fid, ok := s.getFid(req.Fid)
		if !ok {
			return rError(req, "fid not found")
		}

		if fid.IsAuth {
			resp.Data = fid.AuthNonce
			return resp
		}

		if fid.Dir {
			var buf []byte
			for fid.DirOffset < len(fid.DirList) {
				d := fid.DirList[fid.DirOffset]
				db := d.Bytes()
				if len(buf)+len(db) > int(req.Count) {
					break
				}
				buf = append(buf, db...)
				fid.DirOffset++
			}
			resp.Data = buf
		} else {
			if fid.File == nil {
				return rError(req, "file not open")
			}

			seeker, ok := fid.File.(io.Seeker)
			if ok {
				seeker.Seek(int64(req.Offset), io.SeekStart)
			} else {
				log.Printf("VFS: File %s is not a Seeker", fid.Path)
			}

			buf := make([]byte, req.Count)
			n, err := fid.File.Read(buf)
			log.Printf("VFS: Read %s Offset=%d Count=%d -> n=%d err=%v", fid.Path, req.Offset, req.Count, n, err)

			if err != nil && err != io.EOF {
				return rError(req, err.Error())
			}
			resp.Data = buf[:n]
		}

	case p9.Twrite:
		fid, ok := s.getFid(req.Fid)
		if !ok {
			return rError(req, "fid not found")
		}

		if fid.IsAuth {
			sig := req.Data
			if len(sig) != ed25519.SignatureSize {
				return rError(req, "invalid signature length")
			}

			if ed25519.Verify(s.trustedKey, fid.AuthNonce, sig) {
				fid.AuthSuccess = true
				resp.Count = uint32(len(sig))
			} else {
				return rError(req, "signature verification failed")
			}
			return resp
		}

		if fid.Dir {
			return rError(req, "cannot write to directory")
		}
		if fid.File == nil {
			return rError(req, "file not open")
		}

		seeker, ok := fid.File.(io.Seeker)
		if ok {
			seeker.Seek(int64(req.Offset), io.SeekStart)
		}

		n, err := fid.File.Write(req.Data)
		if err != nil {
			return rError(req, err.Error())
		}
		resp.Count = uint32(n)

	case p9.Tclunk:
		fid, ok := s.getFid(req.Fid)
		if ok {
			if fid.File != nil {
				fid.File.Close()
			}
			s.delFid(req.Fid)
		}
		resp.Type = p9.Rclunk

	case p9.Tremove:
		fid, ok := s.getFid(req.Fid)
		if !ok {
			return rError(req, "fid not found")
		}
		if fid.IsAuth {
			return rError(req, "permission denied")
		}

		err := s.backend.Remove(fid.Path)
		if err != nil {
			return rError(req, err.Error())
		}
		s.delFid(req.Fid)

	case p9.Twstat:
		fid, ok := s.getFid(req.Fid)
		if !ok {
			return rError(req, "fid not found")
		}
		if fid.IsAuth {
			return rError(req, "permission denied")
		}

		if len(req.Stat) < 2 {
			return rError(req, "invalid stat data")
		}
		newDir, _, err := p9.UnmarshalDir(req.Stat)
		if err != nil {
			return rError(req, "failed to parse stat: "+err.Error())
		}

		oldDir, err := s.backend.Stat(fid.Path)
		if err != nil {
			return rError(req, "stat failed: "+err.Error())
		}

		if newDir.Name != "" && newDir.Name != oldDir.Name {
			parentPath := resolveParent(fid.Path)
			newPath := resolveJoin(parentPath, newDir.Name)
			if err := s.backend.Rename(fid.Path, newPath); err != nil {
				return rError(req, "rename failed: "+err.Error())
			}
			fid.Path = newPath
		}

		if newDir.Mode != 0xFFFFFFFF && newDir.Mode != oldDir.Mode {
			if err := s.backend.Chmod(fid.Path, newDir.Mode); err != nil {
				return rError(req, "chmod failed: "+err.Error())
			}
		}

		if newDir.Length != 0xFFFFFFFFFFFFFFFF && newDir.Length != oldDir.Length {
			if err := s.backend.Truncate(fid.Path, int64(newDir.Length)); err != nil {
				return rError(req, "truncate failed: "+err.Error())
			}
		}

		resp.Type = p9.Rwstat

	default:
		return rError(req, fmt.Sprintf("unknown type: %d", req.Type))
	}

	return resp
}

func (s *Session) getFid(id uint32) (*Fid, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	f, ok := s.fids[id]
	return f, ok
}

func (s *Session) putFid(id uint32, f *Fid) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.fids[id] = f
}

func (s *Session) delFid(id uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.fids, id)
}

func (s *Session) clunkAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, f := range s.fids {
		if f.File != nil {
			f.File.Close()
		}
	}
	s.fids = make(map[uint32]*Fid)
}

// --- Helpers ---

func rError(req *p9.Fcall, ename string) *p9.Fcall {
	return &p9.Fcall{
		Type:  p9.Rerror,
		Tag:   req.Tag,
		Ename: ename,
	}
}

func resolveJoin(base, add string) string {
	if base == "/" {
		return "/" + add
	}
	return base + "/" + add
}

func resolveParent(path string) string {
	if path == "/" {
		return "/"
	}
	parts := strings.Split(path, "/")
	if len(parts) <= 2 {
		return "/"
	}
	return strings.Join(parts[:len(parts)-1], "/")
}
