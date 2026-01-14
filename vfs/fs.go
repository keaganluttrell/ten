package vfs

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

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
	Dir  bool // Is directory
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
		// Host Challenge Protocol
		// 1. Client sends Tauth(uname).
		// 2. Server generates nonce, returns Qid(QTAUTH).
		// 3. Client Reads nonce.
		// 4. Client Signs nonce.
		// 5. Client Writes signature.

		// Only allow Tauth if we have a Trusted Key
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
		// Check Privileged Access
		isPrivileged := req.Uname == "kernel" || req.Uname == "host" || req.Uname == "adm"

		if isPrivileged && s.trustedKey != nil {
			// Require successful Afid
			if req.Afid == p9.NOFID {
				return rError(req, "auth_required")
			}
			afid, ok := s.getFid(req.Afid)
			if !ok || !afid.IsAuth || !afid.AuthSuccess {
				return rError(req, "auth_failed")
			}
			// Verify Afid belongs to same user? Spec says yes.
			if afid.AuthUser != req.Uname {
				return rError(req, "auth_user_mismatch")
			}
		}

		// Attach to path specified in Aname (default to root)
		attachPath := req.Aname
		if attachPath == "" {
			attachPath = "/"
		}
		// Normalize: ensure starts with /
		if !strings.HasPrefix(attachPath, "/") {
			attachPath = "/" + attachPath
		}

		fid := &Fid{Path: attachPath}
		// Stat the attach path to get Qid
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
			// Cannot walk auth file
			return rError(req, "cannot walk auth fid")
		}

		wqid := make([]p9.Qid, 0, len(req.Wname))
		currPath := fid.Path

		for _, name := range req.Wname {
			if name == ".." {
				// Parent
				currPath = resolveParent(currPath)
			} else {
				currPath = resolveJoin(currPath, name)
			}

			d, err := s.backend.Stat(currPath)
			if err != nil {
				// Stop walk here
				if len(wqid) == 0 {
					return rError(req, "not found")
				}
				break
			}
			wqid = append(wqid, d.Qid)
		}

		if len(wqid) == len(req.Wname) {
			// Successful full walk
			newFid := &Fid{Path: currPath}
			// Stat to check if dir
			if len(wqid) > 0 {
				newFid.Dir = (wqid[len(wqid)-1].Type & p9.QTDIR) != 0
			} else {
				newFid.Dir = fid.Dir // Clone
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
			// Auth file is "open" implicitly? or requires open?
			// 9P spec says Tauth returns AQid, then can serve Read/Write without open?
			// No, 9P2000 says Tauth establishes AFID.
			// "The afid is opened as a file of type QTAUTH".
			// So Topen isn't strictly needed for afid usually, but if client sends it, we ACK.
			resp.Qid = p9.Qid{Type: p9.QTAUTH, Vers: 1, Path: uint64(req.Fid)}
			resp.Iounit = 8192
			return resp
		}

		// If explicit Open
		// If it's a file, open raw
		if !fid.Dir {
			f, err := s.backend.Open(fid.Path, req.Mode)
			if err != nil {
				return rError(req, err.Error())
			}
			fid.File = f
		} else {
			// Directory: Prepare listing
			list, err := s.backend.List(fid.Path)
			if err != nil {
				return rError(req, err.Error())
			}
			fid.DirList = list
			fid.DirOffset = 0
		}

		// Return Qid again
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
		// If perm has DMDIR, it's a dir, close result (nil) and treat as dir?
		if req.Perm&p9.DMDIR != 0 {
			fid.Dir = true
			if f != nil {
				f.Close()
			} // Directories don't stay open as files usually here
			fid.File = nil
			// Re-open/list empty?
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
			// READ returns Nonce
			resp.Data = fid.AuthNonce
			return resp
		}

		if fid.Dir {
			// Directory Read
			// Pack Dir structs into response
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
			// File Read
			if fid.File == nil {
				return rError(req, "file not open")
			}

			// We need io.Seeker or just ReadAt

			// With OS file, we should use ReadAt or Seek.
			// Let's assume simplest: Seek then Read
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
			// WRITE accepts Signature
			// Verify(PubKey, Start+Nonce, Signature)?
			// Protocol: Kernel signs the Nonce.
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

		// ... existing Twrite ...
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

		// Parse the stat data
		if len(req.Stat) < 2 {
			return rError(req, "invalid stat data")
		}
		newDir, _, err := p9.UnmarshalDir(req.Stat)
		if err != nil {
			return rError(req, "failed to parse stat: "+err.Error())
		}

		// Get current stat for comparison
		oldDir, err := s.backend.Stat(fid.Path)
		if err != nil {
			return rError(req, "stat failed: "+err.Error())
		}

		// Handle rename: if Name changed and is not empty/"~"
		if newDir.Name != "" && newDir.Name != oldDir.Name {
			// Rename: compute new path in same directory
			parentPath := resolveParent(fid.Path)
			newPath := resolveJoin(parentPath, newDir.Name)
			if err := s.backend.Rename(fid.Path, newPath); err != nil {
				return rError(req, "rename failed: "+err.Error())
			}
			fid.Path = newPath // Update FID path
		}

		// Handle chmod: if Mode changed (ignore if all 1s = "don't change")
		if newDir.Mode != 0xFFFFFFFF && newDir.Mode != oldDir.Mode {
			if err := s.backend.Chmod(fid.Path, newDir.Mode); err != nil {
				return rError(req, "chmod failed: "+err.Error())
			}
		}

		// Handle truncate: if Length changed (ignore if all 1s)
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
	// split logic
	parts := strings.Split(path, "/")
	if len(parts) <= 2 {
		return "/"
	}
	return strings.Join(parts[:len(parts)-1], "/")
}
