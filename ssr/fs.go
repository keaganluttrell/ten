package ssr

import (
	"fmt"
	"log"
	"net"
	"sync"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

type Session struct {
	conn    net.Conn
	vfsAddr string
	fids    map[uint32]*Fid
	mu      sync.Mutex
}

type Fid struct {
	Path   string
	VfsFid uint32 // The FID we use on the VFS connection side?
	// No, every 9P request is a new RPC?
	// Better: We need a persistent VFS client per session?
	// If we want to maintain state (like walk history), we need to mirror FIDs on VFS.
	// Simplification V1: SSR is a "browsing proxy".
	// We can use One VFS Client per SSR Session.
	// And Map SSR Fid -> VFS Fid.

	VfsC *Client // Client associated with this session

	IsDir   bool
	Content []byte // Rendered HTML content
}

func NewSession(conn net.Conn, vfsAddr string) *Session {
	return &Session{
		conn:    conn,
		vfsAddr: vfsAddr,
		fids:    make(map[uint32]*Fid),
	}
}

func (s *Session) Serve() {
	defer s.conn.Close()

	// Create VFS Client
	vfsC, err := Dial(s.vfsAddr)
	if err != nil {
		log.Printf("failed to dial vfs: %v", err)
		return
	}
	defer vfsC.Close()

	// Init VFS
	if _, err := vfsC.RPC(&p9.Fcall{Type: p9.Tversion, Msize: 8192, Version: "9P2000"}); err != nil {
		log.Printf("vfs version failed: %v", err)
		return
	}

	for {
		req, err := p9.ReadFcall(s.conn)
		if err != nil {
			return
		}

		resp := s.handle(req, vfsC)
		resp.Tag = req.Tag

		b, _ := resp.Bytes()
		s.conn.Write(b)
	}
}

func (s *Session) handle(req *p9.Fcall, vfsC *Client) *p9.Fcall {
	resp := &p9.Fcall{Type: req.Type + 1}

	switch req.Type {
	case p9.Tversion:
		resp.Msize = req.Msize
		resp.Version = "9P2000"

	case p9.Tattach:
		// Attach to Root
		// Mirror on VFS
		// Use Fid 0 on VFS? Use same ID as request?
		// req.Fid is local. We use same Fid ID on VFS for 1:1 mapping.

		vfsReq := &p9.Fcall{
			Type:  p9.Tattach,
			Fid:   req.Fid,
			Afid:  p9.NOFID,
			Uname: req.Uname,
			Aname: req.Aname, // /view -> /data mapping happens by just attaching to /data?
			// The SPEC says /view matches /data.
			// Assumption: VFS root IS /data (or contains it).
			// If VFS root is /, then we walk to /view?
			// But SSR serves /view as ITS root.
			// So SSR Root -> VFS Root for now.
		}

		vfsResp, err := vfsC.RPC(vfsReq)
		if err != nil {
			return rError(req, err.Error())
		}

		f := &Fid{
			Path:   "/",
			VfsFid: req.Fid,
			VfsC:   vfsC,
		}
		s.putFid(req.Fid, f)
		resp.Qid = vfsResp.Qid

	case p9.Twalk:
		fid, ok := s.getFid(req.Fid)
		if !ok {
			return rError(req, "fid not found")
		}

		vfsReq := &p9.Fcall{
			Type:   p9.Twalk,
			Fid:    fid.VfsFid,
			Newfid: req.Newfid,
			Wname:  req.Wname,
		}

		vfsResp, err := vfsC.RPC(vfsReq)
		if err != nil {
			return rError(req, err.Error())
		}

		if len(vfsResp.Wqid) == len(req.Wname) {
			newPath := fid.Path // Calculate path if needed for Title
			// Simplified path tracking
			for _, w := range req.Wname {
				if w == ".." {
					// Handle parent logic or ignore for now
				} else {
					if newPath == "/" {
						newPath += w
					} else {
						newPath += "/" + w
					}
				}
			}

			nf := &Fid{
				Path:   newPath,
				VfsFid: req.Newfid,
				VfsC:   vfsC,
			}
			s.putFid(req.Newfid, nf)
		}
		resp.Wqid = vfsResp.Wqid

	case p9.Tstat:
		fid, ok := s.getFid(req.Fid)
		if !ok {
			return rError(req, "fid not found")
		}

		// If content is loaded, use that length
		// Else ask VFS stat

		if len(fid.Content) > 0 {
			// Synthetic Stat
			// How to marshal a Stat? We need to construct a Dir?
			// This is complex. 9P requires Stat to match Open Qid.
			// Let's just forward Tstat to VFS for basic metadata (ModTime etc),
			// BUT we must override Length if we are presenting HTML instead of raw.
			// Problem: Browser does Tstat BEFORE Open.
			// We don't know HTML size yet.
			// Solution: Report Length 0 or try to guess?
			// Or just forward VFS stat. Browser reads until EOF anyway?
			// If Browser relies on Size, it might be confused if we say 100 bytes (raw) and send 500 (html).
			// If we say 0, it reads until 0 returned?
			// Let's forward VFS stat for now.
		}

		vfsReq := &p9.Fcall{Type: p9.Tstat, Fid: fid.VfsFid}
		vfsResp, err := vfsC.RPC(vfsReq)
		if err != nil {
			return rError(req, err.Error())
		}
		resp.Stat = vfsResp.Stat

	case p9.Topen:
		fid, ok := s.getFid(req.Fid)
		if !ok {
			return rError(req, "fid not found")
		}

		// 1. Open on VFS
		openReq := &p9.Fcall{Type: p9.Topen, Fid: fid.VfsFid, Mode: req.Mode}
		openResp, err := vfsC.RPC(openReq)
		if err != nil {
			return rError(req, err.Error())
		}
		resp.Qid = openResp.Qid
		resp.Iounit = openResp.Iounit // We honor VFS or set own?

		// 2. Fetch Content and Render
		// If Dir
		if (resp.Qid.Type & p9.QTDIR) != 0 {
			// Read Directory Listing
			// Read All Loop
			var allData []byte
			offset := uint64(0)
			for {
				readReq := &p9.Fcall{
					Type:   p9.Tread,
					Fid:    fid.VfsFid,
					Offset: offset,
					Count:  8192,
				}
				rResp, err := vfsC.RPC(readReq)
				if err != nil || len(rResp.Data) == 0 {
					break
				}
				allData = append(allData, rResp.Data...)
				offset += uint64(len(rResp.Data))
			}

			// Unmarshal Dirs
			var dirs []p9.Dir
			scan := allData
			for len(scan) > 0 {
				d, n, err := p9.UnmarshalDir(scan)
				if err != nil {
					break
				}
				dirs = append(dirs, d)
				scan = scan[n:]
			}

			// Render
			html := RenderDir(dirs)
			fid.Content = RenderLayout(fid.Path, html)
			fid.IsDir = true

		} else {
			// File
			// Read All
			var allData []byte
			offset := uint64(0)
			for {
				readReq := &p9.Fcall{
					Type:   p9.Tread,
					Fid:    fid.VfsFid,
					Offset: offset,
					Count:  8192,
				}
				rResp, err := vfsC.RPC(readReq)
				if err != nil || len(rResp.Data) == 0 {
					break
				}
				allData = append(allData, rResp.Data...)
				offset += uint64(len(rResp.Data))
			}

			html := RenderFile(string(allData))
			fid.Content = RenderLayout(fid.Path, html)
		}

	case p9.Tread:
		fid, ok := s.getFid(req.Fid)
		if !ok {
			return rError(req, "fid not found")
		}

		if int(req.Offset) >= len(fid.Content) {
			resp.Data = []byte{}
		} else {
			end := int(req.Offset) + int(req.Count)
			if end > len(fid.Content) {
				end = len(fid.Content)
			}
			resp.Data = fid.Content[req.Offset:end]
		}

	case p9.Tclunk:
		fid, ok := s.getFid(req.Fid)
		if ok {
			vfsC.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: fid.VfsFid})
			s.delFid(req.Fid)
		}
		resp.Type = p9.Rclunk

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

func rError(req *p9.Fcall, ename string) *p9.Fcall {
	return &p9.Fcall{
		Type:  p9.Rerror,
		Tag:   req.Tag,
		Ename: ename,
	}
}
