package factotum

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// StartServer starts the Factotum service.
func StartServer(addr string, dataPath string, vfsAddr string) error {
	cfg := Config{
		ListenAddr: addr,
		DataPath:   dataPath,
		VFSAddr:    vfsAddr,
	}
	s, err := NewServer(cfg)
	if err != nil {
		return err
	}
	return s.Run()
}

// Config holds server configuration.
type Config struct {
	ListenAddr string // TCP address to listen on (e.g., ":9003")
	DataPath   string // Path to /priv/factotum (local fs for v1)
	VFSAddr    string // Address of VFS Service
}

// Server is the Factotum 9P server.
type Server struct {
	listenAddr string
	keyring    *Keyring
	sessions   *Sessions
	rpc        *RPC
	ctl        *Ctl
}

// NewServer creates a new Factotum server.
func NewServer(cfg Config) (*Server, error) {
	keyring, err := NewKeyring(cfg.DataPath)
	if err != nil {
		return nil, fmt.Errorf("keyring init failed: %w", err)
	}

	sessions := NewSessions()

	return &Server{
		listenAddr: cfg.ListenAddr,
		keyring:    keyring,
		sessions:   sessions,
		rpc:        NewRPC(sessions, keyring, cfg.VFSAddr), // Pass VFSAddr
		ctl:        NewCtl(keyring),
	}, nil
}

// Run starts the TCP listener and accepts connections.
func (s *Server) Run() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Printf("factotum listening on %s", s.listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

// handleConn handles a single client connection.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	fids := make(map[uint32]*PFid)
	var mu sync.Mutex

	for {
		req, err := p9.ReadFcall(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("read error: %v", err)
			}
			return
		}

		resp := &p9.Fcall{Type: req.Type + 1, Tag: req.Tag}

		switch req.Type {
		case p9.Tversion:
			resp.Version = "9P2000"
			resp.Msize = req.Msize

		case p9.Tattach:
			mu.Lock()
			fids[req.Fid] = &PFid{Path: "/"}
			mu.Unlock()
			resp.Qid = p9.Qid{Type: p9.QTDIR, Path: 0, Vers: 0}

		case p9.Twalk:
			mu.Lock()
			fid, ok := fids[req.Fid]
			mu.Unlock()

			if !ok {
				resp = rError(req, "fid not found")
				break
			}

			wqid := make([]p9.Qid, 0)
			currPath := fid.Path

			for _, w := range req.Wname {
				if currPath == "/" {
					if w == "rpc" || w == "ctl" || w == "proto" {
						currPath = "/" + w
						wqid = append(wqid, p9.Qid{Type: p9.QTFILE, Path: qidPath(currPath)})
					} else {
						// Error or stop? Twalk stops at first failure without erroring if partial
						break
					}
				} else {
					// Sub-files? None for now.
					break
				}
			}

			if len(wqid) == len(req.Wname) {
				mu.Lock()
				fids[req.Newfid] = &PFid{Path: currPath}
				mu.Unlock()
			}
			resp.Wqid = wqid

		case p9.Topen:
			mu.Lock()
			fid, ok := fids[req.Fid]
			mu.Unlock()

			if !ok {
				resp = rError(req, "fid not found")
				break
			}

			if fid.Path == "/rpc" {
				s.rpc.Open(req.Fid) // Should tie to Session ID? RPC.Open just inits state
			}

			resp.Qid = p9.Qid{Type: p9.QTFILE, Path: qidPath(fid.Path)} // Dir?
			if fid.Path == "/" {
				resp.Qid.Type = p9.QTDIR
			}
			resp.Iounit = 8192

		case p9.Tread:
			mu.Lock()
			fid, ok := fids[req.Fid]
			mu.Unlock()
			if !ok {
				resp = rError(req, "fid not found")
				break
			}

			if fid.Path == "/rpc" {
				str, err := s.rpc.Read(req.Fid)
				if err != nil {
					resp = rError(req, err.Error())
				} else {
					resp.Data = []byte(str)
				}
			} else if fid.Path == "/proto" {
				// return proto js
				resp.Data = []byte("var Proto = {};") // Placeholder or read from proto.go
			} else if fid.Path == "/" {
				// Dir listing
				if req.Offset == 0 {
					d1 := p9.Dir{Name: "rpc", Qid: p9.Qid{Type: p9.QTFILE}}
					d2 := p9.Dir{Name: "ctl", Qid: p9.Qid{Type: p9.QTFILE}}
					d3 := p9.Dir{Name: "proto", Qid: p9.Qid{Type: p9.QTFILE}}
					resp.Data = append(d1.Bytes(), d2.Bytes()...)
					resp.Data = append(resp.Data, d3.Bytes()...)
				}
			}

		case p9.Twrite:
			mu.Lock()
			fid, ok := fids[req.Fid]
			mu.Unlock()
			if !ok {
				resp = rError(req, "fid not found")
				break
			}

			if fid.Path == "/rpc" {
				if err := s.rpc.Write(req.Fid, req.Data); err != nil {
					resp = rError(req, err.Error())
				} else {
					resp.Count = req.Count
				}
			} else if fid.Path == "/ctl" {
				// ctl handler
				resp.Count = req.Count
			} else {
				resp = rError(req, "permission denied")
			}

		case p9.Tclunk:
			mu.Lock()
			fid, ok := fids[req.Fid]
			delete(fids, req.Fid)
			mu.Unlock()
			if ok && fid.Path == "/rpc" {
				s.rpc.Close(req.Fid)
			}
			resp.Type = p9.Rclunk

		default:
			resp = rError(req, "unknown type")
		}

		b, _ := resp.Bytes()
		conn.Write(b)
	}
}

type PFid struct {
	Path string
}

func rError(req *p9.Fcall, ename string) *p9.Fcall {
	return &p9.Fcall{
		Type:  p9.Rerror,
		Tag:   req.Tag,
		Ename: ename,
	}
}

func qidPath(path string) uint64 {
	// Simple hash or ID
	if path == "/rpc" {
		return 1
	}
	if path == "/ctl" {
		return 2
	}
	if path == "/proto" {
		return 3
	}
	return 0
}
