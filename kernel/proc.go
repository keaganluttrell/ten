package kernel

import (
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// StartProcFS starts the internal ProcFS 9P service.
func StartProcFS(addr string) error {
	s := &ProcServer{
		listenAddr: addr,
	}
	return s.Run()
}

type ProcServer struct {
	listenAddr string
}

func (s *ProcServer) Run() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	log.Printf("ProcFS listening on %s", s.listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go s.handleConn(conn)
	}
}

func (s *ProcServer) handleConn(conn net.Conn) {
	defer conn.Close()
	fids := make(map[uint32]*PFid)
	var mu sync.Mutex

	for {
		req, err := p9.ReadFcall(conn)
		if err != nil {
			if err != io.EOF {
				log.Printf("procfs read error: %v", err)
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
				if w == ".." {
					// Handle parent (naive)
					if currPath != "/" {
						// Split and drop last
						parts := strings.Split(currPath, "/")
						if len(parts) > 1 {
							currPath = strings.Join(parts[:len(parts)-1], "/")
						}
						if currPath == "" {
							currPath = "/"
						}
					}
					// Qid logic for parent is tricky without full map.
					// Root is always 0.
					wqid = append(wqid, p9.Qid{Type: p9.QTDIR, Path: 0})
					continue
				}

				nextPath := currPath
				if nextPath == "/" {
					nextPath += w
				} else {
					nextPath += "/" + w
				}

				// Resolve Path
				q, err := resolveProcPath(nextPath)
				if err != nil {
					// Stop walk
					goto endWalk
				}
				wqid = append(wqid, q)
				currPath = nextPath
			}
		endWalk:
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
			q, _ := resolveProcPath(fid.Path)
			resp.Qid = q
			resp.Iounit = 8192

		case p9.Tread:
			mu.Lock()
			fid, ok := fids[req.Fid]
			mu.Unlock()
			if !ok {
				resp = rError(req, "fid not found")
				break
			}

			data, err := readProcFile(fid.Path)
			if err != nil {
				resp = rError(req, err.Error())
				break
			}

			// Handle Offset
			if req.Offset >= uint64(len(data)) {
				resp.Data = []byte{}
			} else {
				end := req.Offset + uint64(req.Count)
				if end > uint64(len(data)) {
					end = uint64(len(data))
				}
				resp.Data = data[req.Offset:end]
			}

		case p9.Tclunk:
			mu.Lock()
			delete(fids, req.Fid)
			mu.Unlock()
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

func resolveProcPath(path string) (p9.Qid, error) {
	if path == "/" {
		return p9.Qid{Type: p9.QTDIR, Path: 0}, nil
	}

	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 1 {
		// /<pid>
		pid, err := strconv.Atoi(parts[0])
		if err != nil {
			return p9.Qid{}, fmt.Errorf("not found")
		}
		// Verify existence?
		if Registry.Get(uint32(pid)) == nil {
			return p9.Qid{}, fmt.Errorf("pid not found")
		}
		return p9.Qid{Type: p9.QTDIR, Path: uint64(pid) << 8}, nil
	}

	if len(parts) == 2 {
		// /<pid>/file
		pid, err := strconv.Atoi(parts[0])
		if err != nil || Registry.Get(uint32(pid)) == nil {
			return p9.Qid{}, fmt.Errorf("pid not found")
		}

		switch parts[1] {
		case "status", "ctl", "ns":
			// Low bits identify file type
			ftype := uint64(0)
			if parts[1] == "status" {
				ftype = 1
			}
			if parts[1] == "ctl" {
				ftype = 2
			}
			if parts[1] == "ns" {
				ftype = 3
			}

			return p9.Qid{Type: p9.QTFILE, Path: (uint64(pid) << 8) | ftype}, nil
		}
	}

	return p9.Qid{}, fmt.Errorf("not found")
}

func readProcFile(path string) ([]byte, error) {
	if path == "/" {
		// List Session IDs
		ids := Registry.List()
		var data []byte
		for _, id := range ids {
			d := p9.Dir{
				Name:  fmt.Sprintf("%d", id),
				Qid:   p9.Qid{Type: p9.QTDIR, Path: uint64(id) << 8},
				Mode:  p9.DMDIR | 0755,
				Atime: uint32(time.Now().Unix()),
				Mtime: uint32(time.Now().Unix()),
			}
			data = append(data, d.Bytes()...)
		}
		return data, nil
	}

	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 1 {
		// Directory listing of /<pid>
		pid, _ := strconv.Atoi(parts[0]) // Validated by resolve
		var data []byte
		// status
		d1 := p9.Dir{Name: "status", Qid: p9.Qid{Type: p9.QTFILE, Path: (uint64(pid) << 8) | 1}, Mode: 0644}
		// ctl
		d2 := p9.Dir{Name: "ctl", Qid: p9.Qid{Type: p9.QTFILE, Path: (uint64(pid) << 8) | 2}, Mode: 0200}
		// ns
		d3 := p9.Dir{Name: "ns", Qid: p9.Qid{Type: p9.QTFILE, Path: (uint64(pid) << 8) | 3}, Mode: 0444}

		data = append(data, d1.Bytes()...)
		data = append(data, d2.Bytes()...)
		data = append(data, d3.Bytes()...)
		return data, nil
	}

	if len(parts) == 2 {
		pid, _ := strconv.Atoi(parts[0])
		sess := Registry.Get(uint32(pid))
		if sess == nil {
			return nil, fmt.Errorf("process gone")
		}

		switch parts[1] {
		case "status":
			return []byte(fmt.Sprintf("%d %s state=running\n", pid, sess.user)), nil
		case "ns":
			return []byte(sess.ns.String()), nil // Need to implement String() on ns?
		case "ctl":
			return []byte{}, nil
		}
	}

	return nil, fmt.Errorf("not a file")
}
