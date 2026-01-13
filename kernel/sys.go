package kernel

import (
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// SysDevice is a special file server for system control (e.g., /dev/sys/ctl).
type SysDevice struct {
	ns     *Namespace
	dialer Dialer
	mu     sync.Mutex
	fids   map[uint32]string // Fid -> Path
}

func NewSysDevice(ns *Namespace, d Dialer) *SysDevice {
	return &SysDevice{
		ns:     ns,
		dialer: d,
		fids:   make(map[uint32]string),
	}
}

// NewSysClient spawns the SysDevice server and returns a connected Client.
func NewSysClient(ns *Namespace, d Dialer) *Client {
	c1, c2 := net.Pipe()
	sys := NewSysDevice(ns, d)
	go sys.Serve(c2)
	return &Client{
		addr: "internal!sys",
		conn: c1,
		tag:  1,
	}
}

func (sys *SysDevice) Serve(conn net.Conn) {
	defer conn.Close()
	for {
		req, err := p9.ReadFcall(conn)
		if err != nil {
			return
		}
		resp := sys.handle(req)
		resp.Tag = req.Tag
		b, _ := resp.Bytes()
		conn.Write(b)
	}
}

// file IDs
const (
	QidRoot = 0
	QidCtl  = 1
)

func (sys *SysDevice) handle(req *p9.Fcall) *p9.Fcall {
	resp := &p9.Fcall{Type: req.Type + 1}
	sys.mu.Lock()
	defer sys.mu.Unlock()

	switch req.Type {
	case p9.Tversion:
		resp.Msize = req.Msize
		resp.Version = "9P2000"

	case p9.Tattach:
		sys.fids[req.Fid] = "/"
		resp.Qid = p9.Qid{Type: p9.QTDIR, Vers: 1, Path: QidRoot}

	case p9.Twalk:
		path, ok := sys.fids[req.Fid]
		if !ok {
			return rError(req, "fid not found")
		}

		wqids := []p9.Qid{}
		newPath := path

		if len(req.Wname) == 0 {
			sys.fids[req.Newfid] = path
		} else if len(req.Wname) == 1 && req.Wname[0] == "ctl" && path == "/" {
			newPath = "/ctl"
			wqids = append(wqids, p9.Qid{Type: p9.QTFILE, Vers: 1, Path: QidCtl})
			sys.fids[req.Newfid] = newPath
		} else {
			return rError(req, "not found")
		}
		resp.Wqid = wqids

	case p9.Topen:
		path, ok := sys.fids[req.Fid]
		if !ok {
			return rError(req, "fid not found")
		}
		if path == "/" {
			resp.Qid = p9.Qid{Type: p9.QTDIR, Vers: 1, Path: QidRoot}
		} else {
			resp.Qid = p9.Qid{Type: p9.QTFILE, Vers: 1, Path: QidCtl}
		}
		resp.Iounit = 0 // use msize

	case p9.Tread:
		path, ok := sys.fids[req.Fid]
		if !ok {
			return rError(req, "fid not found")
		}
		if path == "/" {
			// Dir Read (just ctl)
			dir := p9.Dir{
				Qid:    p9.Qid{Type: p9.QTFILE, Path: QidCtl},
				Mode:   0666,
				Name:   "ctl",
				Length: 0,
				Uid:    "sys", Gid: "sys", Muid: "sys",
				Atime: uint32(time.Now().Unix()),
				Mtime: uint32(time.Now().Unix()),
			}
			b := dir.Bytes()
			if req.Offset == 0 && req.Count >= uint32(len(b)) {
				resp.Data = b
			} else {
				resp.Data = []byte{}
			}
		} else {
			// Read ctl - empty?
			resp.Data = []byte{}
		}

	case p9.Twrite:
		path, ok := sys.fids[req.Fid]
		if !ok {
			return rError(req, "fid not found")
		}
		if path != "/ctl" {
			return rError(req, "permission denied")
		}

		// Execute Command
		cmd := string(req.Data)
		if err := sys.execute(cmd); err != nil {
			return rError(req, err.Error())
		}
		resp.Count = req.Count

	case p9.Tclunk:
		delete(sys.fids, req.Fid)
		resp.Type = p9.Rclunk

	case p9.Tstat:
		resp.Stat = make([]byte, 0)

	default:
		return rError(req, fmt.Sprintf("unknown type: %d", req.Type))
	}
	return resp
}

func (sys *SysDevice) execute(cmd string) error {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return nil
	}

	switch parts[0] {
	case "mount":
		// mount <addr> <path>
		// e.g. mount tcp!localhost:9999 /ext
		if len(parts) != 3 {
			return fmt.Errorf("usage: mount <addr> <path>")
		}
		addr := convertAddr(parts[1])
		path := parts[2]

		client, err := sys.dialer.Dial(addr)
		if err != nil {
			return err
		}

		// Attempt Attach? Usually mount implies Attach.
		// Standard Plan 9 mount does: dial -> ssl -> auth -> attach.
		// Here we do dial -> attach.
		// Tattach(root)
		// We can't attach here easily because Client.Attach is not exposed nicely,
		// but Client assumes attached?
		// No, `Dial` methods returns a Client, but that client is just a connection wrapper.
		// We need to perform Tver/Tattach.

		// Perform Handshake
		if _, err := client.RPC(&p9.Fcall{Type: p9.Tversion, Msize: 8192, Version: "9P2000"}); err != nil {
			client.Close()
			return err
		}
		if _, err := client.RPC(&p9.Fcall{Type: p9.Tattach, Fid: 0, Uname: "user", Aname: "/"}); err != nil {
			client.Close()
			return err
		}
		// Now Fid 0 is Root.
		// Wait, Client struct handles tag, but FID management is up to caller usually?
		// No, Client struct is very thin.
		// Namespace expects Client to be ready to accept Walks from Fid 0?
		// Let's check kernel/session.go logic or Client.

		sys.ns.Mount(path, client)
		log.Printf("Sys: Mounted %s at %s", addr, path)
		return nil

	case "bind":
		// bind <old> <new> (Not implemented in Namespace yet? Let's check.)
		return fmt.Errorf("bind not implemented")

	default:
		return fmt.Errorf("unknown command: %s", parts[0])
	}
}
