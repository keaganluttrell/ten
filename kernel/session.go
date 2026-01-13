package kernel

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"strings"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

type fidRef struct {
	client    *Client
	remoteFid uint32
	path      string // Track absolute path
}

// Session represents a single WebSocket connection.
type Session struct {
	socket  *Socket
	ns      *Namespace
	user    string
	vfsAddr string
	pubKey  ed25519.PublicKey
	host    *HostIdentity // Identity of the Kernel itself
	dialer  Dialer

	fids map[uint32]fidRef
}

func NewSession(sock *Socket, vfsAddr string, pubKey ed25519.PublicKey, host *HostIdentity, d Dialer) *Session {
	return &Session{
		socket:  sock,
		vfsAddr: vfsAddr,
		pubKey:  pubKey,
		host:    host,
		dialer:  d,
		fids:    make(map[uint32]fidRef),
	}
}

// Serve handles the 9P message loop.
func (s *Session) Serve() {
	defer s.socket.Close()
	ctx := context.Background()

	for {
		// Read Message
		msg, err := s.socket.ReadMsg(ctx)
		if err != nil {
			// Connection closed or error
			return
		}

		// Process Message
		resp := s.handle(msg)

		// Write Response
		if err := s.socket.WriteMsg(ctx, resp); err != nil {
			log.Printf("write error: %v", err)
			return
		}
	}
}

func (s *Session) handle(req *p9.Fcall) *p9.Fcall {
	resp := &p9.Fcall{
		Tag:  req.Tag,
		Type: req.Type + 1, // Default response type
	}

	switch req.Type {
	case p9.Tversion:
		resp.Msize = req.Msize
		resp.Version = "9P2000"

	case p9.Tattach:
		// 1. Try to Fetch Namespace Manifest from VFS
		// If this fails, we enter Rescue Mode (if bootstrapping) or fail (if authenticating).
		manifest, err := fetchNamespaceManifest(s.vfsAddr, s.dialer, s.host)

		s.ns = NewNamespace()

		// Decide Mode: Bootstrap (Aname empty or /) or Ticket (Aname = /priv/...)
		isBootstrap := req.Aname == "" || req.Aname == "/"

		if err != nil {
			if isBootstrap {
				log.Printf("Boot Warning: VFS unavailable (%v). Entering Rescue Mode.", err)
				s.mountRescueFS()
				s.user = "rescue"
			} else {
				return rError(req, "vfs_unavailable: "+err.Error())
			}
		} else {
			// VFS Alive - Normal Boot
			if isBootstrap {
				// Bootstrap Mode: Only mount Factotum (or VFS if Factotum not found?)
				// Spec says Factotum. But if we have manifest, we should follow it.
				factotumAddr := findMountAddr(manifest, "/dev/factotum")
				if factotumAddr != "" {
					c, err := s.dialer.Dial(factotumAddr)
					if err == nil {
						s.ns.Mount("/", c) // Client sees Factotum at Root
						s.user = "none"
					} else {
						// Factotum Dial Failed? Rescue?
						log.Printf("Boot Warning: Factotum unavailable (%v).", err)
						s.mountRescueFS()
					}
				} else {
					log.Printf("Boot Warning: Factotum not in manifest.")
					s.mountRescueFS()
				}
			} else {
				// Ticket Mode
				ticket, err := ValidateTicket(req.Aname, s.vfsAddr, s.pubKey, s.host, s.dialer)
				if err != nil {
					return rError(req, err.Error())
				}
				s.user = ticket.User

				// Build Full Namespace
				if err := s.ns.Build(manifest, s.dialer); err != nil {
					return rError(req, "namespace_build_failed: "+err.Error())
				}
			}
		}

		// Mount /dev/sys (Always)
		sysClient := NewSysClient(s.ns, s.dialer)
		s.ns.Mount("/dev/sys", sysClient)

		// Attach to Root
		rootClient, relPath := s.ns.Route("/")
		if rootClient == nil {
			return rError(req, "root_mount_missing")
		}

		fReq := &p9.Fcall{
			Type:  p9.Tattach,
			Fid:   req.Fid,
			Afid:  p9.NOFID,
			Uname: s.user,
			Aname: relPath,
		}

		fResp, err := rootClient.RPC(fReq)
		if err != nil {
			return rError(req, "attach_failed: "+err.Error())
		}

		resp.Qid = fResp.Qid
		s.putFid(req.Fid, rootClient, req.Fid, "/") // Store "/"

	case p9.Tflush:
		resp.Type = p9.Rflush

	case p9.Twalk:
		ref, ok := s.getFid(req.Fid)
		if !ok {
			return rError(req, "fid_not_found")
		}

		// Step-by-step walk to handle mount boundaries
		var wqids []p9.Qid
		currClient := ref.client
		currFid := ref.remoteFid
		currPath := ref.path

		// If we are cloning (len(wname) == 0)
		if len(req.Wname) == 0 {
			fReq := &p9.Fcall{Type: p9.Twalk, Fid: currFid, Newfid: req.Newfid}
			_, err := currClient.RPC(fReq)
			if err != nil {
				return rError(req, "walk_clone_error: "+err.Error())
			}
			s.putFid(req.Newfid, currClient, req.Newfid, currPath)
			resp.Wqid = []p9.Qid{}
			break
		}

		walkFid := req.Newfid
		if req.Fid != req.Newfid {
			// Clone first: Twalk(Fid, Newfid, [])
			fReq := &p9.Fcall{Type: p9.Twalk, Fid: ref.remoteFid, Newfid: walkFid}
			if _, err := currClient.RPC(fReq); err != nil {
				return rError(req, "walk_setup_error: "+err.Error())
			}
		} else {
			walkFid = ref.remoteFid
		}

		success := true
		for _, name := range req.Wname {
			// Calculate next path
			nextPath := resolvePath(currPath, name)

			// Check Route
			nextClient, _ := s.ns.Route(nextPath)

			if nextClient != currClient {
				// MOUNT CROSSING
				currClient.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: walkFid})

				currClient = nextClient

				// Attach to new root
				fReq := &p9.Fcall{
					Type:  p9.Tattach,
					Fid:   walkFid,
					Afid:  p9.NOFID,
					Uname: s.user,
					Aname: "/", // Assume mount point maps to root of service
				}
				fResp, err := currClient.RPC(fReq)
				if err != nil {
					success = false
					break // Fail walk
				}
				wqids = append(wqids, fResp.Qid)

			} else {
				// SAME CLIENT
				// Walk one step
				fReq := &p9.Fcall{
					Type:   p9.Twalk,
					Fid:    walkFid,
					Newfid: walkFid, // Walk in place
					Wname:  []string{name},
				}
				fResp, err := currClient.RPC(fReq)
				if err != nil {
					success = false
					break
				}
				if len(fResp.Wqid) == 0 {
					success = false
					break
				}
				wqids = append(wqids, fResp.Wqid...)
			}
			currPath = nextPath
		}

		if !success {
			if len(wqids) < len(req.Wname) {
				// Partial
				if req.Newfid != req.Fid {
					currClient.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: walkFid})
				}
			}
		} else {
			// Success: Map Newfid
			s.putFid(req.Newfid, currClient, walkFid, currPath)
		}

		resp.Wqid = wqids

	case p9.Tclunk:
		ref, ok := s.getFid(req.Fid)
		if ok {
			ref.client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: ref.remoteFid})
			s.delFid(req.Fid)
		}
		resp.Type = p9.Rclunk

	case p9.Topen:
		// Forward Topen
		ref, ok := s.getFid(req.Fid)
		if !ok {
			return rError(req, "fid_not_found")
		}
		fReq := *req
		fReq.Fid = ref.remoteFid // Use backend FID
		fResp, err := ref.client.RPC(&fReq)
		if err != nil {
			return rError(req, "open_error: "+err.Error())
		}
		resp.Qid = fResp.Qid
		resp.Iounit = fResp.Iounit

	case p9.Tcreate:
		ref, ok := s.getFid(req.Fid)
		if !ok {
			return rError(req, "fid_not_found")
		}
		fReq := *req
		fReq.Fid = ref.remoteFid
		fResp, err := ref.client.RPC(&fReq)
		if err != nil {
			return rError(req, "create_error: "+err.Error())
		}
		resp.Qid = fResp.Qid
		resp.Iounit = fResp.Iounit

	case p9.Tread:
		ref, ok := s.getFid(req.Fid)
		if !ok {
			return rError(req, "fid_not_found")
		}
		fReq := *req
		fReq.Fid = ref.remoteFid
		fResp, err := ref.client.RPC(&fReq)
		if err != nil {
			return rError(req, "read_error: "+err.Error())
		}
		resp.Data = fResp.Data

	case p9.Twrite:
		ref, ok := s.getFid(req.Fid)
		if !ok {
			return rError(req, "fid_not_found")
		}
		fReq := *req
		fReq.Fid = ref.remoteFid
		fResp, err := ref.client.RPC(&fReq)
		if err != nil {
			return rError(req, "write_error: "+err.Error())
		}
		resp.Count = fResp.Count

	case p9.Tstat:
		ref, ok := s.getFid(req.Fid)
		if !ok {
			return rError(req, "fid_not_found")
		}
		fReq := *req
		fReq.Fid = ref.remoteFid
		fResp, err := ref.client.RPC(&fReq)
		if err != nil {
			return rError(req, "stat_error: "+err.Error())
		}
		resp.Stat = fResp.Stat

	case p9.Tremove:
		ref, ok := s.getFid(req.Fid)
		if ok {
			ref.client.RPC(&p9.Fcall{Type: p9.Tremove, Fid: ref.remoteFid})
			s.delFid(req.Fid)
		}
		resp.Type = p9.Rremove

	default:
		return rError(req, fmt.Sprintf("unknown type: %d", req.Type))
	}

	return resp
}

func (s *Session) getFid(id uint32) (fidRef, bool) {
	f, ok := s.fids[id]
	return f, ok
}

func (s *Session) putFid(fid uint32, client *Client, remoteFid uint32, path string) {
	s.fids[fid] = fidRef{client: client, remoteFid: remoteFid, path: path}
}

func (s *Session) delFid(fid uint32) {
	delete(s.fids, fid)
}

func resolvePath(base, name string) string {
	if name == ".." {
		parts := strings.Split(base, "/")
		if len(parts) <= 2 {
			return "/"
		}
		return strings.Join(parts[:len(parts)-1], "/")
	}
	if base == "/" {
		return "/" + name
	}
	return base + "/" + name
}

func rError(req *p9.Fcall, ename string) *p9.Fcall {
	return &p9.Fcall{
		Tag:   req.Tag,
		Type:  p9.Rerror,
		Ename: ename,
	}
}

// Helper functions fetchNamespaceManifest and findMountAddr are assumed to be in the same package (e.g. they were in session.go or another file).
// Wait, they WERE in session.go at bottom. I must preserve them!
// Checking previous view of session.go... yes they were there.
// I will include them here.

func (s *Session) mountRescueFS() {
	client := NewBootFSClient()
	s.ns.Mount("/", client)
}

func fetchNamespaceManifest(vfsAddr string, d Dialer, host *HostIdentity) (string, error) {
	// 1. Dial VFS
	client, err := d.Dial(vfsAddr)
	if err != nil {
		return "", fmt.Errorf("dial_vfs_failed: %w", err)
	}
	defer client.Close()

	// Helper to reduce boilerplate and check Rerror
	rpcCheck := func(req *p9.Fcall) (*p9.Fcall, error) {
		resp, err := client.RPC(req)
		if err != nil {
			return nil, err
		}
		if resp.Type == p9.Rerror {
			return nil, fmt.Errorf("9p_error: %s", resp.Ename)
		}
		return resp, nil
	}

	// 2. Auth (If HostIdentity present)
	var afid uint32 = p9.NOFID
	if host != nil {
		afid = 100 // Arbitrary
		// Tauth
		_, err := rpcCheck(&p9.Fcall{Type: p9.Tauth, Afid: afid, Uname: "kernel", Aname: "/"})
		if err != nil {
			log.Printf("Boot Warning: Tauth failed: %v", err)
			afid = p9.NOFID
		} else {
			// Host Challenge Protocol
			// 1. Read Nonce (32 bytes)
			rResp, err := rpcCheck(&p9.Fcall{Type: p9.Tread, Fid: afid, Offset: 0, Count: 32})
			if err != nil {
				return "", fmt.Errorf("auth_read_nonce_failed: %w", err)
			}
			nonce := rResp.Data

			// 2. Sign Nonce
			sig := host.Sign(nonce)

			// 3. Write Signature
			if _, err := rpcCheck(&p9.Fcall{Type: p9.Twrite, Fid: afid, Data: sig, Count: uint32(len(sig))}); err != nil {
				return "", fmt.Errorf("auth_write_sig_failed: %w", err)
			}
			log.Printf("Boot: Host Auth Successful")
		}
	}

	// 3. Attach (as kernel)
	if _, err := rpcCheck(&p9.Fcall{Type: p9.Tattach, Fid: 0, Afid: afid, Uname: "kernel", Aname: "/"}); err != nil {
		return "", fmt.Errorf("vfs_attach_failed: %w", err)
	}

	// 4. Walk to /lib/namespace
	if _, err := rpcCheck(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: 1, Wname: []string{"lib", "namespace"}}); err != nil {
		return "", fmt.Errorf("walk_manifest_failed: %w", err)
	}
	defer client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: 1})

	// 5. Open
	if _, err := rpcCheck(&p9.Fcall{Type: p9.Topen, Fid: 1, Mode: 0}); err != nil {
		return "", fmt.Errorf("open_manifest_failed: %w", err)
	}

	// 6. Read
	resp, err := rpcCheck(&p9.Fcall{Type: p9.Tread, Fid: 1, Count: 8192})
	if err != nil {
		return "", fmt.Errorf("read_manifest_failed: %w", err)
	}

	return string(resp.Data), nil
}

func findMountAddr(manifest, path string) string {
	// Simple parsing of "mount <path> <addr>"
	lines := strings.Split(manifest, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		// Format: mount point addr
		// e.g. "mount /dev/factotum tcp!127.0.0.1:9003"
		if len(fields) >= 3 && fields[0] == "mount" && fields[1] == path {
			addr := fields[2]
			// Strip protocol "tcp!" if present
			if strings.HasPrefix(addr, "tcp!") {
				return addr[4:]
			}
			return addr
		}
	}
	return ""
}
