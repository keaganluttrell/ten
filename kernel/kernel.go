package kernel

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// --- Server & Startup ---

// StartServer starts the Kernel TCP and WebSocket servers.
func StartServer(listenAddr, vfsAddr, wsAddr, keyPath string) error {
	pubKey := loadPublicKey(keyPath)
	host, err := LoadHostIdentity()
	if err != nil {
		log.Printf("Warning: Failed to load Host Identity: %v. Bootstrapping will invoke Tauth failure handling.", err)
	}

	dialer := NewNetworkDialer()

	// 1. Start WebSocket Server (HTTP)
	go func() {
		if err := StartWebSocketServer(wsAddr, vfsAddr, pubKey, host, dialer); err != nil {
			log.Printf("WebSocket server failed: %v", err)
		}
	}()

	// 2. Start TCP Server
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return err
	}
	log.Printf("Kernel listening on %s (TCP)", listenAddr)

	// Start embedded ProcFS
	go func() {
		if err := StartProcFS(":9004"); err != nil {
			log.Printf("ProcFS failed: %v", err)
		}
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept failed: %v", err)
			continue
		}

		go func(c net.Conn) {
			transport := &TCPTransport{conn: c}
			sess := NewSession(transport, vfsAddr, pubKey, host, dialer)
			sess.Serve()
		}(conn)
	}
}

// StartWebSocketServer starts the HTTP server for WebSocket upgrades.
func StartWebSocketServer(addr, vfsAddr string, pubKey ed25519.PublicKey, host *HostIdentity, dialer *NetworkDialer) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		socket, err := Upgrade(w, r)
		if err != nil {
			log.Printf("WS Upgrade failed: %v", err)
			return
		}
		// Bridge Socket to Session
		sess := NewSession(socket, vfsAddr, pubKey, host, dialer)
		sess.Serve()
	})

	log.Printf("Kernel listening on %s (WebSocket /ws)", addr)
	return http.ListenAndServe(addr, mux)
}

type TCPTransport struct {
	conn net.Conn
}

func (t *TCPTransport) ReadMsg(ctx context.Context) (*p9.Fcall, error) {
	return p9.ReadFcall(t.conn)
}

func (t *TCPTransport) WriteMsg(ctx context.Context, f *p9.Fcall) error {
	b, err := f.Bytes()
	if err != nil {
		return err
	}
	_, err = t.conn.Write(b)
	return err
}

func (t *TCPTransport) Close() error {
	return t.conn.Close()
}

func loadPublicKey(path string) ed25519.PublicKey {
	if val := os.Getenv("SIGNING_KEY_BASE64"); val != "" {
		b, _ := base64.StdEncoding.DecodeString(val)
		return ed25519.PublicKey(b)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Warning: failed to load signing key from %s: %v. Validation will fail.", path, err)
		return nil
	}

	b, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		log.Printf("Warning: invalid base64 key in %s", path)
		return nil
	}

	return ed25519.PublicKey(b)
}

// --- Session Logic ---

type fidRef struct {
	client    *Client
	remoteFid uint32
	path      string // Track absolute path
	isOpen    bool
	openMode  uint8
}

// MessageTransport abstracts the connection (WebSocket or other).
type MessageTransport interface {
	ReadMsg(ctx context.Context) (*p9.Fcall, error)
	WriteMsg(ctx context.Context, f *p9.Fcall) error
	Close() error
}

// Session represents a single WebSocket connection.
type Session struct {
	socket  MessageTransport
	ns      *Namespace
	user    string
	vfsAddr string
	pubKey  ed25519.PublicKey
	host    *HostIdentity // Identity of the Kernel itself
	dialer  Dialer

	fids map[uint32]fidRef
}

// SessionRegistry tracks all active sessions.
type SessionRegistry struct {
	mu       sync.RWMutex
	sessions map[uint32]*Session
	nextID   uint32
}

var Registry = &SessionRegistry{
	sessions: make(map[uint32]*Session),
	nextID:   1,
}

func (r *SessionRegistry) Register(s *Session) uint32 {
	r.mu.Lock()
	defer r.mu.Unlock()
	id := r.nextID
	r.nextID++
	r.sessions[id] = s
	return id
}

func (r *SessionRegistry) Unregister(id uint32) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, id)
}

func (r *SessionRegistry) List() []uint32 {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]uint32, 0, len(r.sessions))
	for id := range r.sessions {
		ids = append(ids, id)
	}
	// Sort?
	return ids
}

func (r *SessionRegistry) Get(id uint32) *Session {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.sessions[id]
}

func NewSession(sock MessageTransport, vfsAddr string, pubKey ed25519.PublicKey, host *HostIdentity, d Dialer) *Session {
	return &Session{
		socket:  sock,
		vfsAddr: vfsAddr,
		pubKey:  pubKey,
		host:    host,
		dialer:  d,
		fids:    make(map[uint32]fidRef),
		ns:      NewNamespace(),
	}
}

// Serve handles the 9P message loop.
func (s *Session) Serve() {
	defer s.socket.Close()

	// Register Session
	id := Registry.Register(s)
	defer Registry.Unregister(id)

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

		// Decide Mode: Bootstrap (Aname empty or /) or Ticket (Aname = /adm/...)
		isBootstrap := req.Aname == "" || req.Aname == "/"

		if err != nil {
			if isBootstrap {
				// FAIL FAST: Consistent with Audit. No RAMFS.
				return rError(req, "vfs_unavailable: "+err.Error())
			} else {
				return rError(req, "vfs_unavailable: "+err.Error())
			}
		} else {
			// VFS Alive - Normal Boot
			if isBootstrap {
				// Bootstrap Mode: Build Full Namespace from Manifest
				if err := s.ns.Build(manifest, s.dialer); err != nil {
					return rError(req, "namespace_build_failed: "+err.Error())
				}
				s.user = "none"
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
		s.ns.Mount("/dev/sys", sysClient, MREPL)

		// Mount /env
		envClient := NewEnvClient()
		s.ns.Mount("/env", envClient, MREPL)

		// Attach to Root
		rootStack := s.ns.Route("/")
		if len(rootStack) == 0 {
			return rError(req, "root_mount_missing")
		}
		// Default to first match for root attach?
		// In Plan 9, attaching to / usually lands you on the head of the union.
		rootRoute := rootStack[0]

		fReq := &p9.Fcall{
			Type:  p9.Tattach,
			Fid:   req.Fid,
			Afid:  p9.NOFID,
			Uname: s.user,
			Aname: rootRoute.RelPath,
		}

		fResp, err := rootRoute.Client.RPC(fReq)
		if err != nil {
			return rError(req, "attach_failed: "+err.Error())
		}

		resp.Qid = fResp.Qid
		s.putFid(req.Fid, rootRoute.Client, req.Fid, "/") // Store "/"

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

		log.Printf("DEBUG: Twalk Start. Fid=%d NewFid=%d Wname=%v", req.Fid, req.Newfid, req.Wname)

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

		// Helper to find current mount point
		getMountPoint := func(path string, client *Client) string {
			stack := s.ns.Route(path)
			for _, r := range stack {
				if r.Client == client {
					return r.MountPoint
				}
			}
			return "/"
		}
		currMountPoint := getMountPoint(currPath, currClient)

		for _, name := range req.Wname {
			log.Printf("DEBUG: Twalk Loop Name=%s CurrPath=%s", name, currPath)
			// Calculate next path
			nextPath := resolvePath(currPath, name)

			// Get the Stack for the *next* path
			nextStack := s.ns.Route(nextPath)
			if len(nextStack) == 0 {
				log.Printf("DEBUG: Route failed for path %s (curr=%s, name=%s)", nextPath, currPath, name)
				success = false
				break
			}

			// Union Walk Strategy
			log.Printf("DEBUG: Twalk Stack Len=%d", len(nextStack))

			var foundClient *Client
			var foundQid p9.Qid
			var foundMountPoint string
			found := false

			var candidateErrors []string

			for _, candidate := range nextStack {
				// Check if we are staying within the same mount point
				isSameMount := (candidate.Client == currClient && candidate.MountPoint == currMountPoint)
				log.Printf("DEBUG: Candidate %v same=%v", candidate.MountPoint, isSameMount)

				if isSameMount {
					// Optimized Walk on existing client
					fReq := &p9.Fcall{
						Type:   p9.Twalk,
						Fid:    walkFid,
						Newfid: walkFid,
						Wname:  []string{name},
					}
					fResp, err := currClient.RPC(fReq)
					if err == nil && len(fResp.Wqid) > 0 {
						found = true
						foundClient = currClient
						foundQid = fResp.Wqid[0]
						foundMountPoint = candidate.MountPoint
						break // Found valid implementation for this component
					}
					msg := "nil"
					if err != nil {
						msg = err.Error()
					}
					candidateErrors = append(candidateErrors, fmt.Sprintf("SameMount(%v): %s (len=%d)", currClient, msg, len(fResp.Wqid)))
					continue // Try next candidate in the union stack
				}

				// Cross Mount Boundary (Jump)
				probFid := s.nextInternalFid()

				// Attach to Root of candidate client
				aResp, err := candidate.Client.RPC(&p9.Fcall{Type: p9.Tattach, Fid: probFid, Afid: p9.NOFID, Uname: s.user, Aname: "/"})
				if err == nil {
					// Walk to the target RelPath
					pathParts := strings.Split(strings.Trim(candidate.RelPath, "/"), "/")
					if candidate.RelPath == "" || candidate.RelPath == "/" {
						pathParts = []string{}
					}

					fResp, err := candidate.Client.RPC(&p9.Fcall{Type: p9.Twalk, Fid: probFid, Newfid: probFid, Wname: pathParts})

					if err == nil {
						// Success! We found the file on this client.
						if len(fResp.Wqid) != len(pathParts) {
							// Partial walk on cross-mount? Treat as failure for now or handle gracefully.
							// For cross-mount jump, we expect full resolution of the relative path.
							candidateErrors = append(candidateErrors, fmt.Sprintf("CrossMountWalk(%v): partial walk %d/%d", candidate.Client, len(fResp.Wqid), len(pathParts)))
							candidate.Client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: probFid})
							continue
						}

						// Cleanup old walkFid (it was on the old client/path)
						currClient.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: walkFid})

						// Adopt the new fid
						walkFid = probFid

						found = true
						foundClient = candidate.Client
						foundMountPoint = candidate.MountPoint

						// Determine Qid
						if len(pathParts) > 0 {
							foundQid = fResp.Wqid[len(fResp.Wqid)-1]
						} else {
							// We are at root of mount. Use Attach QID.
							foundQid = aResp.Qid
						}
						break
					} else {
						candidateErrors = append(candidateErrors, fmt.Sprintf("CrossMountWalk(%v): %v", candidate.Client, err))
						// Failed to walk to target on this client
						candidate.Client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: probFid})
					}
				} else {
					candidateErrors = append(candidateErrors, fmt.Sprintf("CrossMountAttach(%v): %v", candidate.Client, err))
				}
			}

			if found {
				currClient = foundClient
				currMountPoint = foundMountPoint
				wqids = append(wqids, foundQid)
				currPath = nextPath
			} else {
				log.Printf("DEBUG: Not Found %s", name)
				success = false
				return rError(req, fmt.Sprintf("not_found: %s | tried: %v", name, candidateErrors))
			}
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
		log.Printf("DEBUG: Twalk Return. Wqids=%d", len(wqids))
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

		// Update ref state
		ref.isOpen = true
		ref.openMode = req.Mode
		s.fids[req.Fid] = ref

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

		// Update ref state - Tcreate opens the file
		ref.isOpen = true
		ref.openMode = req.Mode
		// Note: Tcreate modifies the path of the fid to the new file
		ref.path = resolveJoin(ref.path, req.Name)
		s.fids[req.Fid] = ref

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

		// Recovery Logic
		if err != nil || fResp.Type == p9.Rerror {
			// Check if we should recover
			shouldRecover := err != nil
			if fResp != nil && fResp.Type == p9.Rerror && (strings.Contains(fResp.Ename, "fid not found") || strings.Contains(fResp.Ename, "file not open")) {
				shouldRecover = true
			}

			if shouldRecover {
				log.Printf("Session: Recovering stale handle for %s", ref.path)
				client, newFid, rErr := s.recoverFid(ref)
				if rErr == nil {
					// Update ref
					s.putFid(req.Fid, client, newFid, ref.path)
					// Retry RPC
					fReq.Fid = newFid
					retryReq := fReq // Copy request to avoid tag issues
					fResp, err = client.RPC(&retryReq)
				}
			}
		}

		if err != nil {
			return rError(req, "read_error: "+err.Error())
		}
		if fResp.Type == p9.Rerror {
			return fResp // Pass through Rerror
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

func resolveJoin(base, name string) string {
	if base == "/" {
		return "/" + name
	}
	return base + "/" + name
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

// recoverFid attempts to re-establish a FID for a given path using the namespace.
func (s *Session) recoverFid(ref fidRef) (*Client, uint32, error) {
	routeStack := s.ns.Route(ref.path)
	if len(routeStack) == 0 {
		return nil, 0, fmt.Errorf("route not found for %s", ref.path)
	}

	var targetRoute *ResolvedPath
	for _, r := range routeStack {
		if r.Client == ref.client {
			targetRoute = r
			break
		}
	}

	if targetRoute == nil {
		targetRoute = routeStack[0]
	}

	client := targetRoute.Client
	newFid := s.nextInternalFid()

	// Walk from root to path
	parts := strings.Split(strings.Trim(targetRoute.RelPath, "/"), "/")
	if targetRoute.RelPath == "" || targetRoute.RelPath == "/" {
		parts = []string{}
	}

	rootFid := s.nextInternalFid()
	// Tattach (assumes no auth needed for recovery in this iteration)
	_, err := client.RPC(&p9.Fcall{Type: p9.Tattach, Fid: rootFid, Afid: p9.NOFID, Uname: "kernel", Aname: "/"})
	if err != nil {
		return nil, 0, fmt.Errorf("recover_attach_failed: %w", err)
	}

	// Walk
	if len(parts) > 0 {
		_, err = client.RPC(&p9.Fcall{Type: p9.Twalk, Fid: rootFid, Newfid: newFid, Wname: parts})
		client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: rootFid}) // Cleanup root
		if err != nil {
			return nil, 0, fmt.Errorf("recover_walk_failed: %w", err)
		}
	} else {
		newFid = rootFid // Root is the target
	}

	// Restore Open State
	if ref.isOpen {
		_, err := client.RPC(&p9.Fcall{Type: p9.Topen, Fid: newFid, Mode: ref.openMode})
		if err != nil {
			// Failed to open, close fid and abort
			client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: newFid})
			return nil, 0, fmt.Errorf("recover_open_failed: %w", err)
		}
	}

	return client, newFid, nil
}

func (s *Session) nextInternalFid() uint32 {
	// Start from high numbers to avoid collision with user FIDs (usually low numbers)
	// Simple collision check against s.fids
	for i := uint32(0xFFFFFFFE); i > 0; i-- {
		if _, ok := s.fids[i]; !ok {
			return i
		}
	}
	return 0 // Full?
}

func rError(req *p9.Fcall, ename string) *p9.Fcall {
	return &p9.Fcall{
		Tag:   req.Tag,
		Type:  p9.Rerror,
		Ename: ename,
	}
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

	// 1b. Negotiate Version
	if _, err := rpcCheck(&p9.Fcall{Type: p9.Tversion, Msize: 8192, Version: "9P2000"}); err != nil {
		return "", fmt.Errorf("version_failed: %w", err)
	}

	// 2. Auth (If HostIdentity present)
	var afid uint32 = p9.NOFID
	if host != nil {
		var err error
		afid, err = HostAuthHandshake(client, host)
		if err != nil {
			log.Printf("Boot Warning: Auth failed: %v", err)
			afid = p9.NOFID
		} else {
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
	lines := strings.Split(manifest, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == "mount" && fields[1] == path {
			addr := fields[2]
			if strings.HasPrefix(addr, "tcp!") {
				return addr[4:]
			}
			return addr
		}
	}
	return ""
}

// --- Namespace Logic ---

// Bind Flags
const (
	MREPL   = 0x0000 // Replace (default)
	MBEFORE = 0x0001 // Add to head of union
	MAFTER  = 0x0002 // Add to tail of union
	MCREATE = 0x0004 // Allow creation in this union element
)

// mountEntry represents a mount point with an optional path offset for binds.
type mountEntry struct {
	client *Client
	offset string // For bind: the source path prefix (e.g., "/a/b" if "bind /a/b /c")
	flags  int    // MCREATE, etc.
}

// Namespace maps paths to lists of backend clients (Union Mounts).
// Note: Plan 9 uses a mount table. We simulate this with a map of paths to stacks.
type Namespace struct {
	mu     sync.RWMutex
	mounts map[string][]*mountEntry // e.g., "/bin" -> [entry1, entry2]
}

// NewNamespace creates a correctly initialized namespace.
func NewNamespace() *Namespace {
	return &Namespace{
		mounts: make(map[string][]*mountEntry),
	}
}

// BootstrapNamespace creates the minimal environment for auth.
// Only mounts /dev/factotum.
func BootstrapNamespace(factotumAddr string, d Dialer) (*Namespace, error) {
	ns := NewNamespace()

	// Dial Factotum
	c, err := d.Dial(factotumAddr)
	if err != nil {
		return nil, fmt.Errorf("dial factotum failed: %w", err)
	}

	ns.Mount("/dev/factotum", c, MREPL)
	return ns, nil
}

// Mount adds a client at a specific path.
func (ns *Namespace) Mount(path string, client *Client, flags int) {
	ns.BindEntry(path, &mountEntry{client: client, offset: "", flags: flags}, flags)
}

// Bind creates a path alias or union.
// oldPath: The existing path to bind from (the source).
// newPath: The location to bind to (the target).
// flags: MREPL, MBEFORE, MAFTER, MCREATE
func (ns *Namespace) Bind(oldPath, newPath string, flags int) error {
	ns.mu.Lock() // We need lock to resolve oldPath
	// Resolve oldPath to find the underlying client(s)
	// Bind copies the "connection" (Client + Offset) from oldPath to newPath.

	// 1. Find best match for oldPath
	// We only bind the *first* match of oldPath? Or logically, we are binding a specific directory.
	// In Plan 9, bind takes a file descriptor. Here we take a path.
	// We resolve it to the specific client/path it points to.

	bestMatch, bestEntry := ns.resolveBestMatchLocked(oldPath)
	if bestEntry == nil {
		ns.mu.Unlock()
		return fmt.Errorf("bind source not found: %s", oldPath)
	}
	ns.mu.Unlock()

	// Calculate offset for the new entry
	var offset string
	if bestMatch == "/" {
		offset = oldPath
	} else {
		offset = strings.TrimPrefix(oldPath, bestMatch)
		if offset == "" {
			offset = "/"
		}
	}

	if bestEntry.offset != "" && bestEntry.offset != "/" {
		if offset == "/" {
			offset = bestEntry.offset
		} else {
			offset = bestEntry.offset + offset
		}
	}

	// Create new entry
	newEntry := &mountEntry{
		client: bestEntry.client,
		offset: offset,
		flags:  flags,
	}

	ns.BindEntry(newPath, newEntry, flags)
	return nil
}

// BindEntry adds a pre-constructed entry to the namespace.
func (ns *Namespace) BindEntry(path string, entry *mountEntry, flags int) {
	ns.mu.Lock()
	defer ns.mu.Unlock()

	// Clean path
	if path == "" {
		path = "/"
	}

	current := ns.mounts[path]

	if flags&MREPL == MREPL && flags&MBEFORE == 0 && flags&MAFTER == 0 {
		// Replace logic
		ns.mounts[path] = []*mountEntry{entry}
		return
	}

	if flags&MBEFORE != 0 {
		// Current + Entry? No, Entry + Current
		if current == nil {
			ns.mounts[path] = []*mountEntry{entry}
		} else {
			ns.mounts[path] = append([]*mountEntry{entry}, current...)
		}
	} else if flags&MAFTER != 0 {
		if current == nil {
			ns.mounts[path] = []*mountEntry{entry}
		} else {
			ns.mounts[path] = append(current, entry)
		}
	} else {
		// Default to replace if ambiguous? Or just add?
		// Logic implies MREPL is 0. So if others are 0, it is replace.
		ns.mounts[path] = []*mountEntry{entry}
	}
}

// resolveBestMatchLocked implementation specific for internal use
func (ns *Namespace) resolveBestMatchLocked(path string) (string, *mountEntry) {
	var bestMatch string
	var bestEntry *mountEntry

	for prefix, entries := range ns.mounts {
		if strings.HasPrefix(path, prefix) {
			if len(path) > len(prefix) && path[len(prefix)] != '/' && prefix != "/" {
				continue
			}
			if len(prefix) >= len(bestMatch) { // Longest match
				bestMatch = prefix
				if len(entries) > 0 {
					bestEntry = entries[0] // Always resolve to head of union for "from" side?
				}
			}
		}
	}
	return bestMatch, bestEntry
}

// RouteResult contains the result of a Route lookup.
type RouteResult struct {
	// Stack of possible resolutions for this path
	Stack []*ResolvedPath
}

type ResolvedPath struct {
	Client     *Client
	RelPath    string
	MountPoint string
	CanCreate  bool
}

// Route finds the stack of matching clients for a given path.
// Returns a stack of possible backends.
func (ns *Namespace) Route(path string) []*ResolvedPath {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	// 1. Find the deepest matching mount point
	var bestMatch string
	var bestEntries []*mountEntry

	for prefix, entries := range ns.mounts {
		// Fix: Handle root prefix correctly.
		// If prefix is "/", it matches everything if path is "/" or starts with "/".
		// Otherwise, ensure path starts with prefix + "/" to avoid partial matches (e.g. /sys matching /system).
		match := false
		if prefix == "/" {
			match = true // Root always matches as a candidate
		} else {
			if path == prefix || strings.HasPrefix(path, prefix+"/") {
				match = true
			}
		}

		if match {
			if len(prefix) > len(bestMatch) {
				bestMatch = prefix
				bestEntries = entries
			}
		}
	}

	if bestMatch == "" {
		return nil
	}

	// 2. Construct resolution stack
	// Iterate backwards? No, entries are stored [Top, ..., Bottom]
	// Stack should be returned in order of priority (Top first).
	stack := make([]*ResolvedPath, 0, len(bestEntries))

	relPath := strings.TrimPrefix(path, bestMatch)
	if relPath == "" {
		relPath = "/"
	}

	for _, e := range bestEntries {
		// Apply offset if present
		finalRelPath := relPath
		if e.offset != "" && e.offset != "/" {
			if finalRelPath == "/" {
				finalRelPath = e.offset
			} else {
				finalRelPath = e.offset + finalRelPath
			}
		}

		stack = append(stack, &ResolvedPath{
			Client:     e.client,
			MountPoint: bestMatch,
			RelPath:    finalRelPath,
			CanCreate:  (e.flags & MCREATE) != 0,
		})
	}

	return stack
}

func (ns *Namespace) String() string {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	var sb strings.Builder
	for path, entries := range ns.mounts {
		for _, e := range entries {
			flag := ""
			if e.flags&MAFTER != 0 {
				flag = "-a "
			}
			if e.flags&MBEFORE != 0 {
				flag = "-b "
			}
			if e.flags&MCREATE != 0 {
				flag = "-c "
			}
			// We can't easily get remote addr from client here without refactoring Client
			// Just output mount point
			sb.WriteString(fmt.Sprintf("mount %s%s %s\n", flag, "service", path))
		}
	}
	return sb.String()
}

// Build constructs the namespace from a manifest string.
// Format: mount <path> tcp!<host>!<port> [flags...]
// or: bind <old> <new> [flags...]
func (ns *Namespace) Build(manifest string, d Dialer) error {
	lines := strings.Split(manifest, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		cmd := parts[0]

		if cmd == "mount" {
			// mount [flags] <path> <addr>
			// or mount <path> <addr> [flags]
			flags, args := parseFlags(parts[1:])
			if len(args) < 2 {
				continue
			}
			path := args[0]
			addr := convertAddr(args[1])

			client, err := d.Dial(addr)
			if err != nil {
				return fmt.Errorf("failed to mount %s: %w", path, err)
			}
			ns.Mount(path, client, flags)

		} else if cmd == "bind" {
			// bind [flags] <old> <new>
			flags, args := parseFlags(parts[1:])
			if len(args) < 2 {
				continue
			}
			oldP := args[0]
			newP := args[1]

			if err := ns.Bind(oldP, newP, flags); err != nil {
				return err
			}
		}
	}
	return nil
}

func parseFlags(args []string) (int, []string) {
	f := MREPL
	var remaining []string

	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			if a == "-a" {
				f |= MAFTER
				f &^= MREPL
			} else if a == "-b" {
				f |= MBEFORE
				f &^= MREPL
			} else if a == "-c" {
				f |= MCREATE
			}
		} else {
			remaining = append(remaining, a)
		}
	}

	// If After or Before set, clear Replace default (if not explicitly cleared above)
	if (f&MAFTER != 0) || (f&MBEFORE != 0) {
		f &^= MREPL
	}
	return f, remaining
}

// convertAddr converts "tcp!host!port" to "host:port".
func convertAddr(plan9Addr string) string {
	s := strings.TrimPrefix(plan9Addr, "tcp!")
	return strings.Replace(s, "!", ":", 1)
}

// --- Client Logic ---

// Client represents a connection to a backend 9P service.
type Client struct {
	addr    string
	conn    net.Conn
	mu      sync.Mutex
	tag     uint16
	lastFid uint32
}

// --- Retry Logic (inlined from pkg/resilience) ---

// RetryConfig configures retry behavior.
type RetryConfig struct {
	MaxRetries     int
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
	Multiplier     float64
}

// DefaultRetryConfig returns sensible defaults.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxRetries:     3,
		InitialBackoff: 100 * time.Millisecond,
		MaxBackoff:     5 * time.Second,
		Multiplier:     2.0,
	}
}

// Retry executes fn with exponential backoff until success or max retries.
func Retry(cfg RetryConfig, fn func() error) error {
	var lastErr error
	backoff := cfg.InitialBackoff

	for attempt := 0; attempt <= cfg.MaxRetries; attempt++ {
		if err := fn(); err != nil {
			lastErr = err
			if attempt < cfg.MaxRetries {
				time.Sleep(backoff)
				backoff = time.Duration(float64(backoff) * cfg.Multiplier)
				if backoff > cfg.MaxBackoff {
					backoff = cfg.MaxBackoff
				}
			}
		} else {
			return nil
		}
	}
	return lastErr
}

// --- Dialer ---

// Dialer abstracts the connection creation for testing.
type Dialer interface {
	Dial(addr string) (*Client, error)
}

// NetworkDialer implements Dialer using net.Dial with retry.
type NetworkDialer struct {
	RetryConfig RetryConfig
}

// NewNetworkDialer creates a NetworkDialer with default retry settings.
func NewNetworkDialer() *NetworkDialer {
	return &NetworkDialer{
		RetryConfig: DefaultRetryConfig(),
	}
}

// Dial connects to a backend service with retry logic.
func (d *NetworkDialer) Dial(addr string) (*Client, error) {
	var client *Client
	cleanAddr := convertAddr(addr) // Strip tcp!

	err := Retry(d.RetryConfig, func() error {
		conn, err := net.Dial("tcp", cleanAddr)
		if err != nil {
			return err
		}
		client = &Client{
			addr: addr,
			conn: conn,
			tag:  1, // Start tags at 1, 0 is NOTAG
		}
		return nil
	})

	if err != nil {
		return nil, err
	}
	return client, nil
}

// Close closes the connection.
func (c *Client) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// Authenticate performs the Host Challenge Protocol.
// It returns the afid on success, or NOFID on failure/error.
func (c *Client) Authenticate(user string, key ed25519.PrivateKey) (uint32, error) {
	// 1. Tauth
	afid := c.NextFid()
	tAuth := &p9.Fcall{Type: p9.Tauth, Afid: afid, Uname: user, Aname: ""}
	resp, err := c.RPC(tAuth)
	if err != nil {
		return p9.NOFID, err
	}
	if resp.Type == p9.Rerror {
		return p9.NOFID, fmt.Errorf("auth error: %s", resp.Ename)
	}

	// 2. Read Nonce (Tread afid)
	tRead := &p9.Fcall{Type: p9.Tread, Fid: afid, Offset: 0, Count: 8192}
	resp, err = c.RPC(tRead)
	if err != nil {
		return p9.NOFID, err
	}
	if resp.Type == p9.Rerror {
		return p9.NOFID, fmt.Errorf("read nonce failed: %s", resp.Ename)
	}
	nonce := resp.Data

	// 3. Sign Nonce
	sig := ed25519.Sign(key, nonce)

	// 4. Write Signature (Twrite afid)
	tWrite := &p9.Fcall{Type: p9.Twrite, Fid: afid, Offset: 0, Data: sig, Count: uint32(len(sig))}
	resp, err = c.RPC(tWrite)
	if err != nil {
		return p9.NOFID, err
	}
	if resp.Type == p9.Rerror {
		return p9.NOFID, fmt.Errorf("write signature failed: %s", resp.Ename)
	}

	return afid, nil
}

func (c *Client) NextFid() uint32 {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.lastFid++
	// Skip 0 (NOFID)
	if c.lastFid == 0 {
		c.lastFid = 1
	}
	return c.lastFid
}

// RPC sends a request and waits for a response.
func (c *Client) RPC(req *p9.Fcall) (*p9.Fcall, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Alloc Tag
	if req.Tag == p9.NOTAG {
		req.Tag = c.nextTag()
	}

	if err := c.writeFcall(req); err != nil {
		return nil, err
	}
	resp, err := c.readFcall()
	if err != nil {
		return nil, err
	}

	if resp.Tag != req.Tag {
		return nil, fmt.Errorf("tag mismatch: expected %d, got %d", req.Tag, resp.Tag)
	}

	return resp, nil
}

// nextTag increments and returns the next available tag, handling wrap-around.
func (c *Client) nextTag() uint16 {
	c.tag++
	if c.tag == p9.NOTAG { // Wrap around, 0 is NOTAG
		c.tag = 1
	}
	return c.tag
}

// writeFcall encodes and writes an Fcall to the connection.
func (c *Client) writeFcall(req *p9.Fcall) error {
	buf, err := req.Bytes()
	if err != nil {
		return fmt.Errorf("encode failed: %w", err)
	}

	if _, err := c.conn.Write(buf); err != nil {
		return fmt.Errorf("write failed: %w", err)
	}
	return nil
}

// readFcall reads and decodes an Fcall from the connection.
func (c *Client) readFcall() (*p9.Fcall, error) {
	resp, err := p9.ReadFcall(c.conn)
	if err != nil {
		return nil, fmt.Errorf("read failed: %w", err)
	}
	return resp, nil
}

// --- Socket Logic ---

// Socket wraps a WebSocket connection.
type Socket struct {
	conn *websocket.Conn
	mu   sync.Mutex
}

// Upgrade upgrades the HTTP request to a WebSocket connection.
func Upgrade(w http.ResponseWriter, r *http.Request) (*Socket, error) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true, // Allow all origins for now
	})
	if err != nil {
		return nil, err
	}
	return &Socket{conn: c}, nil
}

// Close closes the connection.
func (s *Socket) Close() error {
	return s.conn.Close(websocket.StatusNormalClosure, "")
}

// ReadMsg reads a 9P message from a WebSocket binary frame.
// Framing: [4-byte size][9P Message]
func (s *Socket) ReadMsg(ctx context.Context) (*p9.Fcall, error) {
	_, data, err := s.conn.Read(ctx)
	if err != nil {
		return nil, err
	}

	// Validate size prefix
	if len(data) < 4 {
		return nil, fmt.Errorf("frame too short")
	}
	size := binary.LittleEndian.Uint32(data[0:4])
	if uint32(len(data)) != size {
		return nil, fmt.Errorf("frame size mismatch: header says %d, got %d", size, len(data))
	}

	// Unmarshal 9P message (skipping 4 byte size header, p9.Unmarshal expects type at index 0)
	return p9.Unmarshal(data[4:], size)
}

// WriteMsg writes a 9P message to a WebSocket binary frame.
func (s *Socket) WriteMsg(ctx context.Context, f *p9.Fcall) error {
	buf, err := f.Bytes() // Includes [Size][Type]...
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	// Timeout for writes
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	return s.conn.Write(ctx, websocket.MessageBinary, buf)
}

// --- Proc Logic ---

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

// --- Sys Logic ---

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
		// mount <addr> <path> [flags]
		// e.g. mount tcp!localhost:9999 /ext -c
		if len(parts) < 3 {
			return fmt.Errorf("usage: mount <addr> <path> [flags]")
		}
		addr := convertAddr(parts[1])
		path := parts[2]
		flags, _ := parseFlags(parts[3:])

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

		sys.ns.Mount(path, client, flags)
		log.Printf("Sys: Mounted %s at %s (flags=%d)", addr, path, flags)
		return nil

	case "bind":
		// bind <old> <new> [flags]
		// e.g. bind /data /alias -b
		if len(parts) < 3 {
			return fmt.Errorf("usage: bind <old> <new> [flags]")
		}
		oldPath := parts[1]
		newPath := parts[2]
		flags, _ := parseFlags(parts[3:])

		if err := sys.ns.Bind(oldPath, newPath, flags); err != nil {
			return err
		}
		log.Printf("Sys: Bound %s to %s (flags=%d)", oldPath, newPath, flags)
		return nil

	default:
		return fmt.Errorf("unknown command: %s", parts[0])
	}
}

// --- Env Logic ---

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

// --- PLACEHOLDER: UTILS & AUTH ---

// --- Auth & Host Identity ---

// HostIdentity represents the kernel's identity for signing and auth.
type HostIdentity struct {
	Key ed25519.PrivateKey
}

// LoadHostIdentity loads the host identity from environment or disk.
func LoadHostIdentity() (*HostIdentity, error) {
	val := os.Getenv("HOST_KEY_BASE64")
	if val == "" {
		return nil, fmt.Errorf("HOST_KEY_BASE64 env var not set")
	}

	keyBytes, err := base64.StdEncoding.DecodeString(val)
	if err != nil {
		return nil, fmt.Errorf("invalid base64 HOST_KEY_BASE64: %w", err)
	}

	if len(keyBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid key length: want %d, got %d", ed25519.PrivateKeySize, len(keyBytes))
	}

	return &HostIdentity{Key: ed25519.PrivateKey(keyBytes)}, nil
}

// Sign signs the given data with the host key.
func (h *HostIdentity) Sign(data []byte) []byte {
	return ed25519.Sign(h.Key, data)
}

// HostAuthHandshake performs the Tauth -> Tread(nonce) -> Twrite(sig) ceremony.
// Returns the authenticated afid, or NOFID if auth failed/not attempted.
func HostAuthHandshake(client *Client, host *HostIdentity) (uint32, error) {
	if host == nil {
		return p9.NOFID, nil
	}

	afid := uint32(100) // Reserved range for internal auth?

	// Helper to reduce boilerplate
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

	// 1. Tauth
	_, err := rpcCheck(&p9.Fcall{Type: p9.Tauth, Afid: afid, Uname: "kernel", Aname: "/"})
	if err != nil {
		// Log warning but allow proceeding (maybe VFS has auth disabled?)
		// But if auth is required later, it will fail then.
		log.Printf("Boot Warning: Tauth failed: %v", err)
		return p9.NOFID, nil
	}

	// 2. Read Nonce (32 bytes)
	rResp, err := rpcCheck(&p9.Fcall{Type: p9.Tread, Fid: afid, Offset: 0, Count: 32})
	if err != nil {
		return p9.NOFID, fmt.Errorf("auth_read_nonce_failed: %w", err)
	}
	nonce := rResp.Data

	// 3. Sign Nonce
	sig := host.Sign(nonce)

	// 4. Write Signature
	if _, err := rpcCheck(&p9.Fcall{Type: p9.Twrite, Fid: afid, Data: sig, Count: uint32(len(sig))}); err != nil {
		return p9.NOFID, fmt.Errorf("auth_write_sig_failed: %w", err)
	}

	log.Printf("Boot: Host Auth Successful")
	return afid, nil
}

// --- Ticket Logic ---

// Ticket represents a verified session token.
type Ticket struct {
	User   string
	Expiry time.Time
	Nonce  string
}

// ValidateTicket fetches a ticket from VFS and verifies its signature.
func ValidateTicket(path string, vfsAddr string, pubKey ed25519.PublicKey, host *HostIdentity, d Dialer) (*Ticket, error) {
	// 1. Dial VFS (Bootstrap connection)
	client, err := d.Dial(vfsAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to dial vfs: %w", err)
	}
	defer client.Close()

	// 2. Host Auth (Required by VFS for "kernel" user)
	afid, err := HostAuthHandshake(client, host)
	if err != nil {
		// Log but proceed? Failure usually blocks attach.
		fmt.Printf("Warning: Host Auth failed during ticket validation: %v\n", err)
		afid = p9.NOFID
	}

	// Helper for RPC error checking
	rpcCheck := func(req *p9.Fcall) (*p9.Fcall, error) {
		resp, err := client.RPC(req)
		if err != nil {
			return nil, err
		}
		if resp.Type == p9.Rerror {
			return nil, fmt.Errorf("9p error: %s", resp.Ename)
		}
		return resp, nil
	}

	// 3. Attach (as 'none' or 'adm' - kernel needs to read the ticket)
	// In Plan 9, kernel has special access. Here we just attach as "kernel".
	rootFid := uint32(0)
	req := &p9.Fcall{
		Type:  p9.Tattach,
		Fid:   rootFid,
		Afid:  afid,
		Uname: "kernel",
		Aname: "/",
	}
	if _, err := rpcCheck(req); err != nil {
		return nil, fmt.Errorf("vfs attach failed: %w", err)
	}

	// 3. Walk to ticket file
	// path is like "/adm/sessions/alice/abc..."
	// We need to walk to it.
	// Since path is absolute, we should strip leading /.
	cleanPath := strings.TrimPrefix(path, "/")
	parts := strings.Split(cleanPath, "/")

	fileFid := uint32(1)
	walkReq := &p9.Fcall{
		Type:   p9.Twalk,
		Fid:    rootFid,
		Newfid: fileFid,
		Wname:  parts,
	}
	if _, err := rpcCheck(walkReq); err != nil {
		return nil, fmt.Errorf("ticket lookup failed: %w", err)
	}
	defer client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: fileFid}) // Cleanup logic

	// 4. Open
	openReq := &p9.Fcall{
		Type: p9.Topen,
		Fid:  fileFid,
		Mode: 0, // Read
	}
	if _, err := rpcCheck(openReq); err != nil {
		return nil, fmt.Errorf("ticket open failed: %w", err)
	}

	// 5. Read content
	// Tickets are small (< 200 bytes)
	readReq := &p9.Fcall{
		Type:   p9.Tread,
		Fid:    fileFid,
		Offset: 0,
		Count:  1024,
	}
	resp, err := rpcCheck(readReq)
	if err != nil {
		return nil, fmt.Errorf("ticket read failed: %w", err)
	}

	// 6. Parse and Verify
	return parseAndVerify(string(resp.Data), pubKey)
}

func parseAndVerify(content string, pubKey ed25519.PublicKey) (*Ticket, error) {
	// Format: <user> <expiry> <nonce> <sig>
	fields := strings.Fields(content)
	if len(fields) != 4 {
		return nil, errors.New("invalid ticket format")
	}

	user := fields[0]
	expiryStr := fields[1]
	nonce := fields[2]
	sigB64 := fields[3]

	// Check Expiry
	expiryInt, err := strconv.ParseInt(expiryStr, 10, 64)
	if err != nil {
		return nil, errors.New("invalid expiry format")
	}
	expiry := time.Unix(expiryInt, 0)
	if time.Now().After(expiry) {
		return nil, errors.New("ticket_expired")
	}

	// Check Signature
	// Message = user + expiry + nonce
	message := fmt.Sprintf("%s%s%s", user, expiryStr, nonce)
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return nil, errors.New("invalid signature encoding")
	}

	if !ed25519.Verify(pubKey, []byte(message), sig) {
		return nil, errors.New("invalid_signature")
	}

	return &Ticket{
		User:   user,
		Expiry: expiry,
		Nonce:  nonce,
	}, nil
}
