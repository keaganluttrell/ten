package kernel

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"log"
	"strings"
	"sync"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

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
				// Bootstrap Mode: Build Full Namespace from Manifest
				if err := s.ns.Build(manifest, s.dialer); err != nil {
					log.Printf("Boot Warning: Namespace Build Failed (%v)", err)
					s.mountRescueFS()
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

// 3. Attach (as kernel)
// recoverFid attempts to re-establish a FID for a given path using the namespace.
func (s *Session) recoverFid(ref fidRef) (*Client, uint32, error) {
	routeStack := s.ns.Route(ref.path)
	if len(routeStack) == 0 {
		return nil, 0, fmt.Errorf("route not found for %s", ref.path)
	}

	// Try all backends in the union stack?
	// For recovery, we probably want the *primary* one or try them all until one works.
	// Since we don't know which one the original FID belonged to without tracking it...
	// Wait, fidRef stores 'client'. We can match it!

	var targetRoute *ResolvedPath
	for _, r := range routeStack {
		if r.Client == ref.client {
			targetRoute = r
			break
		}
	}

	if targetRoute == nil {
		// Client is no longer in the route for this path?
		// Fallback to head of stack? Or fail?
		// If the namespace changed, the fid is invalid.
		// But let's try head of stack as best effort.
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

// Helper functions fetchNamespaceManifest and findMountAddr are assumed to be in the same package (e.g. they were in session.go or another file).
// Wait, they WERE in session.go at bottom. I must preserve them!
// Checking previous view of session.go... yes they were there.
// I will include them here.

func (s *Session) mountRescueFS() {
	client := NewBootFSClient()
	s.ns.Mount("/", client, MREPL)
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
		afid, err = client.Authenticate("kernel", host.PrivateKey)
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
