// Package ssr provides the Server-Side Rendering logic for Project Ten.
// It serves a file browser UI over HTTP with WebSocket for live updates.
package ssr

import (
	"context"
	"encoding/base64"
	"fmt"
	"html"
	"html/template"
	"log"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/coder/websocket"
	"github.com/coder/websocket/wsjson"
	"github.com/keaganluttrell/ten/kernel"
	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// --- Data Structures ---

type Message struct {
	Type   string `json:"type"`
	Ticket string `json:"ticket,omitempty"`
	User   string `json:"user,omitempty"`
	Path   string `json:"path,omitempty"`
}

type Response struct {
	Type  string `json:"type"`
	Html  string `json:"html,omitempty"`
	Path  string `json:"path,omitempty"`
	Value string `json:"value,omitempty"`
	Error string `json:"error,omitempty"`
}

// --- Data Structures ---

type Breadcrumb struct {
	Name string
	Href string
}

type TreeEntry struct {
	Name  string
	Href  string
	IsDir bool
	Depth int
}

type DirEntry struct {
	Name  string
	Href  string
	IsDir bool
}

type PageData struct {
	Path        string
	Breadcrumbs []Breadcrumb
	Tree        []TreeEntry
	IsDir       bool
	Entries     []DirEntry
	Content     string
}

// --- Server ---

type Server struct {
	KernelAddr   string
	FactotumAddr string
	TemplatesDir string
	StaticDir    string
	tmpl         *template.Template
}

// Start launches the SSR HTTP server.
func Start(httpAddr, kernelAddr, factotumAddr string) error {
	templatesDir := os.Getenv("TEMPLATES_DIR")
	if templatesDir == "" {
		templatesDir = "/templates"
	}
	staticDir := os.Getenv("STATIC_DIR")
	if staticDir == "" {
		staticDir = "/static"
	}

	s := &Server{
		KernelAddr:   kernelAddr,
		FactotumAddr: factotumAddr,
		TemplatesDir: templatesDir,
		StaticDir:    staticDir,
	}

	log.Printf("SSR Gateway listening on %s (Kernel: %s, Factotum: %s)", httpAddr, kernelAddr, factotumAddr)
	log.Printf("SSR Templates: %s, Static: %s", templatesDir, staticDir)
	return http.ListenAndServe(httpAddr, s)
}

// ServeHTTP handles incoming HTTP requests.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	reqPath := path.Clean(r.URL.Path)

	// Route: Static files
	if strings.HasPrefix(reqPath, "/static/") {
		s.serveStatic(w, r, reqPath)
		return
	}

	// Route: WebSocket Proxy
	if reqPath == "/ws" {
		s.handleWebSocket(w, r)
		return
	}

	// Route: File Browser (everything else)
	s.handleBrowser(w, r, reqPath)
}

// serveStatic serves static files from the static directory.
func (s *Server) serveStatic(w http.ResponseWriter, r *http.Request, reqPath string) {
	// Strip /static/ prefix and serve from StaticDir
	filename := strings.TrimPrefix(reqPath, "/static/")
	filePath := filepath.Join(s.StaticDir, filename)

	// Security: prevent directory traversal
	if !strings.HasPrefix(filepath.Clean(filePath), filepath.Clean(s.StaticDir)) {
		http.Error(w, "Forbidden", 403)
		return
	}

	http.ServeFile(w, r, filePath)
}

// handleBrowser renders the file browser UI (Shell).
func (s *Server) handleBrowser(w http.ResponseWriter, r *http.Request, reqPath string) {
	// Parse template (read from disk each time for HMR)
	tmplPath := filepath.Join(s.TemplatesDir, "layout.html")
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("Template error: %v", err), 500)
		return
	}

	// Serve empty shell, content is loaded via WebSocket
	data := PageData{
		Path:        reqPath,
		Breadcrumbs: []Breadcrumb{{Name: "root", Href: "/"}},
		Tree:        []TreeEntry{},
		IsDir:       true,
		Entries:     []DirEntry{},
		Content:     "Loading...", // Initial state
	}

	w.Header().Set("Content-Type", "text/html")
	if err := tmpl.Execute(w, data); err != nil {
		log.Printf("SSR: Template execution error: %v", err)
	}
}

// buildBreadcrumbs creates navigation breadcrumbs from a path.
func buildBreadcrumbs(p string) []Breadcrumb {
	crumbs := []Breadcrumb{{Name: "root", Href: "/"}}
	if p == "/" || p == "" {
		return crumbs
	}
	parts := strings.Split(strings.Trim(p, "/"), "/")
	href := ""
	for _, part := range parts {
		href += "/" + part
		crumbs = append(crumbs, Breadcrumb{Name: part, Href: href})
	}
	return crumbs
}

// buildTree recursively builds the file tree.
func (s *Server) buildTree(client *kernel.Client, rootFid uint32, dirPath string, depth int) ([]TreeEntry, error) {
	var result []TreeEntry

	// Read directory entries
	var entries []DirEntry
	var err error

	if dirPath == "/" {
		entries, err = s.readDir(client, rootFid, "/")
	} else {
		parts := strings.Split(strings.Trim(dirPath, "/"), "/")
		targetFid := client.NextFid()
		resp, err := client.RPC(&p9.Fcall{
			Type:   p9.Twalk,
			Fid:    rootFid,
			Newfid: targetFid,
			Wname:  parts,
		})
		if err != nil || resp.Type == p9.Rerror || len(resp.Wqid) != len(parts) {
			if targetFid != 0 {
				client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: targetFid})
			}
			return nil, fmt.Errorf("walk failed")
		}
		defer client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: targetFid})

		entries, err = s.readDirFid(client, targetFid, dirPath)
		if err != nil {
			return nil, err
		}
	}

	if err != nil {
		return nil, err
	}

	for _, e := range entries {
		result = append(result, TreeEntry{
			Name:  e.Name,
			Href:  e.Href,
			IsDir: e.IsDir,
			Depth: depth,
		})
		// Recurse into directories (limit depth to avoid infinite loops)
		if e.IsDir && depth < 3 {
			subTree, _ := s.buildTree(client, rootFid, e.Href, depth+1)
			result = append(result, subTree...)
		}
	}

	return result, nil
}

// readDir reads directory entries from root.
func (s *Server) readDir(client *kernel.Client, rootFid uint32, dirPath string) ([]DirEntry, error) {
	// Clone root fid
	targetFid := client.NextFid()
	resp, err := client.RPC(&p9.Fcall{
		Type:   p9.Twalk,
		Fid:    rootFid,
		Newfid: targetFid,
		Wname:  []string{},
	})
	if err != nil || resp.Type == p9.Rerror {
		return nil, fmt.Errorf("clone failed")
	}
	defer client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: targetFid})

	return s.readDirFid(client, targetFid, dirPath)
}

// readDirFid reads directory entries from an open fid.
func (s *Server) readDirFid(client *kernel.Client, fid uint32, dirPath string) ([]DirEntry, error) {
	// Open
	if _, err := client.RPC(&p9.Fcall{Type: p9.Topen, Fid: fid, Mode: 0}); err != nil {
		return nil, err
	}

	// Read
	var allData []byte
	offset := uint64(0)
	for {
		resp, err := client.RPC(&p9.Fcall{Type: p9.Tread, Fid: fid, Offset: offset, Count: 8192})
		if err != nil || len(resp.Data) == 0 {
			break
		}
		allData = append(allData, resp.Data...)
		offset += uint64(len(resp.Data))
	}

	// Parse
	var entries []DirEntry
	scan := allData
	for len(scan) > 0 {
		d, n, err := p9.UnmarshalDir(scan)
		if err != nil {
			break
		}
		href := path.Join(dirPath, d.Name)
		if !strings.HasPrefix(href, "/") {
			href = "/" + href
		}
		entries = append(entries, DirEntry{
			Name:  d.Name,
			Href:  href,
			IsDir: d.Mode&p9.DMDIR != 0,
		})
		scan = scan[n:]
	}

	return entries, nil
}

// readFile reads file content.
func (s *Server) readFile(client *kernel.Client, fid uint32) (string, error) {
	// Open
	if _, err := client.RPC(&p9.Fcall{Type: p9.Topen, Fid: fid, Mode: 0}); err != nil {
		return "", err
	}

	// Read
	var allData []byte
	offset := uint64(0)
	for {
		resp, err := client.RPC(&p9.Fcall{Type: p9.Tread, Fid: fid, Offset: offset, Count: 8192})
		if err != nil || len(resp.Data) == 0 {
			break
		}
		allData = append(allData, resp.Data...)
		offset += uint64(len(resp.Data))
	}

	return html.EscapeString(string(allData)), nil
}

// handleWebSocket handles the "Thin Client" protocol.
func (s *Server) handleWebSocket(w http.ResponseWriter, r *http.Request) {
	c, err := websocket.Accept(w, r, &websocket.AcceptOptions{
		InsecureSkipVerify: true,
	})
	if err != nil {
		log.Printf("SSR: Failed to accept websocket: %v", err)
		return
	}
	defer c.Close(websocket.StatusInternalError, "internal error")

	ctx := r.Context()
	var client *kernel.Client
	var rootFid uint32
	// Registration state
	var regClient *kernel.Client
	var regFid uint32

	defer func() {
		if client != nil {
			client.Close()
		}
	}()

	log.Printf("SSR: New connection")

	// Message Loop
	for {
		// Read text message
		msgType, data, err := c.Read(ctx)
		if err != nil {
			return
		}
		if msgType != websocket.MessageText {
			continue
		}

		msg := string(data)
		parts := strings.Fields(msg)
		if len(parts) == 0 {
			continue
		}

		verb := parts[0]
		params := parseParams(parts[1:])

		switch verb {
		case "auth":
			// Protocol: auth user=<user> ticket=<ticket>
			userVal := params["user"]
			ticket := params["ticket"]

			if userVal == "" || ticket == "" {
				s.writeText(ctx, c, "error msg=missing_params")
				continue
			}

			// Dial Kernel
			cli, fid, err := s.dialKernelAuth(userVal, ticket)
			if err != nil {
				log.Printf("SSR: Auth failed for %s: %v", userVal, err)
				s.writeText(ctx, c, "login_required error=auth_failed")
				continue
			}
			if client != nil {
				client.Close()
			}
			client = cli
			client = cli
			rootFid = fid
			// user = userVal (Already set if we were tracking it)

			// Render root (or requested path)
			s.renderPath(ctx, c, client, rootFid, "/")

		case "login":
			// Protocol: login user=<user>
			userVal := params["user"]
			if userVal == "" {
				s.writeText(ctx, c, "error msg=missing_user")
				continue
			}

			// Request ticket from Factotum
			ticket, err := s.dialFactotumLogin(userVal)
			if err != nil {
				log.Printf("SSR: Login failed for %s: %v", userVal, err)
				s.writeText(ctx, c, fmt.Sprintf("login_required error=%s", err))
				continue
			}
			// Protocol: ticket ticket=<ticket>
			// Note: Ticket string itself might have spaces?
			// In V1 Simple Proto: ticket is path "/adm/sessions/..." (no spaces).
			// If we move to full ticket string, we must ensure it is quoted or handled.
			// Current Factotum returns ticket path. Safe.
			s.writeText(ctx, c, fmt.Sprintf("ticket ticket=%s", ticket))
			log.Printf("SSR: Issued simple ticket for %s", userVal)

		case "register":
			// Protocol: register user=<user>
			userVal := params["user"]
			if userVal == "" {
				s.writeText(ctx, c, "error msg=missing_user")
				continue
			}

			// 1. Start Registration
			challenge, fid, cli, err := s.dialFactotumRegister(userVal)
			if err != nil {
				log.Printf("SSR: Register start failed: %v", err)
				s.writeText(ctx, c, fmt.Sprintf("error msg=%s", err))
				continue
			}

			// Store for next step
			if regClient != nil {
				regClient.Close()
			}
			regClient = cli
			regFid = fid

			s.writeText(ctx, c, fmt.Sprintf("challenge %s", challenge))

		case "register_finish":
			// Protocol: register_finish response=<base64_json>
			// Or just proxy the write? Factotum expects "write <data>".
			response := params["response"]
			if regClient == nil {
				s.writeText(ctx, c, "error msg=no_registration_session")
				continue
			}

			// Write the response to Factotum
			// "write <data>"
			data := fmt.Sprintf("write %s", response)
			if _, err := regClient.RPC(&p9.Fcall{Type: p9.Twrite, Fid: regFid, Offset: 0, Data: []byte(data)}); err != nil {
				log.Printf("SSR: Register finish failed: %v", err)
				s.writeText(ctx, c, fmt.Sprintf("error msg=%s", err))
				regClient.Close()
				regClient = nil
				continue
			}

			// Read result (OK or Error)
			// Factotum should return "ok" or similar?
			// Actually, after write, we can Read again to get status?
			// Factotum `handleWrite` returns error if failed, nil if success.
			// But we need to know if it's done.
			// `Read` on the file might return the ticket or "ok"?
			// Let's check Factotum `Read` implementation.

			// Assume success if write succeeded for now?
			// Or read response.
			resp, err := regClient.RPC(&p9.Fcall{Type: p9.Tread, Fid: regFid, Offset: 0, Count: 8192})
			if err != nil {
				s.writeText(ctx, c, fmt.Sprintf("error msg=%s", err))
			} else {
				s.writeText(ctx, c, string(resp.Data)) // "ok ..."
			}

			regClient.Close()
			regClient = nil
		}
	}
}

// dialFactotumRegister initiates registration
func (s *Server) dialFactotumRegister(user string) (string, uint32, *kernel.Client, error) {
	dialer := kernel.NewNetworkDialer()
	client, err := dialer.Dial(s.FactotumAddr)
	if err != nil {
		return "", 0, nil, err
	}

	if _, err := client.RPC(&p9.Fcall{Type: p9.Tversion, Msize: 8192, Version: "9P2000"}); err != nil {
		client.Close()
		return "", 0, nil, err
	}

	rootFid := client.NextFid()
	if _, err := client.RPC(&p9.Fcall{Type: p9.Tattach, Fid: rootFid, Uname: "none"}); err != nil {
		client.Close()
		return "", 0, nil, err
	}

	rpcFid := client.NextFid()
	if _, err := client.RPC(&p9.Fcall{Type: p9.Twalk, Fid: rootFid, Newfid: rpcFid, Wname: []string{"rpc"}}); err != nil {
		client.Close()
		return "", 0, nil, err
	}

	if _, err := client.RPC(&p9.Fcall{Type: p9.Topen, Fid: rpcFid, Mode: p9.ORDWR}); err != nil {
		client.Close()
		return "", 0, nil, err
	}

	// Start Registration
	cmd := fmt.Sprintf("start proto=webauthn role=register user=%s", user)
	if _, err := client.RPC(&p9.Fcall{Type: p9.Twrite, Fid: rpcFid, Data: []byte(cmd)}); err != nil {
		client.Close()
		return "", 0, nil, err
	}

	// Read Challenge
	resp, err := client.RPC(&p9.Fcall{Type: p9.Tread, Fid: rpcFid, Count: 8192})
	if err != nil {
		client.Close()
		return "", 0, nil, err
	}

	// Returns: "challenge user=... challenge=..."
	// We just pass it through.
	return string(resp.Data), rpcFid, client, nil
}

func (s *Server) writeText(ctx context.Context, c *websocket.Conn, msg string) {
	c.Write(ctx, websocket.MessageText, []byte(msg))
}

func parseParams(parts []string) map[string]string {
	m := make(map[string]string)
	for _, p := range parts {
		if kv := strings.SplitN(p, "=", 2); len(kv) == 2 {
			m[kv[0]] = kv[1]
		}
	}
	return m
}

// dialKernelAuth connects to the kernel and authenticates with a ticket.
func (s *Server) dialKernelAuth(user, ticket string) (*kernel.Client, uint32, error) {
	dialer := kernel.NewNetworkDialer()
	client, err := dialer.Dial(s.KernelAddr)
	if err != nil {
		return nil, 0, err
	}

	if _, err := client.RPC(&p9.Fcall{Type: p9.Tversion, Msize: 8192, Version: "9P2000"}); err != nil {
		client.Close()
		return nil, 0, err
	}

	rootFid := client.NextFid()
	// Tattach(uname=user, aname=ticket)
	if _, err := client.RPC(&p9.Fcall{Type: p9.Tattach, Fid: rootFid, Afid: p9.NOFID, Uname: user, Aname: ticket}); err != nil {
		client.Close()
		return nil, 0, err
	}

	return client, rootFid, nil
}

// dialFactotumLogin connects to Factotum and requests a ticket for the user.
func (s *Server) dialFactotumLogin(user string) (string, error) {
	dialer := kernel.NewNetworkDialer()
	client, err := dialer.Dial(s.FactotumAddr)
	if err != nil {
		return "", err
	}
	defer client.Close()

	if _, err := client.RPC(&p9.Fcall{Type: p9.Tversion, Msize: 8192, Version: "9P2000"}); err != nil {
		return "", err
	}

	// Attach as anyone to talk to factotum RPC?
	// Usually factotum allows attach by anyone, authentication is done via RPC commands.
	rootFid := client.NextFid()
	if _, err := client.RPC(&p9.Fcall{Type: p9.Tattach, Fid: rootFid, Afid: p9.NOFID, Uname: "none", Aname: ""}); err != nil {
		return "", err
	}
	defer client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: rootFid})

	// Walk to rpc
	rpcFid := client.NextFid()
	if _, err := client.RPC(&p9.Fcall{Type: p9.Twalk, Fid: rootFid, Newfid: rpcFid, Wname: []string{"rpc"}}); err != nil {
		return "", err
	}
	defer client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: rpcFid})

	// Open rpc
	if _, err := client.RPC(&p9.Fcall{Type: p9.Topen, Fid: rpcFid, Mode: p9.ORDWR}); err != nil {
		return "", err
	}

	// Write start command
	cmd := fmt.Sprintf("start proto=simple user=%s", user)
	if _, err := client.RPC(&p9.Fcall{Type: p9.Twrite, Fid: rpcFid, Offset: 0, Data: []byte(cmd)}); err != nil {
		return "", err
	}

	// Read response (Ticket)
	resp, err := client.RPC(&p9.Fcall{Type: p9.Tread, Fid: rpcFid, Offset: 0, Count: 8192})
	if err != nil {
		return "", err
	}

	// Response should be "ok <ticket>" or just "<ticket>"?
	// I'll make Factotum return just the ticket string for simple proto.
	ticket := string(resp.Data)
	if strings.HasPrefix(ticket, "error") {
		return "", fmt.Errorf("%s", ticket)
	}
	return ticket, nil
}

// renderPath renders the UI for the given path.
func (s *Server) renderPath(ctx context.Context, c *websocket.Conn, client *kernel.Client, rootFid uint32, reqPath string) {
	// ... Logic from handleBrowser but sending JSON ...

	// 1. Build Breadcrumbs
	breadcrumbs := buildBreadcrumbs(reqPath)

	// 2. Build Tree
	tree, err := s.buildTree(client, rootFid, "/", 0)
	if err != nil {
		log.Printf("SSR: Failed to build tree: %v", err)
		tree = []TreeEntry{}
	}

	// 3. Read Content/Entries
	isDir := true
	var entries []DirEntry
	var content string

	if reqPath == "/" {
		entries, err = s.readDir(client, rootFid, "/")
	} else {
		// Walk logic ... reusing snippets
		parts := strings.Split(strings.Trim(reqPath, "/"), "/")
		targetFid := client.NextFid()

		valid := true
		resp, err := client.RPC(&p9.Fcall{Type: p9.Twalk, Fid: rootFid, Newfid: targetFid, Wname: parts})
		if err != nil || resp.Type == p9.Rerror || len(resp.Wqid) != len(parts) {
			valid = false
		} else {
			if resp.Wqid[len(resp.Wqid)-1].Type&p9.QTDIR != 0 {
				isDir = true
				entries, err = s.readDirFid(client, targetFid, reqPath)
			} else {
				isDir = false
				content, err = s.readFile(client, targetFid)
			}
			client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: targetFid})
		}

		if !valid || err != nil {
			wsjson.Write(ctx, c, Response{Type: "error", Error: "Not Found"})
			return
		}
	}

	data := PageData{
		Path:        reqPath,
		Breadcrumbs: breadcrumbs,
		Tree:        tree,
		IsDir:       isDir,
		Entries:     entries,
		Content:     content,
	}

	// Render Request
	// Note: We need to render the *body* of the layout, not the whole HTML?
	// Actually, the client just replaces the whole body or a container.
	// For simplicity, let's render the whole page and let client replace document.documentElement.innerHTML
	// OR just the main container.
	// The current layout.html includes <html><body>...
	// Ideally we separate the inner content.
	// But `handleBrowser` rendered the whole thing.
	// Let's render the whole thing string to a buffer.

	// Create buffer
	// (Need bytes package) -> Use strings.Builder
	var buf strings.Builder
	// Parse template again to be safe (HMR) or use cached
	tmplPath := filepath.Join(s.TemplatesDir, "layout.html")
	tmpl, err := template.ParseFiles(tmplPath)
	if err != nil {
		log.Printf("SSR: Template error: %v", err)
		return
	}

	if err := tmpl.Execute(&buf, data); err != nil {
		log.Printf("SSR: Render error: %v", err)
		return
	}

	htmlContent := base64.StdEncoding.EncodeToString([]byte(buf.String()))
	s.writeText(ctx, c, fmt.Sprintf("render path=%s html=%s", reqPath, htmlContent))
}
