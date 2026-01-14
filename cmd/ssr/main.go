package main

import (
	_ "embed"
	"flag"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"

	"github.com/keaganluttrell/ten/kernel"
	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

var (
	kernelAddr = flag.String("kernel", "127.0.0.1:9000", "Kernel address")
	addr       = flag.String("addr", ":8080", "HTTP listen address")
)

//go:embed index.html
var indexHTML []byte

func main() {
	flag.Parse()

	if v := os.Getenv("KERNEL_ADDR"); v != "" {
		*kernelAddr = v
	}
	if v := os.Getenv("ADDR"); v != "" {
		*addr = v
	}

	gw := &Gateway{
		addr: *kernelAddr,
	}

	http.HandleFunc("/", gw.handle)
	log.Printf("SSR Gateway listening on %s", *addr)
	log.Fatal(http.ListenAndServe(*addr, nil))
}

type Gateway struct {
	addr    string
	client  *kernel.Client
	rootFid uint32
	mu      sync.Mutex
}

func (gw *Gateway) getClient() (*kernel.Client, uint32, error) {
	gw.mu.Lock()
	defer gw.mu.Unlock()

	// If we have a client, try a quick ping (Tversion) to see if it's alive
	if gw.client != nil {
		_, err := gw.client.RPC(&p9.Fcall{Type: p9.Tversion, Msize: 8192, Version: "9P2000"})
		if err == nil {
			return gw.client, gw.rootFid, nil
		}
		log.Printf("Kernel connection lost, reconnecting...")
		gw.client.Close()
		gw.client = nil
	}

	// Dial
	dialer := kernel.NewNetworkDialer()
	client, err := dialer.Dial(gw.addr)
	if err != nil {
		return nil, 0, err
	}

	// Handshake
	if _, err := client.RPC(&p9.Fcall{Type: p9.Tversion, Msize: 8192, Version: "9P2000"}); err != nil {
		client.Close()
		return nil, 0, err
	}

	// Attach
	rootFid := client.NextFid()
	if _, err := client.RPC(&p9.Fcall{Type: p9.Tattach, Fid: rootFid, Afid: p9.NOFID, Uname: "http", Aname: "/"}); err != nil {
		client.Close()
		return nil, 0, err
	}

	gw.client = client
	gw.rootFid = rootFid
	return client, rootFid, nil
}

func (gw *Gateway) handle(w http.ResponseWriter, r *http.Request) {
	client, rootFid, err := gw.getClient()
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to connect to Kernel: %v", err), 503)
		return
	}

	reqPath := path.Clean(r.URL.Path)
	if reqPath == "/" || reqPath == "/index.html" {
		w.Header().Set("Content-Type", "text/html")
		w.Write(indexHTML)
		return
	}
	parts := strings.Split(strings.Trim(reqPath, "/"), "/")

	// 1. Walk to target
	targetFid := client.NextFid()

	// We walk from rootFid to targetFid using parts
	req := &p9.Fcall{
		Type:   p9.Twalk,
		Fid:    rootFid,
		Newfid: targetFid,
		Wname:  parts,
	}
	resp, err := client.RPC(req)
	if err != nil {
		http.Error(w, fmt.Sprintf("9P Error: %v", err), 500)
		return
	}
	if resp.Type == p9.Rerror {
		http.Error(w, fmt.Sprintf("Not Found: %s", resp.Ename), 404)
		return
	}
	// Verify full walk
	if len(resp.Wqid) != len(parts) {
		client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: targetFid})
		http.Error(w, "Not Found", 404)
		return
	}
	defer client.RPC(&p9.Fcall{Type: p9.Tclunk, Fid: targetFid})

	// 2. Stat (to check if Dir or File) -- actually we can check qid from walk resp?
	// The last Qid in Wqid corresponds to the target file.
	// If Wqid is empty (root), we stat rootFid? Unnecessary, we assume root is Dir.

	isDir := false
	if len(resp.Wqid) > 0 {
		if resp.Wqid[len(resp.Wqid)-1].Type&p9.QTDIR != 0 {
			isDir = true
		}
	} else {
		// Root is dir
		isDir = true
	}

	// 3. Open
	if _, err := gw.client.RPC(&p9.Fcall{Type: p9.Topen, Fid: targetFid, Mode: 0}); err != nil {
		http.Error(w, "Permission Denied", 403)
		return
	}

	// 4. Read & Render
	if isDir {
		gw.renderDir(w, targetFid, reqPath)
	} else {
		gw.renderFile(w, targetFid)
	}
}

func (gw *Gateway) renderDir(w http.ResponseWriter, fid uint32, ps string) {
	fmt.Fprintf(w, "<h1>Index of %s</h1><ul>", ps)
	if ps != "/" {
		fmt.Fprintf(w, "<li><a href=\"..\">..</a></li>")
	}

	offset := uint64(0)
	for {
		resp, err := gw.client.RPC(&p9.Fcall{Type: p9.Tread, Fid: fid, Offset: offset, Count: 8192})
		if err != nil || len(resp.Data) == 0 {
			break
		}

		data := resp.Data
		for len(data) > 0 {
			dir, n, err := p9.UnmarshalDir(data)
			if err != nil {
				break
			}

			name := dir.Name
			if dir.Mode&p9.DMDIR != 0 {
				name += "/"
			}
			link := path.Join(ps, name)
			// Handle root path join quirk: path.Join("/", "foo") -> "/foo" (good)

			fmt.Fprintf(w, "<li><a href=\"%s\">%s</a></li>", checkPath(link, dir.Mode&p9.DMDIR != 0), html.EscapeString(dir.Name))

			data = data[n:]
		}
		offset += uint64(len(resp.Data))
	}
	fmt.Fprintf(w, "</ul>")
}

func checkPath(p string, isDir bool) string {
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if isDir && !strings.HasSuffix(p, "/") {
		return p + "/" // Ensure trailing slash for relative links to work nicely?
		// Actually browsers handle directory links better without trailing slash if server redirects,
		// but here we are generating links.
		// If I am at /proc and link to "1", browser goes to /1.
		// If I am at /proc/ and link to "1", browser goes to /proc/1.
		// Since we path.Clean(r.URL.Path), we might lose trailing slash on request.
		// Let's just use absolute paths in hrefs for safety.
	}
	return p
}

func (gw *Gateway) renderFile(w http.ResponseWriter, fid uint32) {
	w.Header().Set("Content-Type", "text/plain")
	offset := uint64(0)
	for {
		resp, err := gw.client.RPC(&p9.Fcall{Type: p9.Tread, Fid: fid, Offset: offset, Count: 8192})
		if err != nil || len(resp.Data) == 0 {
			break
		}
		w.Write(resp.Data)
		offset += uint64(len(resp.Data))
	}
}
