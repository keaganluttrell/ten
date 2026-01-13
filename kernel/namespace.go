package kernel

import (
	"fmt"
	"strings"
	"sync"
)

// Namespace maps paths to backend clients.
type Namespace struct {
	mu     sync.RWMutex
	mounts map[string]*Client // e.g., "/view" -> Client(SSR)
}

// NewNamespace creates a correctly initialized namespace.
func NewNamespace() *Namespace {
	return &Namespace{
		mounts: make(map[string]*Client),
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

	ns.Mount("/dev/factotum", c)
	return ns, nil
}

// Mount adds a client at a specific path.
func (ns *Namespace) Mount(path string, client *Client) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.mounts[path] = client
}

// Route finds the best matching client for a given path.
// Returns the client and the path relative to that mount.
// e.g. Route("/view/index.html") -> Client(SSR), "/index.html"
func (ns *Namespace) Route(path string) (*Client, string) {
	ns.mu.RLock()
	defer ns.mu.RUnlock()

	// 1. Exact match
	if c, ok := ns.mounts[path]; ok {
		return c, "/"
	}

	// 2. Prefix match (longest wins)
	var bestMatch string
	var bestClient *Client

	for prefix, client := range ns.mounts {
		if strings.HasPrefix(path, prefix) {
			// Check that it's a directory boundary: prefix="/a", path="/a/b" (ok), path="/ab" (no)
			if len(path) > len(prefix) && path[len(prefix)] != '/' && prefix != "/" {
				continue
			}

			if len(prefix) > len(bestMatch) {
				bestMatch = prefix
				bestClient = client
			}
		}
	}

	if bestClient != nil {
		// Calculate relative path
		// prefix="/view", path="/view/foo" -> rel="/foo"
		// prefix="/", path="/foo" -> rel="/foo"

		rel := path
		if bestMatch != "/" {
			rel = strings.TrimPrefix(path, bestMatch)
			if rel == "" {
				rel = "/"
			}
		}
		return bestClient, rel
	}

	return nil, ""
}

// Build constructs the namespace from a manifest string.
// Format: mount <path> tcp!<host>!<port>
func (ns *Namespace) Build(manifest string, d Dialer) error {
	lines := strings.Split(manifest, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 3 || parts[0] != "mount" {
			continue // Skip invalid lines logic for now
		}

		mountPath := parts[1]
		addr := convertAddr(parts[2]) // Convert tcp!host!port to host:port

		client, err := d.Dial(addr)
		if err != nil {
			// In production, we might want to log this but continue?
			// For now, return error
			return fmt.Errorf("failed to mount %s: %w", mountPath, err)
		}

		ns.Mount(mountPath, client)
	}
	return nil
}

// convertAddr converts "tcp!host!port" to "host:port".
func convertAddr(plan9Addr string) string {
	// Simple validation and replacement
	s := strings.TrimPrefix(plan9Addr, "tcp!")
	return strings.Replace(s, "!", ":", 1)
}
