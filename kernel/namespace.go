package kernel

import (
	"fmt"
	"strings"
	"sync"
)

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
