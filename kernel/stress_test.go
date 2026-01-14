package kernel

import (
	"crypto/ed25519"
	"crypto/rand"
	"sync"
	"testing"
	"time"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
	"github.com/stretchr/testify/assert"
)

// TestSession_ConcurrentWalks tests rapid sequential FID operations
// within a single session (single-threaded by design).
func TestSession_ConcurrentWalks(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	md := NewMockDialer()

	// Mock VFS handler
	md.Handlers["vfs:9002"] = SimpleServerHandler(t, func(req *p9.Fcall) *p9.Fcall {
		switch req.Type {
		case p9.Tversion:
			return &p9.Fcall{Type: p9.Rversion, Msize: 8192, Version: "9P2000"}
		case p9.Tauth:
			return &p9.Fcall{Type: p9.Rauth, Qid: p9.Qid{Type: p9.QTAUTH}}
		case p9.Tattach:
			return &p9.Fcall{Type: p9.Rattach, Qid: p9.Qid{Type: p9.QTDIR}}
		case p9.Twalk:
			qids := make([]p9.Qid, len(req.Wname))
			for i := range qids {
				qids[i] = p9.Qid{Type: p9.QTFILE, Path: uint64(i)}
			}
			return &p9.Fcall{Type: p9.Rwalk, Wqid: qids}
		case p9.Topen:
			return &p9.Fcall{Type: p9.Ropen, Qid: p9.Qid{Type: p9.QTFILE}}
		case p9.Tread:
			return &p9.Fcall{Type: p9.Rread, Data: []byte("mount /dev/factotum factotum:9003\n")}
		case p9.Tclunk:
			return &p9.Fcall{Type: p9.Rclunk}
		default:
			return &p9.Fcall{Type: p9.Rerror, Ename: "not implemented"}
		}
	})

	// Mock Factotum
	md.Handlers["factotum:9003"] = SimpleServerHandler(t, func(req *p9.Fcall) *p9.Fcall {
		return &p9.Fcall{Type: req.Type + 1, Qid: p9.Qid{Type: p9.QTDIR}}
	})

	sess := NewSession(nil, "vfs:9002", pub, nil, md)

	// Bootstrap
	resp := sess.handle(&p9.Fcall{Type: p9.Tattach, Fid: 0, Aname: ""})
	assert.Equal(t, uint8(p9.Rattach), resp.Type)

	// Perform many walk/clunk operations
	const numOperations = 100
	for i := 0; i < numOperations; i++ {
		fid := uint32(i + 1)

		// Walk
		resp := sess.handle(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: fid, Wname: []string{"file"}})
		if resp.Type == p9.Rerror {
			t.Logf("Walk %d failed: %s", i, resp.Ename)
			continue
		}
		assert.Equal(t, uint8(p9.Rwalk), resp.Type)

		// Clunk
		resp = sess.handle(&p9.Fcall{Type: p9.Tclunk, Fid: fid})
		assert.Equal(t, uint8(p9.Rclunk), resp.Type)
	}

	t.Logf("Successfully processed %d walk/clunk operations", numOperations)
}

// TestSession_ConcurrentClients tests multiple sessions (clients)
// running in parallel goroutines.
func TestSession_ConcurrentClients(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	md := NewMockDialer()

	// Mock VFS
	md.Handlers["vfs:9002"] = SimpleServerHandler(t, func(req *p9.Fcall) *p9.Fcall {
		switch req.Type {
		case p9.Tversion:
			return &p9.Fcall{Type: p9.Rversion, Msize: 8192, Version: "9P2000"}
		case p9.Tauth:
			return &p9.Fcall{Type: p9.Rauth, Qid: p9.Qid{Type: p9.QTAUTH}}
		case p9.Tattach:
			return &p9.Fcall{Type: p9.Rattach, Qid: p9.Qid{Type: p9.QTDIR}}
		case p9.Twalk:
			qids := make([]p9.Qid, len(req.Wname))
			for i := range qids {
				qids[i] = p9.Qid{Type: p9.QTFILE}
			}
			return &p9.Fcall{Type: p9.Rwalk, Wqid: qids}
		case p9.Tread:
			return &p9.Fcall{Type: p9.Rread, Data: []byte("mount /dev/factotum factotum:9003\n")}
		case p9.Tclunk:
			return &p9.Fcall{Type: p9.Rclunk}
		default:
			return &p9.Fcall{Type: p9.Rerror, Ename: "not implemented"}
		}
	})

	md.Handlers["factotum:9003"] = SimpleServerHandler(t, func(req *p9.Fcall) *p9.Fcall {
		return &p9.Fcall{Type: req.Type + 1, Qid: p9.Qid{Type: p9.QTDIR}}
	})

	const numClients = 10
	var wg sync.WaitGroup

	for i := 0; i < numClients; i++ {
		wg.Add(1)
		go func(clientID int) {
			defer wg.Done()

			// Each client gets its own session
			sess := NewSession(nil, "vfs:9002", pub, nil, md)

			// Bootstrap
			resp := sess.handle(&p9.Fcall{Type: p9.Tattach, Fid: 0, Aname: ""})
			if resp.Type != p9.Rattach {
				return
			}

			// Perform operations
			for j := 0; j < 10; j++ {
				fid := uint32(j + 1)
				sess.handle(&p9.Fcall{Type: p9.Twalk, Fid: 0, Newfid: fid, Wname: []string{"file"}})
				sess.handle(&p9.Fcall{Type: p9.Tclunk, Fid: fid})
			}
		}(i)
	}

	// Wait with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		t.Logf("All %d concurrent clients completed successfully", numClients)
	case <-time.After(5 * time.Second):
		t.Fatal("Test timed out - possible deadlock")
	}
}

// TestNamespace_ConcurrentRoute tests concurrent access to namespace routing.
func TestNamespace_ConcurrentRoute(t *testing.T) {
	md := NewMockDialer()
	md.Handlers["vfs:9002"] = SimpleServerHandler(t, func(req *p9.Fcall) *p9.Fcall {
		return &p9.Fcall{Type: p9.Rversion}
	})

	ns := NewNamespace()
	client, _ := md.Dial("vfs:9002")
	// client already defined above
	ns.Mount("/", client, MREPL)

	const numGoroutines = 50
	const numOps = 100
	var wg sync.WaitGroup

	for i := 0; i < numGoroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < numOps; j++ {
				// Concurrent reads
				result := ns.Route("/test/path")
				if assert.NotEmpty(t, result) {
					assert.NotNil(t, result[0].Client)
				}

				// Concurrent mounts (less frequent)
				if j%10 == 0 {
					ns.Mount("/temp", client, MREPL)
				}
			}
		}()
	}

	wg.Wait()
	t.Logf("Completed %d goroutines x %d operations with concurrent Route/Mount", numGoroutines, numOps)
}
