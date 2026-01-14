package kernel

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"log"
	"net"
	"net/http"
	"os"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

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
