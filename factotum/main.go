// Package factotum is the authentication agent for Project Ten.
// It provides WebAuthn ceremonies and ticket-based session management.
package factotum

import (
	"fmt"
	"log"
	"net"
	"os"
)

// Server is the Factotum 9P server.
type Server struct {
	listenAddr string
	keyring    *Keyring
	sessions   *Sessions
	rpc        *RPC
	ctl        *Ctl
}

// Config holds server configuration.
type Config struct {
	ListenAddr string // TCP address to listen on (e.g., ":9003")
	DataPath   string // Path to /priv/factotum (local fs for v1)
}

// NewServer creates a new Factotum server.
func NewServer(cfg Config) (*Server, error) {
	keyring, err := NewKeyring(cfg.DataPath)
	if err != nil {
		return nil, fmt.Errorf("keyring init failed: %w", err)
	}

	sessions := NewSessions()

	return &Server{
		listenAddr: cfg.ListenAddr,
		keyring:    keyring,
		sessions:   sessions,
		rpc:        NewRPC(sessions, keyring),
		ctl:        NewCtl(keyring),
	}, nil
}

// Run starts the TCP listener and accepts connections.
func (s *Server) Run() error {
	ln, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return err
	}
	defer ln.Close()

	log.Printf("factotum listening on %s", s.listenAddr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go s.handleConn(conn)
	}
}

// handleConn handles a single client connection.
// TODO: Implement 9P protocol handling using pkg/9p.
func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	log.Printf("new connection from %s", conn.RemoteAddr())

	// 9P message loop would go here:
	// 1. Read 9P message (Tversion, Tattach, Twalk, Topen, Tread, Twrite, Tclunk)
	// 2. Dispatch to /rpc, /ctl, or /proto handler
	// 3. Write 9P response

	// For now, this is a placeholder.
	// Full 9P implementation requires pkg/9p to be complete.
}

// Main entry point.
func Main() {
	cfg := Config{
		ListenAddr: getEnv("LISTEN_ADDR", ":9003"),
		DataPath:   getEnv("DATA_PATH", "/tmp/factotum"),
	}

	server, err := NewServer(cfg)
	if err != nil {
		log.Fatalf("failed to create server: %v", err)
	}

	if err := server.Run(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
