package vfs

import (
	"log"
	"net"
)

// StartServer starts the VFS 9P server on the given address.
func StartServer(addr string, root string, trustedKey string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("VFS listening on %s, root=%s", addr, root)

	backend, err := NewLocalBackend(root)
	if err != nil {
		return err
	}

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}

		session := NewSession(conn, backend, trustedKey)
		go session.Serve()
	}
}
