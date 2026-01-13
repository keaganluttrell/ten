package ssr

import (
	"log"
	"net"
)

func StartServer(addr, vfsAddr string) error {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	log.Printf("SSR listening on %s, vfs=%s", addr, vfsAddr)

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}

		session := NewSession(conn, vfsAddr)
		go session.Serve()
	}
}
