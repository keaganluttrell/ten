package main

import (
	"log"
	"os"

	"github.com/keaganluttrell/ten/ssr"
)

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":9001"
	}

	vfsAddr := os.Getenv("VFS_ADDR")
	if vfsAddr == "" {
		vfsAddr = "vfs-service:9002"
	}

	if err := ssr.StartServer(addr, vfsAddr); err != nil {
		log.Fatal(err)
	}
}
