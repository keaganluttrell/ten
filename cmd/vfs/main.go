package main

import (
	"log"
	"os"

	"github.com/keaganluttrell/ten/vfs"
)

func main() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":9002"
	}

	root := os.Getenv("DATA_ROOT")
	if root == "" {
		root = "/tmp/ten-data"
	}

	trustedKey := os.Getenv("TRUSTED_KEY")

	if err := vfs.StartServer(addr, root, trustedKey); err != nil {
		log.Fatal(err)
	}
}
