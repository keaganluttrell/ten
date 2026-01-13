package main

import (
	"log"
	"os"

	"github.com/keaganluttrell/ten/kernel"
)

func main() {
	listenAddr := getEnv("LISTEN_ADDR", ":8080")
	vfsAddr := getEnv("VFS_ADDR", "vfs-service:9002")
	keyPath := getEnv("SIGNING_KEY_PATH", "/priv/factotum/signing.key")

	if err := kernel.StartServer(listenAddr, vfsAddr, keyPath); err != nil {
		log.Fatal(err)
	}
}

func getEnv(key, def string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return def
}
