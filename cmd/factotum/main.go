package main

import (
	"log"
	"os"

	"github.com/keaganluttrell/ten/factotum"
)

func main() {
	addr := getEnv("LISTEN_ADDR", ":9003")
	dataPath := getEnv("DATA_ROOT", "/priv/factotum")
	vfsAddr := getEnv("VFS_ADDR", "vfs:9002")

	if err := factotum.StartServer(addr, dataPath, vfsAddr); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func getEnv(key, defaultVal string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return defaultVal
}
