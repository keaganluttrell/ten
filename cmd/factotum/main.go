package main

import (
	"flag"
	"log"
	"os"

	"github.com/keaganluttrell/ten/factotum"
)

func main() {
	addr := flag.String("addr", ":9003", "Address to listen on")
	data := flag.String("data", "/priv/factotum", "Path to data directory")
	vfsAddr := flag.String("vfs", "vfs:9002", "Address of VFS service")
	flag.Parse()

	// Env fallback
	if v := os.Getenv("LISTEN_ADDR"); v != "" && !isFlagPassed("addr") {
		*addr = v
	}
	if v := os.Getenv("DATA_ROOT"); v != "" && !isFlagPassed("data") {
		*data = v
	}
	if v := os.Getenv("VFS_ADDR"); v != "" && !isFlagPassed("vfs") {
		*vfsAddr = v
	}

	if err := factotum.StartServer(*addr, *data, *vfsAddr); err != nil {
		log.Fatalf("Server failed: %v", err)
	}
}

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}
