package main

import (
	"flag"
	"log"
	"os"

	"github.com/keaganluttrell/ten/kernel"
)

func main() {
	// Address Flags
	addr := flag.String("addr", ":8080", "Address to listen on")
	vfsAddr := flag.String("vfs", "vfs-service:9002", "Address of VFS service")
	wsAddr := flag.String("ws", ":9009", "Address for WebSocket listener (Env: WS_ADDR)")
	keyPath := flag.String("key", "/adm/factotum/signing.key", "Path to signing key")

	// env is passed but StartServer signature might not take it? Checking main.go signature, it takes 3 args.
	// Check dev.sh: uses -env "dev".
	// We need to see if kernel.StartServer accepts env.
	// Step 1509 view showed: StartServer(listenAddr, vfsAddr, keyPath)
	// It doesn't take env. dev.sh passed it.
	// Let's add the flag but ignore it if unused, or check if StartServer needs update?
	// Phase 1 roadmap said no env switching yet.
	// We will parse it to avoid errors but ignore it for now.
	_ = flag.String("env", "dev", "Environment (ignored)")

	flag.Parse()

	// Env fallback
	if v := os.Getenv("ADDR"); v != "" && !isFlagPassed("addr") {
		*addr = v
	}
	if v := os.Getenv("VFS_ADDR"); v != "" && !isFlagPassed("vfs") {
		*vfsAddr = v
	}
	if v := os.Getenv("WS_ADDR"); v != "" && !isFlagPassed("ws") {
		*wsAddr = v
	}
	if v := os.Getenv("SIGNING_KEY_PATH"); v != "" && !isFlagPassed("key") {
		*keyPath = v
	}

	if err := kernel.StartServer(*addr, *vfsAddr, *wsAddr, *keyPath); err != nil {
		log.Fatal(err)
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
