package main

import (
	"flag"
	"log"
	"os"

	"github.com/keaganluttrell/ten/vfs"
)

func main() {
	addr := flag.String("addr", ":9002", "Address to listen on (Env: LISTEN_ADDR)")
	root := flag.String("root", "/tmp/ten-data", "Data root directory (Env: DATA_ROOT)")
	authKey := flag.String("auth", "", "Trusted host public key (Env: TRUSTED_KEY)")
	flag.Parse()

	// Env var override (optional, or prefer flags)
	if v := os.Getenv("LISTEN_ADDR"); v != "" && !isFlagPassed("addr") {
		*addr = v
	}
	if v := os.Getenv("DATA_ROOT"); v != "" && !isFlagPassed("root") {
		*root = v
	}
	if v := os.Getenv("TRUSTED_KEY"); v != "" && !isFlagPassed("auth") {
		*authKey = v
	}

	if err := vfs.StartServer(*addr, *root, *authKey); err != nil {
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
