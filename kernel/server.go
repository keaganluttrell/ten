package kernel

import (
	"crypto/ed25519"
	"encoding/base64"
	"log"
	"net/http"
	"os"
)

// StartServer starts the Kernel WebSocket server.
func StartServer(listenAddr, vfsAddr, keyPath string) error {
	pubKey := loadPublicKey(keyPath)
	host, err := LoadHostIdentity()
	if err != nil {
		log.Printf("Warning: Failed to load Host Identity: %v. Bootstrapping will invoke Tauth failure handling.", err)
	}

	log.Printf("Kernel listening on %s", listenAddr)
	log.Printf("Bootstrap VFS at %s", vfsAddr)

	mux := http.NewServeMux()
	mux.HandleFunc("/9p", func(w http.ResponseWriter, r *http.Request) {
		sock, err := Upgrade(w, r)
		if err != nil {
			log.Printf("Upgrade failed: %v", err)
			return
		}

		sess := NewSession(sock, vfsAddr, pubKey, host, NetworkDialer{})
		go sess.Serve()
	})

	return http.ListenAndServe(listenAddr, mux)
}

func loadPublicKey(path string) ed25519.PublicKey {
	if val := os.Getenv("SIGNING_KEY_BASE64"); val != "" {
		b, _ := base64.StdEncoding.DecodeString(val)
		return ed25519.PublicKey(b)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		log.Printf("Warning: failed to load signing key from %s: %v. Validation will fail.", path, err)
		return nil
	}

	b, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		log.Printf("Warning: invalid base64 key in %s", path)
		return nil
	}

	return ed25519.PublicKey(b)
}
