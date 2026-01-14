#!/bin/bash
set -e

# Configuration
DATA_DIR=".data"
VFS_DIR="$DATA_DIR/vfs"
FACTOTUM_DIR="$DATA_DIR/factotum"
KEYS_DIR="$DATA_DIR/keys"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[DEV]${NC} $1"
}

error() {
    echo -e "${RED}[ERR]${NC} $1"
    exit 1
}

setup_dirs() {
    mkdir -p "$VFS_DIR" "$FACTOTUM_DIR" "$KEYS_DIR"
    mkdir -p "$VFS_DIR/lib" "$VFS_DIR/dev/sys"
}

generate_keys() {
    if [ ! -f "$KEYS_DIR/host.key" ] || [ ! -f "$KEYS_DIR/signing.key" ]; then
        log "Generating keys..."
        cat > "$DATA_DIR/keygen.go" <<EOF
package main
import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)
func main() {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	os.WriteFile("$KEYS_DIR/host.key", []byte(base64.StdEncoding.EncodeToString(priv)), 0600)
    os.WriteFile("$KEYS_DIR/host.pub", []byte(base64.StdEncoding.EncodeToString(pub)), 0644)
    
    pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
    os.WriteFile("$KEYS_DIR/signing.key", []byte(base64.StdEncoding.EncodeToString(priv2)), 0600)
    os.WriteFile("$KEYS_DIR/signing.pub", []byte(base64.StdEncoding.EncodeToString(pub2)), 0644)
    
    fmt.Println("Keys generated")
}
EOF
        go run "$DATA_DIR/keygen.go"
        rm "$DATA_DIR/keygen.go"
    fi
}

start_services() {
    export HOST_KEY_BASE64=$(cat "$KEYS_DIR/host.key")
    export SIGNING_KEY_BASE64=$(cat "$KEYS_DIR/signing.key")
    export TRUSTED_HOST_KEY=$(cat "$KEYS_DIR/host.pub")

    log "Starting VFS on :9001..."
    ./bin/vfs \
        -addr :9001 \
        -root "$VFS_DIR" \
        -auth "$TRUSTED_HOST_KEY" &
    VFS_PID=$!

    log "Starting Factotum on :9002..."
    ./bin/factotum \
        -addr :9002 \
        -data "$FACTOTUM_DIR" \
        -vfs "tcp!localhost:9001" &
    FACT_PID=$!

    # Create namespace manifest
    echo "mount / tcp!localhost:9001" > "$VFS_DIR/lib/namespace"
    echo "mount -b /dev/factotum tcp!localhost:9002" >> "$VFS_DIR/lib/namespace"

    echo "mount /proc tcp!localhost:9004" >> "$VFS_DIR/lib/namespace"

    # Wait for services to be ready
    sleep 1

    log "Starting Kernel on :9000..."
    ./bin/kernel \
        -addr :9000 \
        -vfs "tcp!localhost:9001" \
        -env "dev" &
    KERNEL_PID=$!
    
    sleep 1
}

cleanup() {
    log "Shutting down..."
    kill $VFS_PID $FACT_PID $KERNEL_PID 2>/dev/null || true
    wait
}

trap cleanup EXIT

setup_dirs
generate_keys
start_services

log "System Ready."
log "Use './bin/rc' to connect."
log "Press Ctrl+C to stop."

wait
