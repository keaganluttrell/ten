#!/bin/sh
set -e

# Only perform mount if we are the VFS service
if [ "$SERVICE" = "vfs" ]; then
    echo "Starting SeaweedFS FUSE Mount..."
    
    # Create mount point
    mkdir -p /data
    
    # Ensure FUSE device is available
    if [ ! -e /dev/fuse ]; then
        echo "Error: /dev/fuse not found. container needs --privileged or --device /dev/fuse"
        exit 1
    fi

    # Start weed mount in background
    # -dir: where to mount
    # -filer: address of filer
    # -filer.path: mount specific bucket or root? Root (/) is fine.
    weed mount -dir=/data -filer="seaweedfs:8888" -filer.path="/" &
    
    # Wait for mount to be ready
    echo "Waiting for mount /data..."
    timeout=60
    while ! mountpoint -q /data && [ $timeout -gt 0 ]; do
        sleep 1
        timeout=$((timeout - 1))
    done
    
    if [ $timeout -eq 0 ]; then
        echo "Warning: Mount check timed out. Attempting setup anyway..."
    else
        echo "SeaweedFS mounted at /data."
    fi

    # Create bucket directory if it doesn't exist (Best Effort)
    if mkdir -p /data/ten; then
         echo "Ensured /data/ten exists."
    else
         echo "Warning: Failed to create /data/ten"
    fi

    # Populate SeaweedFS from local seed (mounted at /import)
    if [ -d "/import" ]; then
        echo "Populating /data/ten/vfs with content from /import..."
        mkdir -p /data/ten/vfs
        cp -rn /import/* /data/ten/vfs/
        # Ensure required directories exist (cp -rn skips empty dirs)
        mkdir -p /data/ten/vfs/adm/sessions
        echo "Population complete."
    fi
fi

# Exec the Go Binary
exec /service
