# Build Stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install git for fetching dependencies
RUN apk add --no-cache git

# Cache dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Build the service
# CGO_ENABLED=0 creates a statically linked binary
# -ldflags="-s -w" strips debug information for smaller binaries
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/vfs ./cmd/vfs

# Runtime Stage
FROM alpine:latest

# Install runtime dependencies (FUSE for VFS, CA Certs for purity)
RUN apk add --no-cache fuse ca-certificates

# Copy SeaweedFS binary (needed for 'weed mount' in VFS)
COPY --from=chrislusf/seaweedfs:3.59 /usr/bin/weed /usr/bin/weed

WORKDIR /

COPY --from=builder /bin/vfs /service
COPY vfs/entrypoint.sh /vfs-entrypoint.sh
RUN chmod +x /vfs-entrypoint.sh

# Expose ports
EXPOSE 9001

ENTRYPOINT ["/vfs-entrypoint.sh"]
