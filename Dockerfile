# Build Stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git

# Copy dependency definitions
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build argument to select service (kernel, vfs, ssr, factotum)
ARG SERVICE
RUN if [ -z "$SERVICE" ]; then echo "SERVICE argument not set" && exit 1; fi

# Build the binary
# -ldflags="-s -w" strips debug information for smaller binaries
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /bin/service ./cmd/$SERVICE

# Runtime Stage
FROM scratch

WORKDIR /

COPY --from=builder /bin/service /service

# Expose ports (can be overridden by docker-compose)
EXPOSE 8080 9000 9001 9002

ENTRYPOINT ["/service"]
