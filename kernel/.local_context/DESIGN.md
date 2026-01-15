# Design: Kernel

## High Level Diagram

```text
       +-------------+
       |   Browser   |
       +------+------+
              |
        WebSocket / 9P
              |
    +---------v---------+
    |      Kernel       |
    | (Namespace Router)|
    +----+----+----+----+
         |    |    |
    +----+    |    +----+
    |         |         |
+---v---+ +---v---+ +---v---+
|  VFS  | |  SSR  | |Factotum|
+-------+ +-------+ +--------+
```

This document outlines the architectural design and implementation details for the Kernel, which acts as the 9P switchboard and session manager for Project Ten.

## Architecture

The Kernel is a WebSocket Termination Proxy that routes 9P requests to backend services based on a per-session namespace.

1.  **Transport**: Receives WebSocket frames containing 9P messages.
2.  **Session**: Validates authentication ticket on `Tattach`.
3.  **Namespace**: Dynamically constructs a mount table from `/lib/namespace` (hosted on VFS).
4.  **Routing**: Forwards 9P requests to the appropriate service (VFS, SSR, Factotum).

## Components

> **Note**: All components are consolidated in `kernel/kernel.go` following Locality of Behavior.

### 1. Entry Point (`cmd/kernel/main.go`)
- **Responsibility**: Loads config from environment, starts TCP and WebSocket servers.
- **Loop**: Accepts connections, spawns `Session.Serve()`.

### 2. Session
- **Responsibility**: Manages state for one client connection.
- **State**:
    - `socket`: MessageTransport (WebSocket or TCP).
    - `ns`: `Namespace` struct (Mount table).
    - `fids`: Map of local FIDs to backend FID references.
    - `user`: Authenticated user name.
- **Protocol Loop**:
    - Reads message -> Decodes `Fcall`.
    - Handles `Tversion` (Negotiates msize).
    - Handles `Tattach`:
        - Fetches `/lib/namespace` from VFS (with Host Auth).
        - If `aname` is empty -> **Bootstrap Mode** (user="none", full namespace).
        - If `aname` is ticket -> **Ticket Mode** (Validates ticket, extracts user).
    - Handles other requests -> Routes via `ns.Route(path)`.

### 3. Namespace
- **Responsibility**: Map logical paths to backend services (Union Mounts).
- **Structure**: Map of mount point -> stack of `mountEntry`.
- **Logic**:
    - `Build(manifest, dialer)`: Parses manifest, dials services, mounts at paths.
    - `Route(path)`: Returns stack of matching backends for union resolution.
    - `Bind(old, new, flags)`: Creates path aliases.

### 4. Host Authentication
- **Responsibility**: Authenticate kernel to VFS using Ed25519 challenge-response.
- **Process**:
    - `LoadHostIdentity()`: Loads `HOST_KEY_BASE64` from environment.
    - `HostAuthHandshake(client, host)`: Tauth -> Read nonce -> Sign -> Write signature.

### 5. Ticket Validation
- **Responsibility**: Verify session tickets.
- **Process**:
    - `ValidateTicket(path, vfsAddr, pubKey, host, dialer)`:
        - Dials VFS with Host Auth.
        - Reads ticket file content.
        - Parses User, Expiry, Nonce, Signature.
        - Verifies Ed25519 signature using `SIGNING_KEY_BASE64`.

### 6. Client / Dialer
- **Responsibility**: Manage TCP connections to backends with retry logic.
- **Abstraction**: `Dialer` interface for testing (injecting mocks).

## Data Flow

### Connection Setup
1. Browser connects via WebSocket.
2. Kernel accepts, creates `Session`.
3. Browser sends `Tversion`. Kernel replies `Rversion`.

### Bootstrap (No Ticket)
1. Browser sends `Tattach` (aname="").
2. Kernel fetches `/lib/namespace` from VFS (using Host Auth).
3. Kernel builds full namespace, sets user to "none".
4. Browser walks to `/dev/factotum/rpc` to authenticate.

### Authenticated Session
1. Browser sends `Tattach` (aname="/priv/sessions/...").
2. Kernel calls `ValidateTicket`.
    - Dials VFS (Bootstrap address).
    - Reads ticket.
    - Verifies signature.
3. If Valid:
    - Kernel calls `ns.Build`.
    - Reads `/lib/namespace` from VFS.
    - Dials all services found (SSR, VFS, etc).
4. Kernel replies `Rattach` (Root Qid).

## Error Handling
- **Ticket Invalid**: Return `Rerror("invalid ticket")`.
- **Service Down**: Return `Rerror("service unavailable")` on `Tattach` or forwarding.

## Security
- **Trust**: Kernel trusts backend services (Internal Network).
- **Client**: Kernel does NOT trust client. Validates all FIDs and Paths.
- **Signature**: Tickets prevent spoofing sessions.

## Dependencies
- `pkg/9p`: 9P protocol encoding/decoding.
- `pkg/resilience`: Retry logic for network dialing.
- `github.com/coder/websocket`: WebSocket handling.
- `crypto/ed25519`: Signature verification and host authentication.
