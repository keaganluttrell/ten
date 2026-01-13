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
    +----v-   |   -v----+
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

### 1. Main / Listener (`main.go`)
- **Responsibility**: Loads config, starts WebSocket server (`http.ListenAndServe`).
- **Loop**: Upgrades connection, spawns `Session.Serve()`.

### 2. Session (`session.go`)
- **Responsibility**: Manages state for one client connection.
- **State**:
    - `ws`: WebSocket connection.
    - `ns`: `Namespace` struct (Mount table).
    - `fids`: Map of local FIDs to `Namespace` resources.
- **Protocol Loop**:
    - Reads WS message -> Decodes `Fcall`.
    - Handles `Tversion` (Negotiates msize).
    - Handles `Tattach`:
        - If `aname` is empty -> **Bootstrap Mode** (Mounts only Factotum).
        - If `aname` is ticket -> **Full Mode** (Validates ticket, Builds Namespace).
    - Handles other requests -> Forwards to `ns.Route(path)`.

### 3. Namespace (`namespace.go`)
- **Responsibility**: Map logical paths to backend services.
- **Structure**: Trie or Map of prefix -> `Client`.
- **Logic**:
    - `Build(dialer)`: Fetches `/lib/namespace` from VFS, parses `mount` commands, dials services.
    - `Route(path)`: Finds longest matching prefix, returns `Client` and `RelativePath`.

### 4. Ticket Validation (`ticket.go`)
- **Responsibility**: Verify session tickets.
- **Process**:
    - `ValidateTicket(path, dialer)`:
        - Dials VFS.
        - Reads ticket file content.
        - Parses User, Expiry, Signature.
        - Verifies Ed25519 signature using Public Key.

### 5. Client / Dialer (`client.go`)
- **Responsibility**: Manage TCP connections to backends.
- **Abstraction**: `Dialer` interface for testing (injecting mocks).

## Data Flow

### Connection Setup
1. Browser connects via WebSocket.
2. Kernel accepts, creates `Session`.
3. Browser sends `Tversion`. Kernel replies `Rversion`.

### Bootstrap (No Ticket)
1. Browser sends `Tattach` (aname="").
2. Kernel creates Request-Specific Namespace: `/dev/factotum` -> `FactotumService`.
3. Browser talks to Factotum to authenticate.

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
- `pkg/9p`
- `golang.org/x/net/websocket` (or `github.com/coder/websocket`)
- `crypto/ed25519`
