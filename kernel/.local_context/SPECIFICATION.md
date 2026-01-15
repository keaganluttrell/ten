# Specification: Kernel

## Inherited Context
From Root `SPECIFICATION.md`: The Kernel is a "Logic Blind" 9P Switchboard. It accepts WebSocket connections and **Dials** backend services (VFS, SSR, Factotum) over TCP.

## Role in Project Ten
The Kernel is the **only** gateway between the Browser (Terminal) and the backend services. It:
*   Terminates WebSocket connections.
*   Translates WebSocket frames to 9P.
*   Constructs per-session namespaces.
*   Validates tickets and attaches sessions.

---

## Inputs
*   **WebSocket Connections**: From Browser Clients (Port 443/8080).
*   **System Signals**: SIGINT/SIGTERM for graceful shutdown.
*   **Config**: Environment variables:
    *   `ADDR`: TCP listen address (default `:9000`).
    *   `WS_ADDR`: WebSocket listen address (default `:9009`).
    *   `VFS_ADDR`: VFS-Service address in Plan 9 dial format (`tcp!vfs!9001`). Required.
    *   `SIGNING_KEY_BASE64`: Base64-encoded Ed25519 public key for ticket verification.
    *   `HOST_KEY_BASE64`: Base64-encoded Ed25519 private key for host authentication with VFS.

## Outputs
*   **9P Packets**: Forwarded to dialed Services.
*   **WebSocket Frames**: 9P Responses sent back to Client.

---

## WebSocket <-> 9P Framing

**Rule: 1 WebSocket Message = 1 9P Fcall.**

*   WebSocket is a **message-based** protocol.
*   Each WebSocket binary message contains exactly one complete 9P message.
*   The first 4 bytes of the 9P message are the size (little-endian), followed by the payload.
*   No additional framing. No streaming partial messages.

### Example
```text
Browser sends: [WebSocket Binary Frame]
  Payload: [4-byte size][9P Tversion message]

Kernel receives: Decode as Fcall, route to service.

Kernel sends: [WebSocket Binary Frame]
  Payload: [4-byte size][9P Rversion message]
```

---

## Connection Lifecycle

### 1. WebSocket Handshake
```text
Browser: GET /9p HTTP/1.1
         Upgrade: websocket
Kernel:  101 Switching Protocols
```

### 2. Tversion (Protocol Negotiation)
```text
Browser: Tversion { msize=65536, version="9P2000" }
Kernel:  Rversion { msize=65536, version="9P2000" }
```

### 3. Tattach (Session Attachment)
```text
Browser: Tattach { fid=0, afid=NOFID, uname="alice", aname="/priv/sessions/alice/abc123" }
Kernel:  [Validates ticket, see below]
         Rattach { qid=<root-qid> }
```

**Note: We skip `Tauth`.** In Plan 9, `afid` references an auth FID from a prior `Tauth` exchange. In Project Ten, the ticket path in `aname` replaces this mechanism. This is a documented deviation for Web simplicity.

---

## First-Time Authentication (No Ticket)

New users have no ticket. They must authenticate before receiving one.

### Bootstrap Namespace (Unauthenticated)
When `Tattach` has no ticket (`aname` is empty or invalid), the Kernel provides a **minimal bootstrap namespace**:

| Path | Target | Access |
| :--- | :--- | :--- |
| `/dev/factotum` | Factotum Service | Write-only (for auth). |

**No access to VFS or SSR.** The user can only interact with Factotum.

### Flow
1.  Browser connects, sends `Tattach { aname="" }`.
2.  Kernel grants bootstrap namespace (Factotum only).
3.  Browser walks to `/dev/factotum/rpc`, completes WebAuthn ceremony.
4.  Factotum returns ticket path.
5.  Browser disconnects, reconnects with `Tattach { aname="/priv/sessions/alice/abc123" }`.
6.  Kernel validates ticket, grants full namespace.

---

## Ticket Validation (On Tattach)

When the Kernel receives `Tattach`:

1.  **Extract ticket path** from `aname` field.
2.  **Dial VFS-Service** and read ticket file.
3.  **Parse ticket** (userid, expiry, signature).
4.  **Verify signature** using Factotum's public signing key (loaded at startup).
5.  **Check TTL**: If expired, return `Rerror { ename="ticket_expired" }`.
6.  **Attach session** as `uname` with access to the constructed namespace.

### On Validation Failure
```text
Kernel: Rerror { ename="invalid_ticket" }
# or
Kernel: Rerror { ename="ticket_expired" }
```

---

## Namespace Construction (Per Session)

After successful `Tattach` with a valid ticket, the Kernel constructs a namespace for the session.

**When is `/lib/namespace` read?**
*   **During bootstrap auth (no ticket)?** No. Only Factotum is mounted.
*   **After successful ticket validation?** Yes. Full namespace is constructed.

### Bootstrap Pattern

The namespace is constructed dynamically from `/lib/namespace`, not hardcoded.

**Step 1: Bootstrap Dial**
*   The Kernel has ONE hardcoded address: `VFS_ADDR` (from environment/config).
*   This is the bootstrap — the Kernel needs VFS to read anything.

**Step 2: Read Manifest**
```text
Kernel: Dial VFS_ADDR
Kernel: Tread /lib/namespace
VFS:    Rread { data="mount / tcp!vfs-service!9002\nmount /dev/factotum tcp!factotum!9003\n..." }
```

**Step 3: Parse & Mount**
*   Parse each line of `/lib/namespace`.
*   Dial and mount each service.

### `/lib/namespace` Format (Plan 9 Style)
```text
# Comments start with #
mount /              tcp!vfs-service!9002
mount /dev/factotum  tcp!factotum!9003
mount /view          tcp!ssr!9004
```

*   `mount <path> <address>`: Dial `address` and mount at `path`.
*   `<address>` format: `tcp!<host>!<port>`

### Why This Matters
*   **Policy in Files**: The Kernel binary doesn't decide what services exist.
*   **Dynamic**: Add a new service by editing `/lib/namespace`, not recompiling.
*   **Per-User Namespaces**: Future support for `/usr/<user>/lib/namespace`.

### Config (Bootstrap Only)
| Variable | Purpose |
| :--- | :--- |
| `VFS_ADDR` | Address of VFS-Service in Plan 9 dial format (`tcp!vfs!9001`). Required. |
| `ADDR` | TCP listen address (e.g., `:9000`). |
| `WS_ADDR` | WebSocket listen address (e.g., `:9009`). |
| `SIGNING_KEY_BASE64` | Base64-encoded Ed25519 public key for ticket verification. |
| `HOST_KEY_BASE64` | Base64-encoded Ed25519 private key for VFS host authentication. |

---

## Request Routing

When the Kernel receives a 9P request (e.g., `Twalk`, `Tread`, `Twrite`):

1.  **Match path** to namespace mount.
2.  **Forward request** to the appropriate backend service.
3.  **Return response** to Browser.

### Example
```text
Browser: Twalk { fid=0, newfid=1, wname=["view", "index.html"] }
Kernel:  [Path "/view" matches SSR mount]
         Forward to SSR: Twalk { fid=0, newfid=1, wname=["index.html"] }
SSR:     Rwalk { wqid=[...] }
Kernel:  Forward to Browser: Rwalk { wqid=[...] }
```

---

## Error Handling

### Dial Failure
If a backend service is unreachable during namespace construction:
```text
Kernel: Rerror { ename="service_unavailable: vfs-service" }
```

### Mid-Session Dial Failure
If a service becomes unreachable during an active session:
```text
Kernel: Rerror { ename="connection_lost: ssr" }
```

### Invalid 9P Message
```text
Kernel: Rerror { ename="protocol_error: malformed fcall" }
```

---

## Dependencies
*   **Internal**: `pkg/9p` (Protocol encoding/decoding).
*   **Standard**: `net/http` (WebSocket upgrade), `net` (TCP Dial), `crypto/ed25519` (Signature verification).

## Constraints
1.  **No Business Logic**: The Kernel does not interpret file contents.
2.  **Stateless**: If the Kernel restarts, all sessions terminate. Clients reconnect with tickets.
3.  **Concurrency**: One goroutine per WebSocket connection.
4.  **No FUSE**: The Kernel dials services over TCP. No local mounts.

---

## Code Structure

> **Locality of Behavior**: All kernel logic is consolidated into `kernel.go`.

*   `kernel.go`: Contains Session, Namespace, Client, Ticket validation, Socket handling.
*   `cmd/kernel/main.go`: Entry point, config loading, starts TCP and WebSocket servers.
