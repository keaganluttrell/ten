# Specification: Factotum

## Inherited Context
From Root `SPECIFICATION.md`: Factotum is the Authentication Agent. It is a standalone 9P Server that manages user identity and performs WebAuthn ceremonies on behalf of the Kernel.

## Role in Project Ten
Factotum is the **only** component that understands authentication. The Kernel is blind to auth logic; it simply proxies 9P packets to Factotum. The Browser (Terminal) initiates the WebAuthn ceremony by writing to Factotum's files.

---

## File Interface (9P Server)

Factotum exposes three virtual files:

### `/rpc` — The Conversation File
*   **Purpose**: Stateful authentication dialogue.
*   **Semantics**: Each open FID represents one auth session.
*   **Operations**:
    *   `Twrite`: Send a command.
    *   `Tread`: Receive a response.

### `/ctl` — The Control File
*   **Purpose**: Key management (admin only).
*   **Commands**:
    *   `key proto=webauthn user=<userid> cose=<base64-cose-key>` — Register WebAuthn public key.
    *   `key proto=ssh user=<userid> <ssh-pubkey-text>` — Register SSH public key (as-is).
    *   `delkey user=<userid>` — Remove a user's keys.
*   **Key Format**:
    *   **SSH/PGP**: Send the `.pub` file content verbatim. It's already text.
    *   **WebAuthn**: The COSE key is binary; prefix with `cose=` and base64-encode.

### `/proto` — The Protocol List
*   **Purpose**: Advertise supported auth protocols.
*   **Semantics**: Read-only. Returns `webauthn\n`.

---

## Response Format

All responses follow Plan 9's simple text protocol:

### Success
```text
ok [<key>=<value> ...]
```
Examples:
*   `ok`
*   `ok ticket=/priv/sessions/alice/abc123`

### Error
```text
error <message>
```
Examples:
*   `error invalid_signature`
*   `error user_not_found`
*   `error challenge_expired`

---

## Session Model (File-Based Ticket)

Plan 9 uses file descriptors as sessions. The Web requires persistence across TCP disconnects. We compromise with a **File-Based Ticket**.

### The Flow
1.  Browser completes WebAuthn ceremony via `/rpc`.
2.  Factotum generates a signed ticket (userid, expiry, signature).
3.  Factotum writes ticket to VFS: `/priv/sessions/<userid>/<nonce>`.
4.  Factotum returns ticket path to Browser.
5.  Browser stores ticket in **OPFS**: `/lib/ticket`.
6.  On reconnect, Browser sends `Tattach` with `aname=<ticket-path>`.
7.  **Kernel validates ticket** (reads from VFS, verifies signature and TTL).
8.  Connection is attached as user.

### Ticket Format
Space-delimited, one line:
```text
<user> <expiry> <nonce> <sig>
```
*   `user`: User ID (no spaces).
*   `expiry`: Unix timestamp (seconds).
*   `nonce`: Random identifier for this ticket.
*   `sig`: Base64-encoded Ed25519 signature of `user+expiry+nonce`.

**Example:**
```text
alice 1736723456 abc123 ZWQ...base64...==
```

### Ticket Validation (Kernel Responsibility)
The Kernel validates tickets as a **mechanism**, not policy:
*   Read ticket file from VFS-Service.
*   Verify signature using Factotum's public signing key.
*   Check TTL has not expired.
*   This is analogous to checking file permissions — pure mechanism.

### Why This is Plan 9
*   The ticket is a **file**, not a magic header.
*   Server writes to VFS. Browser reads from OPFS. Separation of concerns.
*   No cookies, no JWTs in HTTP headers. Just paths and files.

---

## Registration & Auto-Authentication

**Design Decision**: Registration automatically authenticates the user.

### Rationale
*   UX: Users expect to be "logged in" after creating an account.
*   Security: The WebAuthn attestation proves possession of the private key.
*   Simplicity: Avoids a redundant auth step immediately after registration.

### Flow
```text
# Registration completes
Rread /rpc: "ok ticket=/priv/sessions/alice/abc123"
# User is now authenticated. No separate auth step required.
```

---

## Ticket TTL & Cleanup

### TTL Enforcement
*   Tickets contain an `expiry` timestamp (e.g., 7 days from creation).
*   **Validation on Read**: Kernel checks TTL when ticket is presented.
*   Expired tickets return `Rerror: ticket_expired`.

### Cleanup Strategy
*   **Lazy Deletion**: Expired tickets are deleted when validation fails.
*   **Periodic Pruning**: Factotum runs a background goroutine that scans `/priv/sessions/` and deletes tickets past expiry (e.g., every hour).

---

## WebAuthn Protocol (Text-Based RPC)

### Registration (New User)
```text
Twrite /rpc: "start proto=webauthn role=register user=alice"
Rread  /rpc: "challenge <base64-challenge>"

# Browser performs navigator.credentials.create()

Twrite /rpc: "write <base64-attestation>"
Rread  /rpc: "ok ticket=/priv/sessions/alice/abc123"
# User is now authenticated.
```

### Authentication (Existing User)
```text
Twrite /rpc: "start proto=webauthn role=auth user=alice"
Rread  /rpc: "challenge <base64-challenge>"

# Browser performs navigator.credentials.get()

Twrite /rpc: "write <base64-assertion>"
Rread  /rpc: "ok ticket=/priv/sessions/alice/def456"
```

### Reconnect (Returning User)
```text
# Browser reads /lib/ticket from OPFS
# Browser sends Tattach with aname="/priv/sessions/alice/def456"
# Kernel validates ticket, attaches session as "alice"
```

---

## Client-Side Storage (Browser Terminal)

The Browser uses **Origin Private File System (OPFS)** for local persistence.

### File Structure
```text
Browser OPFS Root
└── lib/
    └── ticket        <-- ticket path + content
```

### API (JS Client)
```javascript
// Write ticket after auth
const root = await navigator.storage.getDirectory();
const lib = await root.getDirectoryHandle('lib', { create: true });
const file = await lib.getFileHandle('ticket', { create: true });
const writable = await file.createWritable();
await writable.write(ticketData);
await writable.close();

// Read ticket on reconnect
const file = await lib.getFileHandle('ticket');
const data = await (await file.getFile()).text();
```

---

## Server-Side Storage (VFS-Service)

| Data | Location | Persistence |
| :--- | :--- | :--- |
| **Public Keys** | `/priv/factotum/<userid>/pubkey` | Persistent. |
| **Signing Key** | `/priv/factotum/signing.key` | Persistent. Factotum's private key for signing tickets. |
| **Tickets** | `/priv/sessions/<userid>/<nonce>` | Persistent. Pruned by TTL. |
| **Challenges** | RAM only | Ephemeral. Never written to disk. |

---

## Inputs
*   **9P Packets**: From Kernel (TCP).

## Outputs
*   **9P Responses**: Challenges, ticket paths, errors.
*   **Ticket Files**: Written to VFS-Service.

## Dependencies
*   **Internal**: `pkg/9p` (Protocol).
*   **External**: VFS-Service (Dials to read/write keys and tickets).
*   **Library**: `github.com/go-webauthn/webauthn` (FIDO2 logic).

## Constraints
1.  **Never Store User Private Keys**: Private keys live in user's hardware token.
2.  **RAM Secrets**: Challenges must never touch disk.
3.  **Text Protocol**: Commands and responses are UTF-8.
4.  **Stateful FID**: Each `/rpc` open is a separate auth session.
5.  **Ticket Expiry**: Default TTL is 7 days. Configurable.

---

## Inner Modules
*   `main.go`: 9P Server loop (listens on TCP).
*   `rpc.go`: `/rpc` file handler (state machine).
*   `ctl.go`: `/ctl` file handler (key management).
*   `webauthn.go`: FIDO2 verification logic.
*   `keyring.go`: Key loading/searching (Dials VFS-Service).
*   `ticket.go`: Ticket generation, signing, and validation.
