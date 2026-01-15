# Design: Factotum

## Architecture Overview

**Principle: Locality of Behavior**
All interactions, state management, and 9P handling live in a single file: `factotum.go`. This reduces context switching and simplifies the mental model.

```
┌─────────────────────────────────────────────────────────────┐
│                   Factotum (factotum.go)                    │
│                                                             │
│   ┌─────────────────────────────────────────────────────┐   │
│   │  TCP Listener (:9003)                               │   │
│   │  └─ Accept → connection loop                        │   │
│   └──────────────────────────┬──────────────────────────┘   │
│                              │                              │
│             ┌────────────────┼────────────────┐             │
│             ▼                ▼                ▼             │
│        [RPC Handler]    [Ctl Handler]   [File System]       │
│        (Auth Logic)     (Key Mgmt)      (9P Dispatch)       │
│             │                │                │             │
│             ▼                ▼                ▼             │
│    [WebAuthn Handler]    [Keyring]        [Sessions]        │
│    (Ceremony Logic)      (Signing)        (State Map)       │
│             │                │                              │
│             └───────┬────────┘                              │
│                     ▼                                       │
│             [9P Client Helper]                              │
│             (Talks to VFS)                                  │
│                     │                                       │
│                     ▼                                       │
│             ┌────────────────┐                              │
│             │  VFS (9P)      │                              │
│             │ /priv/factotum │                              │
│             │ /priv/sessions │                              │
│             └────────────────┘                              │
└─────────────────────────────────────────────────────────────┘
```

---

## Internal Components (Structs)

All components are defined within `factotum.go`.

| Component | Responsibility |
| :--- | :--- |
| `Server` | Main TCP loop, 9P request dispatcher (switch statement). |
| `RPC` | Handles `/rpc` file. Manages the "Start -> Challenge -> Write" state machine. |
| `Ctl` | Handles `/ctl` file. Parses admin commands (`key`, `delkey`). |
| `Keyring` | Manages the Service's Ed25519 signing key and user public keys. |
| `WebAuthnHandler` | Wraps `go-webauthn` library. Performs FIDO2 verification. |
| `CredentialStore` | **VFS Persistence**. Dials VFS to save/load user WebAuthn credentials. |
| `Ticket` | Struct for the auth token. Generates and signs tickets. |
| `Sessions` | Thread-safe map of active FIDs to Auth State. |

---

## Module Interactions

### Request Flow: Registration

```
Browser → Kernel → Factotum

1. Topen /dev/factotum/rpc (fid=1)
2. Twrite fid=1 "start proto=webauthn role=register user=alice"
   → Server dispatches to RPC.handleStart
   → WebAuthnHandler.BeginRegistration
   → Stores challenge in Sessions (RAM)
3. Tread fid=1
   → RPC.Read checks state "challenged"
   → Returns "challenge <base64>"
4. Twrite fid=1 "<base64-attestation>"
   → RPC.handleWrite
   → WebAuthnHandler.FinishRegistration
   → CredentialStore.AddCredential (Dials VFS -> Writes /priv/factotum/alice/creds)
   → Sets Session State = "done"
5. Tread fid=1
   → RPC.Read checks state "done"
   → Ticket.Generate (Signs user+expiry+nonce)
   → RPC.writeTicketToVFS (Dials VFS -> Writes /priv/sessions/alice/<nonce>)
   → Returns "ok ticket=/priv/sessions/alice/<nonce>"
```

### Request Flow: Authentication

```
1. Twrite "start proto=webauthn role=auth user=alice"
   → WebAuthnHandler calls CredentialStore.LoadUser (Dials VFS -> Reads creds)
   → WebAuthnHandler.BeginLogin
2. Tread → "challenge <base64>"
3. Twrite "<base64-assertion>"
   → WebAuthnHandler.FinishLogin
   → Session State = "done"
4. Tread → "ok ticket=/priv/sessions/alice/<nonce>"
```

---

## Data Structures

### Session (RAM only)

```go
type Session struct {
    FID               uint32
    User              string
    Role              string          // "register" | "auth"
    State             string          // "start" | "challenged" | "done"
    SessionData       *webauthn.SessionData
}
```

### Ticket (Persisted to VFS)

**Format:** Space-delimited, one line.
```text
<user> <expiry> <nonce> <sig>
```

---

## Dependencies

| Dependency | Purpose |
| :--- | :--- |
| `pkg/9p` | 9P protocol encoding/decoding |
| `github.com/go-webauthn/webauthn` | FIDO2/WebAuthn logic |
| `crypto/ed25519` | Ticket signing |
| `encoding/base64` | Protocol encoding |

---

## Conformity Checklist

- [x] **Locality of Behavior**: All logic in `factotum.go`.
- [x] **Single Binary/Package**: No sub-packages.
- [x] **Network Transparency**: Credentials and Tickets stored in VFS (via 9P Dial).
- [x] **State Separation**: Sessions are RAM, State is VFS.
