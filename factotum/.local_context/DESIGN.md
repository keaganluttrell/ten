# Design: Factotum

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        Factotum                             │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  main.go                                                    │
│  ┌─────────────────────────────────────────────────────┐   │
│  │  TCP Listener (:9003)                               │   │
│  │  └─ Accept → goroutine per connection               │   │
│  │     └─ 9P Server Loop (pkg/9p)                      │   │
│  └─────────────────────────────────────────────────────┘   │
│                           │                                 │
│           ┌───────────────┼───────────────┐                 │
│           ▼               ▼               ▼                 │
│      ┌─────────┐    ┌─────────┐    ┌─────────┐             │
│      │  /rpc   │    │  /ctl   │    │ /proto  │             │
│      │ rpc.go  │    │ ctl.go  │    │ proto.go│             │
│      └────┬────┘    └────┬────┘    └─────────┘             │
│           │              │                                  │
│           ▼              ▼                                  │
│      ┌──────────────────────────────────┐                  │
│      │         webauthn.go              │                  │
│      │  - BeginRegistration()           │                  │
│      │  - FinishRegistration()          │                  │
│      │  - BeginLogin()                  │                  │
│      │  - FinishLogin()                 │                  │
│      └──────────────────────────────────┘                  │
│                     │                                       │
│           ┌─────────┴─────────┐                            │
│           ▼                   ▼                            │
│      ┌──────────┐       ┌──────────┐                       │
│      │keyring.go│       │ticket.go │                       │
│      │ Load/Save│       │ Generate │                       │
│      │ PubKeys  │       │ Sign     │                       │
│      └────┬─────┘       └────┬─────┘                       │
│           │                  │                              │
│           └────────┬─────────┘                             │
│                    ▼                                        │
│           ┌────────────────┐                               │
│           │  VFS (9P)      │                               │
│           │ /priv/factotum │                               │
│           │ /priv/sessions │                               │
│           └────────────────┘                               │
└─────────────────────────────────────────────────────────────┘
```

---

## Module Interactions

### Request Flow: Registration

```
Browser → Kernel → Factotum

1. Topen /dev/factotum/rpc (fid=1)
2. Twrite fid=1 "start proto=webauthn role=register user=alice"
   → rpc.go: creates session, calls webauthn.BeginRegistration()
   → stores challenge in RAM (map[fid]*Session)
3. Tread fid=1
   → returns "challenge <base64>"
4. Twrite fid=1 "<base64-attestation>"
   → rpc.go: calls webauthn.FinishRegistration()
   → keyring.go: writes pubkey to VFS /priv/factotum/alice/pubkey
   → ticket.go: generates and signs ticket
   → writes ticket to VFS /priv/sessions/alice/<nonce>
5. Tread fid=1
   → returns "ok ticket=/priv/sessions/alice/<nonce>"
6. Tclunk fid=1
   → rpc.go: cleans up session
```

### Request Flow: Authentication

```
1. Twrite "start proto=webauthn role=auth user=alice"
   → keyring.go: loads pubkey from VFS /priv/factotum/alice/pubkey
   → webauthn.BeginLogin()
2. Tread → "challenge <base64>"
3. Twrite "<base64-assertion>"
   → webauthn.FinishLogin() (verifies signature)
   → ticket.go: generates ticket
4. Tread → "ok ticket=/priv/sessions/alice/<nonce>"
```

---

## Data Structures

### Session (RAM only)

```go
type Sessions struct {
    mu   sync.Mutex
    data map[uint32]*Session  // keyed by FID
}

type Session struct {
    FID       uint32
    User      string
    Role      string          // "register" | "auth"
    State     string          // "start" | "challenged" | "done"
    Challenge []byte          // ephemeral, never persisted
    WebAuthn  *webauthn.SessionData
}
```

**Concurrency:** `sync.Mutex` protects the session map. One lock for all sessions.

### Ticket (Persisted to VFS)

**Format:** Space-delimited, one line.
```text
<user> <expiry> <nonce> <sig>
```

**Example:**
```text
alice 1736723456 abc123 ZWQ...base64...==
```

```go
type Ticket struct {
    User   string
    Expiry time.Time
    Nonce  string
    Sig    string  // base64(ed25519.Sign(user+expiry+nonce))
}

// Parse
func ParseTicket(line string) (Ticket, error) {
    fields := strings.Fields(line)
    if len(fields) != 4 {
        return Ticket{}, errors.New("invalid ticket format")
    }
    expiry, _ := strconv.ParseInt(fields[1], 10, 64)
    return Ticket{
        User:   fields[0],
        Expiry: time.Unix(expiry, 0),
        Nonce:  fields[2],
        Sig:    fields[3],
    }, nil
}

// Generate
func (t Ticket) String() string {
    return fmt.Sprintf("%s %d %s %s", t.User, t.Expiry.Unix(), t.Nonce, t.Sig)
}
```

---

## Key Files

| Module | Key Types/Functions |
| :--- | :--- |
| `main.go` | `main()`, `handleConn()`, 9P dispatch |
| `rpc.go` | `RPCOpen()`, `RPCWrite()`, `RPCRead()`, session map |
| `ctl.go` | `CtlWrite()` — parses `key` and `delkey` commands |
| `proto.go` | `ProtoRead()` — returns `"webauthn\n"` |
| `webauthn.go` | Wraps `go-webauthn/webauthn` library |
| `keyring.go` | `LoadKey()`, `SaveKey()`, `DeleteKey()` — 9P client to VFS |
| `ticket.go` | `Generate()`, `Sign()`, `Write()` — 9P client to VFS |

---

## Startup Sequence

```go
func main() {
    // 1. Load config (LISTEN_ADDR, VFS_ADDR)
    // 2. Load signing key from VFS (/priv/factotum/signing.key)
    //    - If not exists, generate and save
    // 3. Start TCP listener
    // 4. Start ticket pruning goroutine
    // 5. Accept loop → spawn handleConn()
}
```

---

## Dependencies

| Dependency | Purpose |
| :--- | :--- |
| `pkg/9p` | 9P protocol encoding/decoding |
| `github.com/go-webauthn/webauthn` | FIDO2/WebAuthn logic |
| `crypto/ed25519` | Ticket signing |
| `encoding/base64` | COSE key and attestation encoding |

---

## Next Steps

1. Implement `main.go` — TCP listener and 9P dispatch.
2. Implement `keyring.go` — 9P client to VFS for key storage.
3. Implement `ticket.go` — Ticket generation and signing.
4. Implement `webauthn.go` — Wrap go-webauthn library.
5. Implement `rpc.go` — State machine for auth sessions.
6. Implement `ctl.go` — Key management commands.
7. Implement `proto.go` — Already scaffolded (trivial).
