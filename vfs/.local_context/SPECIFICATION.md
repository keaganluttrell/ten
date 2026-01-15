# Specification: VFS-Service

## Inherited Context
From Root `SPECIFICATION.md`: The VFS-Service is a standalone 9P Server that abstracts SeaweedFS from the Kernel.

## Role in Project Ten
VFS-Service is the **File Server**. It:
*   Serves the file tree via 9P.
*   Abstracts SeaweedFS via FUSE mount (the Kernel doesn't know the backend).
*   Authenticates privileged clients (kernel, host, adm) via Ed25519 challenge-response.

---

## File Tree Structure

VFS-Service exposes the following tree:

| Path | Purpose |
| :--- | :--- |
| `/adm/` | Admin data: `/adm/users`, `/adm/factotum/`, `/adm/sessions/`. |
| `/lib/` | System files: `/lib/namespace`. |

All paths are served from the local filesystem (FUSE-mounted SeaweedFS in production).

---

## 9P File Interface

VFS-Service implements the 9P2000 protocol:

| Operation | Behavior |
| :--- | :--- |
| `Tversion` | Negotiate msize and protocol version. |
| `Tauth` | Host authentication via Ed25519 nonce challenge. |
| `Tattach` | Attach to root. Privileged users require successful Tauth. |
| `Twalk` | Navigate tree. Maps to local filesystem path. |
| `Topen` | Open file/directory for read or write. |
| `Tread` | Read file content or directory listing. |
| `Twrite` | Write to file or auth signature. |
| `Tstat` | Return file/directory metadata. |
| `Twstat` | Modify file metadata (rename, chmod, truncate). |
| `Tcreate` | Create new file or directory. |
| `Tremove` | Delete file. |
| `Tclunk` | Close FID. |
| `Tflush` | Cancel pending request by tag. *(Future)* |

---

## Host Authentication

VFS enforces authentication for privileged users (`kernel`, `host`, `adm`):

1. Client sends `Tauth(uname)`.
2. VFS generates 32-byte nonce, returns `Rauth(qid)`.
3. Client reads nonce via `Tread(afid)`.
4. Client signs nonce with Ed25519 private key.
5. Client writes signature via `Twrite(afid)`.
6. VFS verifies against `TRUSTED_KEY`. If valid, marks afid as authenticated.
7. Client sends `Tattach(afid)` - VFS checks afid is authenticated.

Non-privileged users can attach without authentication.

---

## Configuration

| Variable | Purpose |
| :--- | :--- |
| `ADDR` | TCP listen address (e.g., `:9001`). |
| `DATA_ROOT` | Root filesystem path (e.g., `/data/ten/vfs`). |
| `TRUSTED_KEY` | Base64-encoded Ed25519 public key for host auth. |

---

## Error Handling

| Error | Response |
| :--- | :--- |
| File not found | `Rerror { ename="..." }` (OS error) |
| Permission denied | `Rerror { ename="permission denied" }` |
| Auth required | `Rerror { ename="auth_required" }` |
| Auth failed | `Rerror { ename="auth_failed" }` |

---

## Dependencies
*   **External**: SeaweedFS FUSE mount (production).
*   **Internal**: `pkg/9p` (Protocol).

## Constraints
1.  **No Business Logic**: Serves files as-is. Does not interpret content.
2.  **Stateless**: Restart clears all session state.

---

## Code Structure

> **Locality of Behavior**: All VFS logic is consolidated into `vfs.go`.

*   `vfs.go`: Server, Session, Backend interface, LocalBackend, 9P handlers.
*   `cmd/vfs/main.go`: Entry point, loads config, calls `StartServer()`.

---

## Future Features

### Blocking Directory Reads
Directory `Tread` will block until content changes, enabling real-time updates without polling.

### Version History (`/n/` namespace)
Following Plan 9 conventions, version history will be exposed via the `/n/` namespace:
*   `/n/dump/YYYY/MMDD/...` - Snapshot at date.
*   Mirrors the main tree but returns historical data.

### Tflush Handler
Cancel pending (blocked) requests by tag.
