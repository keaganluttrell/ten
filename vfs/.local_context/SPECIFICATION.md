# Specification: VFS-Service (SeaweedFS Gateway)

## Inherited Context
From Root `SPECIFICATION.md`: The VFS-Service is a standalone 9P Server that abstracts SeaweedFS from the Kernel.

## Role in Project Ten
VFS-Service is the **File Server**. It:
*   Serves the file tree via 9P.
*   Abstracts SeaweedFS (the Kernel doesn't know the backend).
*   Provides per-file version history via S3 Versioning.
*   Enables real-time directory watching via NATS subscription.

---

## File Tree Structure

VFS-Service exposes the following tree:

| Path | Purpose |
| :--- | :--- |
| `/data/` | User files. The main content tree. |
| `/lib/` | System files: `/lib/namespace`, `/lib/templates/`. |
| `/priv/` | Private files: `/priv/factotum/`, `/priv/sessions/`. |
| `/hist/` | Version history. Mirrors `/data/` with version data. |

All paths are served directly from SeaweedFS via FUSE mount or S3 API.

---

## 9P File Interface

VFS-Service implements the full 9P2000 protocol:

| Operation | Behavior |
| :--- | :--- |
| `Twalk` | Navigate tree. Maps to SeaweedFS path. |
| `Topen` | Open file/directory for read or write. |
| `Tread` | Read file content or directory listing. **Blocks on directories until change.** |
| `Twrite` | Write to file. Creates new version (S3 Versioning). |
| `Tstat` | Return file/directory metadata. |
| `Tcreate` | Create new file. |
| `Tremove` | Delete file (soft delete if versioning enabled). |
| `Tclunk` | Close FID. Cleans up pending reads. |
| `Tflush` | Cancel pending request by tag. |

---

## Real-Time Directory Watching

VFS-Service enables real-time updates via **blocking Tread**.

### How It Works
1.  Browser sends `Tread` on a directory.
2.  VFS-Service returns current listing **and holds the read** (pending).
3.  VFS-Service subscribes to NATS for events matching that directory.
4.  When SeaweedFS Filer publishes a change event → VFS-Service unblocks the next read.
5.  Browser sends another `Tread` → gets updated listing.

**All directory reads block until content changes or client disconnects.** This is the blocking read pattern.

### NATS Role
*   **SeaweedFS Filer** → Publishes events to NATS (built-in feature).
*   **VFS-Service** → Subscribes to NATS. Matches events to pending reads.

VFS-Service does **NOT** publish to NATS. It only subscribes.

---

## History (Parallel `/hist/` Tree)

VFS-Service exposes version history via a parallel namespace:

| Path | Purpose |
| :--- | :--- |
| `/data/blog/post` | Current content. |
| `/hist/data/blog/post` | Directory listing of version IDs. |
| `/hist/data/blog/post/v123` | Content of version `v123`. |

### How It Works
*   `/hist/` mirrors `/data/` but returns version data instead of current data.
*   `Twalk /hist/data/blog/post` → Returns directory of version IDs.
*   `Tread /hist/data/blog/post/v123` → Returns content of that version.

### Permissions
History inherits permissions from the canonical path:
*   If you can read `/data/blog/post`, you can read `/hist/data/blog/post`.

### Implementation
VFS-Service detects `/hist/` prefix and routes to S3 `ListObjectVersions` / `GetObject(versionId)`.

---

## Configuration

| Variable | Purpose |
| :--- | :--- |
| `LISTEN_ADDR` | TCP listen address (e.g., `:9002`). |
| `SEAWEED_FILER` | SeaweedFS Filer address (e.g., `filer:8888`). |
| `NATS_URL` | NATS server address (e.g., `nats://nats:4222`). |
| `MOUNT_PATH` | Local FUSE mount path (e.g., `/mnt/seaweed`). |

---

## Error Handling

| Error | Response |
| :--- | :--- |
| File not found | `Rerror { ename="file_not_found" }` |
| Permission denied | `Rerror { ename="permission_denied" }` |
| SeaweedFS unavailable | `Rerror { ename="backend_unavailable" }` |
| NATS unavailable | Watch degrades to poll (no blocking). |

---

## Inputs
*   **9P Packets**: From Kernel, SSR, Factotum (TCP).

## Outputs
*   **9P Responses**: File data, directory listings.

## Dependencies
*   **External**: SeaweedFS Binary (`weed filer`, `weed mount`).
*   **External**: NATS Server (for directory watching).
*   **Internal**: `pkg/9p` (Protocol).

## Constraints
1.  **No Business Logic**: Serves files as-is. Does not interpret content.
2.  **S3 Versioning**: All buckets MUST have Object Versioning enabled.
3.  **Stateless**: Pending reads are in-memory. Restart clears them.

---

## Inner Modules
*   `main.go`: 9P Server loop (listens on TCP).
*   `fs.go`: 9P handlers (Twalk, Tread, Twrite, etc.).
*   `seaweed.go`: SeaweedFS client (FUSE or S3 API).
*   `watch.go`: NATS subscription and pending read management.
*   `version.go`: S3 version history queries.
