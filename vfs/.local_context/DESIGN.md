# Design: VFS-Service

## High Level Diagram

```text
           +-------------+
           | Client      |  (Kernel / SSR)
           +------+------+
                  |
              9P / TCP
                  |
        +---------v---------+
        |   VFS Service     |
        +---------+---------+
                  |
             Abstraction
                  |
        +---------v---------+
        |      Backend      |
        +----+---------+----+
             |         |
      +------v----+ +--v----------+
      | Local Disk| |  SeaweedFS  |
      +-----------+ +-------------+
            (dev)       (FUSE mount)
```

This document outlines the architectural design for the VFS-Service.

## Architecture

The VFS Service is a 9P2000 File Server that abstracts the underlying storage via a `Backend` interface.

> **Note**: All components are consolidated in `vfs/vfs.go` following Locality of Behavior.

## Components

### 1. Server
- **Function**: `StartServer(addr, root, trustedKey)`
- Listens on TCP, spawns Session goroutine per connection.

### 2. Session
- **State**:
    - `conn`: Network connection.
    - `backend`: Backend interface.
    - `trustedKey`: Ed25519 public key for host auth.
    - `fids`: Map of FID → `*Fid`.
    - `mu`: Mutex for thread safety.
- **Lifecycle**:
    - `Tversion`: Negotiate protocol.
    - `Tauth`: (Privileged users) Generate nonce, verify signature.
    - `Tattach`: Check auth, stat root, create FID.
    - `Twalk`/`Topen`/`Tread`/`Twrite`/`Tclunk`: Standard 9P ops.

### 3. Backend Interface
```go
type Backend interface {
    Stat(path string) (p9.Dir, error)
    List(path string) ([]p9.Dir, error)
    Open(path string, mode uint8) (io.ReadWriteCloser, error)
    Create(path string, perm uint32, mode uint8) (io.ReadWriteCloser, error)
    Remove(path string) error
    Rename(oldPath, newPath string) error
    Chmod(path string, mode uint32) error
    Truncate(path string, size int64) error
}
```

### 4. LocalBackend
- Implements `Backend` using `os` package calls.
- `toLocal(path)`: Maps 9P path to local filesystem path under `Root`.
- Includes directory traversal prevention.

### 5. Fid
```go
type Fid struct {
    Path        string
    File        io.ReadWriteCloser
    Dir         bool
    DirOffset   int
    DirList     []p9.Dir
    // Auth state
    IsAuth      bool
    AuthUser    string
    AuthNonce   []byte
    AuthSuccess bool
}
```

## Request Flow

1. `Serve()` reads 9P message via `p9.ReadFcall()`.
2. Dispatches to `handle(req)`.
3. Switch on `req.Type`:
   - `Tversion`: Return msize, version.
   - `Tauth`: Generate nonce, store in auth Fid.
   - `Tattach`: Check auth (if privileged), stat attach path.
   - `Twalk`: Stat each path element, create new Fid.
   - `Topen`: Open file or list directory.
   - `Tread`: Return file data or encoded Dir entries.
   - `Twrite`: Write to file or verify auth signature.
   - `Twstat`: Rename, chmod, or truncate.
   - `Tclunk`/`Tremove`: Cleanup.
4. Returns `Rerror` on failure.

## Security

- **Privileged users** (`kernel`, `host`, `adm`) require Ed25519 auth.
- **Signature verification** uses `TRUSTED_KEY` environment variable.
- Non-privileged users attach without authentication.

## Dependencies
- `pkg/9p`: 9P protocol encoding/decoding.
- `crypto/ed25519`: Host authentication.

## Future Features
- **Blocking Tread**: Directory reads block until content changes.
- **Tflush**: Cancel pending blocked requests.
- **Version History**: `/n/dump/` namespace for historical snapshots.
