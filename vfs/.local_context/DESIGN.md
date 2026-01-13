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
        |   VFS Service     | <-----> NATS (Subscription)
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
```

This document outlines the architectural design and implementation details for the VFS-Service, which acts as the primary file server for Project Ten using the 9P2000 protocol.


## Architecture

The VFS Service is a 9P2000 File Server that abstracts the underlying storage (Local or SeaweedFS) via a `Backend` interface.

```mermaid
graph TD
    A[Client (Kernel/SSR)] -- 9P/TCP --> B[vfs.Server]
    B -- Spawn --> C[vfs.Session]
    C -- 9P Request --> D[vfs.Handlers (fs.go)]
    D -- Abstraction --> E[vfs.Backend Interface]
    E -- Impl --> F[LocalBackend / SeaweedBackend]
    F -- I/O --> G[Filesystem / S3]
```

## Components

### 1. Server (`server.go`)
- **Responsibility**: Listens on a TCP port and accepts incoming connections.
- **Loop**: Spawns a new `Session` goroutine for each connection.

### 2. Session (`fs.go`)
- **Responsibility**: Manages the state of a single 9P connection.
- **State**:
    - `conn`: Network connection.
    - `fids`: Map of FID (uint32) to `*Fid` struct.
    - `mu`: Mutex for thread safety.
- **Fid Lifecycle**:
    - Tracks path and open file handles for each client FID.
    - `Tattach` creates Root FID.
    - `Twalk` clones FIDs and navigates paths.
    - `Topen` opens the underlying file/directory.
    - `Tclunk` closes handles and removes FID.

### 3. Backend Interface (`seaweed.go`)
abstracts the storage layer to allow switching between Local FS (for dev/MVP) and SeaweedFS (prod).

```go
type Backend interface {
    Stat(path string) (p9.Dir, error)
    List(path string) ([]p9.Dir, error)
    Open(path string, mode uint8) (io.ReadWriteCloser, error)
    Create(path string, perm uint32, mode uint8) (io.ReadWriteCloser, error)
    Remove(path string) error
}
```

### 4. 9P Logic (`fs.go`)
Implements the core 9P2000 handlers:
- **Navigation**: `Twalk` (Resolves paths relative to current FID).
- **Metadata**: `Tstat`, `Tcreate` (Mapping 9P modes to OS flags).
- **I/O**: `Tread`, `Twrite` (Forwarding to `io.ReadWriteCloser`).
- **Directory**: `Tread` on directories synthesizes `Stat` blocks for listing.

## Data Structures

### `Fid`
Represents an active pointer to a file in the session.
```go
type Fid struct {
    Path      string
    File      io.ReadWriteCloser
    Dir       bool       // Is directory?
    DirList   []p9.Dir  // Cached listing for Tread
    DirOffset int       // Current offset in listing
}
```

### `Dir` (from `pkg/9p/stat.go`)
Represents a Plan 9 directory entry (Stat).
```go
type Dir struct {
    Type   uint16
    Dev    uint32
    Qid    Qid
    Mode   uint32
    Atime  uint32
    Mtime  uint32
    Length uint64
    Name   string
    Uid    string
    Gid    string
    Muid   string
}
```

## Logic Flow

### Request Handling Loop
1. `Serve()` reads a 9P message (`ReadFcall`).
2. Dispatches to `handle(req)`.
3. Switch based on `req.Type`:
   - `Tversion`: Negotiate msize.
   - `Tattach`: Stat root, create FID 0.
   - `Twalk`: Stat each path element, if exists -> New FID.
   - `Topen`: Call `Backend.Open()`. If dir, `Backend.List()`.
   - `Tread`:
     - If Dir: Return chunk of `DirList` encoded as bytes.
     - If File: `File.ReadAt`.
   - `Twrite`: `File.WriteAt`.
   - `Tcreate`: `Backend.Create()`, update FID.
4. Returns generic `Rerror` on failure.

## Future Plans (Detailed in SPECIFICATION)
- **Directory Watching**: Implement Blocking `Tread` for directories using NATS subscription (`watch.go`).
- **History**: Implement `/hist/` tree traversal using `version.go` and S3 object versions.
