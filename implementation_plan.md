# VFS Implementation Gap Analysis

## 1. Persistence & Storage (Status: **CRITICAL FIX NEEDED**)
The infrastructure successfully mounts SeaweedFS at `/data` via FUSE. However, the VFS application is currently misconfigured.

*   **Current Behavior**: `vfs` defaults to serving `/tmp/ten-data` (volatile container storage).
*   **Required Behavior**: `vfs` must serve `/data` (the persistent FUSE mount).
*   **Fix**: Update `docker-compose.yml` to set `DATA_ROOT=/data` for the `vfs` service.

## 2. Code Organization (Refactor)
The codebase has legacy naming from the previous S3 attempt.

*   `vfs/seaweed.go`: Currently contains the `LocalBackend` implementation and `Backend` interface. This is confusing.
*   **Action**:
    *   Rename `vfs/seaweed.go` -> `vfs/backend_local.go` (Implementation).
    *   Extract `Backend` interface to `vfs/backend.go`.

## 3. Real-Time Updates (Missing)
The system requires real-time updates via NATS.

*   **Gap**: `vfs/watch.go` is a stub.
*   **Requirement**:
    *   VFS must subscribe to SeaweedFS events via NATS (JetStream).
    *   When an external event occurs (e.g., file change), VFS must update its internal state or notify connected 9P clients.
    *   *Note*: Since we are using FUSE, the local kernel might see changes, but 9P doesn't have a "push" notification mechanism other than blocking reads on directories or specific event files.
    *   **Spec Check**: Does the Spec require blocking reads? Yes.

## 4. WORM / History (Deferred)
We rely on SeaweedFS for versioning.
*   **Gap**: VFS has no logic to *expose* these versions.
*   **Plan**: For V1, we accept that VFS shows the *HEAD* (latest) version via the mount. Accessing history will be a future feature (potentially via a `.hist` virtual directory).

# Execution Plan

1.  **Config**: Fix `DATA_ROOT` in `docker-compose.yml`.
2.  **Refactor**: Clean up `vfs` file structure.
3.  **Verify**: Restart `vfs` and verify persistence (write file, restart container, read file).
