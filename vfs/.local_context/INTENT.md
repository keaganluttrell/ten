# Intent: VFS-Service

## Vision
VFS-Service is the File Server. It abstracts SeaweedFS behind 9P and enables real-time directory watching.

## Responsibilities
1.  **9P Server**: Listens on TCP. Serves file tree via 9P.
2.  **SeaweedFS Abstraction**: Mounts SeaweedFS. Kernel doesn't know the backend.
3.  **History**: S3 Object Versioning for per-file history.
4.  **Real-Time Watching**: Subscribes to NATS. Unblocks pending Tread on changes.

## Constraints
*   **No Business Logic**: It does not know what a "Post" or "User" is.
*   **Stateless**: Pending reads are in-memory.

## Interfaces
*   **Input**: 9P Client (Kernel, SSR, Factotum).
*   **Output**: 9P Responses.
*   **Dependency**: NATS (subscribe for events).
