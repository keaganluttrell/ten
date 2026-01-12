# Intent: The Kernel

## Vision
The Kernel is the Logic Blind Switchboard of the Ten operating system. It provides the mechanism for the world (Browser) to interact with the state (Files).

## Responsibilities
1.  **Protocol Gateway**: Accept WebSocket connections, extracting binary 9P (fcall) frames.
2.  **Session Management**: For each connection, establish a `Session`.
3.  **Namespace Construction**:
    *   Read `/lib/namespace` (Manifest).
    *   Setup Mounts:
        *   `/` -> FUSE Mount (`/mnt/seaweed`)
        *   `/dev/factotum` -> Unix Socket (Factotum)
        *   `/view` -> Unix Socket (SSR)
4.  **Multiplexing**: Route `T-messages` to the correct Mount.

## Constraints
*   **NO BUSINESS LOGIC**. It does not know what a "Post" or "User" is.
*   **Stateless**: It holds open File Descriptors (FIDs) but stores no persistent data itself.

## Interfaces
*   **Input**: WebSocket (Port 8080/443).
*   **Dependencies**:
    *   `pkg/9p` (Protocol)
    *   `os` (For FUSE interaction)
    *   `net` (For Socket interaction)
