# Specification

## System Overview
Ten is a pure Plan 9 web framework. It connects a Client (Browser) to a Storage Layer (SeaweedFS) via a Logic-Blind Kernel using the 9P Protocol.

## Inner Modules

### 1. Kernel (Custom Build)
- **Role**: The 9P Switchboard / Session Manager.
- **Philosophy**: **Pure Mechanism**.
    - It routes 9P messages. It does not know about "Data", "Events", or "Auth".
- **Responsibility**: 
    - **Protocol Gateway**: terminates `WebSocket` (Client) -> translates to `9P` (Internal).
    - **Namespace Construction**: Per-Session.
        - **Manifest**: reads `/lib/namespace`.
        - **Storage**: Dials `vfs` (TCP) -> Mounts at `/`
        - **Auth**: Dials `factotum` (TCP) -> Mounts at `/dev/factotum`
        - **View**: Dials `ssr` (TCP) -> Mounts at `/view`
- **Interfaces**:
    - `WebSocket` (External)
    - `9P Client` (To VFS/Factotum/SSR)

### 2. VFS (SeaweedFS Gateway)
- **Role**: The File System Export.
- **Architecture**: A Standalone Go Binary.
- **Backing Store**: **SeaweedFS Filer** (Locked In).
- **Integration**: 
    - connects to **SeaweedFS Filer** via HTTP (REST).
    - Acts like `ftpfs`: translates 9P -> Filer API.
    - Listens on TCP. Serves 9P.
- **History (WORM)**:
    - Queries Filer for version history.
    - Every write creates a new version.
- **Responsibility**: 
    - Abstracts Storage from Kernel.
    - Provides per-file version history.

### 3. Server-Side Renderer (SSR) Service (Custom Build)
- **Role**: The View Generator.
- **Integration**: Runs as a standalone 9P Server.
- **Responsibility**: 
    - Renders HTML on demand.

### 4. Factotum (Custom Build)
- **Role**: Authentication & Key Manager.
- **Integration**: Runs as a standalone 9P Server (listening on TCP).
- **Responsibility**:
    - Exposes `/rpc` (WebAuthn state machine).
    - Exposes `/ctl` (Key management).
    - Exposes `/proto` (Supported protocols).
    - Handles the WebAuthn ceremony internally.
    - The Kernel just proxies the 9P Reads/Writes from the Browser.

## Wire Protocol (9P over WebSocket)
*   **Transport**: WebSocket (Secure).
*   **Payload**: Binary 9P (fcall) frames.
*   **Client**: A minimal (<2KB) Vanilla JS 9P Encoder/Decoder.
    *   Write: `Twrite` frame.
    *   Read: `Tread` frame.
*   **Benefit**: Full File System semantics (Offsets, Walk, Stat) in the browser.

## Identity & Permissions (The "Hard Truth")
To enable true collaboration (Groups), we must define the `users` hierarchy.
We follow the Plan 9 standard `/adm/users` file format:

*   **File location**: `/adm/users` (stored in SeaweedFS).
*   **Format**: `user:leader:member1,member2,member3`
*   **Enforcement**:
    *   The **SeaweedFS Driver** (inside Kernel) caches this file.
    *   On `Twalk`/`Topen`, it checks the file's Mode bit (Owner/Group/World) against the Session's User/Group.
    *   *Note*: This moves the Permission Logic to the *Edge* (Kernel Driver), which is acceptable as it adapts the foreign SeaweedFS semantics to strict 9P semantics.

## Logic Flow
1.  **Auth**:
    Client (JS) -> `Twrite /dev/factotum/rpc` (WS) -> Kernel -> TCP -> Factotum.
    *   Factotum handles WebAuthn ceremony.
    *   Returns ticket path to Client.
2.  **Write (Save)**: 
    Client (JS) -> `Twrite /data/post` (WS) -> Kernel -> TCP -> VFS -> SeaweedFS.
    *   SeaweedFS saves data (S3 Versioning).
    *   SeaweedFS emits Event -> NATS.
    *   Kernel returns `Rwrite`.
3.  **Read (View)**:
    Client (JS) -> `Tread /view/post` (WS) -> Kernel -> TCP -> SSR.
    *   SSR reads `/data/post` via 9P from VFS.
    *   SSR wraps content in HTML shell.
    *   Client injects HTML into DOM.
