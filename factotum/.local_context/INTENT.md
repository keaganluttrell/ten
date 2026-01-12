# Intent: Factotum

## Vision
Factotum is the User's Agent. It manages identity, keys, and the authentication ceremony. It is the **only** component that understands auth.

## Responsibilities
1.  **9P Server**: Listens on TCP. Kernel dials and mounts at `/dev/factotum`.
2.  **File Interface**:
    *   `/rpc`: Stateful auth dialogue (challenge-response).
    *   `/ctl`: Key management (add/remove public keys).
    *   `/proto`: Advertises supported protocols.
3.  **WebAuthn Ceremony**: Manages FIDO2 registration and authentication.
4.  **Ticket Generation**: Issues signed file-based tickets for session persistence.

## Interfaces
*   **Input**: 9P Client (Kernel proxies Browser requests).
*   **Output**: Tickets written to VFS-Service (`/priv/sessions/`).
*   **Data**: Public keys stored in VFS-Service (`/priv/factotum/`).
