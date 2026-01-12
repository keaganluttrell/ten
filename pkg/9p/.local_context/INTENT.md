# Intent: pkg/9p (Protocol Library)

## Vision
`pkg/9p` is the shared language of Project Ten. It defines the 9P2000 protocol that all components speak.

## Responsibilities
1.  **Struct Definitions**: All 9P message types (Tversion, Rversion, Tattach, etc.).
2.  **Core Structures**: Qid (file identifier) and Stat (file metadata).
3.  **Encoding/Decoding**: Marshal structs to wire format, unmarshal bytes to structs.
4.  **Constants**: Message type values (100-127), open mode flags, Qid type flags.

## Constraints
*   **Pure Data**: No networking, no server loops, no file system logic.
*   **Standard Library Only**: `encoding/binary`, `io`, `fmt`, `errors`.
*   **Plan 9 Compliant**: Byte-for-byte compatible with the 9P2000 specification.

## Interfaces
*   **Used By**: Kernel, VFS-Service, SSR, Factotum.
