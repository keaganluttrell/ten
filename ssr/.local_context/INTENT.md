# Intent: SSR (Server-Side Renderer)

## Vision
SSR is a File Browser. It reads files from VFS and displays them in HTML.

## Responsibilities
1.  **9P Server**: Listens on TCP. Kernel mounts at `/view`.
2.  **File Display**: Read file → wrap in HTML → return.
3.  **Directory Display**: Read directory → list children as links.
4.  **Minimal Layout**: Navigation breadcrumb + content slot.

## Constraints
*   **No Transformation**: Plain text in, HTML wrapped out.
*   **No Extensions**: Plan 9 style. Files have no extensions.
*   **Read-Only**: Pure display layer.

## Interfaces
*   **Input**: 9P Client (Kernel).
*   **Dependency**: 9P Client (Dials VFS-Service).
