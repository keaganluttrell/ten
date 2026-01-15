# Kernel Audit

## Discrepancies Found

### 1. Violation of "Locality of Behavior"
**Severity: High**
The `CONVENTIONS.md` explicitly states: "We should combine all logic related to a package into a single file."
The `kernel` package is currently fragmented across 18+ files:
- `server.go`
- `session.go`
- `client.go`
- `namespace.go`
- `proc.go`
- `ramfs.go`
- `sys.go`
- `env.go`
- `socket.go`
- `ticket.go`
- `host_key.go`
- `auth_handshake.go`
- and various tests.

This fragmentation makes it difficult to understand the complete message flow and session state management in one view.

### 2. Unspecified Functionality: Rescue RAMFS
**Severity: Medium**
`ramfs.go` implements an in-memory `BootFS` that is mounted when VFS is unavailable.
The `SPECIFICATION.md` states:
> If a backend service is unreachable during namespace construction:
> `Kernel: Rerror { ename="service_unavailable: vfs-service" }`

It does **not** specify a "Rescue Mode" or an internal RAM filesystem. This adds unnecessary complexity and "magic" behavior not aligned with the "Simplicity" mantra.

### 3. Architecture Deviation: ProcFS TCP Port
**Severity: Low**
`proc.go` starts a separate TCP listener on port `:9004`.
The `SPECIFICATION.md` states:
> The Kernel is the **only** gateway between the Browser (Terminal) and the backend services.

While unrelated to the Gateway role, exposing internal process state via a side-channel TCP port (9004) bypasses the standard 9P routing through the Gateway if not strictly controlled. If it is intended for internal cluster maintenance, it should be documented.

### 4. Logic Fragmentation: Namespace Routing
**Severity: Medium**
Critical routing logic (`Twalk` across union mounts) is split between `session.go` (the loop) and `namespace.go` (the resolution). This makes the core switching logic harder to follow.

## Recommendations

1.  **Consolidate Codebase**: Merge all `kernel/*.go` files into a single `kernel/kernel.go`.
2.  **Remove RAMFS**: Adhere to the specification by returning a standard Rerror when the VFS is unavailable, rather than entering a complex "Rescue Mode".
3.  **Simplify ProcFS**: Ensure `proc` is served via the standard 9P interface without needing a separate TCP listener, or document the necessity of port 9004.
