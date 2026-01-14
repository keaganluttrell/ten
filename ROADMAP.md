# System Roadmap & Deficiency Report

This document outlines the known architectural flaws, protocol gaps, and security deficiencies in the current `ten` operating system verification.

## 1. Critical Architecture Flaws (Bootstrap & Administration)

### 1.1 VFS Single Point of Failure (SPOF)
- [x] **Deficiency**: The Kernel **cannot start** without the VFS service.
    - [x] Decouple Kernel startup from VFS dial.
    - [x] Implement `boot` process with fallback/rescue logic.
    - [x] Allow Kernel to start with minimal RAMFS if VFS unavailable.

### 1.2 Primitive Bootstrapping Identity
- [x] **Deficiency**: The bootstrap process uses a hardcoded "kernel" user string.
    - [x] Implement Host Identity (Kernel has its own private key).
    - [x] Authenticate Kernel to VFS/Factotum as a service entity.

### 1.3 Static Mount Configuration
- [x] **Deficiency**: Mounts are static and read from a file at connection time.
    - [x] Implement dynamic `mount` / `bind` RPCs for Admin/Sys user.
    - [x] Allow runtime reconfiguration of the namespace.

## 2. 9P Protocol Compliance Gaps

### 2.1 Missing `Twstat` (Metadata Modification)
- [x] **Deficiency**: The VFS service does not implement `Twstat`.
    - [x] Implement `Twstat` in VFS (Rename, Chmod, Touch).
    - [x] Verify `mv`, `chmod` commands work via Kernel.

### 2.2 Mount Boundary Traversal (`..`)
- [x] **Deficiency**: The Kernel's `Twalk` implementation does not robustly handle backward traversal (`..`).
    - [x] implement `..` interception in Kernel `Twalk`.
    - [x] Handle switching back to parent mount client.

## 3. Security & Production Readiness

### 3.1 Public Key Distribution (Security Theater)
- [x] **Deficiency**: Public keys are injected via environment variables.
    - [x] Implement secure KeyStore/PKI (Factotum-based?).
    - [x] Implement Key Rotation logic.

### 3.2 Inter-Service Trust
- [x] **Deficiency**: Zero-trust networking is missing.
    - [x] Implement Factotum-mediated service tickets (like user tickets, but for services).
    - [x] Use 9P Tauth for service-to-service authentication.

### 3.3 Concurrency & State
- [x] **Deficiency**: Session state management (FIDs) assumes simplistic concurrency.
    - [x] Stress test `Twalk` with concurrent requests.
    - [x] Audit FID map locking and lifecycle.

## 4. Stability
- [x] **Deficiency**: No retry logic or circuit breaking.
    - [x] Implement Reconnect/Backoff for backend services.
    - [x] Implement "Stale Handle" recovery where possible.
### 5. Namespace Realism (The Ken Thompson Audit)
- [x] **Deficiency**: Namespace was a simple map, lacking Union Mounts.
    - [x] Implement Union Mounts (stack-based resolution).
    - [x] Implement Bind Flags (`-a`, `-b`, `-c`).
    - [x] Update `Twalk` to traverse union stacks.

## 6. Core Services & Shell (Getting Live)
- [x] **Deficiency**: No way to run the stack locally without manual orchestration.
    - [x] Implement `tools/dev.sh` (Bootstrap script).
    - [x] Auto-generate keys and directories.

- [x] **Deficiency**: No interactive shell or process management.
    - [x] Implement `rc` (Shell) as a standalone client.
    - [x] Implement `proc` file system (Process table).
    - [x] Implement environment variable file interface (`/env`).

## 7. Application Layer
- [ ] **Deficiency**: No useful applications running on the OS.
    - [ ] Implement `cron` (Scheduler) using `/dev/cons`.
    - [ ] Implement `mail` (Messaging) using `/mail` fs.
    - [/] Productionize `ssr` (Web Desktop) to render these apps.
        - [x] Implement minimal read-only file explorer.
