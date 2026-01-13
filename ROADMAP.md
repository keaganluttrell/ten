# System Roadmap & Deficiency Report

This document outlines the known architectural flaws, protocol gaps, and security deficiencies in the current `ten` operating system verification.

## 1. Critical Architecture Flaws (Bootstrap & Administration)

### 1.1 VFS Single Point of Failure (SPOF)
- [ ] **Deficiency**: The Kernel **cannot start** without the VFS service.
    - [ ] Decouple Kernel startup from VFS dial.
    - [ ] Implement `boot` process with fallback/rescue logic.
    - [ ] Allow Kernel to start with minimal RAMFS if VFS unavailable.

### 1.2 Primitive Bootstrapping Identity
- [ ] **Deficiency**: The bootstrap process uses a hardcoded "kernel" user string.
    - [ ] Implement Host Identity (Kernel has its own private key).
    - [ ] Authenticate Kernel to VFS/Factotum as a service entity.

### 1.3 Static Mount Configuration
- [ ] **Deficiency**: Mounts are static and read from a file at connection time.
    - [ ] Implement dynamic `mount` / `bind` RPCs for Admin/Sys user.
    - [ ] Allow runtime reconfiguration of the namespace.

## 2. 9P Protocol Compliance Gaps

### 2.1 Missing `Twstat` (Metadata Modification)
- [ ] **Deficiency**: The VFS service does not implement `Twstat`.
    - [ ] Implement `Twstat` in VFS (Rename, Chmod, Touch).
    - [ ] Verify `mv`, `chmod` commands work via Kernel.

### 2.2 Mount Boundary Traversal (`..`)
- [ ] **Deficiency**: The Kernel's `Twalk` implementation does not robustly handle backward traversal (`..`).
    - [ ] implement `..` interception in Kernel `Twalk`.
    - [ ] Handle switching back to parent mount client.

## 3. Security & Production Readiness

### 3.1 Public Key Distribution (Security Theater)
- [ ] **Deficiency**: Public keys are injected via environment variables.
    - [ ] Implement secure KeyStore/PKI (Factotum-based?).
    - [ ] Implement Key Rotation logic.

### 3.2 Inter-Service Trust
- [ ] **Deficiency**: Zero-trust networking is missing.
    - [ ] Implement mTLS or Factotum-based Service-to-Service Auth.
    - [ ] Verify Origin/Identity of connections.

### 3.3 Concurrency & State
- [ ] **Deficiency**: Session state management (FIDs) assumes simplistic concurrency.
    - [ ] Stress test `Twalk` with concurrent requests.
    - [ ] Audit FID map locking and lifecycle.

## 4. Stability
- [ ] **Deficiency**: No retry logic or circuit breaking.
    - [ ] Implement Reconnect/Backoff for backend services.
    - [ ] Implement "Stale Handle" recovery where possible.
