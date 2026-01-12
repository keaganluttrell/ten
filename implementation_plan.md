# System Scaffolding Implementation Plan

## Goal
Scaffold the directory structure and initial documentation for the child modules of the `ten` framework. This prepares the codebase for the "Implement Up" phase.

## Proposed Changes

### Root Structure
We will create the following directory structure:
```text
/
├── cmd/
│   └── kernel/
├── pkg/
│   ├── 9p/           (Protocol Library)
│   ├── fs/           (SeaweedFS Driver)
│   ├── auth/         (Factotum)
│   └── ssr/          (Renderer)
├── kernel/           (The Core Node)
│   └── INTENT.md
├── worm/             (NATS/Seaweed Config)
│   └── INTENT.md
├── vfs/              (SeaweedFS Filer)
│   └── INTENT.md
├── ssr/              (Renderer)
│   └── INTENT.md
└── factotum/         (Auth)
    └── INTENT.md
```

*(Note: Adjusting structure to match Go standards `pkg/` vs Node Logic folders. We stick to the Node-based folder structure defined in `AI_DEVELOPMENT.md` for the logical nodes, maybe mapping them to `pkg` internally).*
**Correction**: The `AI_DEVELOPMENT.md` says "Node is a workspace". So we should give them top-level directories:

*   `/kernel`
*   `/vfs` (Seaweed Configs)
*   `/ssr`
*   `/factotum`

### 1. [NEW] Kernel Scaffolding
*   Start `kernel/INTENT.md`.
*   Description: The logic-blind 9P switchboard.

### 2. [NEW] VFS Scaffolding
*   Start `vfs/INTENT.md`.
*   Description: The SeaweedFS Filer configuration and mounting instructions.

### 3. [NEW] SSR Scaffolding
*   Start `ssr/INTENT.md`.
*   Description: The rendering service intent.

### 4. [NEW] Factotum Scaffolding
*   Start `factotum/INTENT.md`.
*   Description: Authentication service intent.

## Verification Plan
### Manual Verification
1.  Run `ls -R` to verify the directory structure is created.
2.  Review `INTENT.md` content for each module.
