# Root Node Design

## High Level Architecture

```text
       +---------------------+
       |   Client (Browser)  |
       |  (9P over WebSocket)|
       +----------+----------+
                  |
         [9P Frames / WS]
                  |
+-----------------v-----------------+
|          Kernel (Go)              |
|   (Logic Blind Switchboard)       |
|                                   |
|  +-----------------------------+  |
|  | Namespace (Per User)        |  |
|  | /          -> SeaweedFS     |  |
|  | /dev/auth  -> Factotum      |  |
|  | /view      -> SSR           |  |
|  +--------------+--------------+  |
+-----------------+-----------------+
                  |
    +-------------+-------------+
    |             |             |
+---v---+     +---v---+     +---v---+
| Seaweed |   | Factotum|   |  SSR  |
|  Filer  |   | (Auth)  |   | (View)|
+---+---+     +-------+     +---+---+
    |                           |
+---v---+                       |
| NATS  | <----[Events]---------+
| Stream|
+-------+
```

## Wiring Plan
1.  **Entry Point**: `main.go` launches the Kernel.
2.  **Mounts**:
    *   Kernel connects to SeaweedFS Filer (S3/HTTP/gRPC/FUSE?). *Decision: Use SeaweedFS Filer Client API wrapped as a 9P FileServer.*
    *   Kernel connects to Factotum (Unix Socket or In-Process?). *Decision: In-Process for simplicity, or Unix Socket for purity.*
    *   Kernel connects to SSR (In-Process channel or Unix Socket?).

## Directory Structure (Root)
```text
/
├── cmd/
│   └── kernel/       # The Entry Point
├── pkg/
│   ├── 9p/           # 9P Protocol Library
│   ├── fs/           # SeaweedFS Driver
│   └── auth/         # Factotum Interface
├── global_context/   # Documentation
├── ARCHITECTURE.md
├── SPECIFICATION.md
├── DESIGN.md
└── task.md
```
