# Production Integration Tasks

- [x] **Infrastructure Setup**
    - [x] Dockerize Go Services (Multi-stage build)
    - [x] Create `docker-compose.yml`
    - [x] Configure SeaweedFS (Master, Filer, WORM)
    - [x] Integrate local storage (`.data` bind mount)
    - [x] Integrate SeaweedFS via FUSE

- [x] **Refactor Storage (No S3)**
    - [x] Remove `setup` service (S3 CLI)
    - [x] Bind mount `.data` (Project Root) to SeaweedFS/VFS
    - [x] Update `vfs/entrypoint.sh` to auto-populate keys from host
    - [x] Disable SeaweedFS disk usage check (`minFreeSpacePercent=0`)

- [x] **VFS Implementation**
    - [x] Configure `DATA_ROOT=/data` in Docker Compose
    - [x] Refactor `vfs/backend_local.go`
    - [x] Verify persistence (Manual write test & Host Population verification)

- [x] **Browser Connectivity**
    - [x] Implement WebSocket Transport in Kernel
    - [x] Create simple JS Client
    - [x] Verify E2E (327 bytes read from VFS via WebSocket)
