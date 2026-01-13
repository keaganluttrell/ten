# Design: SSR (Server-Side Renderer)

## High Level Diagram

```text
      +---------+
      | Browser |  (User Agent / JS)
      +----+----+
           |
      9P / WebSocket
           |
      +----v----+
      |  Kernel |  (Namespace Router)
      +----+----+
           |
       9P / TCP
           |
      +----v----+
      |   SSR   |  (View Layer)
      +----+----+
           |
       9P / TCP
           |
      +----v----+
      |   VFS   |  (Data Layer)
      +---------+
```

This document outlines the architectural design and implementation details for the SSR Service, which renders file content from VFS into HTML for browser consumption.

## Architecture

SSR acts as a **Middleware 9P Server**. It exposes a file tree that mirrors the VFS but returns HTML instead of raw data.

1.  **Incoming Request**: Kernel sends `Tread /view/foo`.
2.  **Fetch**: SSR sends `Tread /data/foo` to VFS.
3.  **Render**: SSR wraps the raw content in an HTML shell.
4.  **Response**: SSR returns HTML bytes to Kernel.

## Components

### 1. Server (`server.go`)
- **Responsibility**: Listens on TCP and accepts Kernel connections.
- **Loop**: Spawns `Session`.

### 2. Session (`fs.go`)
- **Responsibility**: Manages 9P connection state.
- **Handlers**:
    - `Tattach`: Connects to VFS (creates VFS Client).
    - `Twalk`: Forwards check to VFS (`Twalk /data/...`), mirrors success/fail.
    - `Topen`: Tracks file type (Dir vs File).
    - `Tread`:
        - If Dir: Fetches VFS directory listing, renders `<ul>...</ul>`.
        - If File: Fetches VFS file content, renders `<pre>...</pre>`.
        - Uses `render.go` helpers.
    - `Tstat`: Returns synthetic stat (size = length of HTML). *Note: Calculating exact size of HTML without generating it is hard. Chunked reads or "unknown size"? 9P requires size? Or we just generate on Open?*
        - **Constraint**: Simple v1: Generate full HTML on open/first read, cache in memory for subsequent reads?
        - **Decision**: On `Topen`, fetch data from VFS, render HTML to buffer attached to FID. `Tread` reads from buffer.

### 3. VFS Client (`client.go`)
- Wraps `pkg/9p` client to communicate with VFS-Service.
- `Dial(vfsAddr)`

### 4. Renderer (`render.go`)
- **Responsibility**: Pure functions to generate HTML strings.
- `RenderLayout(title, content string) []byte`
- `RenderDir(entries []p9.Dir) string`
- `RenderFile(content string) string`

## Data Structures

### `Fid`
Detailed state for an open file.
```go
type Fid struct {
    Path string
    // content is populated on Open
    Content []byte 
}
```

## Logic Flow

### `Topen`
1. Client sends `Topen(fid)`.
2. SSR uses VFS Client to `Twalk` to corresponding path on VFS.
3. SSR `Topen` locally on VFS? Or just `Tread`?
    - If Dir: `VFS.List(path)` -> Get `[]Dir`. Call `RenderDir`. Wrap in `RenderLayout`. Store in `Fid.Content`.
    - If File: `VFS.Read(path)` -> Get bytes. Call `RenderFile`. Wrap in `RenderLayout`. Store in `Fid.Content`.
4. SSR returns `Ropen` with `Qid`.

### `Tread`
1. Client sends `Tread(fid, offset, count)`.
2. SSR reads from `Fid.Content` slice based on offset/count.
3. Returns `Rread`.

### `Tstat`
1. Client sends `Tstat(fid)`.
2. SSR needs to report size.
3. If `Fid.Content` is populated (after Open), report `len(Content)`.
4. If not open, we can't know the HTML size easily without fetching.
5. **Simplification**: `Tstat` before Open reports size=0 or VFS size?
    - Browser uses `Tstat` to show file info?
    - Just report size=0 for un-opened files.

## Dependencies
- `pkg/9p`: Protocol.
- `kernel/client.go` (maybe reuse? or strictly `ssr/client.go`).
