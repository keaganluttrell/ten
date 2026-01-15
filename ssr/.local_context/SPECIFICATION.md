# Specification: SSR (Server-Side Renderer)

## Inherited Context
From Root `SPECIFICATION.md`: The SSR is the View Layer. It is an HTTP Gateway that serves the App Shell and renders VFS content as HTML.

## Role in Project Ten
SSR is the **Window** into the system. 
1.  **App Shell**: Serves the Single Page App (or static shell) for the client.
2.  **File Browser**: Proxies 9P file system state to HTML for standard web browsers.

---

## Core Principle

**Hybrid Architecture**: 
- **View (HTTP)**: "Show me the file." (SSR renders HTML).
- **Action (WebSocket)**: "Log me in." (Client connects to SSR `/ws`, which proxies to Kernel).

---

## HTTP Interface

SSR exposes an HTTP Server (default :8080).

### Routes
| Route | Description | Behavior |
| :--- | :--- | :--- |
| `/` | App Shell | Serves the embedded `index.html` (Client App). |
| `/ws` | WebSocket Proxy | Proxies raw WebSocket frames to the Kernel's TCP port (9P). |
| `/*` | File Browser | Proxies the path to VFS and renders directory/file as HTML. |

### / (Catch-All) Mapping
```text
/           →  App Shell (index.html)
/ws         →  Kernel 9P Proxy
/foo/bar    →  /foo/bar (9P File/Dir)
```
*Note: Any path not matching specific handlers is treated as a 9P path request.*

---

## Inputs
*   **HTTP Requests**: GET requests from Browser.

## Outputs
*   **HTML**:
    - **App Shell**: The client-side application.
    - **File Browser**: Minimal HTML layout listing files or showing content.

---

## Data Access

SSR is a **9P Client** to the Kernel (or VFS directly, configured via flags).
*   It dials the Kernel/VFS to fetch data for `/view/` requests.
*   It does **not** use 9P for `/` (App Shell), which is embedded.

---

## Error Handling

| Error | Response |
| :--- | :--- |
| File not found | HTTP 404 + HTML Error Page |
| VFS unavailable | HTTP 503 + HTML Error Page |

---

## Dependencies
*   **Internal**: `pkg/9p` (Protocol), `kernel` (Client).
*   **External**: Kernel/VFS (Dials for data).
*   **Standard**: `net/http`, `html/template`.

## Constraints
1.  **Locality of Behavior**: All logic in minimal files (ideally one `ssr.go`).
2.  **Read-Only View**: The HTTP interface is Read-Only. Writes happen via WebSocket (System Actions).

---

## Inner Modules
*   `ssr.go`: Contains all logic (Server, Handlers, Renderers, Embedding).
