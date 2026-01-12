# Specification: SSR (Server-Side Renderer)

## Inherited Context
From Root `SPECIFICATION.md`: The SSR is the View Layer. It is a standalone 9P Server that renders file content as HTML.

## Role in Project Ten
SSR is a **File Browser**. It reads files and directories from VFS-Service and wraps them in a simple HTML layout. No transformation. No Markdown parsing. Plain text in, HTML out.

---

## Core Principle

**Plan 9 Simplicity**: Everything is a file. Everything is plain text. SSR just displays it.

---

## 9P File Interface

SSR exposes a virtual tree at `/view` mirroring `/data` from VFS.

### Mapping
```text
/view/        →  /data/        (directory listing)
/view/foo     →  /data/foo     (file or directory)
/view/bar/baz →  /data/bar/baz (nested path)
```

*No file extensions. No transformation. 1:1 mapping.*

### Behavior

| Path Type | SSR Response |
| :--- | :--- |
| **Directory** | HTML page with list of child files/directories. |
| **File** | HTML page with file content (plain text, pre-formatted). |

---

## HTML Layout (Minimal)

SSR wraps all responses in a simple shell:

```html
<!DOCTYPE html>
<html>
<head><title>{path}</title></head>
<body>
  <nav>{breadcrumb}</nav>
  <main>{content}</main>
</body>
</html>
```

### Content Slot

**For Directories:**
```html
<ul>
  <li><a href="child1/">child1/</a></li>
  <li><a href="child2">child2</a></li>
</ul>
```
*Uses relative paths. Browser navigates within namespace.*

**For Files:**
```html
<pre>{file content}</pre>
```

---

## Inputs
*   **9P Packets**: From Kernel (TCP).

## Outputs
*   **HTML Bytes**: Wrapped file/directory content.

---

## Data Access

SSR is a **9P Client** to VFS-Service:
*   Reads file content: `Tread /data/<path>`.
*   Reads directory listing: `Tstat` + `Tread` for directory.

---

## Error Handling

| Error | Response |
| :--- | :--- |
| File not found | HTML page: "Not Found" |
| VFS unavailable | HTML page: "Service Unavailable" |

---

## Dependencies
*   **Internal**: `pkg/9p` (Protocol).
*   **External**: VFS-Service (Dials for data).
*   **Standard**: `fmt` (string formatting for layout).

## Constraints
1.  **No Transformation**: Files are displayed as-is. Plain text.
2.  **No Extensions**: `/view/foo` maps to `/data/foo`. Period.
3.  **Read-Only**: SSR never writes.
4.  **Stateless**: No caching in v1.

---

## Inner Modules
*   `main.go`: 9P Server loop (listens on TCP).
*   `fs.go`: 9P handlers (Twalk, Tread, Tstat).
*   `render.go`: HTML wrapping (layout shell).
*   `client.go`: 9P Client (Dials VFS-Service).
