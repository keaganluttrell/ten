# Implementation Plan: SSR Layout System ("Hello World")

## The Elders' Input
*Intercepted via /dev/cons*

> **Rob**: "The structure of the system should be the structure of the data. If the URL is `/user/alice/dev/file`, that *is* your navigation. Don't build a separate map. The path is the map."
>
> **Ken**: "Keep it simple. You don't need a massive framework to stick a string inside another string. A loop and a print statement usually suffice."
>
> **Consensus**: 
> 1.  **URL = UI**: The hierarchy on the screen must match the hierarchy of the VFS.
> 2.  **No Magic**: The layout is just a wrapper (Header/Nav + Content + Footer).
> 3.  **Composition**: Use simple template definition.

---

## Goal
Implement a reusable **Layout Template** for the SSR Gateway that provides context (Navigation) for every viewed resource.

## Design

### 1. The Shell (Layout)
A single HTML5 skeleton acting as the container.

```html
<!DOCTYPE html>
<html>
<head>
    <title>Ten: {{.Title}}</title>
    <!-- Use Ten CSS -->
    <link rel="stylesheet" href="/style.css"> 
</head>
<body>
    <!-- 1. Header & Navigation -->
    <header>
        <div class="brand">Ten</div>
        <nav class="breadcrumbs">
            <!-- Computed from URL Path -->
            <!-- e.g., / -> user -> alice -> dev -->
            {{.Breadcrumbs}}
        </nav>
    </header>

    <!-- 2. Content Slot -->
    <main>
        {{.Content}}
    </main>

    <!-- 3. Footer -->
    <footer>
        <small>Plan 9 for the Web</small>
    </footer>
</body>
</html>
```

### 2. The Slot (Endpoint Content)
The `{{.Content}}` is populated dynamically based on the resource type.

*   **If Directory**: Renders a `<ul>` list of children.
*   **If File**: Renders a `<pre>` block of text (or specific viewer for images/media).
*   **If App**: Renders the application logic.

### 3. Navigation Logic (Breadcrumbs)
Instead of a complex sidebar, we stick to the Plan 9/Unix ethos: **Breadcrumbs**.
For path `/user/alice/dev/note.txt`:

1.  `/` (Home)
2.  `user/`
3.  `alice/`
4.  `dev/`
5.  `note.txt` (Current)

This provides instant "upward" navigation, which is essential for a filesystem-based UI.

## Implementation Steps (Go)

1.  **Define Template**: Move the hardcoded `layoutStart`/`layoutEnd` strings into a proper `text/template` definition in `ssr.go` (embeddable).
2.  **Struct Data**:
    ```go
    type PageData struct {
        Title       string
        Path        string
        Breadcrumbs []Link // Name, Href
        Content     interface{} // string or template fragment
    }
    ```
3.  **Render Pipeline**:
    *   Handler receives request path.
    *   Fetch Data (9P Read).
    *   Construct `PageData` (Parse path for breadcrumbs).
    *   `tmpl.Execute(w, data)`

## Future Scalability
*   **Slots**: We can add a "Sidebar" slot later if needed, but for "Hello World", Breadcrumbs are sufficient.
*   **Themes**: The `style.css` can be swapped for theming.
