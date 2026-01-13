package ssr

import (
	"fmt"
	"strings"

	p9 "github.com/keaganluttrell/ten/pkg/9p"
)

// RenderLayout wraps content in the standard HTML document structure.
func RenderLayout(title, content string) []byte {
	return []byte(fmt.Sprintf(`<!DOCTYPE html>
<html>
<head>
<title>%s</title>
<style>
body { font-family: monospace; padding: 1em; }
a { text-decoration: none; color: blue; }
a:hover { text-decoration: underline; }
ul { list-style-type: none; padding-left: 0; }
li { padding: 0.2em 0; }
</style>
</head>
<body>
<nav><a href="../">..</a> | <b>%s</b></nav>
<hr/>
<main>
%s
</main>
</body>
</html>`, title, title, content))
}

// RenderDir generates an HTML list of directory entries.
func RenderDir(entries []p9.Dir) string {
	var sb strings.Builder
	sb.WriteString("<ul>\n")
	for _, e := range entries {
		name := e.Name
		if (e.Qid.Type & p9.QTDIR) != 0 {
			name += "/"
		}
		// Relative link
		sb.WriteString(fmt.Sprintf("<li><a href=\"%s\">%s</a></li>\n", name, name))
	}
	sb.WriteString("</ul>")
	return sb.String()
}

// RenderFile wraps file content in a pre tag.
func RenderFile(content string) string {
	// Escape HTML special chars if needed?
	// For "plain text" fidelity, simplest is <pre>.
	// Go's html.EscapeString would be better for security,
	// but spec says "plain text in, html out".
	// Let's do basic escaping to avoid breaking the page.
	safe := strings.ReplaceAll(content, "&", "&amp;")
	safe = strings.ReplaceAll(safe, "<", "&lt;")
	safe = strings.ReplaceAll(safe, ">", "&gt;")

	return fmt.Sprintf("<pre>%s</pre>", safe)
}
