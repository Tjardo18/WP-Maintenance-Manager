import { describe, expect, it } from "vitest";
import { renderMarkdownPreview } from "./markdownPreview";

describe("Markdown preview rendering", () => {
  it("renders the supported Markdown structures", () => {
    const rendered = renderMarkdownPreview(`# Titel

- Eerste
- Tweede met [link](https://example.test)

Gebruik \`inline()\`.

\`\`\`php
echo 'code';
\`\`\``);

    expect(rendered).toContain("<h1>Titel</h1>");
    expect(rendered).toContain("<ul>");
    expect(rendered).toContain('<a href="https://example.test" rel="noopener noreferrer">link</a>');
    expect(rendered).toContain("<code>inline()</code>");
    expect(rendered).toContain('<pre><code class="language-php">');
  });

  it("keeps remote HTML inert and rejects unsafe link protocols", () => {
    const rendered = renderMarkdownPreview('<script>alert("xss")</script>\n\n[gevaar](javascript:alert(1))');

    expect(rendered).not.toContain("<script>");
    expect(rendered).toContain("&lt;script&gt;");
    expect(rendered).not.toContain('href="javascript:');
    expect(rendered).not.toContain("<a ");
  });
});
