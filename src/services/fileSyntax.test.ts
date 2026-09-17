import { describe, expect, it } from "vitest";
import { highlightPreviewContent, previewSyntax, type PreviewSyntax } from "./fileSyntax";

describe("file preview syntax", () => {
  it.each<[string, string | undefined, PreviewSyntax]>([
    ["debug.log", "log", "log"],
    ["index.html", "html", "html"],
    ["style.css", "css", "css"],
    ["app.js", "js", "js"],
    ["plugin.php", "php", "php"],
    [".htaccess", undefined, "htaccess"],
    ["data.json", "json", "json"],
    ["README.md", "md", "md"],
  ])("selects highlighting for %s", (fileName, extension, expected) => {
    expect(previewSyntax(fileName, extension)).toBe(expected);
  });

  it("leaves text and unsupported extensions unhighlighted", () => {
    expect(previewSyntax("notes.txt", "txt")).toBeUndefined();
    expect(previewSyntax("archive.xml", "xml")).toBeUndefined();
    expect(previewSyntax("no-extension", undefined)).toBeUndefined();
  });

  it("escapes untrusted source while adding syntax spans", () => {
    const source = "<script>alert('safe')</script>";
    const highlighted = highlightPreviewContent(source, "html");

    expect(highlighted).toContain("hljs-tag");
    expect(highlighted).toContain("&lt;");
    expect(highlighted).not.toContain("<script>");
  });

  it.each<[PreviewSyntax, string, string]>([
    ["css", ".demo { color: #fff; }", "hljs-selector-class"],
    ["js", "const answer = 42;", "hljs-keyword"],
    ["php", "<?php function demo() { return true; }", "hljs-meta"],
    ["json", '{"enabled": true}', "hljs-attr"],
    ["htaccess", "RewriteEngine On\nRewriteRule ^old$ /new [R=301,L]", "hljs-attribute"],
  ])("adds %s token markup", (syntax, source, expectedClass) => {
    expect(highlightPreviewContent(source, syntax)).toContain(expectedClass);
  });

  it("highlights mixed PHP templates with the matching embedded languages", () => {
    const source = `<?php
$title = 'Voorbeeld';
?>
<div class="card">
  <h1><?php echo $title; ?></h1>
</div>
<style>.card { color: red; }</style>
<script>console.log('test');</script>`;
    const highlighted = highlightPreviewContent(source, "php");

    expect(highlighted).toContain('class="language-php"');
    expect(highlighted).toContain('class="language-xml"');
    expect(highlighted).toContain('class="language-css"');
    expect(highlighted).toContain('class="language-javascript"');
    expect(highlighted).toContain("hljs-variable");
    expect(highlighted).toContain("hljs-tag");
    expect(highlighted).toContain("hljs-selector-class");
    expect(highlighted).toContain("hljs-title");
  });

  it("recognizes JSON data blocks inside PHP templates", () => {
    const source = `<script type="application/json">
{"enabled": true, "items": [1, 2]}
</script>
<script type="application/ld+json">{"@type": "WebSite"}</script>`;
    const highlighted = highlightPreviewContent(source, "php");

    expect(highlighted.match(/class="language-json"/g)).toHaveLength(2);
    expect(highlighted).toContain("hljs-attr");
  });

  it("does not interpret code-like PHP strings or comments as embedded code", () => {
    const source = `<?php
$template = '<script>const fake = true;</script>';
// <style>.fake { color: red; }</style>
echo $template;
?>
<p>Echte HTML</p>`;
    const highlighted = highlightPreviewContent(source, "php");

    expect(highlighted).toContain("hljs-string");
    expect(highlighted).toContain("hljs-comment");
    expect(highlighted).not.toContain('class="language-javascript"');
    expect(highlighted).not.toContain('class="language-css"');
    expect(highlighted).toContain('class="language-xml"');
  });

  it("keeps Markdown as highlighted raw source", () => {
    const source = "# Heading\n\n**bold** and [link](https://example.test)";
    const highlighted = highlightPreviewContent(source, "md");

    expect(highlighted).toContain("# Heading");
    expect(highlighted).toContain("hljs-section");
    expect(highlighted).not.toContain("<h1>");
    expect(highlighted).not.toContain("<strong>");
  });

  it("highlights common access-log fields", () => {
    const highlighted = highlightPreviewContent('127.0.0.1 - - [17/Sep/2026:12:00:00 +0200] "GET /wp-login.php HTTP/1.1" 403 120', "log");

    expect(highlighted).toContain("hljs-number");
    expect(highlighted).toContain("hljs-string");
  });
});
