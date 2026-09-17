import type { LanguageFn } from "highlight.js";
import hljs from "highlight.js/lib/core";
import accesslog from "highlight.js/lib/languages/accesslog";
import apache from "highlight.js/lib/languages/apache";
import css from "highlight.js/lib/languages/css";
import javascript from "highlight.js/lib/languages/javascript";
import json from "highlight.js/lib/languages/json";
import markdown from "highlight.js/lib/languages/markdown";
import php from "highlight.js/lib/languages/php";
import phpTemplate from "highlight.js/lib/languages/php-template";
import scss from "highlight.js/lib/languages/scss";
import twig from "highlight.js/lib/languages/twig";
import xml from "highlight.js/lib/languages/xml";

export type PreviewSyntax = "log" | "html" | "css" | "js" | "php" | "htaccess" | "json" | "md" | "twig" | "scss" | "xml";

const highlighterLanguages: Record<PreviewSyntax, string> = {
  log: "accesslog",
  html: "xml",
  css: "css",
  js: "javascript",
  php: "php-template",
  htaccess: "apache",
  json: "json",
  md: "markdown",
  twig: "twig",
  scss: "scss",
  xml: "xml",
};

hljs.registerLanguage("accesslog", accesslog);
hljs.registerLanguage("apache", apache);
hljs.registerLanguage("css", css);
hljs.registerLanguage("javascript", javascript);
hljs.registerLanguage("json", json);
hljs.registerLanguage("markdown", markdown);
hljs.registerLanguage("php", php);
hljs.registerLanguage("scss", scss);
const xmlWithEmbeddedJson: LanguageFn = (api) => {
  const language = xml(api);
  language.contains?.unshift({
    className: "tag",
    begin: /<script(?=\s|>)(?=[^>]*\btype\s*=\s*(['"])application\/(?:ld\+)?json\1[^>]*>)/i,
    end: />/,
    starts: {
      end: /<\/script>/,
      returnEnd: true,
      subLanguage: "json",
    },
  });
  return language;
};
hljs.registerLanguage("xml", xmlWithEmbeddedJson);
hljs.registerLanguage("php-template", phpTemplate);
hljs.registerLanguage("twig", twig);

export function previewSyntax(fileName: string, extension?: string): PreviewSyntax | undefined {
  if (fileName.toLowerCase() === ".htaccess") return "htaccess";
  const normalized = extension?.toLowerCase().replace(/^\./, "")
    ?? fileName.toLowerCase().match(/\.([^.]+)$/)?.[1];
  if (normalized && Object.prototype.hasOwnProperty.call(highlighterLanguages, normalized)) return normalized as PreviewSyntax;
  return undefined;
}

export function highlightPreviewContent(content: string, syntax: PreviewSyntax): string {
  return hljs.highlight(content, {
    language: highlighterLanguages[syntax],
    ignoreIllegals: true,
  }).value;
}
