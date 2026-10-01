/** Textareas use LF internally. Keep the source's BOM and existing newline sequence. */
export function editorText(source: string): string {
  return source.replace(/^\uFEFF/, "").replace(/\r\n|\r/g, "\n");
}

export function restoreFileText(draft: string, original: string): string {
  const normalized = draft.replace(/\r\n|\r/g, "\n");
  if (normalized === editorText(original)) return original;
  const endings = original.match(/\r\n|\r|\n/g) ?? [];
  const fallback = endings.filter((e) => e === "\r\n").length > endings.length / 2 ? "\r\n" : "\n";
  let index = 0;
  const body = normalized.replace(/\n/g, () => endings[index++] ?? fallback);
  return (original.startsWith("\uFEFF") ? "\uFEFF" : "") + body;
}
