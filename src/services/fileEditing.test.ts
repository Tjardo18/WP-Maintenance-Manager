import { describe, expect, it } from "vitest";
import { editorText, restoreFileText } from "./fileEditing";

describe("lossless editor text", () => {
  it.each(["a\nb\n", "\uFEFFa\r\nb\r\n", "a\rb\n c\r\n", "é ë € 中文 🚀"])("preserves unchanged bytes: %j", (source) => {
    expect(restoreFileText(editorText(source), source)).toBe(source);
  });
  it("keeps BOM and CRLF while adding lines", () => {
    expect(restoreFileText("a\nchanged 中文\nnew\n", "\uFEFFa\r\nb\r\n")).toBe("\uFEFFa\r\nchanged 中文\r\nnew\r\n");
  });
});
