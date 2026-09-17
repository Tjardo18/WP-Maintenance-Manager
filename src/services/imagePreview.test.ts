import { describe, expect, it } from "vitest";
import { binaryImageDataUrl, isImagePreviewExtension } from "./imagePreview";

describe("image preview", () => {
  it.each(["svg", "svgz", "jpg", "jpeg", "png", "gif", "webp", "avif", "ico", "bmp", "tiff", "tif"])("recognizes .%s files", (extension) => {
    expect(isImagePreviewExtension(extension)).toBe(true);
    expect(isImagePreviewExtension(`.${extension.toUpperCase()}`)).toBe(true);
  });

  it("leaves unrelated file types unsupported", () => {
    expect(isImagePreviewExtension("txt")).toBe(false);
    expect(isImagePreviewExtension()).toBe(false);
  });

  it("creates data URLs only for allow-listed binary image MIME types", () => {
    expect(binaryImageDataUrl("image/gif", "R0lGODlh")).toBe("data:image/gif;base64,R0lGODlh");
    expect(binaryImageDataUrl("image/png", "iVBORw0KGgo=")).toBe("data:image/png;base64,iVBORw0KGgo=");
    expect(binaryImageDataUrl("image/svg+xml", "PHN2Zz4=")).toBeUndefined();
    expect(binaryImageDataUrl("text/html", "PGh0bWw+")).toBeUndefined();
  });
});
