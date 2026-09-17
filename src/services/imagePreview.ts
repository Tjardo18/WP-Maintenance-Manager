const supportedImageExtensions = new Set([
  "svg", "svgz", "jpg", "jpeg", "png", "gif", "webp", "avif", "ico", "bmp", "tiff", "tif",
]);

const safeImageMimeTypes = new Set([
  "image/jpeg", "image/png", "image/gif", "image/webp", "image/avif", "image/x-icon", "image/vnd.microsoft.icon", "image/bmp",
]);

export function isImagePreviewExtension(extension?: string) {
  return extension !== undefined && supportedImageExtensions.has(extension.toLowerCase().replace(/^\./, ""));
}

export function binaryImageDataUrl(mimeType?: string, dataBase64?: string): string | undefined {
  if (!mimeType || !dataBase64 || !safeImageMimeTypes.has(mimeType.toLowerCase())) return undefined;
  return `data:${mimeType.toLowerCase()};base64,${dataBase64}`;
}
