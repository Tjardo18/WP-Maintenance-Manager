const svgNamespace = "http://www.w3.org/2000/svg";
const fragmentReference = /^#[A-Za-z_][\w:.-]*$/;
const blockedElements = new Set([
  "audio", "embed", "foreignobject", "iframe", "object", "script", "video",
]);

function removeExternalCssReferences(value: string) {
  return value
    .replace(/@import\s+(?:url\()?\s*(?:["'][^"']*["']|[^;)\s]+)\s*\)?\s*;?/gi, "")
    .replace(/url\(\s*(["']?)(.*?)\1\s*\)/gi, (_match, _quote: string, target: string) => (
      fragmentReference.test(target.trim()) ? `url(${target.trim()})` : "none"
    ))
    .replace(/(?:expression|behavior)\s*\([^)]*\)/gi, "");
}

export function sanitizeSvgPreview(source: string): string | undefined {
  if (/<!DOCTYPE/i.test(source)) return undefined;

  const document = new window.DOMParser().parseFromString(source, "image/svg+xml");
  const root = document.documentElement;
  if (document.querySelector("parsererror") || root.localName.toLowerCase() !== "svg" || (root.namespaceURI && root.namespaceURI !== svgNamespace)) return undefined;

  const elements = [root, ...Array.from(root.querySelectorAll("*"))];
  for (const element of elements) {
    const elementName = element.localName.toLowerCase();
    if (blockedElements.has(elementName) || (element.namespaceURI && element.namespaceURI !== svgNamespace)) {
      element.remove();
      continue;
    }

    if (elementName === "style") element.textContent = removeExternalCssReferences(element.textContent ?? "");
    for (const attribute of Array.from(element.attributes)) {
      const name = attribute.localName.toLowerCase();
      const value = attribute.value.trim();
      if (name.startsWith("on")) {
        element.removeAttributeNode(attribute);
      } else if (["href", "src"].includes(name) && value && !fragmentReference.test(value)) {
        element.removeAttributeNode(attribute);
      } else if (name === "style" || /url\s*\(/i.test(value)) {
        element.setAttribute(attribute.name, removeExternalCssReferences(value));
      }
    }
  }

  const serialized = new window.XMLSerializer().serializeToString(root);
  return root.namespaceURI ? serialized : serialized.replace(/^<svg(?=[\s>])/, `<svg xmlns="${svgNamespace}"`);
}

export function svgPreviewDataUrl(source: string): string | undefined {
  const sanitized = sanitizeSvgPreview(source);
  return sanitized ? `data:image/svg+xml;charset=utf-8,${window.encodeURIComponent(sanitized)}` : undefined;
}
