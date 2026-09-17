import { describe, expect, it } from "vitest";
import { sanitizeSvgPreview, svgPreviewDataUrl } from "./svgPreview";

describe("SVG preview", () => {
  it("keeps common SVG structures, gradients, styles and internal references", () => {
    const source = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
      <defs>
        <linearGradient id="gradient"><stop offset="0" stop-color="#fff" /><stop offset="1" stop-color="#000" /></linearGradient>
        <style>.shape { fill: url(#gradient); }</style>
      </defs>
      <g class="shape"><path d="M0 0h100v100z" /></g>
    </svg>`;

    const sanitized = sanitizeSvgPreview(source);
    expect(sanitized).toContain("linearGradient");
    expect(sanitized).toContain("<style>");
    expect(sanitized).toContain("url(#gradient)");
    expect(sanitized).toContain("<g");
    expect(sanitized).toContain("<path");
    expect(svgPreviewDataUrl(source)).toMatch(/^data:image\/svg\+xml;charset=utf-8,/);
  });

  it("removes executable content and external resource references", () => {
    const source = `<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)">
      <script>alert(1)</script>
      <foreignObject><div>unsafe</div></foreignObject>
      <style>@import "https://tracker.test/style.css"; .safe { fill: url(#paint); } .bad { fill: url(https://tracker.test/pixel); }</style>
      <image href="https://tracker.test/image.png" />
      <use href="#shape" />
      <path id="shape" style="stroke:url(https://tracker.test/stroke);fill:url(#paint)" />
    </svg>`;

    const sanitized = sanitizeSvgPreview(source) ?? "";
    expect(sanitized).not.toMatch(/<script|onload|foreignObject|https:\/\/tracker\.test/i);
    expect(sanitized).toContain('href="#shape"');
    expect(sanitized).toContain("url(#paint)");
    expect(sanitized).toContain("stroke:none");
  });

  it("rejects content without an SVG root", () => {
    expect(sanitizeSvgPreview("<div>not an svg</div>")).toBeUndefined();
    expect(svgPreviewDataUrl("not xml at all")).toBeUndefined();
  });

  it("adds the SVG namespace when older files omit it", () => {
    expect(sanitizeSvgPreview('<svg viewBox="0 0 10 10"><path d="M0 0h10v10z" /></svg>')).toContain(`xmlns="http://www.w3.org/2000/svg"`);
  });
});
