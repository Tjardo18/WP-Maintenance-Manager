import { enableAutoUnmount, mount } from "@vue/test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";

const mockOpenExternalUrl = vi.hoisted(() => vi.fn(async () => undefined));
vi.mock("../services/tauri", () => ({ appApi: { openExternalUrl: mockOpenExternalUrl } }));

import ChecksumFilePreview from "./ChecksumFilePreview.vue";

enableAutoUnmount(afterEach);
afterEach(() => mockOpenExternalUrl.mockClear());

describe("ChecksumFilePreview", () => {
  it("renders remote markup as escaped plain text", () => {
    const dangerous = "<script>alert('xss')</script><img src=x onerror=alert(1)>";
    const wrapper = mount(ChecksumFilePreview, {
      props: {
        preview: {
          finding: { id: "finding", category: "wordpress-core-unexpected", severity: "attention", title: "Unexpected", detail: "File should not exist", path: "wp-admin/extra.php", checksumStatus: "unexpected" },
          fileName: "extra.php", relativePath: "wp-admin/extra.php", sizeBytes: dangerous.length, fileType: "php-bestand", extension: "php", textContent: dangerous, binary: false, truncated: false,
        },
      },
    });
    expect(wrapper.get(".file-preview-code").text()).toBe(dangerous);
    expect(wrapper.find("script").exists()).toBe(false);
    expect(wrapper.get(".file-preview-code code").html()).toContain("&lt;");
  });

  it("does not render binary bytes as text", () => {
    const wrapper = mount(ChecksumFilePreview, {
      props: {
        preview: {
          finding: { category: "wordpress-core-unexpected", severity: "attention", title: "Unexpected", detail: "File should not exist", checksumStatus: "unexpected" },
          fileName: "extra.bin", relativePath: "wp-admin/extra.bin", sizeBytes: 4, fileType: "bin-bestand", binary: true, truncated: false,
        },
      },
    });
    expect(wrapper.find("pre").exists()).toBe(false);
    expect(wrapper.text()).toContain("niet veilig als tekst");
  });

  it("keeps upload and modified-file previews read-only", () => {
    const wrapper = mount(ChecksumFilePreview, {
      props: {
        preview: {
          finding: { id: "finding", category: "uploads", severity: "attention", title: "PHP in uploads", detail: "Controleer het bestand", path: "wp-content/uploads/test.php" },
          fileName: "test.php", relativePath: "wp-content/uploads/test.php", sizeBytes: 20, fileType: "php-bestand", extension: "php", textContent: "<?php echo 'test';", binary: false, truncated: false,
        },
      },
    });

    expect(wrapper.text()).not.toContain("Checksum");
    expect(wrapper.text()).not.toContain("Bestand verwijderen");
    expect(wrapper.text()).toContain("<?php echo 'test';");
  });

  it("retains deletion for unexpected WordPress core files", () => {
    const wrapper = mount(ChecksumFilePreview, {
      props: {
        preview: {
          finding: { id: "finding", category: "wordpress-core-unexpected", severity: "attention", title: "Unexpected", detail: "File should not exist", path: "wp-admin/extra.php", checksumStatus: "unexpected" },
          fileName: "extra.php", relativePath: "wp-admin/extra.php", sizeBytes: 20, fileType: "php-bestand", extension: "php", textContent: "<?php echo 'test';", binary: false, truncated: false,
        },
      },
    });

    expect(wrapper.text()).toContain("Hoort niet aanwezig te zijn");
    expect(wrapper.text()).toContain("Bestand verwijderen");
  });

  it("highlights supported code without rendering Markdown", () => {
    const wrapper = mount(ChecksumFilePreview, {
      props: {
        preview: {
          finding: { id: "finding", category: "recent", severity: "info", title: "Gewijzigd", detail: "Recent gewijzigd", path: "README.md" },
          fileName: "README.md", relativePath: "README.md", sizeBytes: 24, fileType: "md-bestand", extension: "md", textContent: "# Heading\n\n**bold**", binary: false, truncated: false,
        },
      },
    });

    expect(wrapper.get(".file-preview-code code").attributes("data-syntax")).toBe("md");
    expect(wrapper.find(".hljs-section").exists()).toBe(true);
    expect(wrapper.find("h1").exists()).toBe(false);
    expect(wrapper.get(".file-preview-code").text()).toBe("# Heading\n\n**bold**");
    expect(wrapper.get('button[aria-pressed="true"]').text()).toContain("Raw");
    expect(wrapper.text()).toContain("Preview");
  });

  it("renders Markdown by default and keeps switching lossless", async () => {
    const content = "# Heading\n\n- Eerste\n- Tweede met [link](https://example.test)\n\nGebruik `inline()`.\n\n```js\nconst answer = 42;\n```";
    const wrapper = mount(ChecksumFilePreview, {
      props: {
        defaultMarkdownMode: "preview",
        preview: {
          finding: { id: "finding", category: "recent", severity: "info", title: "Gewijzigd", detail: "Recent gewijzigd", path: "README.md" },
          fileName: "README.md", relativePath: "README.md", sizeBytes: content.length, fileType: "md-bestand", extension: "md", textContent: content, binary: false, truncated: false,
        },
      },
    });

    expect(wrapper.get(".markdown-preview h1").text()).toBe("Heading");
    expect(wrapper.findAll(".markdown-preview li")).toHaveLength(2);
    expect(wrapper.get(".markdown-preview a").attributes("href")).toBe("https://example.test");
    expect(wrapper.get(".markdown-preview p code").text()).toBe("inline()");
    expect(wrapper.get(".markdown-preview pre code").text()).toContain("const answer = 42;");
    expect(wrapper.find(".file-preview").exists()).toBe(false);
    await wrapper.get(".markdown-preview a").trigger("click");
    expect(mockOpenExternalUrl).toHaveBeenCalledWith("https://example.test");

    await wrapper.get(".preview-mode-toggle button:first-child").trigger("click");
    expect(wrapper.get(".file-preview-code").text()).toBe(content);
    expect(wrapper.find(".markdown-preview").exists()).toBe(false);

    await wrapper.get(".preview-mode-toggle button:last-child").trigger("click");
    expect(wrapper.get(".markdown-preview h1").text()).toBe("Heading");
  });

  it("does not show Markdown controls for other file types", () => {
    const wrapper = mount(ChecksumFilePreview, {
      props: {
        defaultMarkdownMode: "preview",
        preview: {
          finding: { id: "finding", category: "recent", severity: "info", title: "Gewijzigd", detail: "Recent gewijzigd", path: "notes.txt" },
          fileName: "notes.txt", relativePath: "notes.txt", sizeBytes: 4, fileType: "txt-bestand", extension: "txt", textContent: "text", binary: false, truncated: false,
        },
      },
    });

    expect(wrapper.find(".preview-mode-toggle").exists()).toBe(false);
    expect(wrapper.find(".markdown-preview").exists()).toBe(false);
  });

  it("switches SVG files losslessly between highlighted source and a rendered preview", async () => {
    const content = `<!-- logo --><svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><defs><linearGradient id="paint"><stop offset="0" stop-color="#fff" /></linearGradient></defs><g fill="url(#paint)"><path d="M0 0h100v100z" /></g></svg>`;
    const wrapper = mount(ChecksumFilePreview, {
      props: {
        defaultMarkdownMode: "preview",
        preview: {
          finding: { id: "finding", category: "recent", severity: "info", title: "Gewijzigd", detail: "Recent gewijzigd", path: "logo.svg" },
          fileName: "logo.svg", relativePath: "logo.svg", sizeBytes: content.length, fileType: "svg-bestand", extension: "svg", textContent: content, binary: false, truncated: false,
        },
      },
    });

    expect(wrapper.find('.preview-mode-toggle[aria-label="SVG-weergave"]').exists()).toBe(true);
    expect(wrapper.get(".file-preview-code code").attributes("data-syntax")).toBe("svg");
    expect(wrapper.find(".hljs-tag").exists()).toBe(true);
    expect(wrapper.find(".hljs-attr").exists()).toBe(true);
    expect(wrapper.find(".hljs-comment").exists()).toBe(true);
    expect(wrapper.get(".file-preview-code").text()).toBe(content);

    await wrapper.get(".preview-mode-toggle button:last-child").trigger("click");
    expect(wrapper.find(".file-preview").exists()).toBe(false);
    expect(wrapper.get(".svg-preview img").attributes("src")).toMatch(/^data:image\/svg\+xml;charset=utf-8,/);
    expect(wrapper.emitted("close")).toBeUndefined();

    await wrapper.get('button[aria-label="Fullscreen openen"]').trigger("click");
    expect(wrapper.get(".preview-modal").classes()).toContain("fullscreen");
    expect(wrapper.find(".svg-preview img").exists()).toBe(true);

    await wrapper.get(".preview-mode-toggle button:first-child").trigger("click");
    expect(wrapper.get(".file-preview-code").text()).toBe(content);
    expect(wrapper.get(".preview-modal").classes()).toContain("fullscreen");
  });

  it("opens binary images in Raw and preserves their original data in Preview", async () => {
    const dataBase64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAAB";
    const wrapper = mount(ChecksumFilePreview, {
      props: {
        defaultMarkdownMode: "preview",
        preview: {
          finding: { id: "finding", category: "recent", severity: "info", title: "Gewijzigd", detail: "Recent gewijzigd", path: "pixel.png" },
          fileName: "pixel.png", relativePath: "pixel.png", sizeBytes: 24, fileType: "png-bestand", extension: "png", imageMimeType: "image/png", imageDataBase64: dataBase64, binary: true, truncated: false,
        },
      },
    });

    expect(wrapper.find('.preview-mode-toggle[aria-label="Afbeeldingsweergave"]').exists()).toBe(true);
    expect(wrapper.get('button[aria-pressed="true"]').text()).toContain("Raw");
    expect(wrapper.find(".binary-inspector").exists()).toBe(true);
    expect(wrapper.find(".hljs").exists()).toBe(false);
    expect(wrapper.find(".image-preview").exists()).toBe(false);

    await wrapper.get(".preview-mode-toggle button:last-child").trigger("click");
    expect(wrapper.get(".image-preview img").attributes("src")).toBe(`data:image/png;base64,${dataBase64}`);
    expect(wrapper.find(".binary-inspector").exists()).toBe(false);
    expect(wrapper.emitted("close")).toBeUndefined();

    await wrapper.get('button[aria-label="Fullscreen openen"]').trigger("click");
    expect(wrapper.get(".preview-modal").classes()).toContain("fullscreen");
    expect(wrapper.find(".image-preview img").exists()).toBe(true);

    await wrapper.get(".preview-mode-toggle button:first-child").trigger("click");
    expect(wrapper.find(".binary-inspector").exists()).toBe(true);
    expect(wrapper.get(".preview-modal").classes()).toContain("fullscreen");
  });

  it("shows readable and suspicious code hidden behind PNG data", () => {
    const pngEnd = String.fromCharCode(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0, 0, 0, 0);
    const dataBase64 = window.btoa(`${pngEnd}<?php eval(base64_decode($payload)); ?>`);
    const wrapper = mount(ChecksumFilePreview, {
      props: {
        preview: {
          finding: { id: "finding", category: "recent", severity: "warning", title: "Gewijzigd", detail: "Recent gewijzigd", path: "suspicious.png" },
          fileName: "suspicious.png", relativePath: "suspicious.png", sizeBytes: 61, fileType: "png-bestand", extension: "png", imageMimeType: "image/png", imageDataBase64: dataBase64, binary: true, truncated: false,
        },
      },
    });

    expect(wrapper.get(".readable-binary-text").text()).toContain("<?php eval(base64_decode($payload)); ?>");
    expect(wrapper.get(".binary-suspicious-list").text()).toContain("PHP-openingstag");
    expect(wrapper.get(".binary-suspicious-list").text()).toContain("extra bytes na PNG IEND");
    expect(wrapper.find(".hljs").exists()).toBe(false);
  });

  it("passes animated GIF data through unchanged", async () => {
    const dataBase64 = "R0lGODlhAQABAIAAAAAAAP///ywAAAAAAQABAAACAUwAOw==";
    const wrapper = mount(ChecksumFilePreview, {
      props: {
        preview: {
          finding: { id: "finding", category: "recent", severity: "info", title: "Gewijzigd", detail: "Recent gewijzigd", path: "animation.gif" },
          fileName: "animation.gif", relativePath: "animation.gif", sizeBytes: 34, fileType: "gif-bestand", extension: "gif", imageMimeType: "image/gif", imageDataBase64: dataBase64, binary: true, truncated: false,
        },
      },
    });

    await wrapper.get(".preview-mode-toggle button:last-child").trigger("click");
    expect(wrapper.get(".image-preview img").attributes("src")).toBe(`data:image/gif;base64,${dataBase64}`);
  });

  it("shows decompressed SVGZ source with SVG highlighting before Preview", async () => {
    const content = '<svg xmlns="http://www.w3.org/2000/svg"><!-- compressed --><path fill="red" d="M0 0h10v10z" /></svg>';
    const wrapper = mount(ChecksumFilePreview, {
      props: {
        preview: {
          finding: { id: "finding", category: "recent", severity: "info", title: "Gewijzigd", detail: "Recent gewijzigd", path: "logo.svgz" },
          fileName: "logo.svgz", relativePath: "logo.svgz", sizeBytes: 72, fileType: "svgz-bestand", extension: "svgz", textContent: content, imageMimeType: "image/svg+xml", binary: false, truncated: false,
        },
      },
    });

    expect(wrapper.get('button[aria-pressed="true"]').text()).toContain("Raw");
    expect(wrapper.get(".file-preview-code code").attributes("data-syntax")).toBe("svg");
    expect(wrapper.find(".hljs-comment").exists()).toBe(true);
    expect(wrapper.get(".file-preview-code").text()).toBe(content);

    await wrapper.get(".preview-mode-toggle button:last-child").trigger("click");
    expect(wrapper.get(".svg-preview img").attributes("src")).toMatch(/^data:image\/svg\+xml;charset=utf-8,/);
  });

  it("keeps unsupported text files as plain white text", () => {
    const content = "<script>not executable</script>\nplain text";
    const wrapper = mount(ChecksumFilePreview, {
      props: {
        preview: {
          finding: { id: "finding", category: "recent", severity: "info", title: "Gewijzigd", detail: "Recent gewijzigd", path: "notes.txt" },
          fileName: "notes.txt", relativePath: "notes.txt", sizeBytes: content.length, fileType: "txt-bestand", extension: "txt", textContent: content, binary: false, truncated: false,
        },
      },
    });

    expect(wrapper.get(".file-preview-code code").attributes("data-syntax")).toBe("plain");
    expect(wrapper.find(".file-preview .hljs").exists()).toBe(false);
    expect(wrapper.find("script").exists()).toBe(false);
    expect(wrapper.get(".file-preview-code").text()).toBe(content);
  });

  it("shows correctly sequenced line numbers for long files", () => {
    const content = Array.from({ length: 125 }, (_, index) => `regel ${index + 1}`).join("\n");
    const wrapper = mount(ChecksumFilePreview, {
      props: {
        preview: {
          finding: { id: "finding", category: "recent", severity: "info", title: "Gewijzigd", detail: "Recent gewijzigd", path: "large.log" },
          fileName: "large.log", relativePath: "large.log", sizeBytes: content.length, fileType: "log-bestand", extension: "log", textContent: content, binary: false, truncated: false,
        },
      },
    });

    const numbers = wrapper.get(".file-preview-line-numbers").text().split("\n");
    expect(numbers).toHaveLength(125);
    expect(numbers[0]).toBe("1");
    expect(numbers[124]).toBe("125");
    expect(wrapper.get(".file-preview-code").text()).toBe(content);
  });

  it("toggles fullscreen without replacing the file or losing the scroll position", async () => {
    const content = "<?php\necho 'test';";
    const wrapper = mount(ChecksumFilePreview, {
      props: {
        preview: {
          finding: { id: "finding", category: "recent", severity: "info", title: "Gewijzigd", detail: "Recent gewijzigd", path: "test.php" },
          fileName: "test.php", relativePath: "test.php", sizeBytes: content.length, fileType: "php-bestand", extension: "php", textContent: content, binary: false, truncated: false,
        },
      },
    });
    const scroller = wrapper.get(".file-preview").element as HTMLElement;
    scroller.scrollTop = 80;
    scroller.scrollLeft = 24;

    expect(wrapper.get(".preview-modal").classes()).not.toContain("fullscreen");
    await wrapper.get('button[aria-label="Fullscreen openen"]').trigger("click");
    expect(wrapper.get(".preview-modal").classes()).toContain("fullscreen");
    expect(scroller.scrollTop).toBe(80);
    expect(scroller.scrollLeft).toBe(24);
    expect(wrapper.get(".file-preview-code").text()).toBe(content);

    await wrapper.get('button[aria-label="Fullscreen verlaten"]').trigger("click");
    expect(wrapper.get(".preview-modal").classes()).not.toContain("fullscreen");
    expect(wrapper.get(".file-preview-code").text()).toBe(content);
    expect(window.document.body.style.overflow).toBe("hidden");
    expect(window.document.documentElement.style.overflow).toBe("hidden");
    wrapper.unmount();
    expect(window.document.body.style.overflow).toBe("");
    expect(window.document.documentElement.style.overflow).toBe("");
  });

  it("opens immediately in fullscreen when that is the saved default", () => {
    const wrapper = mount(ChecksumFilePreview, {
      props: {
        defaultFullscreen: true,
        preview: {
          finding: { id: "finding", category: "recent", severity: "info", title: "Gewijzigd", detail: "Recent gewijzigd", path: "test.js" },
          fileName: "test.js", relativePath: "test.js", sizeBytes: 12, fileType: "js-bestand", extension: "js", textContent: "const x = 1;", binary: false, truncated: false,
        },
      },
    });

    expect(wrapper.get(".preview-modal").classes()).toContain("fullscreen");
    expect(wrapper.get('button[aria-label="Fullscreen verlaten"]').attributes("title")).toBe("Fullscreen verlaten");
  });

  it.each([{ label: "normal", defaultFullscreen: false }, { label: "fullscreen", defaultFullscreen: true }])("closes a $label preview with Escape", async ({ defaultFullscreen }) => {
    const wrapper = mount(ChecksumFilePreview, {
      props: {
        defaultFullscreen,
        preview: {
          finding: { id: "finding", category: "recent", severity: "info", title: "Gewijzigd", detail: "Recent gewijzigd", path: "test.php" },
          fileName: "test.php", relativePath: "test.php", sizeBytes: 16, fileType: "php-bestand", extension: "php", textContent: "<?php echo 1;", binary: false, truncated: false,
        },
      },
    });

    window.dispatchEvent(new window.KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));
    await wrapper.vm.$nextTick();

    expect(wrapper.emitted("close")).toHaveLength(1);
  });
});
