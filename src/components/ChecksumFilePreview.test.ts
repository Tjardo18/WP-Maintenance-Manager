import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";
import ChecksumFilePreview from "./ChecksumFilePreview.vue";

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
    expect(wrapper.find("pre").text()).toBe(dangerous);
    expect(wrapper.find("script").exists()).toBe(false);
    expect(wrapper.html()).toContain("&lt;script&gt;");
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
});
