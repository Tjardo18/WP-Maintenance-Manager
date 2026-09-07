import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";
import type { Finding, ScanCheck } from "../types";
import SecurityChecks from "./SecurityChecks.vue";

function finding(path: string, category: string, severity: Finding["severity"] = "info"): Finding {
  return { path, category, severity, title: path.split("/").slice(-1)[0]!, detail: `Details voor ${path}` };
}

const phpFindings = [
  ...Array.from({ length: 1_000 }, (_, index) => finding(`wp-content/plugins/demo/file-${index}.php`, "plugins")),
  finding("wp-content/uploads/2026/a.jpg.php", "uploads", "attention"),
  finding("wp-content/cache/loader.php", "cache", "attention"),
];

const checks: ScanCheck[] = [
  { key: "php_files", label: "PHP in wp-content", status: "warning", summary: "2 opvallende bestanden", findings: phpFindings },
  { key: "modified_files", label: "Gewijzigde bestanden — 30 dagen", status: "success", summary: "60 bestanden gewijzigd", findings: Array.from({ length: 60 }, (_, index) => finding(`wp-content/themes/demo/${index}.php`, "themes")) },
  { key: "permissions", label: "Bestandsrechten", status: "success", summary: "Geen problemen", findings: [] },
];

function render() {
  return mount(SecurityChecks, { props: { checks, finishedAt: "2026-09-07T11:42:00Z", truncated: false, isLatestScan: true, selectedFindingIds: [], showSummary: true } });
}

describe("SecurityChecks", () => {
  it("starts compact with only the first attention section open", () => {
    const wrapper = render();

    expect(wrapper.findAll(".security-accordion-body")).toHaveLength(1);
    expect(wrapper.get("#security-check-php_files").attributes("class")).toContain("security-accordion");
    expect(wrapper.findAll(".security-findings .finding")).toHaveLength(2);
    expect(wrapper.text()).toContain("2 aandachtspunten");
    expect(wrapper.text()).toContain("In orde");
  });

  it("opens and closes sections and navigates from the summary", async () => {
    const wrapper = render();
    await wrapper.get("#security-check-php_files .security-accordion-header").trigger("click");
    expect(wrapper.findAll(".security-accordion-body")).toHaveLength(0);

    const modifiedSummary = wrapper.findAll(".security-summary-grid button").find((button) => button.text().includes("Gewijzigde bestanden"));
    expect(modifiedSummary).toBeDefined();
    await modifiedSummary!.trigger("click");
    expect(wrapper.find("#security-check-modified_files .security-accordion-body").exists()).toBe(true);
  });

  it("filters and paginates thousands of findings without creating a giant DOM", async () => {
    const wrapper = render();
    await wrapper.get(".security-toggle input").setValue(true);
    expect(wrapper.findAll(".security-findings .finding")).toHaveLength(25);
    expect(wrapper.text()).toContain("1–25 van 1002");

    await wrapper.get(".security-search input").setValue("file-999.php");
    expect(wrapper.findAll(".security-findings .finding")).toHaveLength(1);
    expect(wrapper.text()).toContain("file-999.php");

    await wrapper.get(".security-search input").setValue("");
    await wrapper.get(".security-pagination button:last-child").trigger("click");
    expect(wrapper.text()).toContain("26–50 van 1002");
    expect(wrapper.findAll(".security-findings .finding")).toHaveLength(25);
    expect(wrapper.findAll(".finding").length).toBeLessThanOrEqual(25);
  });
});
