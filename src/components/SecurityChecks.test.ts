import { mount } from "@vue/test-utils";
import { describe, expect, it, vi } from "vitest";
import type { Finding, ScanCheck } from "../types";
import SecurityChecks from "./SecurityChecks.vue";

function finding(path: string, category: string, severity: Finding["severity"] = "info"): Finding {
  return { path, category, severity, title: path.split("/").slice(-1)[0]!, detail: `Details voor ${path}` };
}

const phpFindings = [
  ...Array.from({ length: 10_000 }, (_, index) => finding(`wp-content/plugins/demo/file-${index}.php`, "plugins")),
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

  it("uses distinct success, warning and failure icons", () => {
    const statusChecks: ScanCheck[] = [
      { key: "ok", label: "Geslaagd", status: "success", summary: "In orde", findings: [] },
      { key: "warn", label: "Waarschuwing", status: "warning", summary: "Iets gevonden", findings: [] },
      { key: "fail", label: "Mislukt", status: "failed", summary: "Niet uitgevoerd", findings: [] },
    ];
    const wrapper = mount(SecurityChecks, { props: { checks: statusChecks, finishedAt: "2026-09-07T11:42:00Z", truncated: false, isLatestScan: true, selectedFindingIds: [], showSummary: true } });
    const icons = wrapper.findAll(".security-summary-icon");

    expect(icons[0]!.get("[data-status-icon]").attributes("data-status-icon")).toBe("success");
    expect(icons[1]!.get("[data-status-icon]").attributes("data-status-icon")).toBe("warning");
    expect(icons[2]!.get("[data-status-icon]").attributes("data-status-icon")).toBe("failed");
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
    vi.useFakeTimers();
    const wrapper = render();
    await wrapper.get(".security-toggle input").setValue(true);
    expect(wrapper.findAll(".security-findings .finding")).toHaveLength(25);
    expect(wrapper.text()).toContain("1–25 van 10002");

    await wrapper.get(".security-search input").setValue("file-999.php");
    await vi.advanceTimersByTimeAsync(200);
    expect(wrapper.findAll(".security-findings .finding")).toHaveLength(1);
    expect(wrapper.text()).toContain("file-999.php");

    await wrapper.get(".security-search input").setValue("");
    await vi.advanceTimersByTimeAsync(200);
    await wrapper.get(".security-pagination button:last-child").trigger("click");
    expect(wrapper.text()).toContain("26–50 van 10002");
    expect(wrapper.findAll(".security-findings .finding")).toHaveLength(25);
    expect(wrapper.findAll(".finding").length).toBeLessThanOrEqual(25);
    vi.useRealTimers();
  });

  it("offers exact ignore, temporary ignore and hash trust actions for an existing file", async () => {
    const actionable: ScanCheck[] = [{ key: "core_checksum", label: "Core", status: "warning", summary: "Afwijking", findings: [{ id: "finding-1", category: "wordpress-core-unexpected", severity: "warning", title: "Onverwacht", detail: "Controleer dit bestand", path: "wp-content/custom-loader.php", checksumStatus: "unexpected", disposition: "active" }] }];
    const wrapper = mount(SecurityChecks, { props: { checks: actionable, finishedAt: "2026-09-07T11:42:00Z", truncated: false, isLatestScan: true, selectedFindingIds: [], showSummary: true } });
    const buttons = wrapper.findAll(".finding-actions button");
    await buttons.find((button) => button.text().includes("Melding negeren"))!.trigger("click");
    await buttons.find((button) => button.text().includes("Tijdelijk negeren"))!.trigger("click");
    await buttons.find((button) => button.text().includes("Bestand vertrouwen"))!.trigger("click");
    expect(wrapper.emitted("ignore")).toEqual([[actionable[0]!.findings[0], false], [actionable[0]!.findings[0], true]]);
    expect(wrapper.emitted("trust")).toEqual([[actionable[0]!.findings[0]]]);
  });

  it("shows vulnerability context and uses the existing typed update action", async () => {
    const vulnerability: Finding = {
      id: "vulnerability-finding",
      category: "vulnerability",
      severity: "warning",
      title: "Example Plugin: issue",
      detail: "Geïnstalleerde versie is kwetsbaar.",
      vulnerability: {
        provider: "wordfence", vulnerabilityId: "vulnerability-1", title: "Stored XSS", informational: false,
        cvssScore: 8.1, cvssRating: "High", cve: "CVE-2026-1234", researchers: [], references: [],
        softwareType: "plugin", softwareSlug: "example-plugin", softwareName: "Example Plugin",
        affectedRanges: [], patched: true, patchedVersions: ["1.2.4"], installedVersion: "1.2.3",
        installedStatus: "inactive", updateVersion: "1.2.4", matchedRanges: ["1.0 - 1.2.3"],
      },
    };
    const update = { kind: "plugin" as const, slug: "example-plugin", name: "Example Plugin", currentVersion: "1.2.3", newVersion: "1.2.4", status: "available" };
    const vulnerabilityChecks: ScanCheck[] = [{ key: "vulnerabilities", label: "Kwetsbaarheden", status: "warning", summary: "1 bekende kwetsbaarheid", findings: [vulnerability] }];
    const wrapper = mount(SecurityChecks, { props: { checks: vulnerabilityChecks, updates: [update], finishedAt: "2026-09-07T11:42:00Z", truncated: false, isLatestScan: true, selectedFindingIds: [], showSummary: true } });
    expect(wrapper.text()).toContain("1 hoog");
    expect(wrapper.text()).toContain("Inactief");
    const buttons = wrapper.findAll("button");
    await buttons.find((button) => button.text().includes("Details"))?.trigger("click");
    await buttons.find((button) => button.text().trim() === "Bijwerken")?.trigger("click");
    expect(wrapper.emitted("details")).toEqual([[vulnerability]]);
    expect(wrapper.emitted("update")).toEqual([[update]]);
  });
});
