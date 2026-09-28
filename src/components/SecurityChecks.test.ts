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

  it("formats large recent-change counts as informational inventory", () => {
    const modifiedChecks: ScanCheck[] = [{
      key: "modified_files",
      label: "Gewijzigde bestanden afgelopen 30 dagen",
      status: "success",
      summary: "1284 gewijzigde bestanden gevonden.",
      findings: Array.from({ length: 1_284 }, (_, index) => finding(`wp-content/cache/${index}.txt`, "other")),
    }];

    const wrapper = mount(SecurityChecks, { props: { checks: modifiedChecks, finishedAt: "2026-09-28T08:40:00Z", truncated: false, isLatestScan: true, selectedFindingIds: [], showSummary: true } });

    expect(wrapper.get(".security-summary-grid button").text()).toContain("1.284 gewijzigd");
    expect(wrapper.text()).toContain("Geen aandachtspunten");
  });

  it("shows recent changes as informational data with one explanatory notice", async () => {
    const legacyDetail = "Gewijzigd op Unix-tijd 1789627074.9670225510 met permissiemodus 644. Een recente wijziging is niet automatisch kwaadaardig.";
    const modifiedChecks: ScanCheck[] = [{
      key: "modified_files",
      label: "Gewijzigde bestanden",
      status: "success",
      summary: "2 bestanden gewijzigd",
      findings: [
        { ...finding("wp-content/themes/demo/one.php", "themes"), detail: legacyDetail },
        { ...finding("wp-content/themes/demo/two.php", "themes"), detail: legacyDetail },
      ],
    }];
    const wrapper = mount(SecurityChecks, { props: { checks: modifiedChecks, finishedAt: "2026-09-17T08:40:00Z", truncated: false, isLatestScan: true, selectedFindingIds: [], showSummary: false } });
    await wrapper.get("#security-check-modified_files .security-accordion-header").trigger("click");

    expect(wrapper.findAll(".modified-files-context")).toHaveLength(1);
    expect(wrapper.get(".modified-files-context").text()).toBe("Een recente wijziging is op zichzelf informatief. Als voor hetzelfde bestand een concrete securitybevinding bestaat, toont het label hier de ernst daarvan.");
    expect(wrapper.findAll(".modified-file-heading>span").map((badge) => badge.text())).toEqual(["Informatief", "Informatief"]);
    expect(wrapper.find(".security-disposition-tabs").exists()).toBe(false);
    expect(wrapper.text()).not.toContain("Melding negeren");
    expect(wrapper.text()).not.toContain("Bestand vertrouwen");
    expect(wrapper.text()).not.toContain("Unix-tijd");
    expect(wrapper.text()).not.toContain("Een recente wijziging is niet automatisch kwaadaardig.");
    expect(wrapper.findAll(".finding-copy p").map((paragraph) => paragraph.text())).toEqual([
      "Gewijzigd op 17 september 2026 om 08:37 uur en heeft permissies 644.",
      "Gewijzigd op 17 september 2026 om 08:37 uur en heeft permissies 644.",
    ]);
  });

  it("shows and prioritizes the severity of a related security finding for a modified file", async () => {
    const safeChange = finding("wp-content/cache/safe.php", "other");
    const criticalChange = finding("wp-admin/includes/ajax-actions.php", "core");
    const correlatedChecks: ScanCheck[] = [
      {
        key: "core_checksum",
        label: "WordPress core",
        status: "warning",
        summary: "1 gewijzigd bestand",
        findings: [{ ...criticalChange, severity: "critical", checksumStatus: "modified", disposition: "active" }],
      },
      {
        key: "modified_files",
        label: "Gewijzigde bestanden",
        status: "success",
        summary: "2 bestanden gewijzigd",
        findings: [safeChange, criticalChange],
      },
    ];
    const wrapper = mount(SecurityChecks, { props: { checks: correlatedChecks, finishedAt: "2026-09-28T08:40:00Z", truncated: false, isLatestScan: true, selectedFindingIds: [], showSummary: false } });
    await wrapper.get("#security-check-modified_files .security-accordion-header").trigger("click");

    const rows = wrapper.findAll("#security-check-modified_files .finding");
    expect(rows[0]!.text()).toContain("ajax-actions.php");
    expect(rows[0]!.get(".modified-file-heading>span").text()).toBe("Kritiek");
    expect(rows[0]!.get(".modified-file-heading>span").classes()).toContain("critical");
    expect(rows[1]!.get(".modified-file-heading>span").text()).toBe("Informatief");
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

  it("opens files from PHP uploads and recently modified files", async () => {
    const uploadFinding = { ...finding("wp-content/uploads/2026/suspicious.php", "uploads", "attention"), id: "upload-finding" };
    const modifiedFinding = { ...finding("wp-content/themes/demo/functions.php", "themes"), id: "modified-finding" };
    const previewChecks: ScanCheck[] = [
      { key: "php_uploads", label: "PHP in uploads", status: "warning", summary: "1 bestand gevonden", findings: [uploadFinding] },
      { key: "modified_files", label: "Gewijzigde bestanden", status: "success", summary: "1 bestand gewijzigd", findings: [modifiedFinding] },
    ];
    const wrapper = mount(SecurityChecks, { props: { checks: previewChecks, finishedAt: "2026-09-07T11:42:00Z", truncated: false, isLatestScan: true, selectedFindingIds: [], showSummary: true } });

    await wrapper.get("#security-check-php_uploads .finding-actions .secondary").trigger("click");
    await wrapper.get("#security-check-modified_files .security-accordion-header").trigger("click");
    const modifiedPreview = wrapper.findAll("#security-check-modified_files .finding-actions button").find((button) => button.text().includes("Bekijken"));
    await modifiedPreview!.trigger("click");

    expect(wrapper.emitted("preview")).toEqual([[uploadFinding], [modifiedFinding]]);
    expect(wrapper.findAll(".finding-actions button").some((button) => button.text().includes("Verwijderen"))).toBe(false);
  });

  it("previews existing core checksum deviations but not missing files or scan errors", async () => {
    const modified = { ...finding("wp-includes/PHPMailer/PHPMailer.php", "wordpress-core-modified", "critical"), id: "modified-core", checksumStatus: "modified" as const };
    const unexpected = { ...finding("wp-admin/unexpected.php", "wordpress-core-unexpected", "warning"), id: "unexpected-core", checksumStatus: "unexpected" as const };
    const missing = { ...finding("wp-includes/missing.php", "wordpress-core-missing"), id: "missing-core", checksumStatus: "missing" as const };
    const scanError = { ...finding("wp-includes/unreadable.php", "wordpress-core-scan-error", "warning"), id: "scan-error-core", checksumStatus: "scan_error" as const };
    const coreChecks: ScanCheck[] = [{ key: "core_checksum", label: "WordPress core", status: "warning", summary: "Afwijkingen", findings: [missing, scanError, modified, unexpected] }];
    const wrapper = mount(SecurityChecks, { props: { checks: coreChecks, finishedAt: "2026-09-28T08:40:00Z", truncated: false, isLatestScan: true, selectedFindingIds: [], showSummary: true } });

    const rows = wrapper.findAll("#security-check-core_checksum .finding");
    const modifiedRow = rows.find((row) => row.text().includes("PHPMailer.php"));
    const unexpectedRow = rows.find((row) => row.text().includes("unexpected.php"));
    const missingRow = rows.find((row) => row.text().includes("missing.php"));
    const scanErrorRow = rows.find((row) => row.text().includes("unreadable.php"));

    await modifiedRow!.get("button").trigger("click");
    await unexpectedRow!.findAll("button").find((button) => button.text().includes("Bekijken"))!.trigger("click");
    expect(missingRow!.text()).not.toContain("Bekijken");
    expect(scanErrorRow!.text()).not.toContain("Bekijken");
    expect(wrapper.emitted("preview")).toEqual([[modified], [unexpected]]);
  });

  it("does not offer file previews for old scans or unrelated checks", async () => {
    const unrelated: ScanCheck[] = [{ key: "permissions", label: "Bestandsrechten", status: "warning", summary: "Controleer", findings: [{ ...finding("wp-content/test.php", "other"), id: "permission-finding" }] }];
    const current = mount(SecurityChecks, { props: { checks: unrelated, finishedAt: "2026-09-07T11:42:00Z", truncated: false, isLatestScan: true, selectedFindingIds: [], showSummary: true } });
    const historical = mount(SecurityChecks, { props: { checks: [{ key: "php_uploads", label: "PHP in uploads", status: "warning", summary: "Controleer", findings: [{ ...finding("wp-content/uploads/test.php", "uploads"), id: "upload-finding" }] }], finishedAt: "2026-09-06T11:42:00Z", truncated: false, isLatestScan: false, selectedFindingIds: [], showSummary: true } });

    expect(current.text()).not.toContain("Bekijken");
    expect(historical.text()).not.toContain("Bekijken");
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
