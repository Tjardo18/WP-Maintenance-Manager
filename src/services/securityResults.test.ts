import { describe, expect, it } from "vitest";
import type { Finding, ScanCheck } from "../types";
import { filterSecurityFindings, noteworthyFindingCount, paginateSecurityFindings, sortSecurityFindings } from "./securityResults";

function finding(path: string, category: string, severity: Finding["severity"] = "info"): Finding {
  return { path, category, severity, title: path.split("/").slice(-1)[0]!, detail: `Controle van ${path}` };
}

function check(key: string, findings: Finding[]): ScanCheck {
  return { key, label: key, status: "warning", summary: "Test", findings };
}

describe("security result filtering", () => {
  it("hides normal plugin, theme and mu-plugin PHP by default", () => {
    const php = check("php_files", [
      finding("wp-content/plugins/shop/plugin.php", "plugins"),
      finding("wp-content/themes/theme/functions.php", "themes"),
      finding("wp-content/mu-plugins/custom.php", "mu-plugins"),
      finding("wp-content/uploads/2026/shell.php", "uploads", "attention"),
    ]);

    expect(filterSecurityFindings(php, { query: "", category: "all", showAllPhp: false })).toHaveLength(1);
    expect(filterSecurityFindings(php, { query: "", category: "all", showAllPhp: true })).toHaveLength(4);
    expect(noteworthyFindingCount(php)).toBe(1);
  });

  it("filters PHP and modified files by category and query", () => {
    const php = check("php_files", [
      finding("wp-content/uploads/a.jpg.php", "uploads", "attention"),
      finding("wp-content/cache/loader.php", "cache", "attention"),
      finding("wp-content/plugins/shop/plugin.php", "plugins"),
    ]);

    expect(filterSecurityFindings(php, { query: "jpg", category: "uploads", showAllPhp: true }).map((item) => item.path)).toEqual(["wp-content/uploads/a.jpg.php"]);
    expect(filterSecurityFindings(php, { query: "", category: "other", showAllPhp: true }).map((item) => item.path)).toEqual(["wp-content/cache/loader.php"]);
    expect(filterSecurityFindings(php, { query: "shop", category: "plugins", showAllPhp: true })).toHaveLength(1);
  });

  it("defaults to active findings while keeping ignored and trusted states discoverable", () => {
    const active = { ...finding("active.php", "root", "warning"), disposition: "active" as const };
    const ignored = { ...finding("ignored.php", "root", "critical"), disposition: "ignored" as const };
    const trusted = { ...finding("trusted.php", "root", "warning"), disposition: "trusted" as const };
    const changed = { ...finding("changed.php", "root", "warning"), disposition: "trusted_changed" as const };
    const findings = check("core_checksum", [active, ignored, trusted, changed]);

    expect(filterSecurityFindings(findings, { query: "", category: "all", showAllPhp: true }).map((item) => item.path)).toEqual(["active.php", "changed.php"]);
    expect(filterSecurityFindings(findings, { query: "", category: "all", disposition: "ignored", showAllPhp: true })).toEqual([ignored]);
    expect(filterSecurityFindings(findings, { query: "", category: "all", disposition: "trusted", showAllPhp: true })).toEqual([changed, trusted]);
    expect(noteworthyFindingCount(findings)).toBe(2);
  });

  it("sorts actionable findings before informational and handled findings", () => {
    const info = { ...finding("info.php", "root"), disposition: "active" as const };
    const warning = { ...finding("warning.php", "root", "warning"), disposition: "active" as const };
    const critical = { ...finding("critical.php", "root", "critical"), disposition: "active" as const };
    const problem = { ...finding("problem.php", "root", "problem"), disposition: "active" as const };
    const attention = { ...finding("attention.php", "root", "attention"), disposition: "active" as const };
    const changed = { ...finding("changed.php", "root", "warning"), disposition: "trusted_changed" as const };
    const ignored = { ...finding("ignored.php", "root", "critical"), disposition: "ignored" as const };
    const trusted = { ...finding("trusted.php", "root", "critical"), disposition: "trusted" as const };

    expect(sortSecurityFindings([info, warning, ignored, changed, critical, trusted, attention, problem]).map((item) => item.path)).toEqual([
      "critical.php",
      "problem.php",
      "warning.php",
      "attention.php",
      "changed.php",
      "info.php",
      "ignored.php",
      "trusted.php",
    ]);
  });

  it("keeps the original order within the same priority group", () => {
    const first = finding("first.php", "root", "warning");
    const second = finding("second.php", "root", "attention");
    const third = finding("third.php", "root", "warning");

    expect(sortSecurityFindings([first, second, third])).toEqual([first, second, third]);
  });

  it("paginates thousands of findings without copying them into the visible page", () => {
    const findings = Array.from({ length: 5_000 }, (_, index) => finding(`wp-content/uploads/${index}.php`, "uploads", "attention"));
    const first = paginateSecurityFindings(findings, 1, 25);
    const last = paginateSecurityFindings(findings, 999, 100);

    expect(first.items).toHaveLength(25);
    expect(first).toMatchObject({ page: 1, pageCount: 200, start: 1, end: 25, total: 5_000 });
    expect(last.items).toHaveLength(100);
    expect(last).toMatchObject({ page: 50, pageCount: 50, start: 4_901, end: 5_000 });
    expect(paginateSecurityFindings([], 1, 25)).toMatchObject({ items: [], page: 1, pageCount: 1, start: 0, end: 0, total: 0 });
  });
});
