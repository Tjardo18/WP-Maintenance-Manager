import { describe, expect, it } from "vitest";
import type { Finding, ScanCheck } from "../types";
import { filterSecurityFindings, noteworthyFindingCount, paginateSecurityFindings } from "./securityResults";

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
