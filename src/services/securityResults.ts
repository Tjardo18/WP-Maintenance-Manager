import type { Finding, ScanCheck } from "../types";

export type SecurityCategory = "all" | "noteworthy" | "uploads" | "other" | "plugins" | "themes" | "core" | "root";
export type SecurityDisposition = "active" | "ignored" | "trusted" | "all";

export interface SecurityFindingFilter {
  query: string;
  category: SecurityCategory;
  disposition?: SecurityDisposition;
  showAllPhp: boolean;
}

export function isNoteworthyFinding(finding: Finding) {
  return ["active", "expired_exception", "trusted_changed"].includes(finding.disposition ?? "active") && finding.severity !== "info";
}

export function noteworthyFindingCount(check: ScanCheck) {
  return check.findings.filter(isNoteworthyFinding).length;
}

function normalizedCategory(finding: Finding) {
  return finding.category.trim().toLocaleLowerCase("nl-NL");
}

function belongsToCategory(finding: Finding, category: SecurityCategory) {
  if (category === "all") return true;
  if (category === "noteworthy") return isNoteworthyFinding(finding);

  const value = normalizedCategory(finding);
  if (category === "plugins") return value === "plugins" || value === "mu-plugins";
  if (category === "themes") return value === "themes";
  if (category === "uploads") return value === "uploads";
  if (category === "core") return value === "core" || value === "wordpress-core";
  if (category === "root") return value === "root" || value === "wp-content-root";

  const known = new Set(["plugins", "mu-plugins", "themes", "uploads", "core", "wordpress-core", "root", "wp-content-root"]);
  return !known.has(value);
}

function belongsToDisposition(finding: Finding, disposition: SecurityDisposition) {
  if (disposition === "all") return true;
  const value = finding.disposition ?? "active";
  if (disposition === "ignored") return value === "ignored";
  if (disposition === "trusted") return ["trusted", "trusted_changed", "trusted_missing"].includes(value);
  return ["active", "expired_exception", "trusted_changed"].includes(value);
}

export function filterSecurityFindings(check: ScanCheck, filter: SecurityFindingFilter) {
  const query = filter.query.trim().toLocaleLowerCase("nl-NL");
  return check.findings.filter((finding) => {
    if (!belongsToDisposition(finding, filter.disposition ?? "active")) return false;
    if (check.key === "php_files" && !filter.showAllPhp && !isNoteworthyFinding(finding)) return false;
    if (!belongsToCategory(finding, filter.category)) return false;
    if (!query) return true;

    return [finding.path, finding.title, finding.detail, finding.category]
      .filter(Boolean)
      .some((value) => value!.toLocaleLowerCase("nl-NL").includes(query));
  });
}

export function paginateSecurityFindings(findings: Finding[], page: number, pageSize: number) {
  const safePageSize = [25, 50, 100].includes(pageSize) ? pageSize : 25;
  const pageCount = Math.max(1, Math.ceil(findings.length / safePageSize));
  const safePage = Math.max(1, Math.min(pageCount, Math.trunc(page) || 1));
  const start = (safePage - 1) * safePageSize;
  return {
    items: findings.slice(start, start + safePageSize),
    page: safePage,
    pageCount,
    start: findings.length ? start + 1 : 0,
    end: Math.min(start + safePageSize, findings.length),
    total: findings.length,
  };
}
