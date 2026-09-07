import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { AppSettings, AuditEvent, AuthStatus, BulkScanProgress, BulkScanResult, ChecksumDeleteResult, ConnectionTestResult, CoreOperationInfo, CoreOperationResult, FilePreview, LoginResult, MaintenanceRun, MaintenanceStep, PasswordChangeInput, ScanResult, Site, SiteInput, UpdateItem, WordPressUserDeleteInput, WordPressUsersData, WordPressUserUpdateInput, WpCliCatalog } from "../types";
import { demoHistory, demoScan, demoSites, demoUpdates, demoUsers } from "./fixtures";

const isTauri = () => "__TAURI_INTERNALS__" in window;
let browserSites = structuredClone(demoSites);
const browserUsers = structuredClone(demoUsers);
let sessionToken: string | undefined;
let browserConfigured = false;
let browserPasswordHash = "";
let browserIdleMinutes = 15;

async function call<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  if (!sessionToken) throw { category: "locked", userMessage: "WP Maintenance Manager is vergrendeld.", retryable: false };
  try { return await invoke<T>(command, { ...args, sessionToken }); }
  catch (cause) {
    const category = typeof cause === "object" && cause !== null && "category" in cause ? String((cause as { category: unknown }).category) : "";
    if (["locked", "session_expired", "invalid_session", "setup_required"].includes(category)) {
      sessionToken = undefined;
      window.dispatchEvent(new CustomEvent("wpmm:locked", { detail: cause }));
    }
    throw cause;
  }
}

async function publicCall<T>(command: string, args: Record<string, unknown> = {}): Promise<T> { return invoke<T>(command, args); }
async function demoHash(password: string): Promise<string> { const bytes = new TextEncoder().encode(password); const hash = await crypto.subtle.digest("SHA-256", bytes); return Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join(""); }

export const authApi = {
  setSessionToken(token?: string) { sessionToken = token; },
  async status(): Promise<AuthStatus> { if (isTauri()) return publicCall("get_auth_status", { sessionToken: sessionToken ?? null }); return { configured: browserConfigured, authenticated: Boolean(sessionToken), idleTimeoutMinutes: browserIdleMinutes, retryAfterSeconds: 0 }; },
  async setup(password: string): Promise<LoginResult> { if (isTauri()) { const result = await publicCall<LoginResult>("setup_password", { password }); sessionToken = result.sessionToken; return result; } if (browserConfigured) throw new Error("De applicatiebeveiliging is al ingesteld."); browserPasswordHash = await demoHash(password); browserConfigured = true; sessionToken = crypto.randomUUID(); return { sessionToken, idleTimeoutMinutes: browserIdleMinutes }; },
  async login(password: string): Promise<LoginResult> { if (isTauri()) { const result = await publicCall<LoginResult>("login", { password }); sessionToken = result.sessionToken; return result; } if (await demoHash(password) !== browserPasswordHash) throw { category: "invalid_password", userMessage: "Het wachtwoord is niet correct.", retryable: false }; sessionToken = crypto.randomUUID(); return { sessionToken, idleTimeoutMinutes: browserIdleMinutes }; },
  async touch(): Promise<void> { if (isTauri()) await call("touch_session"); },
  async lock(): Promise<void> { try { if (isTauri() && sessionToken) await call("lock_app"); } finally { sessionToken = undefined; } },
  async changePassword(input: PasswordChangeInput): Promise<void> { if (isTauri()) await call("change_password", { input }); else { if (await demoHash(input.currentPassword) !== browserPasswordHash) throw { category: "invalid_password", userMessage: "Het huidige wachtwoord is niet correct.", retryable: false }; browserPasswordHash = await demoHash(input.newPassword); } sessionToken = undefined; },
  async setIdleTimeout(minutes: number): Promise<AuthStatus> { if (isTauri()) return call("set_idle_timeout", { minutes }); browserIdleMinutes = minutes; return { configured: true, authenticated: true, idleTimeoutMinutes: minutes, retryAfterSeconds: 0 }; },
};

export const appApi = {
  async getWpCliCatalog(): Promise<WpCliCatalog> { return isTauri() ? call("get_wp_cli_catalog") : { available: false, rootCommandCount: 0, totalCommandCount: 0, globalParameterCount: 0, globalParameters: [], commands: [], error: "WP-CLI commandodatabase niet gevonden", technicalDetails: "De browserdemo laadt geen lokale Tauri-resources." }; },
  async listSites(): Promise<Site[]> { return isTauri() ? call("list_sites") : structuredClone(browserSites); },
  async saveSite(input: SiteInput): Promise<Site> {
    if (isTauri()) return call("save_site", { input });
    const now = new Date().toISOString();
    const existing = browserSites.find((site) => site.id === input.id);
    const saved: Site = { ...existing, ...input, id: input.id ?? crypto.randomUUID(), status: existing?.status ?? "unscanned", updateCount: existing?.updateCount ?? 0, createdAt: existing?.createdAt ?? now, updatedAt: now };
    delete (saved as Site & { credentialSecret?: string }).credentialSecret;
    browserSites = existing ? browserSites.map((site) => site.id === saved.id ? saved : site) : [...browserSites, saved];
    return structuredClone(saved);
  },
  async deleteSite(id: string): Promise<void> { if (isTauri()) await call("delete_site", { id }); else browserSites = browserSites.filter((site) => site.id !== id); },
  async testConnection(input: SiteInput): Promise<ConnectionTestResult> {
    if (isTauri()) return call("test_connection", { input });
    await new Promise((resolve) => setTimeout(resolve, 600));
    return { success: true, requiresHostKeyAcceptance: false, fingerprint: "SHA256:demo-fingerprint", wordpressVersion: "6.8.2", phpVersion: "8.3.12", wpCliVersion: "2.12.0", detectedUrl: input.url, steps: ["SSH bereikbaar", "Host fingerprint gecontroleerd", "Authenticatie geslaagd", "WordPress-pad gevonden", "WP-CLI werkt", "WordPress-installatie gevonden", "Database bereikbaar"].map((label, index) => ({ key: String(index), label, status: "success" })) };
  },
  async acceptHostKey(siteId: string, fingerprint: string): Promise<void> { if (isTauri()) await call("accept_host_key", { siteId, fingerprint }); },
  async scanSite(siteId: string, modifiedDays = 30): Promise<ScanResult> { return isTauri() ? call("scan_site", { siteId, modifiedDays }) : { ...structuredClone(demoScan), id: crypto.randomUUID(), siteId }; },
  async listScans(siteId: string): Promise<ScanResult[]> { return isTauri() ? call("list_scan_runs", { siteId }) : [{ ...structuredClone(demoScan), siteId }]; },
  async previewChecksumFinding(siteId: string, findingId: string): Promise<FilePreview> { if (isTauri()) return call("preview_checksum_finding", { siteId, findingId }); const finding = demoScan.checks.flatMap((check) => check.findings).find((item) => item.id === findingId); if (!finding?.path) throw new Error("Checksumfinding niet gevonden."); const parts = finding.path.split("/"); return { finding: structuredClone(finding), fileName: parts[parts.length - 1] ?? finding.path, relativePath: finding.path, sizeBytes: 54, modifiedAt: new Date().toISOString(), fileType: "php-bestand", extension: "php", textContent: "<script>alert('preview wordt als tekst getoond')</script>\n<?php // demo ?>", binary: false, truncated: false }; },
  async deleteChecksumFinding(siteId: string, findingId: string): Promise<ChecksumDeleteResult> { if (isTauri()) return call("delete_checksum_finding", { siteId, findingId }); const path = demoScan.checks.flatMap((check) => check.findings).find((item) => item.id === findingId)?.path; return { requested: 1, deleted: path ? 1 : 0, deletedPaths: path ? [path] : [], failures: [], scan: { ...structuredClone(demoScan), siteId } }; },
  async deleteChecksumFindings(siteId: string, findingIds: string[]): Promise<ChecksumDeleteResult> { if (isTauri()) return call("delete_checksum_findings", { siteId, findingIds }); const paths = demoScan.checks.flatMap((check) => check.findings).filter((item) => item.id && findingIds.includes(item.id)).flatMap((item) => item.path ? [item.path] : []); return { requested: findingIds.length, deleted: paths.length, deletedPaths: paths, failures: [], scan: { ...structuredClone(demoScan), siteId } }; },
  async listWordPressUsers(siteId: string): Promise<WordPressUsersData> { return isTauri() ? call("list_wordpress_users", { siteId }) : structuredClone(browserUsers); },
  async updateWordPressUser(siteId: string, input: WordPressUserUpdateInput): Promise<WordPressUsersData> { if (isTauri()) return call("update_wordpress_user", { siteId, input }); browserUsers.users = browserUsers.users.map((user) => user.id === input.userId ? { ...user, displayName: input.displayName, email: input.email, roles: input.role ? [input.role] : user.roles } : user); return structuredClone(browserUsers); },
  async deleteWordPressUser(siteId: string, input: WordPressUserDeleteInput): Promise<WordPressUsersData> { if (isTauri()) return call("delete_wordpress_user", { siteId, input }); browserUsers.users = browserUsers.users.filter((user) => user.id !== input.userId); return structuredClone(browserUsers); },
  async inspectCoreOperation(siteId: string): Promise<CoreOperationInfo> { if (isTauri()) return call("inspect_core_operation", { siteId }); const currentVersion = browserSites.find((site) => site.id === siteId)?.wordpressVersion ?? "6.8.2"; return { currentVersion, locale: "nl_NL", wordpressPath: browserSites.find((site) => site.id === siteId)?.wordpressPath ?? "/var/www/html", availableVersion: demoUpdates.find((update) => update.kind === "core")?.newVersion, diskAvailableMb: 2048 }; },
  async repairWordPressCore(siteId: string): Promise<CoreOperationResult> { if (isTauri()) return call("repair_wordpress_core", { siteId }); const run = { ...structuredClone(demoHistory[0]), id: crypto.randomUUID(), siteId, beforeVersions: "WordPress 6.8.2 · locale nl_NL", afterVersions: "WordPress 6.8.2 · core hersteld" }; return { run, scan: { ...structuredClone(demoScan), siteId }, updatesAfter: structuredClone(demoUpdates), currentVersion: "6.8.2" }; },
  async updateWordPressCore(siteId: string): Promise<CoreOperationResult> { if (isTauri()) return call("update_wordpress_core", { siteId }); const run = { ...structuredClone(demoHistory[0]), id: crypto.randomUUID(), siteId, beforeVersions: "WordPress 6.8.1", afterVersions: "WordPress 6.8.2" }; return { run, scan: { ...structuredClone(demoScan), siteId }, updatesAfter: structuredClone(demoUpdates.filter((update) => update.kind !== "core")), currentVersion: "6.8.2" }; },
  async checkUpdates(siteId: string): Promise<UpdateItem[]> { return isTauri() ? call("check_updates", { siteId }) : structuredClone(demoUpdates); },
  async runUpdate(siteId: string, kind: string, slug?: string): Promise<void> { if (isTauri()) await call("run_update", { siteId, kind, slug }); else await new Promise((resolve) => setTimeout(resolve, 700)); },
  async runMaintenance(siteId: string): Promise<MaintenanceRun> { return isTauri() ? call("run_maintenance", { siteId }) : { ...structuredClone(demoHistory[0]), id: crypto.randomUUID(), siteId }; },
  async listHistory(siteId?: string): Promise<MaintenanceRun[]> { return isTauri() ? call("list_maintenance_runs", { siteId: siteId ?? null }) : structuredClone(demoHistory.filter((run) => !siteId || run.siteId === siteId)); },
  async onMaintenanceProgress(handler: (payload: { siteId: string; runId: string; step: MaintenanceStep }) => void): Promise<UnlistenFn> { if (!isTauri()) return () => undefined; return listen("maintenance-progress", (event) => handler(event.payload as { siteId: string; runId: string; step: MaintenanceStep })); },
  async scanAllSites(onProgress: (progress: BulkScanProgress) => void): Promise<BulkScanResult> { if (isTauri()) { const unlisten = await listen("bulk-scan-progress", (event) => onProgress(event.payload as BulkScanProgress)); try { return await call("scan_all_sites"); } finally { unlisten(); } } let completed = 0; const failures: BulkScanResult["failures"] = []; const queue = [...browserSites]; while (queue.length) { const batch = queue.splice(0, 4); onProgress({ total: browserSites.length, completed, activeSites: batch.map((site) => site.name), failedSites: failures.map((item) => item.siteName) }); await Promise.all(batch.map(async (site) => { await new Promise((resolve) => setTimeout(resolve, 250)); if (site.status === "unreachable") failures.push({ siteId: site.id, siteName: site.name, error: { category: "dns_host_error", userMessage: "Niet bereikbaar", retryable: true } }); completed += 1; })); onProgress({ total: browserSites.length, completed, activeSites: [], failedSites: failures.map((item) => item.siteName) }); } return { total: browserSites.length, completed, cancelled: false, failures }; },
  async cancelBulkScan(): Promise<void> { if (isTauri()) await call("cancel_bulk_scan"); },
  async getSettings(): Promise<AppSettings> { return isTauri() ? call("get_settings") : { scanConcurrency: 4 }; },
  async saveSettings(settings: AppSettings): Promise<AppSettings> { return isTauri() ? call("save_settings", { settings }) : settings; },
  async listAuditEvents(siteId?: string): Promise<AuditEvent[]> { return isTauri() ? call("list_audit_events", { siteId: siteId ?? null }) : []; },
};
