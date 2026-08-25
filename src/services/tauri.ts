import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { ConnectionTestResult, MaintenanceRun, MaintenanceStep, ScanResult, Site, SiteInput, UpdateItem } from "../types";
import { demoHistory, demoScan, demoSites, demoUpdates } from "./fixtures";

const isTauri = () => "__TAURI_INTERNALS__" in window;
let browserSites = structuredClone(demoSites);

async function call<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  return invoke<T>(command, args);
}

export const appApi = {
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
  async checkUpdates(siteId: string): Promise<UpdateItem[]> { return isTauri() ? call("check_updates", { siteId }) : structuredClone(demoUpdates); },
  async runUpdate(siteId: string, kind: string, slug?: string): Promise<void> { if (isTauri()) await call("run_update", { siteId, kind, slug }); else await new Promise((resolve) => setTimeout(resolve, 700)); },
  async runMaintenance(siteId: string): Promise<MaintenanceRun> { return isTauri() ? call("run_maintenance", { siteId }) : { ...structuredClone(demoHistory[0]), id: crypto.randomUUID(), siteId }; },
  async listHistory(siteId?: string): Promise<MaintenanceRun[]> { return isTauri() ? call("list_maintenance_runs", { siteId: siteId ?? null }) : structuredClone(demoHistory.filter((run) => !siteId || run.siteId === siteId)); },
  async onMaintenanceProgress(handler: (payload: { siteId: string; runId: string; step: MaintenanceStep }) => void): Promise<UnlistenFn> { if (!isTauri()) return () => undefined; return listen("maintenance-progress", (event) => handler(event.payload as { siteId: string; runId: string; step: MaintenanceStep })); },
};
