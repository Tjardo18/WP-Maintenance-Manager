import { invoke } from "@tauri-apps/api/core";
import type { FilemanagerAuthorization, FilemanagerBulkItem, FilemanagerBulkResult, FilemanagerContext, FilemanagerDirectoryListing, FilemanagerFilePreview, FilemanagerMutationKind, FilemanagerMutationResult } from "../types/filemanager";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type { AppSettings, AuditEvent, AuthStatus, BulkScanStart, ChecksumDeleteProgress, ChecksumDeleteResult, ConnectionTestResult, CoreOperationInfo, CoreOperationResult, DatabaseCleanupOption, DatabaseCleanupRequest, DatabaseCleanupResult, DatabaseCleanupTarget, ErrorLogFilter, ErrorLogPage, FilePreview, FindingException, FindingExceptionInput, LoginResult, MaintenanceRun, MaintenanceStep, PasswordChangeInput, ScanJobState, ScanResult, SecurityPolicyMutationResult, Site, SiteChangeHistory, SiteChangeSummary, SiteInput, SnapshotDiff, SnapshotHistoryItem, SnapshotMetadata, TerminalChallengeInfo, TerminalConnectionInfo, TerminalOutputEvent, TerminalStatusEvent, TrustedFile, TrustedFileInput, UpdateItem, VulnerabilityRefreshJobState, WordfenceIntegrationStatus, WordPressUserDeleteInput, WordPressUsersData, WordPressUserUpdateInput, WpCliCatalog, WpCliCommandInspection, WpCliExecutionResult } from "../types";
import type { MediaKeyCommand } from "./keyboardShortcuts";
import { demoChanges, demoHistory, demoScan, demoSites, demoUpdates, demoUsers } from "./fixtures";

const isTauri = () => "__TAURI_INTERNALS__" in window;
let browserSites = structuredClone(demoSites);
const browserUsers = structuredClone(demoUsers);
let sessionToken: string | undefined;
let browserConfigured = false;
let browserPasswordHash = "";
let browserIdleMinutes = 15;
let browserSettings: AppSettings = { scanConcurrency: 4, filePreviewMode: "normal", markdownPreviewMode: "raw" };
let browserMaintenanceRuns = structuredClone(demoHistory);
const browserTerminalChallenges = new Map<string, { siteId: string; expiresAt: number }>();
const browserScanJobs = new Map<string, ScanJobState>();
const browserScanJobListeners = new Set<(job: ScanJobState) => void>();
const browserChecksumDeleteProgressListeners = new Set<(progress: ChecksumDeleteProgress) => void>();
const browserExceptions: FindingException[] = [];
const browserTrustedFiles: TrustedFile[] = [];
const browserScans = new Map<string, ScanResult>();
const browserSnapshotBaselines = new Map<string, string>();
const browserSeenSnapshots = new Set<string>();
let browserWordfenceConfigured = false;
let browserWordfenceJob: VulnerabilityRefreshJobState | undefined;
const browserWordfenceJobListeners = new Set<(job: VulnerabilityRefreshJobState) => void>();

function browserScan(siteId: string) {
  const existing = browserScans.get(siteId);
  if (existing) return existing;
  const scan = { ...structuredClone(demoScan), siteId };
  scan.checks.forEach((check) => check.findings.forEach((finding) => { finding.disposition ??= "active"; }));
  browserScans.set(siteId, scan);
  return scan;
}

function browserFinding(siteId: string, findingId: string) {
  return browserScan(siteId).checks.flatMap((check) => check.findings).find((finding) => finding.id === findingId);
}

function emitBrowserChecksumDeleteProgress(progress: ChecksumDeleteProgress) {
  browserChecksumDeleteProgressListeners.forEach((listener) => listener(structuredClone(progress)));
}

function browserSiteChanges(siteId: string): SiteChangeHistory {
  const history = structuredClone(demoChanges);
  const snapshots = [history.latestSnapshot, history.baselineSnapshot].flatMap((snapshot) => snapshot ? [snapshot] : []);
  for (const snapshot of snapshots) snapshot.siteId = siteId;
  const baselineId = browserSnapshotBaselines.get(siteId) ?? history.baselineSnapshot?.snapshotId;
  for (const snapshot of snapshots) snapshot.isBaseline = snapshot.snapshotId === baselineId;
  history.baselineSnapshot = snapshots.find((snapshot) => snapshot.snapshotId === baselineId) ?? null;
  history.latestSnapshot = snapshots.find((snapshot) => snapshot.snapshotId === demoChanges.latestSnapshot?.snapshotId) ?? null;
  if (history.comparison) {
    history.comparison.siteId = siteId;
    history.comparison.changes.forEach((change) => { change.siteId = siteId; change.seen = browserSeenSnapshots.has(`${siteId}:${change.toSnapshotId}`); });
  }
  return history;
}

function browserCleanupOptions(): DatabaseCleanupOption[] {
  const counts: Record<DatabaseCleanupTarget, number> = {
    sites: browserSites.length,
    scan_runs: browserScans.size,
    site_snapshots: browserSnapshotBaselines.size,
    maintenance_runs: browserMaintenanceRuns.length,
    error_logs: 0,
    audit_events: 0,
  };
  const definitions: Array<[DatabaseCleanupTarget, string, string, string[], string[], string]> = [
    ["sites", "Websites", "Alle websites die aan WP Maintenance Manager zijn toegevoegd.", ["Website- en SSH-configuratie.", "Relaties tussen root- en childwebsites."], ["Scans, snapshots, uitzonderingen, vertrouwde bestanden en onderhoudshistorie."], "Alle websites en uitsluitend daaraan gekoppelde gegevens worden verwijderd. Globale instellingen en authenticatie blijven behouden."],
    ["scan_runs", "Scanhistorie", "Alle uitgevoerde websitescans en resultaten.", ["Scantijden, controles en bevindingen."], ["Scancontroles en bevindingen worden verwijderd; website-scansamenvattingen worden gereset."], "Websites en snapshots blijven behouden."],
    ["site_snapshots", "Snapshots en wijzigingen", "Alle opgeslagen momentopnames en berekende verschillen.", ["Websiteconfiguratie op meetmomenten en wijzigingshistorie."], ["Vergelijkingen, wijzigingen en baseline-statussen worden verwijderd."], "Scans, websites en onderhoudsrecords blijven behouden."],
    ["maintenance_runs", "Onderhoudshistorie", "Alle geregistreerde onderhouds- en updateacties.", ["Onderhoudsstappen en lokale back-upregistraties."], ["Lokale .sql.gz-bestanden blijven op de computer staan."], "De onderhoudshistorie wordt verwijderd; back-upbestanden zelf blijven behouden."],
    ["error_logs", "Foutenlog", "Alle lokaal opgeslagen technische fouten en waarschuwingen.", ["Fout-ID's, tijdstippen, categorieën en technische details."], ["Er zijn geen afhankelijke tabellen."], "Alleen de foutregels worden verwijderd."],
    ["audit_events", "Auditlog", "De lokale beveiligings- en actiehistorie.", ["Geslaagde en mislukte beheeracties en tijdstippen."], ["Er zijn geen afhankelijke tabellen."], "Het volledige auditlog wordt verwijderd en kan niet worden gereconstrueerd."],
  ];
  return definitions.map(([target, title, description, storedData, dependencies, cleanupEffect]) => ({
    target,
    tableName: target,
    title,
    description,
    storedData,
    dependencies,
    cleanupEffect,
    recordCount: counts[target],
    impacts: [{ key: target, label: title.toLocaleLowerCase("nl-NL"), count: counts[target], effect: "verwijderd" }],
    previewToken: `${target}:${counts[target]}`,
    confirmationMode: target === "sites" ? "typed" : "dialog",
    confirmationPhrase: target === "sites" ? "VERWIJDEREN" : target,
    irreversible: true,
  }));
}

const demoScanSteps: ScanJobState["steps"] = [
  ["ssh_connect", "SSH-verbinding"], ["wordpress_detection", "WordPress detecteren"],
  ["wordpress", "WordPress controleren"],
  ["wp_cli_version", "WP-CLI-versie"],
  ["checksum", "Core-checksums"], ["users", "Gebruikers"],
  ["php", "PHP-bestanden"], ["uploads", "Uploads"],
  ["modified", "Gewijzigde bestanden"], ["permissions", "Bestandsrechten"],
  ["configuration", "WordPress-configuratie"], ["cron", "WordPress-cron"], ["database", "Database"],
  ["core_updates", "WordPress-updates"], ["plugin_list", "Plugin-updates"],
  ["theme_list", "Thema-updates"], ["homepage", "Homepage"],
  ["vulnerabilities", "Kwetsbaarheden"], ["persist", "Resultaat opslaan"],
].map(([key, label]) => ({ key, label, status: "pending" }));

function emitBrowserScanJob(job: ScanJobState) {
  const snapshot = structuredClone(job);
  browserScanJobs.set(job.id, snapshot);
  browserScanJobListeners.forEach((listener) => listener(structuredClone(snapshot)));
}

function startBrowserScanJob(site: Site): ScanJobState {
  const existing = [...browserScanJobs.values()].find((job) => job.siteId === site.id && ["queued", "running"].includes(job.status));
  if (existing) return structuredClone(existing);
  const createdAt = new Date().toISOString();
  const job: ScanJobState = { id: crypto.randomUUID(), jobType: "site_scan", siteId: site.id, siteName: site.name, status: "queued", createdAt, completedSteps: 0, totalSteps: demoScanSteps.length, cancellationRequested: false, steps: structuredClone(demoScanSteps) };
  emitBrowserScanJob(job);
  window.setTimeout(() => {
    const current = browserScanJobs.get(job.id);
    if (!current || current.status === "cancelled") return;
    current.status = "running"; current.startedAt = new Date().toISOString(); current.currentStep = current.steps[0]?.key; if (current.steps[0]) { current.steps[0].status = "running"; current.steps[0].startedAt = current.startedAt; } emitBrowserScanJob(current);
  }, 0);
  window.setTimeout(() => {
    const current = browserScanJobs.get(job.id);
    if (!current || current.status === "cancelled") return;
    site.wpCliVersion = "WP-CLI 2.12.0";
    site.wpCliVersionCheckedAt = new Date().toISOString();
    site.lastScanAt = site.wpCliVersionCheckedAt;
    site.updatedAt = site.lastScanAt;
    current.status = "completed"; current.finishedAt = new Date().toISOString(); current.currentStep = undefined; current.completedSteps = current.totalSteps; current.resultScanId = crypto.randomUUID(); current.steps = current.steps.map((step) => ({ ...step, status: "success", durationMs: 20 })); emitBrowserScanJob(current);
  }, 300);
  return structuredClone(job);
}

function demoWpCliInspection(command: string): WpCliCommandInspection {
  const family = command.trim().split(/\s+/)[1]?.replace(/[^a-z0-9_-]/gi, "") || "custom";
  const highRisk = /^wp\s+(eval(?:-file)?|db\s+(query|drop|reset|clean|import)|config\s+(create|set|delete)|core\s+(download|update)|cli\s+update)\b/i.test(command) || /\s--(?:exec|require)(?:=|\s|$)/i.test(command);
  const readOnly = /^wp\s+(core\s+(version|check-update|verify-checksums)|plugin\s+list|theme\s+list|user\s+list|option\s+get)\b/i.test(command);
  const risk = highRisk ? "highRisk" : readOnly ? "readOnly" : "mutating";
  return { risk, commandFamily: family, summary: risk === "readOnly" ? "Alleen-lezen of normale WP-CLI-controle." : risk === "highRisk" ? "Dit krachtige WP-CLI-commando kan ingrijpende of destructieve wijzigingen uitvoeren." : "Dit commando kan de geselecteerde WordPress-site wijzigen.", requiresConfirmation: risk !== "readOnly", requiresTypedConfirmation: risk === "highRisk", confirmationPhrase: risk === "highRisk" ? "UITVOEREN" : undefined };
}

async function call<T>(command: string, args: Record<string, unknown> = {}): Promise<T> {
  if (!sessionToken) throw { category: "locked", userMessage: "WP Maintenance Manager is vergrendeld.", retryable: false };
  const started = globalThis.performance.now();
  try {
    const result = await invoke<T>(command, { ...args, sessionToken });
    if (import.meta.env.DEV) {
      const frontendStarted = globalThis.performance.now();
      const responseBytes = new TextEncoder().encode(JSON.stringify(result) ?? "").byteLength;
      const frontendProcessingMs = globalThis.performance.now() - frontendStarted;
      const ipcDurationMs = globalThis.performance.now() - started;
      const message = `[performance] command=${command} ipc_ms=${ipcDurationMs.toFixed(1)} response_bytes=${responseBytes} frontend_processing_ms=${frontendProcessingMs.toFixed(1)}`;
      if (responseBytes > 1024 * 1024) console.warn(message); else console.debug(message);
    }
    return result;
  }
  catch (cause) {
    const category = typeof cause === "object" && cause !== null && "category" in cause ? String((cause as { category: unknown }).category) : "";
    if (["locked", "session_expired", "invalid_session", "setup_required", "app_session_revoked_reauth_failed"].includes(category)) {
      sessionToken = undefined;
      browserTerminalChallenges.clear();
      window.dispatchEvent(new CustomEvent("wpmm:locked", { detail: cause }));
    }
    throw cause;
  }
}

async function publicCall<T>(command: string, args: Record<string, unknown> = {}): Promise<T> { return invoke<T>(command, args); }
async function demoHash(password: string): Promise<string> { const bytes = new TextEncoder().encode(password); const hash = await crypto.subtle.digest("SHA-256", bytes); return Array.from(new Uint8Array(hash), (byte) => byte.toString(16).padStart(2, "0")).join(""); }

export const authApi = {
  setSessionToken(token?: string) { sessionToken = token; if (!token) browserTerminalChallenges.clear(); },
  async status(): Promise<AuthStatus> { if (isTauri()) return publicCall("get_auth_status", { sessionToken: sessionToken ?? null }); return { configured: browserConfigured, authenticated: Boolean(sessionToken), idleTimeoutMinutes: browserIdleMinutes, retryAfterSeconds: 0 }; },
  async setup(password: string): Promise<LoginResult> { if (isTauri()) { const result = await publicCall<LoginResult>("setup_password", { password }); sessionToken = result.sessionToken; return result; } if (browserConfigured) throw new Error("De applicatiebeveiliging is al ingesteld."); browserPasswordHash = await demoHash(password); browserConfigured = true; sessionToken = crypto.randomUUID(); return { sessionToken, idleTimeoutMinutes: browserIdleMinutes }; },
  async login(password: string): Promise<LoginResult> { if (isTauri()) { const result = await publicCall<LoginResult>("login", { password }); sessionToken = result.sessionToken; return result; } if (await demoHash(password) !== browserPasswordHash) throw { category: "invalid_password", userMessage: "Het wachtwoord is niet correct.", retryable: false }; sessionToken = crypto.randomUUID(); return { sessionToken, idleTimeoutMinutes: browserIdleMinutes }; },
  async touch(): Promise<void> { if (isTauri()) await call("touch_session"); },
  async lock(): Promise<void> { try { if (isTauri() && sessionToken) await call("lock_app"); } finally { sessionToken = undefined; } },
  async changePassword(input: PasswordChangeInput): Promise<void> { if (isTauri()) await call("change_password", { input }); else { if (await demoHash(input.currentPassword) !== browserPasswordHash) throw { category: "invalid_password", userMessage: "Het huidige wachtwoord is niet correct.", retryable: false }; browserPasswordHash = await demoHash(input.newPassword); } sessionToken = undefined; },
  async setIdleTimeout(minutes: number): Promise<AuthStatus> { if (isTauri()) return call("set_idle_timeout", { minutes }); browserIdleMinutes = minutes; return { configured: true, authenticated: true, idleTimeoutMinutes: minutes, retryAfterSeconds: 0 }; },
};

export const systemInputApi = {
  isAvailable: isTauri,
  async forwardMediaKey(command: MediaKeyCommand): Promise<void> {
    if (isTauri()) await publicCall("forward_media_key", { command });
  },
};

export const appApi = {
  async createFilemanagerFile(siteId: string, authorizationToken: string, input: { directory: string; name: string }): Promise<FilemanagerMutationResult> {
    if (!isTauri()) throw new Error("De filemanager is alleen beschikbaar in de desktopapp.");
    return call("create_filemanager_file", { siteId, authorizationToken, input });
  },
  async createFilemanagerDirectory(siteId: string, authorizationToken: string, input: { directory: string; name: string }): Promise<FilemanagerMutationResult> {
    if (!isTauri()) throw new Error("De filemanager is alleen beschikbaar in de desktopapp.");
    return call("create_filemanager_directory", { siteId, authorizationToken, input });
  },
  async deleteFilemanagerItem(siteId: string, authorizationToken: string, input: { path: string; expectedKind: FilemanagerMutationKind }): Promise<FilemanagerMutationResult> {
    if (!isTauri()) throw new Error("De filemanager is alleen beschikbaar in de desktopapp.");
    return call("delete_filemanager_item", { siteId, authorizationToken, input });
  },
  async changeFilemanagerPermissions(siteId: string, authorizationToken: string, input: FilemanagerBulkItem & { mode: string }): Promise<void> {
    if (!isTauri()) throw new Error("De filemanager is alleen beschikbaar in de desktopapp.");
    return call("change_filemanager_permissions", { siteId, authorizationToken, input });
  },
  async changeFilemanagerPermissionsBulk(siteId: string, authorizationToken: string, input: { directory: string; items: FilemanagerBulkItem[]; mode: string }): Promise<FilemanagerBulkResult> {
    if (!isTauri()) throw new Error("De filemanager is alleen beschikbaar in de desktopapp.");
    return call("change_filemanager_permissions_bulk", { siteId, authorizationToken, input });
  },
  async deleteFilemanagerBulk(siteId: string, authorizationToken: string, input: { directory: string; items: FilemanagerBulkItem[] }): Promise<FilemanagerBulkResult> {
    if (!isTauri()) throw new Error("De filemanager is alleen beschikbaar in de desktopapp.");
    return call("delete_filemanager_bulk", { siteId, authorizationToken, input });
  },
  async saveFilemanagerFile(siteId: string, authorizationToken: string, input: { path: string; content: string; expectedVersion: string }): Promise<FilemanagerFilePreview> {
    if (!isTauri()) throw new Error("De filemanager is alleen beschikbaar in de desktopapp.");
    return call("save_filemanager_file", { siteId, authorizationToken, input });
  },
  async listFilemanagerDirectory(siteId: string, authorizationToken: string, requestedPath = "/"): Promise<FilemanagerDirectoryListing> {
    if (!isTauri()) throw new Error("De filemanager is alleen beschikbaar in de desktopapp.");
    return call("list_filemanager_directory", { siteId, authorizationToken, requestedPath });
  },
  async readFilemanagerFile(siteId: string, authorizationToken: string, requestedPath: string): Promise<FilemanagerFilePreview> {
    if (!isTauri()) throw new Error("De filemanager is alleen beschikbaar in de desktopapp.");
    return call("read_filemanager_file", { siteId, authorizationToken, requestedPath });
  },
  async beginFilemanagerReauthentication(siteId: string, appPassword: string): Promise<TerminalChallengeInfo> {
    if (!isTauri()) throw new Error("Filemanagerverificatie is alleen beschikbaar in de desktopapp.");
    return call("begin_filemanager_reauthentication", { siteId, appPassword });
  },
  async openFilemanager(siteId: string, challengeToken: string, sshPassword: string): Promise<FilemanagerAuthorization> {
    if (!isTauri()) throw new Error("Filemanagerverificatie is alleen beschikbaar in de desktopapp.");
    return call("open_filemanager", { siteId, challengeToken, sshPassword });
  },
  async getFilemanagerAuthorization(siteId: string, authorizationToken: string): Promise<FilemanagerAuthorization> {
    if (!isTauri()) throw new Error("Filemanagerverificatie is alleen beschikbaar in de desktopapp.");
    return call("get_filemanager_authorization", { siteId, authorizationToken });
  },
  async closeFilemanager(siteId: string, authorizationToken: string): Promise<void> {
    if (isTauri()) await call("close_filemanager", { siteId, authorizationToken });
  },
  async getFilemanagerContext(siteId: string): Promise<FilemanagerContext> {
    if (isTauri()) return call("get_filemanager_context", { siteId });
    const site = browserSites.find((item) => item.id === siteId);
    if (!site) throw new Error("Website niet gevonden.");
    return { siteId: site.id, siteName: site.name, siteUrl: site.url };
  },
  async beginTerminalReauthentication(siteId: string, appPassword: string): Promise<TerminalChallengeInfo> {
    if (isTauri()) return call("begin_terminal_reauthentication", { siteId, appPassword });
    if (await demoHash(appPassword) !== browserPasswordHash) {
      const cause = { category: "app_session_revoked_reauth_failed", userMessage: "Sessie beëindigd. De extra beveiligingscontrole voor de Terminal is mislukt. Log opnieuw in om verder te gaan.", retryable: false };
      sessionToken = undefined;
      browserTerminalChallenges.clear();
      window.dispatchEvent(new CustomEvent("wpmm:locked", { detail: cause }));
      throw cause;
    }
    const challengeToken = crypto.randomUUID();
    browserTerminalChallenges.set(challengeToken, { siteId, expiresAt: Date.now() + 60_000 });
    return { challengeToken, expiresInSeconds: 60 };
  },
  async cancelTerminalReauthentication(siteId: string, challengeToken: string): Promise<void> {
    if (isTauri()) await call("cancel_terminal_reauthentication", { siteId, challengeToken });
    else if (browserTerminalChallenges.get(challengeToken)?.siteId === siteId) browserTerminalChallenges.delete(challengeToken);
  },
  async openTerminal(siteId: string, challengeToken: string, sshPassword: string, columns: number, rows: number): Promise<TerminalConnectionInfo> {
    if (isTauri()) return call("open_terminal", { input: { siteId, challengeToken, sshPassword, columns, rows } });
    const challenge = browserTerminalChallenges.get(challengeToken);
    browserTerminalChallenges.delete(challengeToken);
    if (!challenge || challenge.siteId !== siteId || challenge.expiresAt <= Date.now()) throw { category: "terminal_challenge_invalid", userMessage: "De Terminal-verificatie is ongeldig. Bevestig beide wachtwoorden opnieuw.", retryable: false };
    if (!sshPassword) throw { category: "ssh_authentication", userMessage: "SSH-authenticatie mislukt.", retryable: false };
    return { sessionId: crypto.randomUUID(), authorizationToken: crypto.randomUUID(), siteId, startPath: browserSites.find((site) => site.id === siteId)?.wordpressPath ?? "/var/www/html", columns, rows };
  },
  async writeTerminal(terminalSessionId: string, terminalAuthorization: string, data: string): Promise<void> { if (isTauri()) await call("write_terminal", { terminalSessionId, terminalAuthorization, data }); },
  async resizeTerminal(terminalSessionId: string, terminalAuthorization: string, columns: number, rows: number): Promise<void> { if (isTauri()) await call("resize_terminal", { terminalSessionId, terminalAuthorization, columns, rows }); },
  async closeTerminal(terminalSessionId: string, terminalAuthorization: string): Promise<void> { if (isTauri()) await call("close_terminal", { terminalSessionId, terminalAuthorization }); },
  async onTerminalOutput(handler: (payload: TerminalOutputEvent) => void): Promise<UnlistenFn> { if (!isTauri()) return () => undefined; return listen("terminal-output", (event) => handler(event.payload as TerminalOutputEvent)); },
  async onTerminalStatus(handler: (payload: TerminalStatusEvent) => void): Promise<UnlistenFn> { if (!isTauri()) return () => undefined; return listen("terminal-status", (event) => handler(event.payload as TerminalStatusEvent)); },
  async getWpCliCatalog(): Promise<WpCliCatalog> { return isTauri() ? call("get_wp_cli_catalog") : { available: false, rootCommandCount: 0, totalCommandCount: 0, globalParameterCount: 0, globalParameters: [], commands: [], error: "WP-CLI commandodatabase niet gevonden", technicalDetails: "De browserdemo laadt geen lokale Tauri-resources." }; },
  async inspectWpCliCommand(siteId: string, command: string): Promise<WpCliCommandInspection> { return isTauri() ? call("inspect_wp_cli_command", { siteId, command }) : demoWpCliInspection(command); },
  async executeWpCliCommand(siteId: string, command: string, confirmed = false, typedConfirmation?: string): Promise<WpCliExecutionResult> { if (isTauri()) return call("execute_wp_cli_command", { siteId, command, confirmed, typedConfirmation }); const inspection = demoWpCliInspection(command); if (inspection.risk === "mutating" && !confirmed) throw new Error("Bevestig dit muterende WP-CLI-commando."); if (inspection.risk === "highRisk" && (!confirmed || typedConfirmation !== "UITVOEREN")) throw new Error("Typ UITVOEREN om dit commando te bevestigen."); const now = new Date().toISOString(); return { status: "success", risk: inspection.risk, commandFamily: inspection.commandFamily, stdout: command.includes("core version") ? "6.8.2\n" : "Success: browserdemo — er is niets op afstand uitgevoerd.\n", stderr: "", exitCode: 0, durationMs: 42, startedAt: now, finishedAt: now, truncated: false }; },
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
    return { success: true, requiresHostKeyAcceptance: false, fingerprint: "SHA256:demo-fingerprint", wordpressVersion: "6.8.2", phpVersion: "8.3.12", wpCliVersion: "2.12.0", detectedUrl: input.url, unexpectedDirectories: [], unexpectedDirectoriesTruncated: false, steps: ["SSH bereikbaar", "Host fingerprint gecontroleerd", "Authenticatie geslaagd", "WordPress-pad gevonden", "WP-CLI werkt", "WordPress-installatie gevonden", "Database bereikbaar", "Onbekende hoofdmappen gecontroleerd"].map((label, index) => ({ key: String(index), label, status: "success" })) };
  },
  async acceptHostKey(siteId: string, fingerprint: string): Promise<void> { if (isTauri()) await call("accept_host_key", { siteId, fingerprint }); },
  async startSiteScan(siteId: string, modifiedDays = 30): Promise<ScanJobState> {
    if (isTauri()) return call("start_site_scan", { siteId, modifiedDays });
    const site = browserSites.find((candidate) => candidate.id === siteId);
    if (!site) throw new Error("Website niet gevonden.");
    return startBrowserScanJob(site);
  },
  async getScanJob(jobId: string): Promise<ScanJobState> { if (isTauri()) return call("get_scan_job", { jobId }); const job = browserScanJobs.get(jobId); if (!job) throw new Error("Scantaak niet gevonden."); return structuredClone(job); },
  async getSiteScanJob(siteId: string): Promise<ScanJobState | undefined> { if (isTauri()) return (await call<ScanJobState | null>("get_site_scan_job", { siteId })) ?? undefined; const job = [...browserScanJobs.values()].filter((item) => item.siteId === siteId).sort((a, b) => b.createdAt.localeCompare(a.createdAt))[0]; return job ? structuredClone(job) : undefined; },
  async listScanJobs(activeOnly = false): Promise<ScanJobState[]> { if (isTauri()) return call("list_scan_jobs", { activeOnly }); return [...browserScanJobs.values()].filter((job) => !activeOnly || ["queued", "running"].includes(job.status)).map((job) => structuredClone(job)); },
  async cancelSiteScan(jobId: string): Promise<ScanJobState> { if (isTauri()) return call("cancel_site_scan", { jobId }); const job = browserScanJobs.get(jobId); if (!job) throw new Error("Scantaak niet gevonden."); job.cancellationRequested = true; job.status = "cancelled"; job.currentStep = undefined; job.finishedAt = new Date().toISOString(); emitBrowserScanJob(job); return structuredClone(job); },
  async startAllSiteScans(modifiedDays = 30): Promise<BulkScanStart> { if (isTauri()) return call("start_all_site_scans", { modifiedDays }); return { jobs: browserSites.map(startBrowserScanJob) }; },
  async cancelScanJobs(jobIds: string[]): Promise<ScanJobState[]> { if (isTauri()) return call("cancel_scan_jobs", { jobIds }); return Promise.all(jobIds.map((jobId) => appApi.cancelSiteScan(jobId))); },
  async onScanJobUpdated(handler: (job: ScanJobState) => void): Promise<UnlistenFn> { if (isTauri()) return listen("scan-job-updated", (event) => handler(event.payload as ScanJobState)); browserScanJobListeners.add(handler); return () => browserScanJobListeners.delete(handler); },
  async listScans(siteId: string): Promise<ScanResult[]> { return isTauri() ? call("list_scan_runs", { siteId }) : [structuredClone(browserScan(siteId))]; },
  async getSiteChanges(siteId: string): Promise<SiteChangeHistory> { return isTauri() ? call("get_site_changes", { siteId }) : browserSiteChanges(siteId); },
  async markSiteChangesSeen(siteId: string, snapshotId: string): Promise<void> { if (isTauri()) await call("mark_site_changes_seen", { siteId, snapshotId }); else browserSeenSnapshots.add(`${siteId}:${snapshotId}`); },
  async listSiteSnapshots(siteId: string): Promise<SnapshotMetadata[]> {
    if (isTauri()) return call("list_site_snapshots", { siteId });
    const history = browserSiteChanges(siteId);
    return [history.latestSnapshot, structuredClone(demoChanges.baselineSnapshot)]
      .flatMap((snapshot) => snapshot ? [{ ...snapshot, siteId, isBaseline: snapshot.snapshotId === history.baselineSnapshot?.snapshotId }] : []);
  },
  async listSiteSnapshotHistory(siteId: string): Promise<SnapshotHistoryItem[]> {
    if (isTauri()) return call("list_site_snapshot_history", { siteId });
    const history = browserSiteChanges(siteId);
    const important = history.comparison?.changes.find((change) => ["critical", "warning"].includes(change.severity))?.summary ?? null;
    return (await appApi.listSiteSnapshots(siteId)).map((snapshot) => ({
      snapshot,
      changeCount: snapshot.snapshotId === history.latestSnapshot?.snapshotId ? history.comparison?.changes.length ?? 0 : 0,
      importantChangeSummary: snapshot.snapshotId === history.latestSnapshot?.snapshotId ? important : null,
    }));
  },
  async listSiteChangeSummaries(): Promise<SiteChangeSummary[]> {
    if (isTauri()) return call("list_site_change_summaries");
    return browserSites.flatMap((site) => {
      const history = browserSiteChanges(site.id);
      if (!history.latestSnapshot) return [];
      const unseen = history.comparison?.changes.filter((change) => !change.seen) ?? [];
      return [{ siteId: site.id, latestSnapshotAt: history.latestSnapshot.createdAt, latestChangeCount: history.comparison?.changes.length ?? 0, unseenChangeCount: unseen.length, importantChangeSummary: unseen.find((change) => ["critical", "warning"].includes(change.severity))?.summary ?? null }];
    });
  },
  async compareSiteSnapshots(siteId: string, fromSnapshotId: string, toSnapshotId: string): Promise<SnapshotDiff> {
    if (isTauri()) return call("compare_site_snapshots", { siteId, fromSnapshotId, toSnapshotId });
    const comparison = structuredClone(demoChanges.comparison);
    if (!comparison) throw new Error("Geen demovergelijking beschikbaar.");
    comparison.siteId = siteId;
    comparison.fromSnapshotId = fromSnapshotId;
    comparison.toSnapshotId = toSnapshotId;
    comparison.origin = "manual";
    comparison.changes.forEach((change) => { change.siteId = siteId; change.fromSnapshotId = fromSnapshotId; change.toSnapshotId = toSnapshotId; });
    return comparison;
  },
  async setSiteSnapshotBaseline(siteId: string, snapshotId: string): Promise<void> {
    if (isTauri()) await call("set_site_snapshot_baseline", { siteId, snapshotId });
    else browserSnapshotBaselines.set(siteId, snapshotId);
  },
  async listFindingExceptions(siteId?: string): Promise<FindingException[]> { return isTauri() ? call("list_finding_exceptions", { siteId: siteId ?? null }) : structuredClone(browserExceptions.filter((exception) => !siteId || exception.siteId === siteId)); },
  async ignoreFinding(input: FindingExceptionInput): Promise<SecurityPolicyMutationResult> {
    if (isTauri()) return call("ignore_finding", { input });
    const finding = browserFinding(input.siteId, input.findingId);
    if (!finding) throw new Error("Actuele beveiligingsmelding niet gevonden.");
    const check = browserScan(input.siteId).checks.find((item) => item.findings.includes(finding));
    const site = browserSites.find((item) => item.id === input.siteId);
    const exception: FindingException = { id: crypto.randomUUID(), siteId: input.siteId, siteName: site?.name ?? input.siteId, checkType: check?.key ?? finding.category, findingType: finding.checksumStatus ?? finding.category, target: finding.path ?? finding.category, scope: "site", reason: input.expiresAt ? "Handmatig tijdelijk genegeerd" : "Handmatig genegeerd", note: input.note, createdAt: new Date().toISOString(), expiresAt: input.expiresAt, active: true };
    browserExceptions.push(exception); finding.disposition = "ignored"; finding.exceptionId = exception.id; finding.policyReason = "Deze specifieke melding is genegeerd.";
    return { scan: structuredClone(browserScan(input.siteId)), findingException: structuredClone(exception) };
  },
  async removeFindingException(exceptionId: string): Promise<SecurityPolicyMutationResult> {
    if (isTauri()) return call("remove_finding_exception", { exceptionId });
    const exception = browserExceptions.find((item) => item.id === exceptionId && item.active);
    if (!exception) throw new Error("Actieve uitzondering niet gevonden.");
    exception.active = false;
    browserScan(exception.siteId).checks.flatMap((check) => check.findings).filter((finding) => finding.exceptionId === exceptionId).forEach((finding) => { finding.disposition = "active"; finding.exceptionId = undefined; finding.policyReason = undefined; });
    return { scan: structuredClone(browserScan(exception.siteId)) };
  },
  async removeFindingExceptions(exceptionIds: string[]): Promise<number> {
    if (isTauri()) return call("remove_finding_exceptions", { exceptionIds });
    for (const exceptionId of exceptionIds) await appApi.removeFindingException(exceptionId);
    return exceptionIds.length;
  },
  async cleanupExpiredFindingExceptions(exceptionIds: string[]): Promise<number> {
    if (isTauri()) return call("cleanup_expired_finding_exceptions", { exceptionIds });
    const now = Date.now();
    for (const exceptionId of exceptionIds) {
      const index = browserExceptions.findIndex((item) => item.id === exceptionId && item.active && item.expiresAt && Date.parse(item.expiresAt) <= now);
      if (index < 0) throw new Error("Verlopen uitzondering niet gevonden.");
      const [exception] = browserExceptions.splice(index, 1);
      browserScan(exception!.siteId).checks.flatMap((check) => check.findings).filter((finding) => finding.exceptionId === exceptionId).forEach((finding) => { finding.disposition = "active"; finding.exceptionId = undefined; finding.policyReason = undefined; });
    }
    return exceptionIds.length;
  },
  async listTrustedFiles(siteId?: string): Promise<TrustedFile[]> { return isTauri() ? call("list_trusted_files", { siteId: siteId ?? null }) : structuredClone(browserTrustedFiles.filter((trusted) => !siteId || trusted.siteId === siteId)); },
  async trustFindingFile(input: TrustedFileInput): Promise<SecurityPolicyMutationResult> {
    if (isTauri()) return call("trust_finding_file", { input });
    const finding = browserFinding(input.siteId, input.findingId);
    if (!finding?.path || finding.checksumStatus === "missing" || finding.checksumStatus === "scan_error") throw new Error("Dit bestand kan niet worden vertrouwd.");
    const now = new Date().toISOString(); const hash = await demoHash(`${input.siteId}:${finding.path}`); const site = browserSites.find((item) => item.id === input.siteId);
    const trusted: TrustedFile = { id: crypto.randomUUID(), siteId: input.siteId, siteName: site?.name ?? input.siteId, relativePath: finding.path, trustedSha256: hash, currentSha256: hash, sizeBytes: 54, currentSizeBytes: 54, fileType: "regular", status: "trusted", trustedAt: now, lastCheckedAt: now, note: input.note, active: true };
    browserTrustedFiles.push(trusted); finding.disposition = "trusted"; finding.trustedFileId = trusted.id; finding.policyReason = "De huidige SHA-256-fingerprint komt overeen met de vertrouwde versie.";
    return { scan: structuredClone(browserScan(input.siteId)), trustedFile: structuredClone(trusted) };
  },
  async retrustFile(trustedFileId: string): Promise<SecurityPolicyMutationResult> {
    if (isTauri()) return call("retrust_file", { trustedFileId });
    const trusted = browserTrustedFiles.find((item) => item.id === trustedFileId && item.active); if (!trusted) throw new Error("Vertrouwd bestand niet gevonden.");
    trusted.trustedSha256 = trusted.currentSha256 ?? trusted.trustedSha256; trusted.status = "trusted"; trusted.trustedAt = new Date().toISOString(); trusted.lastCheckedAt = trusted.trustedAt;
    browserScan(trusted.siteId).checks.flatMap((check) => check.findings).filter((finding) => finding.trustedFileId === trusted.id).forEach((finding) => { finding.disposition = "trusted"; finding.policyReason = "De nieuwe fingerprint is vertrouwd."; });
    return { scan: structuredClone(browserScan(trusted.siteId)), trustedFile: structuredClone(trusted) };
  },
  async revokeTrustedFile(trustedFileId: string): Promise<SecurityPolicyMutationResult> {
    if (isTauri()) return call("revoke_trusted_file", { trustedFileId });
    const trusted = browserTrustedFiles.find((item) => item.id === trustedFileId && item.active); if (!trusted) throw new Error("Actief vertrouwd bestand niet gevonden."); trusted.active = false;
    browserScan(trusted.siteId).checks.flatMap((check) => check.findings).filter((finding) => finding.trustedFileId === trusted.id).forEach((finding) => { finding.disposition = "active"; finding.trustedFileId = undefined; finding.policyReason = undefined; });
    return { scan: structuredClone(browserScan(trusted.siteId)) };
  },
  async revokeTrustedFiles(trustedFileIds: string[]): Promise<number> {
    if (isTauri()) return call("revoke_trusted_files", { trustedFileIds });
    for (const trustedFileId of trustedFileIds) await appApi.revokeTrustedFile(trustedFileId);
    return trustedFileIds.length;
  },
  async previewFindingFile(siteId: string, findingId: string): Promise<FilePreview> { if (isTauri()) return call("preview_checksum_finding", { siteId, findingId }); const finding = demoScan.checks.flatMap((check) => check.findings).find((item) => item.id === findingId); if (!finding?.path) throw new Error("Bestandsfinding niet gevonden."); const parts = finding.path.split("/"); return { finding: structuredClone(finding), fileName: parts[parts.length - 1] ?? finding.path, relativePath: finding.path, sizeBytes: 54, modifiedAt: new Date().toISOString(), fileType: "php-bestand", extension: "php", textContent: "<script>alert('preview wordt als tekst getoond')</script>\n<?php // demo ?>", binary: false, truncated: false }; },
  async deleteChecksumFinding(siteId: string, findingId: string): Promise<ChecksumDeleteResult> { if (isTauri()) return call("delete_checksum_finding", { siteId, findingId }); const path = demoScan.checks.flatMap((check) => check.findings).find((item) => item.id === findingId)?.path; return { requested: 1, deleted: path ? 1 : 0, deletedPaths: path ? [path] : [], failures: [], scan: { ...structuredClone(demoScan), siteId } }; },
  async deleteChecksumFindings(siteId: string, findingIds: string[], operationId: string): Promise<ChecksumDeleteResult> {
    if (isTauri()) return call("delete_checksum_findings", { siteId, findingIds, operationId });
    const findings = demoScan.checks.flatMap((check) => check.findings);
    const deletedPaths: string[] = [];
    const failures: ChecksumDeleteResult["failures"] = [];
    emitBrowserChecksumDeleteProgress({ operationId, siteId, phase: "deleting", processed: 0, total: findingIds.length, deleted: 0, failed: 0 });
    for (const [index, findingId] of findingIds.entries()) {
      const finding = findings.find((item) => item.id === findingId);
      if (finding?.path) deletedPaths.push(finding.path);
      else failures.push({ findingId, error: { category: "filesystem", userMessage: "Het bestand kon niet worden gevonden.", retryable: false } });
      emitBrowserChecksumDeleteProgress({ operationId, siteId, phase: "deleting", processed: index + 1, total: findingIds.length, deleted: deletedPaths.length, failed: failures.length });
      await new Promise((resolve) => globalThis.setTimeout(resolve, 20));
    }
    if (deletedPaths.length) {
      emitBrowserChecksumDeleteProgress({ operationId, siteId, phase: "rescanning", processed: findingIds.length, total: findingIds.length, deleted: deletedPaths.length, failed: failures.length });
      await new Promise((resolve) => globalThis.setTimeout(resolve, 80));
    }
    emitBrowserChecksumDeleteProgress({ operationId, siteId, phase: "completed", processed: findingIds.length, total: findingIds.length, deleted: deletedPaths.length, failed: failures.length });
    return { requested: findingIds.length, deleted: deletedPaths.length, deletedPaths, failures, scan: deletedPaths.length ? { ...structuredClone(demoScan), siteId } : undefined };
  },
  async onChecksumDeleteProgress(handler: (progress: ChecksumDeleteProgress) => void): Promise<UnlistenFn> { if (isTauri()) return listen("checksum-delete-progress", (event) => handler(event.payload as ChecksumDeleteProgress)); browserChecksumDeleteProgressListeners.add(handler); return () => browserChecksumDeleteProgressListeners.delete(handler); },
  async listWordPressUsers(siteId: string): Promise<WordPressUsersData> { return isTauri() ? call("list_wordpress_users", { siteId }) : structuredClone(browserUsers); },
  async updateWordPressUser(siteId: string, input: WordPressUserUpdateInput): Promise<WordPressUsersData> { if (isTauri()) return call("update_wordpress_user", { siteId, input }); browserUsers.users = browserUsers.users.map((user) => user.id === input.userId ? { ...user, displayName: input.displayName, email: input.email, roles: input.role ? [input.role] : user.roles } : user); return structuredClone(browserUsers); },
  async deleteWordPressUser(siteId: string, input: WordPressUserDeleteInput): Promise<WordPressUsersData> { if (isTauri()) return call("delete_wordpress_user", { siteId, input }); browserUsers.users = browserUsers.users.filter((user) => user.id !== input.userId); return structuredClone(browserUsers); },
  async inspectCoreOperation(siteId: string): Promise<CoreOperationInfo> { if (isTauri()) return call("inspect_core_operation", { siteId }); const currentVersion = browserSites.find((site) => site.id === siteId)?.wordpressVersion ?? "6.8.2"; return { currentVersion, locale: "nl_NL", wordpressPath: browserSites.find((site) => site.id === siteId)?.wordpressPath ?? "/var/www/html", availableVersion: demoUpdates.find((update) => update.kind === "core")?.newVersion, diskAvailableMb: 2048 }; },
  async repairWordPressCore(siteId: string): Promise<CoreOperationResult> { if (isTauri()) return call("repair_wordpress_core", { siteId }); const run = { ...structuredClone(demoHistory[0]), id: crypto.randomUUID(), siteId, beforeVersions: "WordPress 6.8.2 · locale nl_NL", afterVersions: "WordPress 6.8.2 · core hersteld" }; return { run, scan: { ...structuredClone(demoScan), siteId }, updatesAfter: structuredClone(demoUpdates), currentVersion: "6.8.2" }; },
  async updateWordPressCore(siteId: string): Promise<CoreOperationResult> { if (isTauri()) return call("update_wordpress_core", { siteId }); const run = { ...structuredClone(demoHistory[0]), id: crypto.randomUUID(), siteId, beforeVersions: "WordPress 6.8.1", afterVersions: "WordPress 6.8.2" }; return { run, scan: { ...structuredClone(demoScan), siteId }, updatesAfter: structuredClone(demoUpdates.filter((update) => update.kind !== "core")), currentVersion: "6.8.2" }; },
  async checkUpdates(siteId: string): Promise<UpdateItem[]> { return isTauri() ? call("check_updates", { siteId }) : structuredClone(demoUpdates); },
  async listCachedUpdates(siteId: string): Promise<UpdateItem[]> { return isTauri() ? call("list_cached_updates", { siteId }) : structuredClone(demoUpdates); },
  async runUpdate(siteId: string, kind: string, slug?: string): Promise<void> { if (isTauri()) await call("run_update", { siteId, kind, slug }); else await new Promise((resolve) => setTimeout(resolve, 700)); },
  async runMaintenance(siteId: string): Promise<MaintenanceRun> { if (isTauri()) return call("run_maintenance", { siteId }); const run = { ...structuredClone(demoHistory[0]), id: crypto.randomUUID(), siteId }; browserMaintenanceRuns = [run, ...browserMaintenanceRuns]; return run; },
  async listHistory(siteId?: string): Promise<MaintenanceRun[]> { return isTauri() ? call("list_maintenance_runs", { siteId: siteId ?? null }) : structuredClone(browserMaintenanceRuns.filter((run) => !siteId || run.siteId === siteId)); },
  async onMaintenanceProgress(handler: (payload: { siteId: string; runId: string; step: MaintenanceStep }) => void): Promise<UnlistenFn> { if (!isTauri()) return () => undefined; return listen("maintenance-progress", (event) => handler(event.payload as { siteId: string; runId: string; step: MaintenanceStep })); },
  async getSettings(): Promise<AppSettings> { return isTauri() ? call("get_settings") : structuredClone(browserSettings); },
  async saveSettings(settings: AppSettings): Promise<AppSettings> { if (isTauri()) return call("save_settings", { settings }); browserSettings = structuredClone(settings); return structuredClone(browserSettings); },
  async listDatabaseCleanupOptions(): Promise<DatabaseCleanupOption[]> { return isTauri() ? call("list_database_cleanup_options") : structuredClone(browserCleanupOptions()); },
  async cleanupDatabase(request: DatabaseCleanupRequest): Promise<DatabaseCleanupResult> {
    if (isTauri()) return call("cleanup_database", { request });
    const option = browserCleanupOptions().find((candidate) => candidate.target === request.target);
    if (!option || request.confirmation.trim() !== option.confirmationPhrase) throw new Error("De bevestiging voor deze opschoonactie is niet correct.");
    if (request.previewToken !== option.previewToken) throw new Error("De database is gewijzigd sinds deze aantallen zijn getoond. Vernieuw het overzicht en bevestig opnieuw.");
    if (request.target === "sites") { browserSites = []; browserScans.clear(); browserExceptions.splice(0); browserTrustedFiles.splice(0); browserSnapshotBaselines.clear(); browserSeenSnapshots.clear(); browserMaintenanceRuns = []; }
    if (request.target === "scan_runs") browserScans.clear();
    if (request.target === "site_snapshots") { browserSnapshotBaselines.clear(); browserSeenSnapshots.clear(); }
    if (request.target === "maintenance_runs") browserMaintenanceRuns = [];
    return { target: request.target, tableName: option.tableName, status: "success", impacts: structuredClone(option.impacts), warnings: [], completedAt: new Date().toISOString() };
  },
  async getWordfenceStatus(): Promise<WordfenceIntegrationStatus> { return isTauri() ? call("get_wordfence_status") : { configured: browserWordfenceConfigured, connectionStatus: "not_tested", feedStatus: "missing", vulnerabilityCount: 0, softwareRecordCount: 0, refreshRunning: false, cooldownRemainingSeconds: 0 }; },
  async saveWordfenceApiKey(apiKey: string): Promise<WordfenceIntegrationStatus> { if (isTauri()) return call("save_wordfence_api_key", { apiKey }); browserWordfenceConfigured = Boolean(apiKey.trim()); return appApi.getWordfenceStatus(); },
  async removeWordfenceApiKey(): Promise<WordfenceIntegrationStatus> { if (isTauri()) return call("remove_wordfence_api_key"); browserWordfenceConfigured = false; return appApi.getWordfenceStatus(); },
  async testWordfenceConnection(): Promise<WordfenceIntegrationStatus> { if (isTauri()) return call("test_wordfence_connection"); if (!browserWordfenceConfigured) throw new Error("Sla eerst een Wordfence API-sleutel op."); return { ...(await appApi.getWordfenceStatus()), connectionStatus: "connected" }; },
  async startWordfenceFeedRefresh(): Promise<VulnerabilityRefreshJobState> { if (isTauri()) return call("start_wordfence_feed_refresh"); if (!browserWordfenceConfigured) throw new Error("Sla eerst een Wordfence API-sleutel op."); const now = new Date().toISOString(); browserWordfenceJob = { id: crypto.randomUUID(), status: "running", phase: "download", createdAt: now, startedAt: now, downloadedBytes: 0, vulnerabilityCount: 0, softwareRecordCount: 0, automatic: false }; window.setTimeout(() => { if (!browserWordfenceJob) return; browserWordfenceJob = { ...browserWordfenceJob, status: "completed", phase: "complete", finishedAt: new Date().toISOString(), downloadedBytes: 1_024_000, vulnerabilityCount: 33_000, softwareRecordCount: 36_000 }; browserWordfenceJobListeners.forEach((listener) => listener(structuredClone(browserWordfenceJob!))); }, 500); return structuredClone(browserWordfenceJob); },
  async getWordfenceFeedRefreshJob(): Promise<VulnerabilityRefreshJobState | undefined> { if (isTauri()) return (await call<VulnerabilityRefreshJobState | null>("get_wordfence_feed_refresh_job")) ?? undefined; return browserWordfenceJob ? structuredClone(browserWordfenceJob) : undefined; },
  async openExternalUrl(url: string): Promise<void> { if (isTauri()) await call("open_vulnerability_reference", { url }); else { const parsed = new globalThis.URL(url); if (!["http:", "https:"].includes(parsed.protocol) || !parsed.hostname || parsed.username || parsed.password) throw new Error("Alleen veilige webreferenties kunnen worden geopend."); globalThis.open?.(parsed.toString(), "_blank", "noopener,noreferrer"); } },
  async openVulnerabilityReference(url: string): Promise<void> { await appApi.openExternalUrl(url); },
  async onWordfenceFeedRefreshUpdated(handler: (job: VulnerabilityRefreshJobState) => void): Promise<UnlistenFn> { if (isTauri()) return listen("wordfence-feed-refresh-updated", (event) => handler(event.payload as VulnerabilityRefreshJobState)); browserWordfenceJobListeners.add(handler); return () => browserWordfenceJobListeners.delete(handler); },
  async listAuditEvents(siteId?: string): Promise<AuditEvent[]> { return isTauri() ? call("list_audit_events", { siteId: siteId ?? null }) : []; },
  async listErrorLogs(filter: ErrorLogFilter = {}): Promise<ErrorLogPage> { return isTauri() ? call("list_error_logs", { filter }) : { records: [], total: 0, limit: filter.limit ?? 50, offset: filter.offset ?? 0 }; },
  async deleteErrorLogs(errorIds: string[]): Promise<number> { return isTauri() ? call("delete_error_logs", { errorIds }) : errorIds.length; },
};
