<script setup lang="ts">
import { computed, defineAsyncComponent, onMounted, onUnmounted, ref, watch } from "vue";
import { useRoute, RouterLink } from "vue-router";
import { Check, ChevronRight, CircleAlert, Database, Edit3, FileCode2, HardDriveDownload, LoaderCircle, Play, RefreshCw, ShieldCheck, Trash2 } from "@lucide/vue";
import StatusBadge from "../components/StatusBadge.vue";
import ConfirmDialog from "../components/ConfirmDialog.vue";
import ChecksumFilePreview from "../components/ChecksumFilePreview.vue";
import SecurityChecks from "../components/SecurityChecks.vue";
import VulnerabilityDetails from "../components/VulnerabilityDetails.vue";
import { useSitesStore } from "../stores/sites";
import { useScanJobsStore } from "../stores/scanJobs";
import { appApi } from "../services/tauri";
import type { ChecksumDeleteResult, CoreOperationInfo, CoreOperationKind, FilePreview, Finding, MaintenanceRun, MaintenanceStep, ScanResult, UpdateItem, WordPressUser, WordPressUsersData, WordPressUserUpdateInput } from "../types";
import { errorMessage } from "../utils/errors";
import { formatDate } from "../utils/format";

const route = useRoute(); const store = useSitesStore(); const scanJobs = useScanJobsStore();
const SshTerminal = defineAsyncComponent(() => import("../components/SshTerminal.vue"));
const site = computed(() => store.byId.get(String(route.params.id)));
const tabs = ["Overzicht", "Updates", "Security", "Gebruikers", "Bestanden", "Database", "Onderhoud", "Historie", "Terminal"];
const activeTab = ref("Overzicht"); const scan = ref<ScanResult>(); const scanHistory = ref<ScanResult[]>([]); const updates = ref<UpdateItem[]>([]); const history = ref<MaintenanceRun[]>([]); const liveSteps = ref<MaintenanceStep[]>([]); const busy = ref<string>(); const confirmUpdate = ref<UpdateItem | "all" | "maintenance">(); const error = ref<string>(); let stopProgress: (() => void) | undefined;
const selectedFindingIds = ref<string[]>([]); const preview = ref<FilePreview>(); const pendingDelete = ref<Finding[]>([]); const deleteResult = ref<ChecksumDeleteResult>();
const selectedVulnerability = ref<Finding>();
const pendingPolicyAction = ref<{ kind: "ignore" | "trust"; finding: Finding; temporary: boolean }>(); const policyNote = ref(""); const policyExpiry = ref<"7" | "30" | "date">("7"); const policyExpiryDate = ref("");
const usersData = ref<WordPressUsersData>(); const editUser = ref<WordPressUser>(); const editUserInput = ref<WordPressUserUpdateInput>(); const deleteUser = ref<WordPressUser>(); const deleteMode = ref<"reassign" | "delete">("reassign"); const reassignUserId = ref<number>(); const adminPromotionConfirmed = ref(false);
const pendingCoreOperation = ref<{ kind: CoreOperationKind; info: CoreOperationInfo }>();
const scanJob = computed(() => site.value ? scanJobs.forSite(site.value.id) : undefined);
const scanActive = computed(() => scanJob.value?.status === "queued" || scanJob.value?.status === "running");
const scanProgress = computed(() => scanJob.value?.totalSteps ? Math.round(scanJob.value.completedSteps / scanJob.value.totalSteps * 100) : 0);
const scanClock = ref(Date.now()); const development = import.meta.env.DEV; let scanClockTimer: number | undefined;
const activeScanStep = computed(() => scanJob.value?.steps.find((step) => step.key === scanJob.value?.currentStep));
const activeStepSeconds = computed(() => activeScanStep.value?.startedAt ? Math.max(0, Math.floor((scanClock.value - Date.parse(activeScanStep.value.startedAt)) / 1000)) : 0);
const totalScanDuration = computed(() => scanJob.value?.steps.reduce((total, step) => total + (step.durationMs ?? 0), 0) ?? 0);
let updatesLoaded = false; let usersLoaded = false; let handledScanId: string | undefined;
const updateKinds = computed(() => ({ plugins: updates.value.filter((item) => item.kind === "plugin").length, themes: updates.value.filter((item) => item.kind === "theme").length, core: updates.value.filter((item) => item.kind === "core").length }));
const visibleChecks = computed(() => { if (!scan.value) return []; if (activeTab.value === "Bestanden") return scan.value.checks.filter((check) => ["php_files", "php_uploads", "modified_files", "permissions"].includes(check.key)); if (activeTab.value === "Database") return scan.value.checks.filter((check) => check.key === "database"); return scan.value.checks; });
const unexpectedFindings = computed(() => scan.value?.checks.find((check) => check.key === "core_checksum")?.findings.filter((finding) => finding.checksumStatus === "unexpected" && finding.id) ?? []);
const isLatestScan = computed(() => Boolean(scan.value && scanHistory.value[0]?.id === scan.value.id));
const administratorCount = computed(() => usersData.value?.users.filter((user) => user.roles.includes("administrator")).length ?? 0);
const promotingAdministrator = computed(() => Boolean(editUser.value && editUserInput.value?.role === "administrator" && !editUser.value.roles.includes("administrator")));
async function load() { if (!site.value) return; const results = await Promise.allSettled([appApi.listHistory(site.value.id), appApi.listScans(site.value.id), appApi.listCachedUpdates(site.value.id)]); const [historyResult, scansResult, updateResult] = results; if (historyResult.status === "fulfilled") history.value = historyResult.value; if (scansResult.status === "fulfilled") { scanHistory.value = scansResult.value; scan.value = scansResult.value[0]; } if (updateResult.status === "fulfilled") updates.value = updateResult.value; const failed = results.find((result) => result.status === "rejected"); if (failed?.status === "rejected") error.value = errorMessage(failed.reason); }
async function loadUpdates() { if (!site.value || updatesLoaded) return; updatesLoaded = true; try { updates.value = await appApi.checkUpdates(site.value.id); } catch (cause) { updatesLoaded = false; error.value = errorMessage(cause); } }
async function loadUsers() { if (!site.value || usersLoaded) return; usersLoaded = true; try { usersData.value = await appApi.listWordPressUsers(site.value.id); } catch (cause) { usersLoaded = false; error.value = errorMessage(cause); } }
async function runScan() { if (!site.value || scanActive.value) return; error.value = undefined; selectedFindingIds.value = []; deleteResult.value = undefined; try { await scanJobs.start(site.value.id); } catch (cause) { error.value = errorMessage(cause); } }
async function cancelScan() { if (!scanJob.value || !scanActive.value) return; try { await scanJobs.cancel(scanJob.value.id); } catch (cause) { error.value = errorMessage(cause); } }
function toggleFinding(id: string) { selectedFindingIds.value = selectedFindingIds.value.includes(id) ? selectedFindingIds.value.filter((item) => item !== id) : [...selectedFindingIds.value, id]; }
function selectAllUnexpected() { selectedFindingIds.value = unexpectedFindings.value.flatMap((finding) => finding.id ? [finding.id] : []); }
async function openPreview(finding: Finding) { if (!site.value || !finding.id) return; busy.value = `preview-${finding.id}`; error.value = undefined; try { preview.value = await appApi.previewChecksumFinding(site.value.id, finding.id); } catch (cause) { error.value = errorMessage(cause); } finally { busy.value = undefined; } }
function startIgnore(finding: Finding, temporary: boolean) { pendingPolicyAction.value = { kind: "ignore", finding, temporary }; policyNote.value = ""; policyExpiry.value = "7"; policyExpiryDate.value = ""; }
function startTrust(finding: Finding) { pendingPolicyAction.value = { kind: "trust", finding, temporary: false }; policyNote.value = ""; }
function startVulnerabilityUpdate(item: UpdateItem) { if (item.kind === "core") void openCoreOperation("update"); else confirmUpdate.value = item; }
function isHighRiskVulnerability(finding: Finding) { return Boolean(finding.vulnerability && ["critical", "high"].includes(finding.vulnerability.cvssRating?.toLowerCase() ?? "")); }
async function openVulnerabilityReference(url: string) { error.value = undefined; try { await appApi.openVulnerabilityReference(url); } catch (cause) { error.value = errorMessage(cause); } }
function temporaryExpiration() { if (!pendingPolicyAction.value?.temporary) return undefined; if (policyExpiry.value === "date") { const parsed = new Date(policyExpiryDate.value); return Number.isNaN(parsed.getTime()) ? undefined : parsed.toISOString(); } const expires = new Date(); expires.setUTCDate(expires.getUTCDate() + Number(policyExpiry.value)); return expires.toISOString(); }
async function executePolicyAction() { if (!site.value || !pendingPolicyAction.value?.finding.id) return; const action = pendingPolicyAction.value; const findingId = action.finding.id; const siteId = site.value.id; if (!findingId) return; if (action.temporary && policyExpiry.value === "date" && !temporaryExpiration()) { error.value = "Kies een geldige verloopdatum."; return; } busy.value = "security-policy"; error.value = undefined; try { const result = action.kind === "trust" ? await appApi.trustFindingFile({ siteId, findingId, note: policyNote.value || undefined }) : await appApi.ignoreFinding({ siteId, findingId, note: policyNote.value || undefined, expiresAt: temporaryExpiration() }); if (result.scan) { scan.value = result.scan; scanHistory.value = [result.scan, ...scanHistory.value.filter((item) => item.id !== result.scan?.id)]; } pendingPolicyAction.value = undefined; await store.load(); } catch (cause) { error.value = errorMessage(cause); } finally { busy.value = undefined; } }
async function executeFileDelete() { if (!site.value || !pendingDelete.value.length) return; const ids = pendingDelete.value.flatMap((finding) => finding.id ? [finding.id] : []); busy.value = "file-delete"; error.value = undefined; try { const result = ids.length === 1 ? await appApi.deleteChecksumFinding(site.value.id, ids[0]) : await appApi.deleteChecksumFindings(site.value.id, ids); deleteResult.value = result; if (result.scan) { scan.value = result.scan; scanHistory.value = [result.scan, ...scanHistory.value.filter((item) => item.id !== result.scan?.id)]; } selectedFindingIds.value = []; pendingDelete.value = []; if (result.rescanError) error.value = `De bestanden zijn verwerkt, maar de nacontrole mislukte: ${result.rescanError.userMessage}`; await store.load(); } catch (cause) { error.value = errorMessage(cause); } finally { busy.value = undefined; } }
function roleName(role: string) { return usersData.value?.roles.find((item) => item.role === role)?.name ?? role; }
function isLastAdministrator(user: WordPressUser) { return user.roles.includes("administrator") && administratorCount.value <= 1; }
function startUserEdit(user: WordPressUser) { editUser.value = user; editUserInput.value = { userId: user.id, displayName: user.displayName, email: user.email, role: undefined }; adminPromotionConfirmed.value = false; }
function startUserDelete(user: WordPressUser) { if (isLastAdministrator(user)) return; deleteUser.value = user; const replacement = usersData.value?.users.find((candidate) => candidate.id !== user.id); reassignUserId.value = replacement?.id; deleteMode.value = replacement ? "reassign" : "delete"; }
async function executeUserUpdate() { if (!site.value || !editUserInput.value || (promotingAdministrator.value && !adminPromotionConfirmed.value)) return; busy.value = "user-update"; error.value = undefined; try { usersData.value = await appApi.updateWordPressUser(site.value.id, editUserInput.value); editUser.value = undefined; editUserInput.value = undefined; } catch (cause) { error.value = errorMessage(cause); } finally { busy.value = undefined; } }
async function executeUserDelete() { if (!site.value || !deleteUser.value) return; busy.value = "user-delete"; error.value = undefined; try { usersData.value = await appApi.deleteWordPressUser(site.value.id, { userId: deleteUser.value.id, reassignTo: deleteMode.value === "reassign" ? reassignUserId.value : undefined, deleteContent: deleteMode.value === "delete" }); deleteUser.value = undefined; } catch (cause) { error.value = errorMessage(cause); } finally { busy.value = undefined; } }
async function openCoreOperation(kind: CoreOperationKind) { if (!site.value) return; busy.value = "core-inspect"; error.value = undefined; try { pendingCoreOperation.value = { kind, info: await appApi.inspectCoreOperation(site.value.id) }; } catch (cause) { error.value = errorMessage(cause); } finally { busy.value = undefined; } }
async function executeCoreOperation() { if (!site.value || !pendingCoreOperation.value) return; const kind = pendingCoreOperation.value.kind; busy.value = "core-operation"; error.value = undefined; activeTab.value = "Onderhoud"; liveSteps.value = (kind === "repair" ? [["preflight", "Preflight"], ["backup", "Databasebackup"], ["repair", "Officiële corebestanden opnieuw installeren"], ["checksum", "Core checksum"], ["version", "WordPress-versie"], ["database_check", "Databasecontrole"], ["homepage", "Homepage bereikbaar"], ["updates", "Updatecontrole"]] : [["preflight", "Preflight"], ["backup", "Databasebackup"], ["core", "WordPress core bijwerken"], ["database_update", "WordPress database bijwerken"], ["languages", "Corevertalingen bijwerken"], ["checksum", "Core checksum"], ["version", "WordPress-versie"], ["database_check", "Databasecontrole"], ["homepage", "Homepage bereikbaar"], ["updates", "Updatecontrole"]]).map(([key, label]) => ({ key, label, status: "pending" })); try { const result = kind === "repair" ? await appApi.repairWordPressCore(site.value.id) : await appApi.updateWordPressCore(site.value.id); history.value = [result.run, ...history.value.filter((run) => run.id !== result.run.id)]; updates.value = result.updatesAfter; if (result.scan) { scan.value = result.scan; scanHistory.value = [result.scan, ...scanHistory.value.filter((item) => item.id !== result.scan?.id)]; } if (result.run.status === "failed") error.value = `${kind === "repair" ? "Core-herstel" : "WordPress-update"} is veilig gestopt. Bekijk de onderhoudsstappen voor de oorzaak.`; pendingCoreOperation.value = undefined; await store.load(); } catch (cause) { error.value = errorMessage(cause); } finally { liveSteps.value = []; busy.value = undefined; } }
async function executeConfirmed() {
  if (!site.value || !confirmUpdate.value) return;
  const action = confirmUpdate.value;
  let rescanAfterUpdate = false;
  busy.value = "action";
  try {
    if (action === "maintenance") {
      activeTab.value = "Onderhoud";
      liveSteps.value = [["preflight", "Preflight"], ["precheck", "Voorcontrole"], ["backup", "Databasebackup"], ["core", "WordPress bijwerken"], ["plugins", "Plugins bijwerken"], ["themes", "Thema's bijwerken"], ["languages", "Vertalingen bijwerken"], ["database", "WordPress database bijwerken"], ["postcheck", "Nacontrole"], ["homepage", "Homepage bereikbaar"]].map(([key, label]) => ({ key, label, status: "pending" }));
      const run = await appApi.runMaintenance(site.value.id);
      history.value.unshift(run);
      liveSteps.value = [];
    } else if (action === "all") {
      await appApi.runUpdate(site.value.id, "all");
    } else {
      await appApi.runUpdate(site.value.id, action.kind, action.slug);
      rescanAfterUpdate = true;
    }
    updates.value = await appApi.checkUpdates(site.value.id);
    if (rescanAfterUpdate) await scanJobs.start(site.value.id);
    confirmUpdate.value = undefined;
  } catch (cause) {
    error.value = errorMessage(cause);
  } finally {
    busy.value = undefined;
  }
}
onMounted(async () => { await load(); stopProgress = await appApi.onMaintenanceProgress((payload) => { if (payload.siteId !== site.value?.id) return; const existing = liveSteps.value.findIndex((step) => step.key === payload.step.key); if (existing >= 0) liveSteps.value.splice(existing, 1, payload.step); else liveSteps.value.push(payload.step); }); });
onUnmounted(() => { stopProgress?.(); if (scanClockTimer !== undefined) globalThis.clearInterval(scanClockTimer); });
watch(activeTab, (tab) => { if (tab === "Updates") void loadUpdates(); if (tab === "Gebruikers") void loadUsers(); });
watch(scanActive, (active) => { if (active && scanClockTimer === undefined) scanClockTimer = globalThis.setInterval(() => { scanClock.value = Date.now(); }, 1_000); else if (!active && scanClockTimer !== undefined) { globalThis.clearInterval(scanClockTimer); scanClockTimer = undefined; } }, { immediate: true });
watch(() => scanJob.value?.status, async (status) => {
  const job = scanJob.value;
  if (!job) return;
  if (status === "completed" && job.resultScanId !== handledScanId && site.value) {
    handledScanId = job.resultScanId;
    const scans = await appApi.listScans(site.value.id);
    scanHistory.value = scans; scan.value = scans[0]; activeTab.value = "Security";
    await store.load();
  } else if (status === "failed") error.value = job.error?.userMessage ?? "De scan is mislukt.";
});
</script>

<template>
  <div v-if="site" class="site-detail">
    <section class="site-hero card"><div class="site-avatar xlarge">{{ site.name.slice(0, 2).toUpperCase() }}</div><div class="site-hero-copy"><div><h2>{{ site.name }}</h2><StatusBadge :status="site.status" /></div><span class="site-url">{{ site.url }}</span><p>{{ site.sshUsername }}@{{ site.sshHost }} · {{ site.wordpressPath }}</p></div><div class="hero-actions"><RouterLink class="button secondary" :to="`/websites/${site.id}/bewerken`"><Edit3 :size="16" /> Bewerken</RouterLink><button class="button secondary" :disabled="!!busy || scanActive" @click="runScan"><LoaderCircle v-if="scanActive" class="spin" :size="17" /><RefreshCw v-else :size="17" /> {{ scanActive ? 'Controle bezig…' : 'Website controleren' }}</button><button class="button primary" :disabled="!!busy || scanActive" @click="confirmUpdate = 'maintenance'"><Play :size="17" /> Onderhoud uitvoeren</button></div></section>
    <nav class="tabs" aria-label="Websiteonderdelen"><button v-for="tab in tabs" :key="tab" :class="{ active: activeTab === tab }" @click="activeTab = tab">{{ tab }}<span v-if="tab === 'Updates' && updates.length">{{ updates.length }}</span><span v-else-if="tab === 'Terminal'" class="advanced-tab-badge">🔒 SSH + WP-CLI</span></button></nav>
    <p v-if="error" class="error-banner">{{ error }}</p>
    <section v-if="scanJob && scanActive" class="card live-progress">
      <div class="card-header"><div><h3>Websitecontrole draait op de achtergrond</h3><p>{{ scanJob?.status === 'queued' ? 'Wacht op een beschikbare scanplek…' : `${activeScanStep?.label ?? 'Resultaten verwerken…'}${activeStepSeconds ? ` · ${activeStepSeconds} sec` : ''}` }}</p></div><button class="button small secondary" :disabled="scanJob?.cancellationRequested" @click="cancelScan">{{ scanJob?.cancellationRequested ? 'Annuleren…' : 'Annuleren' }}</button></div>
      <div class="progress-track"><span :style="{ width: `${scanProgress}%` }"></span></div>
      <ol class="step-list"><li v-for="step in scanJob?.steps ?? []" :key="step.key" :class="step.status"><span><Check v-if="step.status === 'success'" :size="15" /><LoaderCircle v-else-if="step.status === 'running'" class="spin" :size="15" /></span><strong>{{ step.label }}</strong><small>{{ step.durationMs !== undefined ? `${step.durationMs} ms` : step.detail }}</small></li></ol>
    </section>
    <details v-if="development && scanJob?.status === 'completed'" class="card scan-diagnostic"><summary>Performance (ontwikkeling) · {{ totalScanDuration }} ms totaal</summary><dl class="info-list"><div v-for="step in scanJob.steps" :key="step.key"><dt>{{ step.label }}</dt><dd>{{ step.durationMs ?? 0 }} ms</dd></div></dl></details>
    <section v-if="liveSteps.length" class="card live-progress"><div class="card-header"><div><h3>Onderhoud wordt uitgevoerd</h3><p>Sluit de app niet zolang muterende stappen bezig zijn.</p></div><LoaderCircle class="spin" :size="20" /></div><ol class="step-list"><li v-for="step in liveSteps" :key="step.key" :class="step.status"><span><Check v-if="step.status === 'success'" :size="15" /><LoaderCircle v-else-if="step.status === 'running'" class="spin" :size="15" /></span><strong>{{ step.label }}</strong><small>{{ step.detail }}</small></li></ol></section>

    <template v-if="activeTab === 'Overzicht'"><div class="detail-stat-grid"><article class="card detail-stat"><span><RefreshCw /></span><small>Beschikbare updates</small><strong>{{ updates.length }}</strong><p>{{ updateKinds.core }} core · {{ updateKinds.plugins }} plugins · {{ updateKinds.themes }} thema's</p></article><article class="card detail-stat"><span><ShieldCheck /></span><small>Laatste securityscan</small><strong>{{ site.securityStatus ?? 'Nog niet uitgevoerd' }}</strong><p>{{ formatDate(site.lastScanAt) }}</p></article><article class="card detail-stat"><span><HardDriveDownload /></span><small>Laatste onderhoud</small><strong>{{ formatDate(site.lastMaintenanceAt) }}</strong><p>{{ history[0]?.status === 'success' ? 'Succesvol afgerond' : 'Geen resultaat' }}</p></article></div><section class="card info-card"><div class="card-header"><div><h3>Technische basisinformatie</h3><p>Automatisch uitgelezen via vooraf ingestelde controles.</p></div></div><dl class="info-list"><div><dt>WordPress-versie</dt><dd>{{ site.wordpressVersion ?? 'Onbekend' }}</dd></div><div><dt>PHP-versie</dt><dd>{{ site.phpVersion ?? 'Onbekend' }}</dd></div><div><dt>SSH host key</dt><dd>{{ site.pinnedHostKey ? 'Vastgezet en gecontroleerd' : 'Nog niet geaccepteerd' }}</dd></div><div><dt>Laatste scan</dt><dd>{{ formatDate(site.lastScanAt) }}</dd></div></dl></section></template>

    <section v-else-if="activeTab === 'Updates'" class="card table-card">
      <div class="card-header"><div><h3>Beschikbare updates</h3><p>Een update installeert een nieuwere versie; core-herstel installeert de huidige versie opnieuw.</p></div><div class="heading-actions"><button class="button secondary" :disabled="!!busy" @click="openCoreOperation('repair')"><LoaderCircle v-if="busy === 'core-inspect'" class="spin" :size="15" /> Core-bestanden herstellen</button><button v-if="updates.length" class="button primary" @click="confirmUpdate = 'maintenance'">Alles veilig bijwerken</button></div></div>
      <div v-if="!updates.length" class="empty-state"><Check :size="38" /><h3>Alles is bijgewerkt</h3><p>Er zijn momenteel geen WordPress-, plugin- of thema-updates. Core-herstel blijft beschikbaar voor de huidige versie.</p></div>
      <table v-else><thead><tr><th>Onderdeel</th><th>Type</th><th>Huidige versie</th><th>Nieuwe versie</th><th></th></tr></thead><tbody><tr v-for="item in updates" :key="`${item.kind}-${item.slug}`"><td><strong>{{ item.name }}</strong><small>{{ item.slug }}</small></td><td class="capitalize">{{ item.kind }}</td><td>{{ item.currentVersion }}</td><td><strong>{{ item.newVersion }}</strong></td><td><button class="button small secondary" :disabled="!!busy" @click="item.kind === 'core' ? openCoreOperation('update') : confirmUpdate = item">{{ item.kind === 'core' ? 'WordPress bijwerken' : 'Bijwerken' }}</button></td></tr></tbody></table>
    </section>

    <section v-else-if="activeTab === 'Gebruikers'" class="card table-card users-card">
      <div class="card-header"><div><h3>WordPress-gebruikers</h3><p>Accounts van de huidige WordPress-site, met rollen en veilige beheeracties.</p></div><span v-if="usersData" class="status-badge status-success"><span class="status-dot"></span>{{ usersData.users.length }} gebruikers</span></div>
      <div v-if="usersData?.multisite" class="multisite-notice"><CircleAlert :size="18" /><div><strong>WordPress Multisite</strong><p>Verwijderen geldt alleen voor de huidige site en gebruikt nooit automatisch <code>--network</code>. Profielvelden zoals naam en e-mail horen bij het netwerkaccount en kunnen ook op andere sites zichtbaar zijn.</p></div></div>
      <div v-if="!usersData" class="empty-state compact"><LoaderCircle class="spin" :size="34" /><h3>Gebruikers laden…</h3></div>
      <div v-else class="table-scroll"><table class="users-table"><thead><tr><th>ID</th><th>Gebruikersnaam</th><th>Weergavenaam / e-mail</th><th>Rollen</th><th>Geregistreerd</th><th></th></tr></thead><tbody><tr v-for="user in usersData.users" :key="user.id"><td>#{{ user.id }}</td><td><strong>{{ user.username }}</strong></td><td><strong>{{ user.displayName }}</strong><small>{{ user.email }}</small></td><td><span v-for="role in user.roles" :key="role" class="role-badge">{{ roleName(role) }}</span><small v-if="!user.roles.length">Geen rol</small></td><td>{{ user.registeredAt }}</td><td><div class="row-actions"><button class="button small secondary" :disabled="!!busy" @click="startUserEdit(user)">Bewerken</button><button class="button small danger-text" :disabled="!!busy || isLastAdministrator(user)" :title="isLastAdministrator(user) ? 'Dit is het laatste Administrator-account.' : 'Gebruiker verwijderen'" @click="startUserDelete(user)">Verwijderen</button></div><small v-if="isLastAdministrator(user)" class="protected-user">Laatste Administrator — verwijderen geblokkeerd</small></td></tr></tbody></table></div>
    </section>

    <template v-else-if="activeTab === 'Security' || activeTab === 'Bestanden' || activeTab === 'Database'">
      <section class="card scan-section">
        <div class="card-header"><div><h3>{{ activeTab === 'Security' ? 'Uitgevoerde securitycontroles' : activeTab }}</h3><p>Resultaten zijn feitelijke controlepunten en geen garantie dat de website volledig veilig is.</p></div><button class="button secondary" :disabled="!!busy || scanActive" @click="runScan">{{ scanActive ? 'Scan bezig…' : 'Securityscan uitvoeren' }}</button></div>
        <div v-if="deleteResult" :class="['delete-result', { partial: deleteResult.failures.length }]">
          <strong>{{ deleteResult.deleted }} van {{ deleteResult.requested }} bestanden verwijderd</strong>
          <p v-if="deleteResult.scan">De checksumscan is opnieuw uitgevoerd.</p>
          <p v-else-if="deleteResult.rescanError">De verwijdering is verwerkt, maar de checksum-nacontrole is mislukt.</p>
          <ul v-else><li v-for="failure in deleteResult.failures" :key="failure.findingId"><code>{{ failure.path ?? failure.findingId }}</code> — {{ failure.error.userMessage }}</li></ul>
        </div>
        <div v-if="activeTab === 'Security' && unexpectedFindings.length" class="checksum-toolbar">
          <div><strong>Hoort niet aanwezig te zijn</strong><small>Alleen actuele unexpected findings kunnen worden geselecteerd.</small></div>
          <button class="button small secondary" :disabled="!isLatestScan" @click="selectAllUnexpected">Alles selecteren</button>
          <button class="button small ghost" :disabled="!selectedFindingIds.length" @click="selectedFindingIds = []">Selectie wissen</button>
          <button class="button small danger" :disabled="!isLatestScan || !selectedFindingIds.length" @click="pendingDelete = unexpectedFindings.filter((finding) => finding.id && selectedFindingIds.includes(finding.id))"><Trash2 :size="14" /> {{ selectedFindingIds.length }} bestanden verwijderen</button>
        </div>
        <div v-if="!scan" class="empty-state compact"><component :is="activeTab === 'Bestanden' ? FileCode2 : activeTab === 'Database' ? Database : ShieldCheck" :size="38" /><h3>Nog geen scanresultaten</h3><p>Voer een scan uit om de resultaten op te slaan en hier te tonen.</p></div>
        <SecurityChecks v-else :checks="visibleChecks" :finished-at="scan.finishedAt" :truncated="scan.truncated" :is-latest-scan="isLatestScan" :selected-finding-ids="selectedFindingIds" :busy="busy" :show-summary="activeTab === 'Security'" :updates="updates" @toggle-finding="toggleFinding" @preview="openPreview" @delete="pendingDelete = [$event]" @ignore="startIgnore" @trust="startTrust" @details="selectedVulnerability = $event" @update="startVulnerabilityUpdate" />
      </section>
    </template>

    <section v-else-if="activeTab === 'Onderhoud'" class="maintenance-layout"><div class="card maintenance-intro"><span class="section-icon"><Play /></span><div><h3>Volledige onderhoudsrun</h3><p>We voeren voorcontroles uit, maken eerst een lokale databasebackup, werken gecontroleerd bij en controleren de website daarna opnieuw.</p></div><button class="button primary" @click="confirmUpdate = 'maintenance'">Onderhoud uitvoeren</button></div><article v-if="history[0]" class="card run-detail"><div class="card-header"><div><h3>Laatste onderhoud</h3><p>{{ formatDate(history[0].startedAt) }}</p></div><StatusBadge :status="history[0].status" /></div><ol class="step-list"><li v-for="step in history[0].steps" :key="step.key" :class="step.status"><span><Check v-if="step.status === 'success'" :size="15" /><LoaderCircle v-else-if="step.status === 'running'" class="spin" :size="15" /></span><strong>{{ step.label }}</strong><small>{{ step.detail }}</small></li></ol></article></section>
    <SshTerminal v-else-if="activeTab === 'Terminal'" :key="site.id" :site="site" @cancel="activeTab = 'Overzicht'" />
    <template v-else-if="activeTab === 'Historie'"><section class="card table-card"><div class="card-header"><div><h3>Scanhistorie</h3><p>Open een eerdere scan met alle afzonderlijke controles en findings.</p></div></div><div v-if="!scanHistory.length" class="empty-state compact"><h3>Nog geen scans opgeslagen</h3></div><table v-else><thead><tr><th>Datum</th><th>Resultaat</th><th>Controles</th><th></th></tr></thead><tbody><tr v-for="item in scanHistory" :key="item.id"><td>{{ formatDate(item.finishedAt) }}</td><td><StatusBadge :status="item.status" /></td><td>{{ item.checks.length }} controles</td><td><button class="button small secondary" @click="scan = item; activeTab = 'Security'">Bekijken</button></td></tr></tbody></table></section><section class="card table-card"><div class="card-header"><div><h3>Onderhoudshistorie</h3><p>Vergelijk eerdere onderhoudsbeurten.</p></div></div><div v-if="!history.length" class="empty-state compact"><h3>Nog geen onderhoud uitgevoerd</h3></div><table v-else><thead><tr><th>Datum</th><th>Resultaat</th><th>Voor</th><th>Na</th><th></th></tr></thead><tbody><tr v-for="run in history" :key="run.id"><td>{{ formatDate(run.startedAt) }}</td><td><StatusBadge :status="run.status" /></td><td>{{ run.beforeVersions }}</td><td>{{ run.afterVersions }}</td><td><ChevronRight :size="17" /></td></tr></tbody></table></section></template>
  </div>
  <div v-else class="empty-state card"><h3>Website niet gevonden</h3><RouterLink class="button secondary" to="/websites">Terug naar websites</RouterLink></div>

  <ConfirmDialog v-if="confirmUpdate" :title="confirmUpdate === 'maintenance' ? 'Onderhoud uitvoeren?' : confirmUpdate === 'all' ? `${updates.length} updates uitvoeren?` : `${confirmUpdate.name} bijwerken?`" :confirm-label="confirmUpdate === 'maintenance' ? 'Onderhoud starten' : 'Bijwerken'" :busy="busy === 'action'" @cancel="confirmUpdate = undefined" @confirm="executeConfirmed"><template v-if="confirmUpdate === 'maintenance'"><p>De app maakt eerst een databasebackup. Als die mislukt, worden er geen updates gestart.</p><ul><li>Voorcontrole en securitychecks</li><li>Lokale databasebackup</li><li>Core, plugins, thema's en vertalingen</li><li>Database- en homepagecontrole</li></ul></template><template v-else-if="confirmUpdate === 'all'"><ul><li v-for="item in updates" :key="item.slug">{{ item.name }}: {{ item.currentVersion }} → {{ item.newVersion }}</li></ul></template><p v-else>{{ confirmUpdate.name }} wordt bijgewerkt van {{ confirmUpdate.currentVersion }} naar {{ confirmUpdate.newVersion }}.</p></ConfirmDialog>
  <ChecksumFilePreview v-if="preview" :preview="preview" @close="preview = undefined" @delete="pendingDelete = [preview.finding]; preview = undefined" />
  <VulnerabilityDetails v-if="selectedVulnerability" :finding="selectedVulnerability" @close="selectedVulnerability = undefined" @open-reference="openVulnerabilityReference" />
  <ConfirmDialog v-if="pendingDelete.length" :title="pendingDelete.length === 1 ? 'Bestand permanent verwijderen?' : `${pendingDelete.length} bestanden permanent verwijderen?`" :confirm-label="pendingDelete.length === 1 ? 'Bestand verwijderen' : `${pendingDelete.length} bestanden verwijderen`" :busy="busy === 'file-delete'" danger @cancel="pendingDelete = []" @confirm="executeFileDelete">
    <p>Deze actie verwijdert de geselecteerde bestanden permanent van de server en kan niet automatisch ongedaan worden gemaakt.</p>
    <ul class="delete-file-list"><li v-for="finding in pendingDelete" :key="finding.id"><code>{{ finding.path }}</code></li></ul>
  </ConfirmDialog>
  <div v-if="pendingPolicyAction" class="modal-backdrop" role="presentation" @click.self="pendingPolicyAction = undefined">
    <form class="modal policy-action-modal" role="dialog" aria-modal="true" :aria-label="pendingPolicyAction.kind === 'trust' ? 'Bestand vertrouwen' : 'Melding negeren'" @submit.prevent="executePolicyAction">
      <h2>{{ pendingPolicyAction.kind === 'trust' ? 'Bestand vertrouwen?' : isHighRiskVulnerability(pendingPolicyAction.finding) ? 'Beveiligingskwetsbaarheid negeren?' : ['critical', 'problem'].includes(pendingPolicyAction.finding.severity) ? 'Belangrijke beveiligingsmelding negeren?' : pendingPolicyAction.temporary ? 'Melding tijdelijk negeren?' : 'Deze melding negeren?' }}</h2>
      <code v-if="pendingPolicyAction.finding.path">{{ pendingPolicyAction.finding.path }}</code>
      <p v-else>{{ pendingPolicyAction.finding.title }}</p>
      <p v-if="pendingPolicyAction.kind === 'trust'">De backend bewaart alleen de SHA-256-fingerprint van de huidige versie. Als de inhoud later verandert, wordt opnieuw een waarschuwing getoond.</p>
      <p v-else>Alleen deze combinatie van website, controle, meldingstype en target telt niet meer mee. Andere afwijkingen blijven zichtbaar.</p>
      <p v-if="pendingPolicyAction.kind === 'ignore' && !pendingPolicyAction.finding.vulnerability && ['critical', 'problem'].includes(pendingPolicyAction.finding.severity)" class="danger-notice"><CircleAlert :size="17" /> Deze melding kan op een ernstige of gewijzigde corefile wijzen. Negeer haar alleen na bewuste controle.</p>
      <p v-if="pendingPolicyAction.kind === 'ignore' && isHighRiskVulnerability(pendingPolicyAction.finding)" class="danger-notice"><CircleAlert :size="17" /> Deze specifieke softwareversie heeft volgens Wordfence een bekende kwetsbaarheid. Negeer haar alleen als je dit risico bewust accepteert.</p>
      <label v-if="pendingPolicyAction.temporary" class="policy-field"><span>Verloopt</span><select v-model="policyExpiry"><option value="7">Over 7 dagen</option><option value="30">Over 30 dagen</option><option value="date">Op specifieke datum</option></select></label>
      <label v-if="pendingPolicyAction.temporary && policyExpiry === 'date'" class="policy-field"><span>Datum en tijd</span><input v-model="policyExpiryDate" type="datetime-local" required /></label>
      <label class="policy-field"><span>Notitie (optioneel)</span><textarea v-model="policyNote" maxlength="500" rows="3" placeholder="Waarom is dit beoordeeld? Sla hier geen geheimen op."></textarea></label>
      <div class="modal-actions"><button type="button" class="button secondary" :disabled="busy === 'security-policy'" @click="pendingPolicyAction = undefined">Annuleren</button><button class="button primary" :disabled="busy === 'security-policy' || (pendingPolicyAction.temporary && policyExpiry === 'date' && !policyExpiryDate)"><LoaderCircle v-if="busy === 'security-policy'" class="spin" :size="14" /> {{ pendingPolicyAction.kind === 'trust' ? 'Bestand vertrouwen' : pendingPolicyAction.temporary ? 'Tijdelijk negeren' : 'Negeren' }}</button></div>
    </form>
  </div>
  <ConfirmDialog v-if="pendingCoreOperation" :title="pendingCoreOperation.kind === 'repair' ? 'WordPress core herstellen' : 'WordPress bijwerken'" :confirm-label="pendingCoreOperation.kind === 'repair' ? 'Core-bestanden herstellen' : 'WordPress bijwerken'" :busy="busy === 'core-operation'" @cancel="pendingCoreOperation = undefined" @confirm="executeCoreOperation">
    <template v-if="pendingCoreOperation.kind === 'repair'"><p>De officiële WordPress-bestanden van versie <strong>{{ pendingCoreOperation.info.currentVersion }}</strong> ({{ pendingCoreOperation.info.locale }}) worden opnieuw gedownload.</p><ul><li>Er wordt eerst verplicht een databasebackup gemaakt.</li><li><code>wp-content</code>, uploads, plugins, thema's en configuratie blijven behouden.</li><li>Onbekende extra bestanden worden niet automatisch verwijderd.</li><li>Daarna volgen checksum-, database-, versie- en homepagecontroles.</li></ul></template>
    <template v-else><p>WordPress wordt bijgewerkt van <strong>{{ pendingCoreOperation.info.currentVersion }}</strong> naar <strong>{{ pendingCoreOperation.info.availableVersion ?? 'de gedetecteerde nieuwe versie' }}</strong>.</p><ul><li>Er wordt eerst verplicht een databasebackup gemaakt.</li><li>Daarna volgen database-update en corevertalingen.</li><li>Checksum, versie, database en homepage worden na afloop gecontroleerd.</li></ul></template>
    <p class="core-preflight-summary">Root: <code>{{ pendingCoreOperation.info.wordpressPath }}</code><br />Vrije ruimte: {{ pendingCoreOperation.info.diskAvailableMb }} MB</p>
  </ConfirmDialog>
  <div v-if="editUser && editUserInput && usersData" class="modal-backdrop" role="presentation" @click.self="editUser = undefined; editUserInput = undefined">
    <form class="modal user-edit-modal" role="dialog" aria-modal="true" aria-label="WordPress-gebruiker bewerken" @submit.prevent="executeUserUpdate">
      <h2>Gebruiker bewerken</h2><p class="user-modal-subtitle">#{{ editUser.id }} · {{ editUser.username }}</p>
      <div class="user-form"><label><span>Weergavenaam</span><input v-model="editUserInput.displayName" required maxlength="250" /></label><label><span>E-mailadres</span><input v-model="editUserInput.email" required type="email" maxlength="254" /></label><label><span>Rol</span><select v-model="editUserInput.role"><option :value="undefined">Bestaande rollen behouden ({{ editUser.roles.map(roleName).join(', ') || 'geen' }})</option><option v-for="role in usersData.roles" :key="role.role" :value="role.role">Instellen als {{ role.name }} ({{ role.role }})</option></select></label></div>
      <p v-if="usersData.multisite" class="inline-warning">Op Multisite zijn weergavenaam en e-mail profielvelden van het netwerkaccount.</p>
      <p v-if="isLastAdministrator(editUser) && editUserInput.role !== 'administrator'" class="danger-notice">De backend blokkeert deze wijziging: dit is het laatste Administrator-account.</p>
      <label v-if="promotingAdministrator" class="admin-confirm"><input v-model="adminPromotionConfirmed" type="checkbox" /><span><strong>Promotie naar Administrator bevestigen</strong>Deze rol geeft volledige beheerrechten over de site.</span></label>
      <div class="modal-actions"><button type="button" class="button secondary" :disabled="busy === 'user-update'" @click="editUser = undefined; editUserInput = undefined">Annuleren</button><button class="button primary" :disabled="busy === 'user-update' || (promotingAdministrator && !adminPromotionConfirmed)"><LoaderCircle v-if="busy === 'user-update'" class="spin" :size="14" /> Wijzigingen opslaan</button></div>
    </form>
  </div>
  <ConfirmDialog v-if="deleteUser && usersData" title="Gebruiker verwijderen" confirm-label="Gebruiker verwijderen" :busy="busy === 'user-delete'" danger @cancel="deleteUser = undefined" @confirm="executeUserDelete">
    <p><strong>{{ deleteUser.username }}</strong> (#{{ deleteUser.id }}) wordt van deze WordPress-site verwijderd.</p>
    <p v-if="usersData.multisite" class="inline-warning">Multisite: alleen het lidmaatschap van de huidige site wordt verwijderd; nooit network-wide.</p>
    <fieldset class="delete-user-options"><legend>Wat moet met gekoppelde content gebeuren?</legend><label><input v-model="deleteMode" type="radio" value="reassign" :disabled="usersData.users.length < 2" /><span>Content toewijzen aan</span></label><select v-model.number="reassignUserId" :disabled="deleteMode !== 'reassign'"><option v-for="candidate in usersData.users.filter((candidate) => candidate.id !== deleteUser?.id)" :key="candidate.id" :value="candidate.id">{{ candidate.displayName }} (#{{ candidate.id }})</option></select><label class="danger-choice"><input v-model="deleteMode" type="radio" value="delete" /><span>Content samen met gebruiker permanent verwijderen</span></label></fieldset>
    <p class="danger-notice">Deze actie kan niet automatisch ongedaan worden gemaakt.</p>
  </ConfirmDialog>
</template>
