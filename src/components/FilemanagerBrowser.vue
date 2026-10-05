<script setup lang="ts">
import { computed, inject, onBeforeUnmount, onMounted, ref, watch } from "vue";
import { routerKey } from "vue-router";
import { AlertTriangle, ArrowLeft, ChevronUp, Download, Eye, File, FileArchive, FileCode2, FilePlus2, FileQuestion, Folder, FolderOpen, FolderPlus, LoaderCircle, RefreshCw, Trash2, LockKeyhole } from "@lucide/vue";
import type { FilePreviewMode, MarkdownPreviewMode } from "../types";
import type { FilemanagerBulkResult, FilemanagerContext, FilemanagerDirectoryItem, FilemanagerDirectoryListing, FilemanagerFilePreview, FilemanagerMutationKind } from "../types/filemanager";
import { appApi } from "../services/tauri";
import { errorMessage } from "../utils/errors";
import { formatDate } from "../utils/format";
import FilemanagerBreadcrumbs from "./FilemanagerBreadcrumbs.vue";
import ChecksumFilePreview from "./ChecksumFilePreview.vue";
import ConfirmDialog from "./ConfirmDialog.vue";
import { vDialogFocus } from "../utils/dialogFocus";
const props = defineProps<{ context: FilemanagerContext; authorizationToken: string }>();
const emit = defineEmits<{ expired: [] }>();
const listing = ref<FilemanagerDirectoryListing>(); const loading = ref(false); const error = ref<string>(); const history = ref<string[]>([]);
let contextGeneration = 0;
function captureContext() {
  const generation = contextGeneration;
  return { site: props.context.siteId, token: props.authorizationToken, current: () => generation === contextGeneration };
}
let requestId = 0; let previewRequestId = 0;
const preview = ref<FilemanagerFilePreview>(); const previewComponent = ref<InstanceType<typeof ChecksumFilePreview>>(); const previewLoadingPath = ref<string>(); const previewError = ref<string>();
const filePreviewMode = ref<FilePreviewMode>("normal"); const markdownPreviewMode = ref<MarkdownPreviewMode>("raw");
const createKind = ref<"file" | "directory">(); const newName = ref(""); const createBusy = ref(false); const createError = ref<string>();
const deleteTarget = ref<FilemanagerDirectoryItem>(); const deleteBusy = ref(false); const deleteError = ref<string>(); const feedback = ref<string>();
const selectedPaths = ref(new Set<string>()); const permissionTarget = ref<FilemanagerDirectoryItem>(); const bulkPermissionOpen = ref(false); const bulkDeleteOpen = ref(false); const permissionMode = ref(""); const actionBusy = ref(false); const actionError = ref<string>(); const bulkResult = ref<FilemanagerBulkResult>();
const downloadBusy = ref(false); const downloadError = ref<string>();
const selectable = computed(() => listing.value?.items.filter((item) => item.kind !== "other") ?? []);
const selectedItems = computed(() => selectable.value.filter((item) => selectedPaths.value.has(item.path)));
const selectedCount = computed(() => selectedItems.value.length);
const allSelected = computed(() => selectable.value.length > 0 && selectedCount.value === selectable.value.length);
const partlySelected = computed(() => selectedCount.value > 0 && !allSelected.value);
const selectAllInput = ref<{ indeterminate: boolean }>();
watch([partlySelected, selectAllInput], () => { if (selectAllInput.value) selectAllInput.value.indeterminate = partlySelected.value; }, { flush: "post" });
watch(() => [props.context.siteId, props.authorizationToken], () => {
  contextGeneration += 1; requestId += 1;
  closePreview(); selectedPaths.value = new Set(); listing.value = undefined; history.value = [];
  createKind.value = undefined; deleteTarget.value = undefined; permissionTarget.value = undefined;
  bulkPermissionOpen.value = false; bulkDeleteOpen.value = false; bulkResult.value = undefined;
  createError.value = undefined; deleteError.value = undefined; actionError.value = undefined; downloadError.value = undefined; feedback.value = undefined;
  loading.value = false; createBusy.value = false; deleteBusy.value = false; actionBusy.value = false; downloadBusy.value = false;
  void load("/");
});
function toggleSelection(path: string) { const next = new Set(selectedPaths.value); if (next.has(path)) next.delete(path); else next.add(path); selectedPaths.value = next; }
function toggleSelectAll() { selectedPaths.value = allSelected.value ? new Set() : new Set(selectable.value.map((item) => item.path)); }
function selectedPayload() { return selectedItems.value.map((item) => ({ path: item.path, expectedKind: item.kind as FilemanagerMutationKind })); }
async function downloadItems(items: FilemanagerDirectoryItem[]) {
  if (busy.value || !listing.value || !items.length || items.length > 100) return;
  const ctx = captureContext(); const directory = listing.value.currentPath;
  downloadBusy.value = true; downloadError.value = undefined; feedback.value = undefined;
  try {
    const result = await appApi.downloadFilemanagerItems(ctx.site, ctx.token, { directory, items: items.map((item) => ({ path: item.path, expectedKind: item.kind as FilemanagerMutationKind })) });
    if (ctx.current() && directory === listing.value?.currentPath && result) feedback.value = `Download opgeslagen: ${result.savedTo ?? result.fileName}`;
  } catch (cause) {
    if (!ctx.current()) return;
    if (authorizationExpired(cause) && categoryOf(cause) !== "filemanager_file_read_failed") { emit("expired"); return; }
    downloadError.value = errorMessage(cause);
  } finally { if (ctx.current()) downloadBusy.value = false; }
}
function openPermissions(item?: FilemanagerDirectoryItem) { if (busy.value || actionBusy.value) return; permissionTarget.value = item; bulkPermissionOpen.value = !item; permissionMode.value = item?.permissions?.match(/^[0-7]{3}$/) ? item.permissions : ""; actionError.value = undefined; bulkResult.value = undefined; }
function closeAction() { if (actionBusy.value) return; permissionTarget.value = undefined; bulkPermissionOpen.value = false; bulkDeleteOpen.value = false; actionError.value = undefined; }
function showBulkResult(result: FilemanagerBulkResult, verb: string) { bulkResult.value = result; feedback.value = `${result.succeeded} van ${result.requested} ${result.requested === 1 ? "item" : "items"} ${verb}.`; if (result.failed) actionError.value = `${result.failed} ${result.failed === 1 ? "item kon" : "items konden"} niet worden verwerkt.`; }
async function refreshMetadata(ctx: ReturnType<typeof captureContext>, directory: string) {
  try {
    const result = await appApi.listFilemanagerDirectory(ctx.site, ctx.token, directory);
    if (ctx.current() && listing.value?.currentPath === directory) { listing.value = result; selectedPaths.value = new Set(); }
  } catch (cause) {
    if (!ctx.current()) return;
    if (authorizationExpired(cause)) emit("expired");
    else error.value = `De actie is uitgevoerd, maar de map kon niet worden vernieuwd: ${errorMessage(cause)}`;
  }
}
async function applyPermissions() {
  if (actionBusy.value || !/^[0-7]{3}$/.test(permissionMode.value) || bulkPermissionOpen.value && (selectedCount.value === 0 || selectedCount.value > 100)) return;
  const ctx = captureContext(); const directory = listing.value?.currentPath; if (!directory) return;
  const mode = permissionMode.value; const target = permissionTarget.value;
  actionBusy.value = true; actionError.value = undefined; feedback.value = undefined;
  try {
    if (target) {
      await appApi.changeFilemanagerPermissions(ctx.site, ctx.token, { path: target.path, expectedKind: target.kind as FilemanagerMutationKind, mode });
      if (!ctx.current()) return;
      feedback.value = `Permissions van ${target.name} gewijzigd naar ${mode}.`; permissionTarget.value = undefined;
    } else {
      const result = await appApi.changeFilemanagerPermissionsBulk(ctx.site, ctx.token, { directory, items: selectedPayload(), mode });
      if (!ctx.current()) return;
      showBulkResult(result, "aangepast"); bulkPermissionOpen.value = false;
    }
    await refreshMetadata(ctx, directory);
  } catch (cause) {
    if (!ctx.current()) return;
    if (authorizationExpired(cause)) { emit("expired"); return; }
    actionError.value = errorMessage(cause);
  } finally { if (ctx.current()) actionBusy.value = false; }
}
async function confirmBulkDelete() {
  if (actionBusy.value || !listing.value || !selectedCount.value || selectedCount.value > 100) return;
  const ctx = captureContext(); const directory = listing.value.currentPath; const items = selectedPayload();
  if (preview.value && items.some((item) => item.path === preview.value?.relativePath) && !(await requestLeave())) return;
  if (!ctx.current() || directory !== listing.value?.currentPath) return;
  actionBusy.value = true; actionError.value = undefined;
  try {
    const result = await appApi.deleteFilemanagerBulk(ctx.site, ctx.token, { directory, items });
    if (!ctx.current()) return;
    showBulkResult(result, "verwijderd"); bulkDeleteOpen.value = false; selectedPaths.value = new Set();
    if (preview.value && items.some((item) => item.path === preview.value?.relativePath)) closePreview();
    await load(directory, "refresh");
  } catch (cause) {
    if (!ctx.current()) return;
    if (authorizationExpired(cause)) { emit("expired"); return; }
    actionError.value = errorMessage(cause);
  } finally { if (ctx.current()) actionBusy.value = false; }
}
const router = inject(routerKey, undefined); const removeNavigationGuard = router?.beforeEach(async () => await previewComponent.value?.requestLeave() ?? true);
async function requestLeave() { return await previewComponent.value?.requestLeave() ?? true; }
defineExpose({ requestLeave, hasUnsavedChanges: () => previewComponent.value?.hasUnsavedChanges() ?? false });
const canGoBack = computed(() => history.value.length > 0 && !busy.value); const canGoUp = computed(() => Boolean(listing.value?.parentPath) && !busy.value); const busy = computed(() => loading.value || createBusy.value || deleteBusy.value || actionBusy.value || downloadBusy.value);
const categoryOf = (cause: unknown) => typeof cause === "object" && cause !== null && "category" in cause && typeof (cause as { category?: unknown }).category === "string" ? (cause as { category: string }).category : undefined;
const authorizationExpired = (cause: unknown) => ["filemanager_auth_required", "filemanager_disconnected", "filemanager_timeout", "filemanager_sftp_failed", "filemanager_file_read_failed", "locked", "session_expired", "invalid_session"].includes(categoryOf(cause) ?? "");
function formatBytes(bytes: number | null) { if (bytes === null) return "—"; if (bytes < 1024) return `${bytes} B`; const units = ["KB", "MB", "GB", "TB"]; let value = bytes / 1024; let unit = 0; while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; } return `${value.toLocaleString("nl-NL", { maximumFractionDigits: 1 })} ${units[unit]}`; }
function typeLabel(item: FilemanagerDirectoryItem) { return item.kind === "directory" ? "Map" : item.kind === "symlink" ? "Symlink" : item.kind === "other" ? "Overig" : item.extension ? item.extension.toUpperCase() : "Bestand"; }
function itemIcon(item: FilemanagerDirectoryItem) { return item.kind === "directory" ? Folder : item.extension && ["zip", "gz", "tar", "rar", "7z"].includes(item.extension) ? FileArchive : item.extension && ["php", "js", "css", "html", "json", "md", "xml", "twig", "scss"].includes(item.extension) ? FileCode2 : item.kind === "file" ? File : FileQuestion; }
function closePreview() { previewRequestId += 1; preview.value = undefined; previewLoadingPath.value = undefined; previewError.value = undefined; }
async function load(path: string, source: "normal" | "back" | "refresh" = "normal") { if (busy.value && source !== "refresh") return; const ctx = captureContext(); if (preview.value && !(await requestLeave())) return; if (!ctx.current()) return; closePreview(); selectedPaths.value = new Set(); if (source !== "refresh") { bulkResult.value = undefined; feedback.value = undefined; } const request = ++requestId; const site = props.context.siteId; loading.value = true; error.value = undefined; try { const result = await appApi.listFilemanagerDirectory(site, props.authorizationToken, path); if (request !== requestId || site !== props.context.siteId || result.currentPath !== path) return; const previous = listing.value?.currentPath; listing.value = result; if (source === "normal" && previous && previous !== result.currentPath) history.value.push(previous); if (source === "back") history.value.pop(); } catch (cause) { if (request !== requestId || site !== props.context.siteId) return; listing.value = undefined; if (authorizationExpired(cause)) { emit("expired"); return; } error.value = errorMessage(cause); } finally { if (request === requestId) loading.value = false; } }
function openDirectory(item: FilemanagerDirectoryItem) { if (item.kind === "directory") void load(item.path); }
async function openFile(item: FilemanagerDirectoryItem) { const ctx = captureContext(); if (item.kind !== "file" || previewLoadingPath.value === item.path || !(await requestLeave())) return; if (!ctx.current()) return; const request = ++previewRequestId; previewLoadingPath.value = item.path; previewError.value = undefined; preview.value = undefined; try { const result = await appApi.readFilemanagerFile(ctx.site, ctx.token, item.path); if (request !== previewRequestId || result.relativePath !== item.path) return; preview.value = result; } catch (cause) { if (request !== previewRequestId) return; if (authorizationExpired(cause)) { emit("expired"); return; } previewError.value = errorMessage(cause); } finally { if (request === previewRequestId) previewLoadingPath.value = undefined; } }
function openCreate(kind: "file" | "directory") { if (busy.value || !listing.value) return; createKind.value = kind; newName.value = ""; createError.value = undefined; }
function closeCreate() { if (!createBusy.value) { createKind.value = undefined; createError.value = undefined; } }
async function createItem() {
  if (!createKind.value || !listing.value || !newName.value.trim() || createBusy.value) return;
  const ctx = captureContext(); const directory = listing.value.currentPath;
  const input = { directory, name: newName.value }; const kind = createKind.value;
  createBusy.value = true; createError.value = undefined; feedback.value = undefined;
  try {
    const result = kind === "file" ? await appApi.createFilemanagerFile(ctx.site, ctx.token, input) : await appApi.createFilemanagerDirectory(ctx.site, ctx.token, input);
    if (!ctx.current()) return;
    createKind.value = undefined; await load(directory, "refresh");
    if (!ctx.current()) return;
    feedback.value = result.kind === "file" ? "Bestand aangemaakt." : "Map aangemaakt.";
    if (result.kind === "file") { const item = listing.value?.items.find((entry) => entry.path === result.path); if (item) await openFile(item); }
  } catch (cause) {
    if (!ctx.current()) return;
    if (authorizationExpired(cause)) { emit("expired"); return; }
    createError.value = errorMessage(cause);
  } finally { if (ctx.current()) createBusy.value = false; }
}
async function requestDelete(item: FilemanagerDirectoryItem) { const ctx = captureContext(); if (!(["file", "directory", "symlink"] as string[]).includes(item.kind) || busy.value) return; if (preview.value?.relativePath === item.path) { if (!(await requestLeave()) || !ctx.current()) return; closePreview(); } if (!ctx.current()) return; deleteTarget.value = item; deleteError.value = undefined; }
function closeDelete() { if (!deleteBusy.value) { deleteTarget.value = undefined; deleteError.value = undefined; } }
async function confirmDelete() {
  const target = deleteTarget.value; if (!target || deleteBusy.value) return;
  const ctx = captureContext(); const directory = listing.value?.currentPath ?? "/";
  deleteBusy.value = true; deleteError.value = undefined; feedback.value = undefined;
  try {
    const result = await appApi.deleteFilemanagerItem(ctx.site, ctx.token, { path: target.path, expectedKind: target.kind as FilemanagerMutationKind });
    if (!ctx.current()) return;
    deleteTarget.value = undefined; await load(directory, "refresh");
    if (ctx.current()) feedback.value = result.kind === "directory" ? "Map verwijderd." : "Bestand verwijderd.";
  } catch (cause) {
    if (!ctx.current()) return;
    if (authorizationExpired(cause)) { emit("expired"); return; }
    deleteError.value = errorMessage(cause);
  } finally { if (ctx.current()) deleteBusy.value = false; }
}
async function saveFile(content: string, expectedVersion: string) { const path = preview.value?.relativePath; const request = previewRequestId; if (!path) throw new Error("Open het bestand opnieuw."); const result = await appApi.saveFilemanagerFile(props.context.siteId, props.authorizationToken, { path, content, expectedVersion }); if (request !== previewRequestId || result.relativePath !== path) throw new Error("De bestandscontext is gewijzigd. Open het bestand opnieuw."); return result; }
function fileSaved(result: FilemanagerFilePreview) { if (preview.value?.relativePath !== result.relativePath) return; preview.value = result; const item = listing.value?.items.find((entry) => entry.path === result.relativePath); if (item) { item.size = result.sizeBytes; item.modifiedAt = result.modifiedAt ?? null; } }
async function reloadFile() { const path = preview.value?.relativePath; const request = previewRequestId; if (!path) return; const result = await appApi.readFilemanagerFile(props.context.siteId, props.authorizationToken, path); if (request === previewRequestId && result.relativePath === path) fileSaved(result); }
function goBack() { const path = history.value[history.value.length - 1]; if (path) void load(path, "back"); } function goUp() { if (listing.value?.parentPath) void load(listing.value.parentPath); }
onMounted(() => { void load("/"); void appApi.getSettings().then((settings) => { filePreviewMode.value = settings.filePreviewMode; markdownPreviewMode.value = settings.markdownPreviewMode; }).catch(() => undefined); }); onBeforeUnmount(() => { contextGeneration += 1; removeNavigationGuard?.(); requestId += 1; previewRequestId += 1; });
</script>
<template>
  <section class="filemanager-browser" :aria-busy="busy">
    <header class="filemanager-browser-heading"><div><div class="filemanager-browser-title"><FolderOpen :size="22" /><h3>Bestanden</h3></div><p>Huidige map: <code>{{ listing?.currentPath ?? '/' }}</code></p></div><div class="filemanager-actions"><button type="button" class="button small secondary" :disabled="busy || !listing" @click="openCreate('file')"><FilePlus2 :size="15" /> Nieuw bestand</button><button type="button" class="button small secondary" :disabled="busy || !listing" @click="openCreate('directory')"><FolderPlus :size="15" /> Nieuwe map</button><button type="button" class="button small secondary" :disabled="!canGoBack || busy" @click="goBack"><ArrowLeft :size="15" /> Terug</button><button type="button" class="button small secondary" :disabled="!canGoUp || busy" @click="goUp"><ChevronUp :size="15" /> Omhoog</button><button type="button" class="icon-button" :disabled="busy" aria-label="Map vernieuwen" title="Map vernieuwen" @click="listing && load(listing.currentPath, 'refresh')"><RefreshCw :class="{ spin: loading }" :size="17" /></button></div></header>
    <FilemanagerBreadcrumbs :current-path="listing?.currentPath ?? '/'" :disabled="busy" @navigate="load($event)" />
    <p v-if="feedback" class="filemanager-success" role="status">{{ feedback }}</p>
    <div v-if="bulkResult?.failed" class="filemanager-warning" role="alert"><AlertTriangle :size="16" /><div><strong>{{ bulkResult.failed }} mislukt</strong><ul><li v-for="failure in bulkResult.failures" :key="failure.path"><code>{{ failure.path }}</code> — {{ failure.reason }}</li></ul></div></div>
    <p v-if="listing?.truncated" class="filemanager-warning"><AlertTriangle :size="16" /> Deze map bevat meer dan 5.000 items. Alleen de eerste veilige selectie wordt getoond.</p>
    <p v-if="error" class="error-banner" role="alert">{{ error }}</p><p v-if="previewError" class="error-banner" role="alert">{{ previewError }}</p><p v-if="downloadError" class="error-banner" role="alert">{{ downloadError }}</p>
    <div v-if="downloadBusy" class="filemanager-preview-loading" role="status"><LoaderCircle class="spin" :size="18" /><strong>Download voorbereiden en veilig opslaan…</strong></div>
    <div v-if="previewLoadingPath" class="filemanager-preview-loading" role="status"><LoaderCircle class="spin" :size="18" /><span><strong>Bestand laden…</strong><code>{{ previewLoadingPath }}</code></span></div>
    <div v-if="selectedCount" class="filemanager-bulk-toolbar" role="toolbar" aria-label="Bulkacties"><strong role="status">{{ selectedCount }} {{ selectedCount === 1 ? 'item geselecteerd' : 'items geselecteerd' }}</strong><button class="button small secondary" :disabled="busy || selectedCount > 100" @click="downloadItems(selectedItems)"><Download :size="15" /> Downloaden</button><button class="button small secondary" :disabled="busy || selectedCount > 100" @click="openPermissions()"><LockKeyhole :size="15" /> Permissions wijzigen</button><button class="button small danger" :disabled="busy || selectedCount > 100" @click="bulkDeleteOpen = true; actionError = undefined; bulkResult = undefined"><Trash2 :size="15" /> Verwijderen</button><small>{{ selectedCount > 100 ? 'Selecteer maximaal 100 items voor een bulkactie.' : 'Bulkacties gelden alleen voor deze map.' }}</small></div>
    <div v-if="loading" class="empty-state compact" role="status"><LoaderCircle class="spin" :size="32" /><h3>Map laden…</h3><p>De beveiligde directorylisting wordt opgehaald.</p></div>
    <div v-else-if="listing && !listing.items.length" class="empty-state compact"><FolderOpen :size="35" /><h3>Deze map is leeg</h3><p>Er zijn geen bestanden of mappen in {{ listing.currentPath }}.</p></div>
    <div v-else-if="listing" class="filemanager-table-scroll"><table class="filemanager-table">
      <thead><tr><th class="filemanager-select"><input ref="selectAllInput" type="checkbox" :checked="allSelected" :disabled="busy || !selectable.length" aria-label="Selecteer alle items in deze map" @change="toggleSelectAll" /></th><th>Naam</th><th>Type</th><th>Grootte</th><th>Permissions</th><th>Gewijzigd</th><th><span class="sr-only">Acties</span></th></tr></thead>
      <tbody><tr v-for="item in listing.items" :key="item.path">
        <td class="filemanager-select"><input v-if="item.kind !== 'other'" type="checkbox" :checked="selectedPaths.has(item.path)" :disabled="busy" :aria-label="`Selecteer ${item.name}`" @change="toggleSelection(item.path)" /></td>
        <td><button v-if="item.kind === 'directory'" type="button" class="filemanager-name-button" :disabled="busy" :title="`Open ${item.name}`" @click="openDirectory(item)"><component :is="itemIcon(item)" :size="18" /><strong>{{ item.name }}</strong></button><button v-else-if="item.kind === 'file'" type="button" class="filemanager-name-button file" :disabled="busy" :aria-label="`Bekijk ${item.name}`" :title="`Bekijk ${item.name}`" @click="openFile(item)"><component :is="itemIcon(item)" :size="18" /><strong>{{ item.name }}</strong><Eye :size="14" /></button><div v-else class="filemanager-name"><component :is="itemIcon(item)" :size="18" /><strong>{{ item.name }}</strong></div></td>
        <td>{{ typeLabel(item) }}</td><td>{{ formatBytes(item.size) }}</td><td><code>{{ item.permissions ?? '—' }}</code></td><td>{{ item.modifiedAt ? formatDate(item.modifiedAt) : '—' }}</td>
        <td><button v-if="item.kind === 'file' || item.kind === 'directory'" type="button" class="icon-button" :disabled="busy" :aria-label="`Download ${item.name}`" :title="`Download ${item.name}`" @click="downloadItems([item])"><Download :size="16" /></button><button v-if="item.kind === 'file' || item.kind === 'directory'" type="button" class="icon-button" :disabled="busy" :aria-label="`Permissions wijzigen van ${item.name}`" :title="`Permissions wijzigen van ${item.name}`" @click="openPermissions(item)"><LockKeyhole :size="16" /></button><button v-if="item.kind !== 'other'" type="button" class="icon-button danger-action" :disabled="busy" :aria-label="`${item.kind === 'directory' ? 'Verwijder map' : 'Verwijder bestand'} ${item.name}`" :title="`Verwijder ${item.name}`" @click="requestDelete(item)"><Trash2 :size="16" /></button></td>
      </tr></tbody>
    </table></div>
    <ChecksumFilePreview v-if="preview" ref="previewComponent" :preview="preview" :save-file="saveFile" :reload-file="reloadFile" :default-fullscreen="filePreviewMode === 'fullscreen'" :default-markdown-mode="markdownPreviewMode" close-label="Terug naar map" @saved="fileSaved" @close="closePreview" />
  </section>
  <div v-if="createKind" class="modal-backdrop" role="presentation" @click.self="closeCreate"><section v-dialog-focus="closeCreate" class="modal" role="dialog" aria-modal="true" :aria-label="createKind === 'file' ? 'Nieuw bestand' : 'Nieuwe map'"><h2>{{ createKind === 'file' ? 'Nieuw bestand' : 'Nieuwe map' }}</h2><p class="modal-copy">Maak dit item aan in <code>{{ listing?.currentPath }}</code>.</p><p v-if="createError" class="error-banner" role="alert">{{ createError }}</p><label for="filemanager-new-name">{{ createKind === 'file' ? 'Bestandsnaam' : 'Mapnaam' }}</label><input id="filemanager-new-name" v-model="newName" :disabled="createBusy" autocomplete="off" @keydown.enter.prevent="createItem" /><div class="modal-actions"><button class="button secondary" :disabled="createBusy" @click="closeCreate">Annuleren</button><button class="button primary" :disabled="createBusy || !newName.trim()" @click="createItem"><LoaderCircle v-if="createBusy" class="spin" :size="15" />{{ createBusy ? 'Aanmaken…' : 'Aanmaken' }}</button></div></section></div>
  <ConfirmDialog v-if="deleteTarget" :title="deleteTarget.kind === 'directory' ? 'Map verwijderen?' : 'Bestand verwijderen?'" confirm-label="Verwijderen" danger :busy="deleteBusy" @cancel="closeDelete" @confirm="confirmDelete"><p>Weet je zeker dat je <strong>{{ deleteTarget.name }}</strong> wilt verwijderen?</p><p v-if="deleteTarget.kind === 'directory'">Alleen een lege map kan worden verwijderd.</p><p v-if="deleteError" class="error-banner" role="alert">{{ deleteError }}</p></ConfirmDialog>
  <div v-if="permissionTarget || bulkPermissionOpen" class="modal-backdrop" role="presentation" @click.self="closeAction"><section v-dialog-focus="closeAction" class="modal" role="dialog" aria-modal="true" aria-label="Permissions wijzigen"><h2>Permissions wijzigen</h2><p v-if="permissionTarget">{{ permissionTarget.kind === 'directory' ? 'Map' : 'Bestand' }}: <strong>{{ permissionTarget.name }}</strong><br />Huidige permissions: <code>{{ permissionTarget.permissions ?? 'onbekend' }}</code></p><p v-else>Nieuwe permissions worden toegepast op {{ selectedCount }} geselecteerde items in deze map, zonder onderliggende bestanden te wijzigen.</p><p v-if="permissionTarget?.kind === 'directory'" class="filemanager-warning">Het wijzigen van maprechten kan de toegang tot die map beperken.</p><label for="filemanager-permissions">Nieuwe permissions</label><input id="filemanager-permissions" v-model="permissionMode" inputmode="numeric" maxlength="3" pattern="[0-7]{3}" :disabled="actionBusy" autocomplete="off" autofocus @keydown.enter.prevent="applyPermissions" /><small>Drie octale cijfers, bijvoorbeeld 644 of 755.</small><p v-if="actionError" class="error-banner" role="alert">{{ actionError }}</p><div class="modal-actions"><button class="button secondary" :disabled="actionBusy" @click="closeAction">Annuleren</button><button class="button primary" :disabled="actionBusy || !/^[0-7]{3}$/.test(permissionMode)" @click="applyPermissions">{{ actionBusy ? 'Toepassen…' : 'Toepassen' }}</button></div></section></div>
  <ConfirmDialog v-if="bulkDeleteOpen" title="Geselecteerde items verwijderen?" :confirm-label="`${selectedCount} items verwijderen`" danger :busy="actionBusy" @cancel="closeAction" @confirm="confirmBulkDelete"><p>Weet je zeker dat je deze {{ selectedCount }} items wilt verwijderen?</p><ul><li v-for="item in selectedItems.slice(0, 5)" :key="item.path">{{ item.name }}</li></ul><p v-if="selectedCount > 5">En nog {{ selectedCount - 5 }} andere items.</p><p>Alleen lege mappen worden verwijderd. Dit kan niet ongedaan worden gemaakt.</p><p v-if="actionError" class="error-banner" role="alert">{{ actionError }}</p></ConfirmDialog>
</template>
<style scoped>
.filemanager-browser{min-width:0}.filemanager-browser-heading{display:flex;align-items:flex-start;justify-content:space-between;gap:14px;padding:4px 0 12px}.filemanager-browser-title,.filemanager-actions,.filemanager-name,.filemanager-name-button{display:flex;align-items:center;gap:8px}.filemanager-browser-title{color:#287257}.filemanager-browser-title h3{margin:0;color:#26382f;font-size:15px}.filemanager-browser-heading p{margin:4px 0 0;color:#75817c;font-size:11px}.filemanager-browser-heading code{color:#406a5a;overflow-wrap:anywhere}.filemanager-actions{flex-wrap:wrap;justify-content:flex-end}.filemanager-breadcrumbs{margin:0 0 12px;padding:9px 10px;border:1px solid #e1e8e4;border-radius:8px;background:#fafcfb}.filemanager-warning,.filemanager-success{display:flex;align-items:flex-start;gap:7px;margin:0 0 12px;padding:9px 10px;border-radius:8px;font-size:11px}.filemanager-warning{background:#fff5df;color:#805d1f}.filemanager-success{background:#edf8f3;color:#27694f}.filemanager-warning ul{margin:5px 0 0;padding-left:18px}.filemanager-warning code{overflow-wrap:anywhere}.filemanager-bulk-toolbar{display:flex;align-items:center;flex-wrap:wrap;gap:8px;margin:0 0 12px;padding:9px 10px;border:1px solid #dce8e2;border-radius:8px;background:#f7fbf9;font-size:11px}.filemanager-bulk-toolbar strong{margin-right:auto}.filemanager-bulk-toolbar small{width:100%;color:#667d71}.filemanager-preview-loading{display:flex;align-items:center;gap:10px;margin:0 0 12px;padding:10px 12px;border:1px solid #dce8e2;border-radius:8px;background:#f7fbf9;color:#315f4e;font-size:11px}.filemanager-table-scroll{overflow-x:auto;border:1px solid #e1e8e4;border-radius:9px}.filemanager-table{min-width:810px}.filemanager-table th:nth-child(2){min-width:260px}.filemanager-table td{white-space:nowrap}.filemanager-table .filemanager-select{width:32px;min-width:32px;text-align:center}.filemanager-select input{cursor:pointer}.filemanager-name-button{width:100%;min-width:0;border:0;padding:0;background:transparent;color:#286f55;text-align:left;cursor:pointer}.filemanager-name-button.file{color:#314e43}.filemanager-name-button:focus-visible{outline:2px solid #4b9178;outline-offset:3px;border-radius:3px}.filemanager-name svg,.filemanager-name-button svg{flex:none;color:#5f7e71}.filemanager-name-button svg{color:#28775b}.filemanager-name strong,.filemanager-name-button strong{max-width:390px;overflow:hidden;text-overflow:ellipsis}.filemanager-table td code{color:#496359;font:11px "Cascadia Mono",Consolas,monospace}.danger-action{color:#a44449}.modal label,.modal input{display:block;width:100%;box-sizing:border-box}.modal label{margin-top:14px;font-size:12px;font-weight:700}.modal input{margin-top:6px}.modal-copy code{overflow-wrap:anywhere}@media(max-width:760px){.filemanager-browser-heading{flex-direction:column}.filemanager-actions{justify-content:flex-start}.filemanager-table{min-width:700px}.filemanager-name strong,.filemanager-name-button strong{max-width:250px}}
</style>
