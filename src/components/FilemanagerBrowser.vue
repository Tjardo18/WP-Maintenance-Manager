<script setup lang="ts">
import { computed, inject, onBeforeUnmount, onMounted, ref } from "vue";
import { routerKey } from "vue-router";
import { AlertTriangle, ArrowLeft, ChevronUp, Eye, File, FileArchive, FileCode2, FileQuestion, Folder, FolderOpen, LoaderCircle, RefreshCw } from "@lucide/vue";
import type { FilePreviewMode, MarkdownPreviewMode } from "../types";
import type { FilemanagerContext, FilemanagerDirectoryItem, FilemanagerDirectoryListing, FilemanagerFilePreview } from "../types/filemanager";
import { appApi } from "../services/tauri";
import { errorMessage } from "../utils/errors";
import { formatDate } from "../utils/format";
import FilemanagerBreadcrumbs from "./FilemanagerBreadcrumbs.vue";
import ChecksumFilePreview from "./ChecksumFilePreview.vue";

const props = defineProps<{ context: FilemanagerContext; authorizationToken: string }>();
const emit = defineEmits<{ expired: [] }>();
const listing = ref<FilemanagerDirectoryListing>();
const loading = ref(false);
const error = ref<string>();
const history = ref<string[]>([]);
let requestId = 0;
let previewRequestId = 0;
const preview = ref<FilemanagerFilePreview>();
const previewComponent = ref<InstanceType<typeof ChecksumFilePreview>>();
const router = inject(routerKey, undefined);
const removeNavigationGuard = router?.beforeEach(async () => await previewComponent.value?.requestLeave() ?? true);
async function requestLeave() { return await previewComponent.value?.requestLeave() ?? true; }
defineExpose({ requestLeave, hasUnsavedChanges: () => previewComponent.value?.hasUnsavedChanges() ?? false });
const previewLoadingPath = ref<string>();
const previewError = ref<string>();
const filePreviewMode = ref<FilePreviewMode>("normal");
const markdownPreviewMode = ref<MarkdownPreviewMode>("raw");
const canGoBack = computed(() => history.value.length > 0 && !loading.value);
const canGoUp = computed(() => Boolean(listing.value?.parentPath) && !loading.value);
const categoryOf = (cause: unknown) => typeof cause === "object" && cause !== null && "category" in cause && typeof (cause as { category?: unknown }).category === "string" ? (cause as { category: string }).category : undefined;
const authorizationExpired = (cause: unknown) => ["filemanager_auth_required", "filemanager_disconnected", "filemanager_timeout", "filemanager_sftp_failed", "filemanager_file_read_failed", "locked", "session_expired", "invalid_session"].includes(categoryOf(cause) ?? "");

function formatBytes(bytes: number | null) { if (bytes === null) return "—"; if (bytes < 1024) return `${bytes} B`; const units = ["KB", "MB", "GB", "TB"]; let value = bytes / 1024; let unit = 0; while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; } return `${value.toLocaleString("nl-NL", { maximumFractionDigits: 1 })} ${units[unit]}`; }
function typeLabel(item: FilemanagerDirectoryItem) { if (item.kind === "directory") return "Map"; if (item.kind === "symlink") return "Symlink"; if (item.kind === "other") return "Overig"; return item.extension ? item.extension.toUpperCase() : "Bestand"; }
function itemIcon(item: FilemanagerDirectoryItem) { return item.kind === "directory" ? Folder : item.extension && ["zip", "gz", "tar", "rar", "7z"].includes(item.extension) ? FileArchive : item.extension && ["php", "js", "css", "html", "json", "md", "xml", "twig", "scss"].includes(item.extension) ? FileCode2 : item.kind === "file" ? File : FileQuestion; }

async function load(path: string, source: "normal" | "back" | "refresh" = "normal") {
  if (loading.value && source !== "refresh") return;
  if (preview.value) {
    if (!(await previewComponent.value?.requestLeave() ?? true)) return;
  }
  closePreview();
  const request = ++requestId;
  loading.value = true; error.value = undefined;
  try {
    const result = await appApi.listFilemanagerDirectory(props.context.siteId, props.authorizationToken, path);
    if (request !== requestId || result.currentPath !== path) return;
    const previous = listing.value?.currentPath;
    listing.value = result;
    if (source === "normal" && previous && previous !== result.currentPath) history.value.push(previous);
    if (source === "back") history.value.pop();
  } catch (cause) {
    if (request !== requestId) return;
    listing.value = undefined;
    if (authorizationExpired(cause)) { emit("expired"); return; }
    error.value = errorMessage(cause);
  } finally { if (request === requestId) loading.value = false; }
}
function openDirectory(item: FilemanagerDirectoryItem) { if (item.kind === "directory") void load(item.path); }
async function openFile(item: FilemanagerDirectoryItem) {
  if (item.kind !== "file" || previewLoadingPath.value === item.path) return;
  if (!(await previewComponent.value?.requestLeave() ?? true)) return;
  const request = ++previewRequestId;
  previewLoadingPath.value = item.path;
  previewError.value = undefined;
  preview.value = undefined;
  try {
    const result = await appApi.readFilemanagerFile(props.context.siteId, props.authorizationToken, item.path);
    if (request !== previewRequestId || result.relativePath !== item.path) return;
    preview.value = result;
  } catch (cause) {
    if (request !== previewRequestId) return;
    if (authorizationExpired(cause)) { emit("expired"); return; }
    previewError.value = errorMessage(cause);
  } finally {
    if (request === previewRequestId) previewLoadingPath.value = undefined;
  }
}
function closePreview() { previewRequestId += 1; preview.value = undefined; previewLoadingPath.value = undefined; previewError.value = undefined; }
async function saveFile(content: string, expectedVersion: string) {
  const path = preview.value?.relativePath;
  const request = previewRequestId;
  if (!path) throw new Error("Open het bestand opnieuw.");
  const result = await appApi.saveFilemanagerFile(props.context.siteId, props.authorizationToken, { path, content, expectedVersion });
  if (request !== previewRequestId || result.relativePath !== path) throw new Error("De bestandscontext is gewijzigd. Open het bestand opnieuw.");
  return result;
}
function fileSaved(result: FilemanagerFilePreview) {
  if (preview.value?.relativePath !== result.relativePath) return;
  preview.value = result;
  const item = listing.value?.items.find((entry) => entry.path === result.relativePath);
  if (item) { item.size = result.sizeBytes; item.modifiedAt = result.modifiedAt ?? null; }
}
async function reloadFile() {
  const path = preview.value?.relativePath;
  const request = previewRequestId;
  if (!path) return;
  const result = await appApi.readFilemanagerFile(props.context.siteId, props.authorizationToken, path);
  if (request === previewRequestId && result.relativePath === path) fileSaved(result);
}
function goBack() { const path = history.value[history.value.length - 1]; if (path) void load(path, "back"); }
function goUp() { if (listing.value?.parentPath) void load(listing.value.parentPath); }
onMounted(() => {
  void load("/");
  void appApi.getSettings().then((settings) => {
    filePreviewMode.value = settings.filePreviewMode;
    markdownPreviewMode.value = settings.markdownPreviewMode;
  }).catch(() => undefined);
});
onBeforeUnmount(() => { removeNavigationGuard?.(); requestId += 1; previewRequestId += 1; });
</script>

<template>
  <section class="filemanager-browser" :aria-busy="loading">
    <header class="filemanager-browser-heading"><div><div class="filemanager-browser-title"><FolderOpen :size="22" /><h3>Bestanden</h3></div><p>Huidige map: <code>{{ listing?.currentPath ?? '/' }}</code></p></div><div class="filemanager-actions"><button type="button" class="button small secondary" :disabled="!canGoBack" @click="goBack"><ArrowLeft :size="15" /> Terug</button><button type="button" class="button small secondary" :disabled="!canGoUp" @click="goUp"><ChevronUp :size="15" /> Omhoog</button><button type="button" class="icon-button" :disabled="loading" aria-label="Map vernieuwen" title="Map vernieuwen" @click="listing && load(listing.currentPath, 'refresh')"><RefreshCw :class="{ spin: loading }" :size="17" /></button></div></header>
    <FilemanagerBreadcrumbs :current-path="listing?.currentPath ?? '/'" :disabled="loading" @navigate="load($event)" />
    <p v-if="listing?.truncated" class="filemanager-warning"><AlertTriangle :size="16" /> Deze map bevat meer dan 5.000 items. Alleen de eerste veilige selectie wordt getoond.</p><p v-if="error" class="error-banner" role="alert">{{ error }}</p><p v-if="previewError" class="error-banner" role="alert">{{ previewError }}</p>
    <div v-if="previewLoadingPath" class="filemanager-preview-loading" role="status"><LoaderCircle class="spin" :size="18" /><span><strong>Bestand laden…</strong><code>{{ previewLoadingPath }}</code></span></div>
    <div v-if="loading" class="empty-state compact" role="status"><LoaderCircle class="spin" :size="32" /><h3>Map laden…</h3><p>De beveiligde directorylisting wordt opgehaald.</p></div><div v-else-if="listing && !listing.items.length" class="empty-state compact"><FolderOpen :size="35" /><h3>Deze map is leeg</h3><p>Er zijn geen bestanden of mappen in {{ listing.currentPath }}.</p></div>
    <div v-else-if="listing" class="filemanager-table-scroll"><table class="filemanager-table"><thead><tr><th>Naam</th><th>Type</th><th>Grootte</th><th>Permissions</th><th>Gewijzigd</th></tr></thead><tbody><tr v-for="item in listing.items" :key="item.path" :class="{ directory: item.kind === 'directory', file: item.kind === 'file' }"><td><button v-if="item.kind === 'directory'" type="button" class="filemanager-name-button" :disabled="loading" :title="`Open ${item.name}`" @click="openDirectory(item)"><component :is="itemIcon(item)" :size="18" /><strong>{{ item.name }}</strong></button><button v-else-if="item.kind === 'file'" type="button" class="filemanager-name-button file" :aria-label="`Bekijk ${item.name}`" :title="`Bekijk ${item.name}`" @click="openFile(item)"><component :is="itemIcon(item)" :size="18" /><strong>{{ item.name }}</strong><Eye :size="14" class="filemanager-preview-icon" /></button><div v-else class="filemanager-name"><component :is="itemIcon(item)" :size="18" /><strong :title="item.name">{{ item.name }}</strong></div></td><td>{{ typeLabel(item) }}</td><td>{{ formatBytes(item.size) }}</td><td><code>{{ item.permissions ?? '—' }}</code></td><td>{{ item.modifiedAt ? formatDate(item.modifiedAt) : '—' }}</td></tr></tbody></table></div>
    <ChecksumFilePreview v-if="preview" ref="previewComponent" :preview="preview" :save-file="saveFile" :reload-file="reloadFile" :default-fullscreen="filePreviewMode === 'fullscreen'" :default-markdown-mode="markdownPreviewMode" close-label="Terug naar map" @saved="fileSaved" @close="closePreview" />
  </section>
</template>

<style scoped>
.filemanager-browser { min-width: 0; }.filemanager-browser-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 14px; padding: 4px 0 12px; }.filemanager-browser-title,.filemanager-actions,.filemanager-name,.filemanager-name-button { display: flex; align-items: center; gap: 8px; }.filemanager-browser-title { color: #287257; }.filemanager-browser-title h3 { margin: 0; color: #26382f; font-size: 15px; }.filemanager-browser-heading p { margin: 4px 0 0; color: #75817c; font-size: 11px; }.filemanager-browser-heading code { color: #406a5a; overflow-wrap: anywhere; }.filemanager-actions { flex-wrap: wrap; justify-content: flex-end; }.filemanager-breadcrumbs { margin: 0 0 12px; padding: 9px 10px; border: 1px solid #e1e8e4; border-radius: 8px; background: #fafcfb; }.filemanager-warning { display: flex; align-items: flex-start; gap: 7px; margin: 0 0 12px; padding: 9px 10px; border-radius: 8px; background: #fff5df; color: #805d1f; font-size: 11px; }.filemanager-warning svg { flex: none; }.filemanager-preview-loading { display:flex;align-items:center;gap:10px;margin:0 0 12px;padding:10px 12px;border:1px solid #dce8e2;border-radius:8px;background:#f7fbf9;color:#315f4e;font-size:11px }.filemanager-preview-loading span,.filemanager-preview-loading code { display:block }.filemanager-preview-loading code { margin-top:2px;overflow-wrap:anywhere;color:#60766d;font-size:10px }.filemanager-table-scroll { overflow-x: auto; border: 1px solid #e1e8e4; border-radius: 9px; }.filemanager-table { min-width: 690px; }.filemanager-table th:first-child { min-width: 260px; }.filemanager-table td { white-space: nowrap; }.filemanager-table tr.directory:hover,.filemanager-table tr.file:hover { background: #f5faf7; }.filemanager-name-button { width: 100%; min-width: 0; border: 0; padding: 0; background: transparent; color: #286f55; text-align: left; cursor: pointer; }.filemanager-name-button.file { color:#314e43 }.filemanager-name-button:hover:not(:disabled) strong,.filemanager-name-button:focus-visible strong { text-decoration: underline; }.filemanager-name-button:focus-visible { outline: 2px solid #4b9178; outline-offset: 3px; border-radius: 3px; }.filemanager-name svg,.filemanager-name-button svg { flex: none; color: #5f7e71; }.filemanager-name-button svg { color: #28775b; }.filemanager-name-button .filemanager-preview-icon { margin-left:auto;color:#719086;opacity:.75 }.filemanager-name strong,.filemanager-name-button strong { max-width: 390px; overflow: hidden; text-overflow: ellipsis; }.filemanager-table td code { color: #496359; font: 11px "Cascadia Mono", Consolas, monospace; }@media(max-width:760px) { .filemanager-browser-heading { flex-direction: column; }.filemanager-actions { justify-content: flex-start; }.filemanager-table { min-width: 620px; }.filemanager-name strong,.filemanager-name-button strong { max-width: 250px; } }
</style>
