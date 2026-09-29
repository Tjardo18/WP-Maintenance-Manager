<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { AlertTriangle, ArrowLeft, ChevronUp, File, FileArchive, FileCode2, FileQuestion, Folder, FolderOpen, LoaderCircle, RefreshCw } from "@lucide/vue";
import type { FilemanagerContext, FilemanagerDirectoryItem, FilemanagerDirectoryListing } from "../types/filemanager";
import { appApi } from "../services/tauri";
import { errorMessage } from "../utils/errors";
import { formatDate } from "../utils/format";
import FilemanagerBreadcrumbs from "./FilemanagerBreadcrumbs.vue";

const props = defineProps<{ context: FilemanagerContext; authorizationToken: string }>();
const emit = defineEmits<{ expired: [] }>();
const listing = ref<FilemanagerDirectoryListing>();
const loading = ref(false);
const error = ref<string>();
const history = ref<string[]>([]);
let requestId = 0;
const canGoBack = computed(() => history.value.length > 0 && !loading.value);
const canGoUp = computed(() => Boolean(listing.value?.parentPath) && !loading.value);
const categoryOf = (cause: unknown) => typeof cause === "object" && cause !== null && "category" in cause && typeof (cause as { category?: unknown }).category === "string" ? (cause as { category: string }).category : undefined;
const authorizationExpired = (cause: unknown) => ["filemanager_auth_required", "locked", "session_expired", "invalid_session"].includes(categoryOf(cause) ?? "");

function formatBytes(bytes: number | null) { if (bytes === null) return "—"; if (bytes < 1024) return `${bytes} B`; const units = ["KB", "MB", "GB", "TB"]; let value = bytes / 1024; let unit = 0; while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit += 1; } return `${value.toLocaleString("nl-NL", { maximumFractionDigits: 1 })} ${units[unit]}`; }
function typeLabel(item: FilemanagerDirectoryItem) { if (item.kind === "directory") return "Map"; if (item.kind === "symlink") return "Symlink"; if (item.kind === "other") return "Overig"; return item.extension ? item.extension.toUpperCase() : "Bestand"; }
function itemIcon(item: FilemanagerDirectoryItem) { return item.kind === "directory" ? Folder : item.extension && ["zip", "gz", "tar", "rar", "7z"].includes(item.extension) ? FileArchive : item.extension && ["php", "js", "css", "html", "json", "md", "xml", "twig", "scss"].includes(item.extension) ? FileCode2 : item.kind === "file" ? File : FileQuestion; }

async function load(path: string, source: "normal" | "back" | "refresh" = "normal") {
  if (loading.value && source !== "refresh") return;
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
function goBack() { const path = history.value[history.value.length - 1]; if (path) void load(path, "back"); }
function goUp() { if (listing.value?.parentPath) void load(listing.value.parentPath); }
onMounted(() => { void load("/"); });
</script>

<template>
  <section class="filemanager-browser" :aria-busy="loading">
    <header class="filemanager-browser-heading"><div><div class="filemanager-browser-title"><FolderOpen :size="22" /><h3>Bestanden</h3></div><p>Huidige map: <code>{{ listing?.currentPath ?? '/' }}</code></p></div><div class="filemanager-actions"><button type="button" class="button small secondary" :disabled="!canGoBack" @click="goBack"><ArrowLeft :size="15" /> Terug</button><button type="button" class="button small secondary" :disabled="!canGoUp" @click="goUp"><ChevronUp :size="15" /> Omhoog</button><button type="button" class="icon-button" :disabled="loading" aria-label="Map vernieuwen" title="Map vernieuwen" @click="listing && load(listing.currentPath, 'refresh')"><RefreshCw :class="{ spin: loading }" :size="17" /></button></div></header>
    <FilemanagerBreadcrumbs :current-path="listing?.currentPath ?? '/'" :disabled="loading" @navigate="load($event)" />
    <p v-if="listing?.truncated" class="filemanager-warning"><AlertTriangle :size="16" /> Deze map bevat meer dan 5.000 items. Alleen de eerste veilige selectie wordt getoond.</p><p v-if="error" class="error-banner" role="alert">{{ error }}</p>
    <div v-if="loading" class="empty-state compact" role="status"><LoaderCircle class="spin" :size="32" /><h3>Map laden…</h3><p>De beveiligde directorylisting wordt opgehaald.</p></div><div v-else-if="listing && !listing.items.length" class="empty-state compact"><FolderOpen :size="35" /><h3>Deze map is leeg</h3><p>Er zijn geen bestanden of mappen in {{ listing.currentPath }}.</p></div>
    <div v-else-if="listing" class="filemanager-table-scroll"><table class="filemanager-table"><thead><tr><th>Naam</th><th>Type</th><th>Grootte</th><th>Permissions</th><th>Gewijzigd</th></tr></thead><tbody><tr v-for="item in listing.items" :key="item.path" :class="{ directory: item.kind === 'directory' }"><td><button v-if="item.kind === 'directory'" type="button" class="filemanager-name-button" :disabled="loading" :title="`Open ${item.name}`" @click="openDirectory(item)"><component :is="itemIcon(item)" :size="18" /><strong>{{ item.name }}</strong></button><div v-else class="filemanager-name"><component :is="itemIcon(item)" :size="18" /><strong :title="item.name">{{ item.name }}</strong></div></td><td>{{ typeLabel(item) }}</td><td>{{ formatBytes(item.size) }}</td><td><code>{{ item.permissions ?? '—' }}</code></td><td>{{ item.modifiedAt ? formatDate(item.modifiedAt) : '—' }}</td></tr></tbody></table></div>
  </section>
</template>

<style scoped>
.filemanager-browser { min-width: 0; }.filemanager-browser-heading { display: flex; align-items: flex-start; justify-content: space-between; gap: 14px; padding: 4px 0 12px; }.filemanager-browser-title,.filemanager-actions,.filemanager-name,.filemanager-name-button { display: flex; align-items: center; gap: 8px; }.filemanager-browser-title { color: #287257; }.filemanager-browser-title h3 { margin: 0; color: #26382f; font-size: 15px; }.filemanager-browser-heading p { margin: 4px 0 0; color: #75817c; font-size: 11px; }.filemanager-browser-heading code { color: #406a5a; overflow-wrap: anywhere; }.filemanager-actions { flex-wrap: wrap; justify-content: flex-end; }.filemanager-breadcrumbs { margin: 0 0 12px; padding: 9px 10px; border: 1px solid #e1e8e4; border-radius: 8px; background: #fafcfb; }.filemanager-warning { display: flex; align-items: flex-start; gap: 7px; margin: 0 0 12px; padding: 9px 10px; border-radius: 8px; background: #fff5df; color: #805d1f; font-size: 11px; }.filemanager-warning svg { flex: none; }.filemanager-table-scroll { overflow-x: auto; border: 1px solid #e1e8e4; border-radius: 9px; }.filemanager-table { min-width: 690px; }.filemanager-table th:first-child { min-width: 260px; }.filemanager-table td { white-space: nowrap; }.filemanager-table tr.directory:hover { background: #f5faf7; }.filemanager-name-button { width: 100%; min-width: 0; border: 0; padding: 0; background: transparent; color: #286f55; text-align: left; cursor: pointer; }.filemanager-name-button:hover:not(:disabled) strong,.filemanager-name-button:focus-visible strong { text-decoration: underline; }.filemanager-name-button:focus-visible { outline: 2px solid #4b9178; outline-offset: 3px; border-radius: 3px; }.filemanager-name svg,.filemanager-name-button svg { flex: none; color: #5f7e71; }.filemanager-name-button svg { color: #28775b; }.filemanager-name strong { max-width: 390px; overflow: hidden; text-overflow: ellipsis; }.filemanager-table td code { color: #496359; font: 11px "Cascadia Mono", Consolas, monospace; }@media(max-width:760px) { .filemanager-browser-heading { flex-direction: column; }.filemanager-actions { justify-content: flex-start; }.filemanager-table { min-width: 620px; }.filemanager-name strong { max-width: 250px; } }
</style>
