<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { AlertTriangle, ChevronLeft, ChevronRight, CircleAlert, Search, Trash2, X } from "@lucide/vue";
import { appApi } from "../services/tauri";
import { useSitesStore } from "../stores/sites";
import type { ErrorCategory, ErrorLogFilter, ErrorLogPage, ErrorLogRecord, ErrorSeverity } from "../types";
import { errorMessage } from "../utils/errors";
import ConfirmDialog from "../components/ConfirmDialog.vue";

const sites = useSitesStore();
const page = ref<ErrorLogPage>({ records: [], total: 0, limit: 25, offset: 0 });
const loading = ref(false);
const error = ref<string>();
const selected = ref<ErrorLogRecord>();
const selectedIds = ref<string[]>([]);
const pendingDelete = ref<ErrorLogRecord[]>([]);
const deleting = ref(false);
const siteId = ref("");
const category = ref<ErrorCategory | "">("");
const severity = ref<ErrorSeverity | "">("");
const period = ref("30");
const query = ref("");

const categories: Array<{ value: ErrorCategory; label: string }> = [
  { value: "network", label: "Netwerk" }, { value: "dns", label: "DNS" }, { value: "connection_timeout", label: "Verbindingstime-out" },
  { value: "ssh_authentication", label: "SSH-authenticatie" }, { value: "ssh_host_key", label: "SSH host key" }, { value: "ssh_channel", label: "SSH-kanaal" },
  { value: "ssh_command", label: "SSH-commando" }, { value: "wp_cli", label: "WP-CLI" }, { value: "database", label: "Database" },
  { value: "http", label: "HTTP" }, { value: "filesystem", label: "Bestandssysteem" }, { value: "backup", label: "Backup" },
  { value: "update", label: "Update" }, { value: "parse", label: "Verwerking" }, { value: "authentication", label: "Applicatielogin" },
  { value: "snapshot_build", label: "Momentopname opbouwen" }, { value: "snapshot_persist", label: "Momentopname opslaan" },
  { value: "snapshot_diff", label: "Wijzigingen vergelijken" }, { value: "snapshot_schema", label: "Momentopnameversie" },
  { value: "application", label: "Applicatie" }, { value: "unknown", label: "Onbekend" },
];

const pageNumber = computed(() => Math.floor(page.value.offset / page.value.limit) + 1);
const pageCount = computed(() => Math.max(1, Math.ceil(page.value.total / page.value.limit)));
const allVisibleSelected = computed(() => Boolean(page.value.records.length) && page.value.records.every((record) => selectedIds.value.includes(record.id)));
const selectedRecords = computed(() => page.value.records.filter((record) => selectedIds.value.includes(record.id)));

function categoryLabel(value: ErrorCategory) {
  return categories.find((item) => item.value === value)?.label ?? value;
}

function severityLabel(value: ErrorSeverity) {
  return value === "critical" ? "Kritiek" : value === "warning" ? "Waarschuwing" : "Fout";
}

function dateTime(value: string) {
  return new Intl.DateTimeFormat("nl-NL", { dateStyle: "short", timeStyle: "medium" }).format(new Date(value));
}

function filter(offset = 0): ErrorLogFilter {
  const from = period.value ? new Date(Date.now() - Number(period.value) * 86_400_000).toISOString() : undefined;
  return { siteId: siteId.value || undefined, category: category.value || undefined, severity: severity.value || undefined, from, query: query.value || undefined, limit: 25, offset };
}

async function load(offset = 0) {
  loading.value = true;
  error.value = undefined;
  try { page.value = await appApi.listErrorLogs(filter(offset)); selectedIds.value = []; }
  catch (cause) { error.value = errorMessage(cause); }
  finally { loading.value = false; }
}

function toggleRecord(id: string) {
  selectedIds.value = selectedIds.value.includes(id) ? selectedIds.value.filter((current) => current !== id) : [...selectedIds.value, id];
}

function toggleVisible() {
  selectedIds.value = allVisibleSelected.value ? [] : page.value.records.map((record) => record.id);
}

function requestDelete(records: ErrorLogRecord[]) {
  pendingDelete.value = records;
}

async function executeDelete() {
  if (!pendingDelete.value.length) return;
  deleting.value = true; error.value = undefined;
  const ids = pendingDelete.value.map((record) => record.id);
  const nextTotal = Math.max(0, page.value.total - ids.length);
  const nextOffset = nextTotal && page.value.offset >= nextTotal ? Math.floor((nextTotal - 1) / page.value.limit) * page.value.limit : page.value.offset;
  try {
    await appApi.deleteErrorLogs(ids);
    if (selected.value && ids.includes(selected.value.id)) selected.value = undefined;
    pendingDelete.value = [];
    await load(nextOffset);
  } catch (cause) { error.value = errorMessage(cause); }
  finally { deleting.value = false; }
}

onMounted(() => void load());
</script>

<template>
  <section class="page-heading"><div><h2>Foutenlog</h2><p>Persistente technische incidenten van de laatste 30 dagen, zonder opgeslagen wachtwoorden of terminalgeschiedenis.</p></div></section>
  <p v-if="error" class="error-banner">{{ error }}</p>

  <section class="card error-log-card">
    <form class="error-log-filters" @submit.prevent="load(0)">
      <label><span>Website</span><select v-model="siteId" @change="load(0)"><option value="">Alle websites</option><option v-for="site in sites.sites" :key="site.id" :value="site.id">{{ site.name }}</option></select></label>
      <label><span>Categorie</span><select v-model="category" @change="load(0)"><option value="">Alle categorieën</option><option v-for="item in categories" :key="item.value" :value="item.value">{{ item.label }}</option></select></label>
      <label><span>Ernst</span><select v-model="severity" @change="load(0)"><option value="">Fouten en waarschuwingen</option><option value="error">Fouten</option><option value="critical">Kritiek</option><option value="warning">Waarschuwingen</option></select></label>
      <label><span>Periode</span><select v-model="period" @change="load(0)"><option value="7">Laatste 7 dagen</option><option value="30">Laatste 30 dagen</option><option value="">Volledige bewaartermijn</option></select></label>
      <label class="error-log-search"><span>Zoeken</span><span><Search :size="14" /><input v-model="query" type="search" placeholder="Zoek in foutmeldingen" /></span></label>
      <button class="button secondary" :disabled="loading"><Search :size="14" /> Zoeken</button>
    </form>

    <div v-if="page.records.length" class="table-selection-toolbar">
      <label class="table-selection-toggle"><input type="checkbox" :checked="allVisibleSelected" :disabled="loading" aria-label="Alle zichtbare fouten selecteren" @change="toggleVisible" /><span>{{ selectedIds.length ? `${selectedIds.length} geselecteerd` : 'Selecteer foutregels om ze te verwijderen' }}</span></label>
      <button class="button small danger-text" :disabled="loading || !selectedRecords.length" @click="requestDelete(selectedRecords)"><Trash2 :size="14" /> Geselecteerde verwijderen</button>
    </div>

    <div v-if="!loading && !page.records.length" class="empty-state"><CircleAlert :size="38" /><h3>Geen fouten gevonden</h3><p>Nieuwe technische incidenten verschijnen hier zodra een backendactie mislukt.</p></div>
    <div v-else class="table-scroll"><table class="error-log-table"><thead><tr><th class="table-select-cell"><span class="sr-only">Selecteren</span></th><th>Datum</th><th>Website</th><th>Categorie</th><th>Actie</th><th>Fout</th><th>Status</th><th></th></tr></thead><tbody><tr v-for="record in page.records" :key="record.id" tabindex="0" @click="selected = record" @keydown.enter="selected = record"><td class="table-select-cell"><input type="checkbox" :checked="selectedIds.includes(record.id)" :aria-label="`${record.id} selecteren`" @click.stop @change="toggleRecord(record.id)" /></td><td>{{ dateTime(record.createdAt) }}</td><td>{{ record.siteName ?? 'Applicatie' }}</td><td><span :class="['error-category', record.category]">{{ categoryLabel(record.category) }}</span></td><td>{{ record.action }}</td><td><strong>{{ record.summary }}</strong><small>{{ record.id }}</small></td><td><span :class="['error-severity', record.severity]"><AlertTriangle :size="12" /> {{ severityLabel(record.severity) }}</span></td><td><button class="button small danger-text" type="button" @click.stop="requestDelete([record])"><Trash2 :size="14" /> Verwijderen</button></td></tr></tbody></table></div>
    <footer v-if="page.total" class="error-log-pagination"><span>{{ page.offset + 1 }}–{{ Math.min(page.offset + page.limit, page.total) }} van {{ page.total }}</span><button class="button small ghost" :disabled="loading || page.offset === 0" @click="load(Math.max(0, page.offset - page.limit))"><ChevronLeft :size="14" /> Vorige</button><strong>{{ pageNumber }} / {{ pageCount }}</strong><button class="button small ghost" :disabled="loading || page.offset + page.limit >= page.total" @click="load(page.offset + page.limit)">Volgende <ChevronRight :size="14" /></button></footer>
  </section>

  <div v-if="selected" class="modal-backdrop" role="presentation" @click.self="selected = undefined">
    <article class="modal error-detail" role="dialog" aria-modal="true" aria-labelledby="error-detail-title">
      <button class="icon-button modal-close" aria-label="Sluiten" @click="selected = undefined"><X :size="18" /></button>
      <span :class="['error-detail-icon', selected.severity]"><AlertTriangle :size="20" /></span>
      <h2 id="error-detail-title">{{ selected.summary }}</h2>
      <dl><div><dt>Website</dt><dd>{{ selected.siteName ?? 'Applicatie' }}</dd></div><div><dt>Tijd</dt><dd>{{ dateTime(selected.createdAt) }}</dd></div><div><dt>Actie</dt><dd>{{ selected.action }}</dd></div><div><dt>Categorie</dt><dd>{{ selected.category }}</dd></div><div><dt>Fout-ID</dt><dd><code>{{ selected.id }}</code></dd></div><div><dt>Opnieuw proberen</dt><dd>{{ selected.retryable ? 'Mogelijk na controle van de oorzaak' : 'Niet automatisch' }}</dd></div><div v-if="selected.exitCode !== undefined"><dt>Exitcode</dt><dd>{{ selected.exitCode }}</dd></div><div v-if="selected.durationMs != null && Number.isFinite(selected.durationMs) && selected.durationMs >= 0"><dt>Duur</dt><dd>{{ selected.durationMs }} ms</dd></div></dl>
      <section v-if="selected.technicalDetails"><h3>Technische details</h3><pre>{{ selected.technicalDetails }}</pre></section>
      <section v-if="selected.causeChain.length"><h3>Cause-chain</h3><ol><li v-for="cause in selected.causeChain" :key="cause"><code>{{ cause }}</code></li></ol></section>
      <p class="error-detail-note">Er wordt geen generieke retry uitgevoerd: alleen acties waarvan veilig exact dezelfde niet-destructieve invoer beschikbaar is, mogen automatisch worden herhaald.</p>
    </article>
  </div>

  <ConfirmDialog v-if="pendingDelete.length" :title="pendingDelete.length === 1 ? 'Foutregel verwijderen?' : `${pendingDelete.length} foutregels verwijderen?`" :confirm-label="pendingDelete.length === 1 ? 'Foutregel verwijderen' : 'Foutregels verwijderen'" :busy="deleting" danger @cancel="pendingDelete = []" @confirm="executeDelete">
    <p>{{ pendingDelete.length === 1 ? 'Deze foutregel wordt definitief uit de lokale foutenlog verwijderd.' : `De ${pendingDelete.length} geselecteerde foutregels worden definitief uit de lokale foutenlog verwijderd.` }}</p>
  </ConfirmDialog>
</template>
