<script setup lang="ts">
import { computed, nextTick, reactive, ref, watch } from "vue";
import { CheckCircle2, ChevronDown, CircleAlert, Eye, LoaderCircle, Search, Trash2 } from "@lucide/vue";
import type { Finding, ScanCheck } from "../types";
import { filterSecurityFindings, noteworthyFindingCount, paginateSecurityFindings, type SecurityCategory } from "../services/securityResults";
import { formatDate } from "../utils/format";
import StatusBadge from "./StatusBadge.vue";

const props = defineProps<{
  checks: ScanCheck[];
  finishedAt: string;
  truncated: boolean;
  isLatestScan: boolean;
  selectedFindingIds: string[];
  busy?: string;
  showSummary?: boolean;
}>();

const emit = defineEmits<{
  toggleFinding: [id: string];
  preview: [finding: Finding];
  delete: [finding: Finding];
}>();

const openKeys = ref<string[]>([]);
const queries = reactive<Record<string, string>>({});
const categories = reactive<Record<string, SecurityCategory>>({});
const pages = reactive<Record<string, number>>({});
const pageSizes = reactive<Record<string, number>>({});
const showAllPhp = ref(false);

watch(() => [props.finishedAt, ...props.checks.map((check) => check.key)], () => {
  for (const check of props.checks) {
    queries[check.key] ??= "";
    categories[check.key] ??= "all";
    pages[check.key] ??= 1;
    pageSizes[check.key] ??= 25;
  }

  const firstAttention = props.checks.find((check) => check.status === "failed" || check.status === "warning" || noteworthyFindingCount(check) > 0);
  openKeys.value = firstAttention ? [firstAttention.key] : [];
  showAllPhp.value = false;
}, { immediate: true });

const results = computed(() => Object.fromEntries(props.checks.map((check) => {
  const findings = filterSecurityFindings(check, {
    query: queries[check.key] ?? "",
    category: categories[check.key] ?? "all",
    showAllPhp: showAllPhp.value,
  });
  return [check.key, paginateSecurityFindings(findings, pages[check.key] ?? 1, pageSizes[check.key] ?? 25)];
})));

const attentionCount = computed(() => props.checks.reduce((count, check) => count + noteworthyFindingCount(check), 0));

function isOpen(key: string) {
  return openKeys.value.includes(key);
}

function toggle(key: string) {
  openKeys.value = isOpen(key) ? openKeys.value.filter((item) => item !== key) : [...openKeys.value, key];
}

async function openAndScroll(key: string) {
  if (!isOpen(key)) openKeys.value = [...openKeys.value, key];
  await nextTick();
  globalThis.document?.getElementById(`security-check-${key}`)?.scrollIntoView?.({ behavior: "smooth", block: "start" });
}

function resultFor(check: ScanCheck) {
  return results.value[check.key] ?? paginateSecurityFindings([], 1, 25);
}

function resetPage(key: string) {
  pages[key] = 1;
}

function setPage(key: string, page: number) {
  pages[key] = Math.max(1, page);
}

function displayCount(check: ScanCheck) {
  return check.key === "php_files" ? noteworthyFindingCount(check) : check.findings.length;
}

function compactSummary(check: ScanCheck) {
  const count = displayCount(check);
  if (check.key === "php_files") return count ? `${count} opvallend` : "Geen opvallende bestanden";
  if (check.key === "php_uploads") return count ? `${count} gevonden` : "Geen bestanden gevonden";
  if (check.key === "modified_files") return `${count} gewijzigd`;
  if (!count && check.status === "success") return "In orde";
  return check.summary;
}

function checksumLabel(finding: Finding) {
  if (finding.checksumStatus === "modified") return "Gewijzigd";
  if (finding.checksumStatus === "missing") return "Ontbreekt";
  if (finding.checksumStatus === "unexpected") return "Hoort niet aanwezig te zijn";
  if (finding.checksumStatus === "scan_error") return "Scan mislukt";
  return finding.title;
}

function categoryOptions(check: ScanCheck): Array<{ value: SecurityCategory; label: string }> {
  const common: Array<{ value: SecurityCategory; label: string }> = [{ value: "all", label: "Alle categorieën" }];
  if (check.key === "php_files") return [...common,
    { value: "noteworthy", label: "Opvallend" }, { value: "uploads", label: "Uploads" },
    { value: "other", label: "Overige" }, { value: "plugins", label: "Plugins / mu-plugins" }, { value: "themes", label: "Thema's" },
  ];
  return [...common,
    { value: "core", label: "Core" }, { value: "plugins", label: "Plugins" }, { value: "themes", label: "Thema's" },
    { value: "uploads", label: "Uploads" }, { value: "root", label: "Root" }, { value: "other", label: "Overige" },
  ];
}
</script>

<template>
  <section v-if="showSummary" class="security-overview card" aria-labelledby="security-overview-title">
    <header>
      <div><small>Securitycontrole</small><h3 id="security-overview-title">{{ attentionCount ? `${attentionCount} aandachtspunten` : 'Geen aandachtspunten' }}</h3></div>
      <span>Laatste scan: {{ formatDate(finishedAt) }}</span>
    </header>
    <div class="security-summary-grid">
      <button v-for="check in checks" :key="check.key" type="button" @click="openAndScroll(check.key)">
        <span :class="['security-summary-icon', check.status]"><CheckCircle2 v-if="check.status === 'success'" :size="16" /><CircleAlert v-else :size="16" /></span>
        <span><strong>{{ check.label }}</strong><small>{{ compactSummary(check) }}</small></span>
        <ChevronDown :size="15" />
      </button>
    </div>
  </section>

  <div class="security-accordions">
    <article v-for="check in checks" :id="`security-check-${check.key}`" :key="check.key" class="security-accordion card">
      <button class="security-accordion-header" type="button" :aria-expanded="isOpen(check.key)" :aria-controls="`security-panel-${check.key}`" @click="toggle(check.key)">
        <span :class="['security-accordion-icon', check.status]"><CheckCircle2 v-if="check.status === 'success'" :size="17" /><CircleAlert v-else :size="17" /></span>
        <span class="security-accordion-copy"><strong>{{ check.label }}</strong><small>{{ compactSummary(check) }}</small></span>
        <span class="security-scan-time">{{ formatDate(finishedAt) }}</span>
        <StatusBadge :status="check.status" />
        <ChevronDown :class="{ rotated: isOpen(check.key) }" :size="17" />
      </button>

      <div v-if="isOpen(check.key)" :id="`security-panel-${check.key}`" class="security-accordion-body">
        <p class="security-check-description">{{ check.summary }}</p>
        <details v-if="check.status === 'failed' && check.technicalDetails" class="scan-diagnostic"><summary>Technische details</summary><pre>{{ check.technicalDetails }}</pre></details>

        <div v-if="check.key === 'php_files' || check.key === 'modified_files'" class="security-result-toolbar">
          <label class="security-search"><Search :size="14" /><input v-model="queries[check.key]" type="search" placeholder="Zoek op pad of bestandsnaam" :aria-label="`Zoeken in ${check.label}`" @input="resetPage(check.key)" /></label>
          <select v-model="categories[check.key]" :aria-label="`Categorie voor ${check.label}`" @change="resetPage(check.key)"><option v-for="option in categoryOptions(check)" :key="option.value" :value="option.value">{{ option.label }}</option></select>
          <label v-if="check.key === 'php_files'" class="security-toggle"><input v-model="showAllPhp" type="checkbox" @change="resetPage(check.key)" /> Toon alle PHP-bestanden</label>
        </div>

        <p v-if="truncated && (check.key === 'php_files' || check.key === 'modified_files')" class="results-truncated">Er zijn meer resultaten dan weergegeven. Verfijn je filters.</p>
        <div v-if="!resultFor(check).total" class="security-no-results">
          <CheckCircle2 v-if="!check.findings.length || (check.key === 'php_files' && !showAllPhp)" :size="19" />
          <Search v-else :size="19" />
          <span>{{ !check.findings.length ? 'Geen bevindingen voor deze controle.' : check.key === 'php_files' && !showAllPhp ? 'Geen opvallende PHP-bestanden. Schakel “Toon alle PHP-bestanden” in voor de volledige inventaris.' : 'Geen resultaten voor deze filters.' }}</span>
        </div>

        <div v-else class="security-findings" data-testid="security-findings">
          <div v-for="finding in resultFor(check).items" :key="finding.id ?? finding.path ?? finding.title" :class="['finding', { 'checksum-finding': finding.checksumStatus }]">
            <label v-if="finding.checksumStatus === 'unexpected' && finding.id" class="finding-select"><input type="checkbox" :checked="selectedFindingIds.includes(finding.id)" :disabled="!isLatestScan" :aria-label="`${finding.path} selecteren`" @change="emit('toggleFinding', finding.id)" /></label>
            <div class="finding-copy"><span v-if="finding.checksumStatus" :class="['checksum-status', finding.checksumStatus]">{{ checksumLabel(finding) }}</span><strong v-else>{{ finding.title }}</strong><p>{{ finding.detail }}</p><code v-if="finding.path">{{ finding.path }}</code></div>
            <div v-if="finding.checksumStatus === 'unexpected' && finding.id" class="finding-actions"><button class="button small secondary" :disabled="!!busy || !isLatestScan" @click="emit('preview', finding)"><LoaderCircle v-if="busy === `preview-${finding.id}`" class="spin" :size="14" /><Eye v-else :size="14" /> Bekijk bestand</button><button class="button small danger-text" :disabled="!!busy || !isLatestScan" @click="emit('delete', finding)"><Trash2 :size="14" /> Verwijderen</button></div>
          </div>
        </div>

        <footer v-if="resultFor(check).total" class="security-pagination">
          <span>{{ resultFor(check).start }}–{{ resultFor(check).end }} van {{ resultFor(check).total }}</span>
          <label>Per pagina <select v-model.number="pageSizes[check.key]" :aria-label="`Resultaten per pagina voor ${check.label}`" @change="resetPage(check.key)"><option :value="25">25</option><option :value="50">50</option><option :value="100">100</option></select></label>
          <button class="button small ghost" :disabled="resultFor(check).page <= 1" @click="setPage(check.key, resultFor(check).page - 1)">Vorige</button>
          <strong>{{ resultFor(check).page }} / {{ resultFor(check).pageCount }}</strong>
          <button class="button small ghost" :disabled="resultFor(check).page >= resultFor(check).pageCount" @click="setPage(check.key, resultFor(check).page + 1)">Volgende</button>
        </footer>
      </div>
    </article>
  </div>
</template>
