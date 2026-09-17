<script setup lang="ts">
import { computed, nextTick, onUnmounted, reactive, ref, watch } from "vue";
import { CheckCircle2, ChevronDown, CircleAlert, CircleX, Clock3, Eye, EyeOff, Info, LoaderCircle, MinusCircle, RefreshCw, Search, ShieldCheck, Trash2 } from "@lucide/vue";
import type { Finding, ScanCheck, UpdateItem } from "../types";
import { filterSecurityFindings, noteworthyFindingCount, paginateSecurityFindings, type SecurityCategory, type SecurityDisposition } from "../services/securityResults";
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
  updates?: UpdateItem[];
}>();

const emit = defineEmits<{
  toggleFinding: [id: string];
  preview: [finding: Finding];
  delete: [finding: Finding];
  ignore: [finding: Finding, temporary: boolean];
  trust: [finding: Finding];
  details: [finding: Finding];
  update: [item: UpdateItem];
}>();

const openKeys = ref<string[]>([]);
const queries = reactive<Record<string, string>>({});
const queryInputs = reactive<Record<string, string>>({});
const queryTimers: Record<string, number | undefined> = {};
const categories = reactive<Record<string, SecurityCategory>>({});
const dispositions = reactive<Record<string, SecurityDisposition>>({});
const pages = reactive<Record<string, number>>({});
const pageSizes = reactive<Record<string, number>>({});
const showAllPhp = ref(false);

watch(() => [props.finishedAt, ...props.checks.map((check) => check.key)], () => {
  for (const check of props.checks) {
    queries[check.key] ??= "";
    queryInputs[check.key] ??= "";
    categories[check.key] ??= "all";
    dispositions[check.key] ??= "active";
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
    disposition: dispositions[check.key] ?? "active",
    showAllPhp: showAllPhp.value,
  });
  return [check.key, paginateSecurityFindings(findings, pages[check.key] ?? 1, pageSizes[check.key] ?? 25)];
})));

const attentionCount = computed(() => props.checks.reduce((count, check) => count + noteworthyFindingCount(check), 0));
const ignoredCount = computed(() => props.checks.flatMap((check) => check.findings).filter((finding) => finding.disposition === "ignored").length);
const trustedCount = computed(() => props.checks.flatMap((check) => check.findings).filter((finding) => ["trusted", "trusted_changed", "trusted_missing"].includes(finding.disposition ?? "")).length);

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

function setDisposition(key: string, disposition: string) {
  dispositions[key] = disposition as SecurityDisposition;
  resetPage(key);
}

function scheduleQuery(key: string) {
  if (queryTimers[key] !== undefined) globalThis.clearTimeout(queryTimers[key]);
  queryTimers[key] = globalThis.setTimeout(() => {
    queries[key] = queryInputs[key] ?? "";
    resetPage(key);
    queryTimers[key] = undefined;
  }, 200);
}

onUnmounted(() => Object.values(queryTimers).forEach((timer) => { if (timer !== undefined) globalThis.clearTimeout(timer); }));

function setPage(key: string, page: number) {
  pages[key] = Math.max(1, page);
}

function displayCount(check: ScanCheck) {
  return check.key === "php_files" ? noteworthyFindingCount(check) : check.findings.filter((finding) => ["active", "expired_exception", "trusted_changed"].includes(finding.disposition ?? "active")).length;
}

function compactSummary(check: ScanCheck) {
  const count = displayCount(check);
  if (check.key === "vulnerabilities") {
    const active = check.findings.filter((finding) => ["active", "expired_exception"].includes(finding.disposition ?? "active") && finding.vulnerability);
    const critical = active.filter((finding) => finding.vulnerability?.cvssRating?.toLowerCase() === "critical").length;
    const high = active.filter((finding) => finding.vulnerability?.cvssRating?.toLowerCase() === "high").length;
    if (!active.length && check.status === "success") return "Geen bekende kwetsbaarheden";
    return [critical && `${critical} kritiek`, high && `${high} hoog`, !critical && !high && `${active.length} gevonden`].filter(Boolean).join(" · ");
  }
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

function dispositionLabel(finding: Finding) {
  if (finding.disposition === "ignored") return "Genegeerd";
  if (finding.disposition === "trusted") return "Vertrouwd";
  if (finding.disposition === "trusted_changed") return "Vertrouwd bestand gewijzigd";
  if (finding.disposition === "trusted_missing") return "Niet meer aanwezig";
  if (finding.disposition === "expired_exception") return "Uitzondering verlopen";
  return undefined;
}

function canTrust(finding: Finding) {
  return Boolean(finding.id && finding.path && !["missing", "scan_error"].includes(finding.checksumStatus ?? "") && finding.disposition !== "trusted");
}

function updateFor(finding: Finding) {
  const vulnerability = finding.vulnerability;
  if (!vulnerability?.updateVersion) return undefined;
  return props.updates?.find((item) => item.kind === vulnerability.softwareType && item.slug === vulnerability.softwareSlug);
}

function vulnerabilityRating(finding: Finding) {
  if (finding.vulnerability?.informational) return "Informatief";
  return finding.vulnerability?.cvssRating ?? "Unknown";
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
    <div class="security-policy-counts"><span><CircleAlert :size="15" /> {{ attentionCount }} actief</span><span><EyeOff :size="15" /> {{ ignoredCount }} genegeerd</span><span><ShieldCheck :size="15" /> {{ trustedCount }} vertrouwd</span></div>
    <div class="security-summary-grid">
      <button v-for="check in checks" :key="check.key" type="button" @click="openAndScroll(check.key)">
        <span :class="['security-summary-icon', check.status]"><CheckCircle2 v-if="check.status === 'success'" data-status-icon="success" :size="16" /><LoaderCircle v-else-if="check.status === 'running'" data-status-icon="running" class="spin" :size="16" /><CircleX v-else-if="check.status === 'failed'" data-status-icon="failed" :size="16" /><CircleAlert v-else-if="check.status === 'warning'" data-status-icon="warning" :size="16" /><MinusCircle v-else data-status-icon="neutral" :size="16" /></span>
        <span><strong>{{ check.label }}</strong><small>{{ compactSummary(check) }}</small></span>
        <ChevronDown :size="15" />
      </button>
    </div>
  </section>

  <div class="security-accordions">
    <article v-for="check in checks" :id="`security-check-${check.key}`" :key="check.key" class="security-accordion card">
      <button class="security-accordion-header" type="button" :aria-expanded="isOpen(check.key)" :aria-controls="`security-panel-${check.key}`" @click="toggle(check.key)">
        <span :class="['security-accordion-icon', check.status]"><CheckCircle2 v-if="check.status === 'success'" data-status-icon="success" :size="17" /><LoaderCircle v-else-if="check.status === 'running'" data-status-icon="running" class="spin" :size="17" /><CircleX v-else-if="check.status === 'failed'" data-status-icon="failed" :size="17" /><CircleAlert v-else-if="check.status === 'warning'" data-status-icon="warning" :size="17" /><MinusCircle v-else data-status-icon="neutral" :size="17" /></span>
        <span class="security-accordion-copy"><strong>{{ check.label }}</strong><small>{{ compactSummary(check) }}</small></span>
        <span class="security-scan-time">{{ formatDate(finishedAt) }}</span>
        <StatusBadge :status="check.status" />
        <ChevronDown :class="{ rotated: isOpen(check.key) }" :size="17" />
      </button>

      <div v-if="isOpen(check.key)" :id="`security-panel-${check.key}`" class="security-accordion-body">
        <p class="security-check-description">{{ check.summary }}</p>
        <details v-if="check.status === 'failed' && check.technicalDetails" class="scan-diagnostic"><summary>Technische details</summary><pre>{{ check.technicalDetails }}</pre></details>

        <div class="security-disposition-tabs" aria-label="Meldingstatus">
          <button v-for="option in [{ value: 'active', label: 'Actief' }, { value: 'ignored', label: 'Genegeerd' }, { value: 'trusted', label: 'Vertrouwd' }, { value: 'all', label: 'Alles' }]" :key="option.value" type="button" :class="{ active: dispositions[check.key] === option.value }" @click="setDisposition(check.key, option.value)">{{ option.label }}</button>
        </div>

        <div v-if="check.key === 'php_files' || check.key === 'modified_files'" class="security-result-toolbar">
          <label class="security-search"><Search :size="14" /><input v-model="queryInputs[check.key]" type="search" placeholder="Zoek op pad of bestandsnaam" :aria-label="`Zoeken in ${check.label}`" @input="scheduleQuery(check.key)" /></label>
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
          <div v-for="finding in resultFor(check).items" :key="finding.id ?? finding.path ?? finding.title" :class="['finding', `finding-${finding.disposition ?? 'active'}`, { 'checksum-finding': finding.checksumStatus, 'vulnerability-finding': finding.vulnerability }]">
            <label v-if="finding.checksumStatus === 'unexpected' && finding.id" class="finding-select"><input type="checkbox" :checked="selectedFindingIds.includes(finding.id)" :disabled="!isLatestScan" :aria-label="`${finding.path} selecteren`" @change="emit('toggleFinding', finding.id)" /></label>
            <div class="finding-copy">
              <template v-if="finding.vulnerability"><div class="vulnerability-finding-heading"><div><strong>{{ finding.vulnerability.softwareName }}</strong><code>{{ finding.vulnerability.softwareSlug }}</code></div><span :class="['vulnerability-rating', (finding.vulnerability.cvssRating ?? 'unknown').toLowerCase()]">{{ vulnerabilityRating(finding) }}<template v-if="finding.vulnerability.cvssScore !== undefined"> · {{ finding.vulnerability.cvssScore }}</template></span></div><p class="vulnerability-title">{{ finding.vulnerability.title }}</p><div class="vulnerability-meta"><span>Geïnstalleerd: <strong>{{ finding.vulnerability.installedVersion }}</strong></span><span v-if="finding.vulnerability.installedStatus === 'inactive'">Inactief</span><span v-if="finding.vulnerability.cve">{{ finding.vulnerability.cve }}</span><span>{{ finding.vulnerability.patchedVersions.length ? `Opgelost: ${finding.vulnerability.patchedVersions.join(', ')}` : finding.vulnerability.patched ? 'Oplossing gemeld' : 'Geen bekende patch beschikbaar' }}</span></div></template>
              <template v-else><span v-if="finding.checksumStatus" :class="['checksum-status', finding.checksumStatus]">{{ checksumLabel(finding) }}</span><strong v-else>{{ finding.title }}</strong><p>{{ finding.detail }}</p><code v-if="finding.path">{{ finding.path }}</code></template>
              <span v-if="dispositionLabel(finding)" :class="['finding-disposition', finding.disposition]">{{ dispositionLabel(finding) }}</span><small v-if="finding.policyReason" class="finding-policy-reason">{{ finding.policyReason }}</small>
            </div>
            <div v-if="finding.id" class="finding-actions">
              <button v-if="finding.vulnerability" class="button small secondary" :disabled="!!busy" @click="emit('details', finding)"><Info :size="14" /> Details</button>
              <button v-if="isLatestScan && updateFor(finding)" class="button small secondary" :disabled="!!busy" @click="emit('update', updateFor(finding)!)"><RefreshCw :size="14" /> {{ finding.vulnerability?.softwareType === 'core' ? 'WordPress bijwerken' : 'Bijwerken' }}</button>
              <button v-if="isLatestScan && finding.checksumStatus === 'unexpected'" class="button small secondary" :disabled="!!busy" @click="emit('preview', finding)"><LoaderCircle v-if="busy === `preview-${finding.id}`" class="spin" :size="14" /><Eye v-else :size="14" /> Bekijken</button>
              <button v-if="isLatestScan && (finding.disposition ?? 'active') !== 'ignored' && finding.disposition !== 'trusted'" class="button small ghost" :disabled="!!busy" @click="emit('ignore', finding, false)"><EyeOff :size="14" /> Melding negeren</button>
              <button v-if="isLatestScan && (finding.disposition ?? 'active') !== 'ignored' && finding.disposition !== 'trusted'" class="button small ghost" :disabled="!!busy" @click="emit('ignore', finding, true)"><Clock3 :size="14" /> Tijdelijk negeren</button>
              <button v-if="isLatestScan && canTrust(finding)" class="button small ghost" :disabled="!!busy" @click="emit('trust', finding)"><ShieldCheck :size="14" /> Bestand vertrouwen</button>
              <button v-if="isLatestScan && finding.checksumStatus === 'unexpected'" class="button small danger-text" :disabled="!!busy" @click="emit('delete', finding)"><Trash2 :size="14" /> Verwijderen</button>
            </div>
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
