<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { RouterLink } from "vue-router";
import { ArrowRight, Bug, CheckCircle2, CircleAlert, GitCompare, Globe2, Plus, RefreshCw, Search, ShieldAlert, WifiOff } from "@lucide/vue";
import StatusBadge from "../components/StatusBadge.vue";
import { useSitesStore } from "../stores/sites";
import { useScanJobsStore } from "../stores/scanJobs";
import { formatDate } from "../utils/format";
import { errorMessage } from "../utils/errors";

const store = useSitesStore();
const scanJobs = useScanJobsStore();
const search = ref("");
const filter = ref("all");
const cancelling = ref(false);
const batchIds = ref<string[]>([]);
const scanError = ref<string>();
const batchJobs = computed(() => batchIds.value.length ? scanJobs.all.filter((job) => batchIds.value.includes(job.id)) : scanJobs.active);
const scanning = computed(() => batchJobs.value.some((job) => job.status === "queued" || job.status === "running"));
const completed = computed(() => batchJobs.value.filter((job) => ["completed", "failed", "cancelled"].includes(job.status)).length);
const currentNames = computed(() => batchJobs.value.filter((job) => job.status === "running").map((job) => job.siteName));
const failures = computed(() => batchJobs.value.filter((job) => job.status === "failed").map((job) => job.siteName));
const vulnerabilityCount = (site: (typeof store.sites)[number]) => { const summary = site.vulnerabilitySummary; return summary ? summary.criticalCount + summary.highCount + summary.mediumCount + summary.lowCount + summary.infoCount + summary.unknownCount : 0; };
const filtered = computed(() => store.sites.filter((site) => (filter.value === "all" || (filter.value === "vulnerabilities" ? vulnerabilityCount(site) > 0 : site.status === filter.value)) && `${site.name} ${site.url}`.toLowerCase().includes(search.value.toLowerCase())));
const count = (statuses: string[]) => store.sites.filter((site) => statuses.includes(site.status)).length;
const vulnerabilityTotals = computed(() => store.sites.reduce((totals, site) => { const summary = site.vulnerabilitySummary; if (!summary) return totals; totals.critical += summary.criticalCount; totals.high += summary.highCount; totals.medium += summary.mediumCount; totals.low += summary.lowCount; totals.info += summary.infoCount; totals.unknown += summary.unknownCount; return totals; }, { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 }));
const totalVulnerabilities = computed(() => Object.values(vulnerabilityTotals.value).reduce((total, value) => total + value, 0));
const priorityVulnerabilitySites = computed(() => [...store.sites].filter((site) => (site.vulnerabilitySummary?.criticalCount ?? 0) + (site.vulnerabilitySummary?.highCount ?? 0) > 0).sort((left, right) => (right.vulnerabilitySummary?.criticalCount ?? 0) - (left.vulnerabilitySummary?.criticalCount ?? 0) || (right.vulnerabilitySummary?.highCount ?? 0) - (left.vulnerabilitySummary?.highCount ?? 0)).slice(0, 5));
const changeSummary = (siteId: string) => store.changeSummaries.get(siteId);
const refreshedJobIds = new Set<string>();

watch(batchJobs, async (jobs) => {
  const newlyCompleted = jobs.filter((job) => job.status === "completed" && !refreshedJobIds.has(job.id));
  if (!newlyCompleted.length) return;
  newlyCompleted.forEach((job) => refreshedJobIds.add(job.id));
  await store.load();
}, { deep: true });

async function scanAll() {
  scanError.value = undefined;
  try { batchIds.value = (await scanJobs.startAll()).map((job) => job.id); }
  catch (cause) { scanError.value = errorMessage(cause); }
}
async function cancelScan() { cancelling.value = true; try { await scanJobs.cancelMany(batchJobs.value.filter((job) => ["queued", "running"].includes(job.status)).map((job) => job.id)); } catch (cause) { scanError.value = errorMessage(cause); } finally { cancelling.value = false; } }
</script>

<template>
  <section class="page-heading">
    <div><h2>Goedemiddag</h2><p>Een actueel overzicht van al je WordPress-websites.</p></div>
    <div class="heading-actions"><RouterLink class="button secondary" to="/websites/toevoegen"><Plus :size="17" /> Website toevoegen</RouterLink><button class="button primary" :disabled="scanning || !store.sites.length" @click="scanAll"><RefreshCw :size="17" :class="{ spin: scanning }" /> Alle websites scannen</button></div>
  </section>

  <div v-if="scanning" class="progress-panel card">
    <div class="progress-copy"><span class="progress-icon"><RefreshCw :size="18" class="spin" /></span><div><strong>{{ completed }} van {{ batchJobs.length }} websites gecontroleerd</strong><small v-if="currentNames.length">Nu bezig: {{ currentNames.join(", ") }}</small><small v-else>Wacht op een beschikbare scanplek…</small></div><span>{{ batchJobs.length ? Math.round(completed / batchJobs.length * 100) : 0 }}%</span><button class="button small secondary" :disabled="cancelling" @click="cancelScan">{{ cancelling ? 'Annuleren…' : 'Annuleren' }}</button></div>
    <div class="progress-track"><span :style="{ width: `${batchJobs.length ? completed / batchJobs.length * 100 : 0}%` }"></span></div>
    <p v-if="failures.length" class="inline-warning">Niet gelukt: {{ failures.join(", ") }}. Andere websites worden gewoon verder gecontroleerd.</p>
  </div>
  <p v-if="scanError" class="error-banner">{{ scanError }}</p>

  <div class="stat-grid">
    <button class="stat-card" @click="filter = 'all'"><span class="stat-icon blue"><Globe2 /></span><span><small>Websites</small><strong>{{ store.sites.length }}</strong></span></button>
    <button class="stat-card" @click="filter = 'healthy'"><span class="stat-icon green"><CheckCircle2 /></span><span><small>Gezond</small><strong>{{ count(['healthy']) }}</strong></span></button>
    <button class="stat-card" @click="filter = 'updates'"><span class="stat-icon amber"><CircleAlert /></span><span><small>Updates beschikbaar</small><strong>{{ count(['updates']) }}</strong></span></button>
    <button class="stat-card" @click="filter = 'attention'"><span class="stat-icon orange"><ShieldAlert /></span><span><small>Controle nodig</small><strong>{{ count(['attention', 'problem']) }}</strong></span></button>
    <button class="stat-card" @click="filter = 'vulnerabilities'"><span class="stat-icon red"><Bug /></span><span><small>Kwetsbaarheden</small><strong>{{ totalVulnerabilities }}</strong></span></button>
    <button class="stat-card" @click="filter = 'unreachable'"><span class="stat-icon gray"><WifiOff /></span><span><small>Niet bereikbaar</small><strong>{{ count(['unreachable']) }}</strong></span></button>
  </div>

  <section v-if="priorityVulnerabilitySites.length" class="card vulnerability-priority">
    <div class="card-header"><div><h3>Direct aandacht nodig</h3><p>Actieve Critical- en High-kwetsbaarheden uit de lokale Wordfence-database.</p></div></div>
    <div class="vulnerability-priority-list"><RouterLink v-for="site in priorityVulnerabilitySites" :key="site.id" :to="`/websites/${site.id}`"><span class="stat-icon red"><Bug :size="17" /></span><span><strong>{{ site.name }}</strong><small><template v-if="site.vulnerabilitySummary?.criticalCount">{{ site.vulnerabilitySummary.criticalCount }} kritiek</template><template v-if="site.vulnerabilitySummary?.criticalCount && site.vulnerabilitySummary?.highCount"> · </template><template v-if="site.vulnerabilitySummary?.highCount">{{ site.vulnerabilitySummary.highCount }} hoog</template></small><small v-if="site.vulnerabilitySummary?.inventoryStale" class="stale-copy">Mogelijk · laatst bekende versies · scan opnieuw</small></span><ArrowRight :size="17" /></RouterLink></div>
  </section>

  <section class="card table-card">
    <div class="card-header"><div><h3>Alle websites</h3><p>Laatste bekende status en onderhoudsinformatie</p></div><div class="table-tools"><label class="search-box"><Search :size="17" /><input v-model="search" type="search" placeholder="Zoek website…" aria-label="Zoek website" /></label><select v-model="filter" aria-label="Filter op status"><option value="all">Alle statussen</option><option value="healthy">Gezond</option><option value="updates">Updates</option><option value="attention">Controle nodig</option><option value="vulnerabilities">Met kwetsbaarheden</option><option value="unreachable">Niet bereikbaar</option><option value="unscanned">Niet gescand</option></select></div></div>
    <div v-if="store.loading" class="skeleton-list"><span v-for="i in 4" :key="i"></span></div>
    <div v-else-if="!store.sites.length" class="empty-state"><Globe2 :size="40" /><h3>Nog geen websites toegevoegd</h3><p>Voeg je eerste WordPress-website toe om te beginnen.</p><RouterLink class="button primary" to="/websites/toevoegen">Website toevoegen</RouterLink></div>
    <div v-else class="table-scroll"><table><thead><tr><th>Website</th><th>Status</th><th>WordPress / PHP</th><th>Updates</th><th>Kwetsbaarheden</th><th>Wijzigingen</th><th>Securitystatus</th><th>Laatste scan</th><th><span class="sr-only">Acties</span></th></tr></thead><tbody><tr v-for="site in filtered" :key="site.id"><td><RouterLink class="site-name" :to="`/websites/${site.id}`"><span class="site-avatar">{{ site.name.slice(0, 2).toUpperCase() }}</span><span><strong>{{ site.name }}</strong><small>{{ site.url }}</small></span></RouterLink></td><td><StatusBadge :status="site.status" /></td><td><strong>{{ site.wordpressVersion ?? '—' }}</strong><small>PHP {{ site.phpVersion ?? '—' }}</small></td><td><span :class="['update-count', { active: site.updateCount }]">{{ site.updateCount }}</span></td><td><span v-if="site.vulnerabilitySummary" :class="['vulnerability-counts', { active: vulnerabilityCount(site), stale: site.vulnerabilitySummary.inventoryStale }]" :title="`Laatst lokaal gecontroleerd: ${formatDate(site.vulnerabilitySummary.lastCheckedAt)}${site.vulnerabilitySummary.inventoryStale ? ' · mogelijk verouderd; scan de website opnieuw' : ''}`"><strong>{{ vulnerabilityCount(site) }}</strong><small v-if="site.vulnerabilitySummary.criticalCount || site.vulnerabilitySummary.highCount">{{ site.vulnerabilitySummary.criticalCount }} kritiek · {{ site.vulnerabilitySummary.highCount }} hoog</small><small v-else>bekende actieve meldingen</small><small v-if="site.vulnerabilitySummary.inventoryStale" class="stale-copy">Mogelijk · scan opnieuw</small></span><span v-else>—</span></td><td><RouterLink v-if="changeSummary(site.id)?.latestSnapshotAt" class="dashboard-changes" :to="{ path: `/websites/${site.id}`, query: { tab: 'Wijzigingen' } }"><GitCompare :size="15" /><span><strong>{{ changeSummary(site.id)?.latestChangeCount ? `${changeSummary(site.id)?.latestChangeCount} wijzigingen` : 'Geen wijzigingen' }}</strong><small v-if="changeSummary(site.id)?.importantChangeSummary" class="important-change">⚠ {{ changeSummary(site.id)?.importantChangeSummary }}</small><small v-else-if="changeSummary(site.id)?.unseenChangeCount" class="unseen-change">{{ changeSummary(site.id)?.unseenChangeCount }} nieuw</small><small v-else>{{ formatDate(changeSummary(site.id)?.latestSnapshotAt) }}</small></span></RouterLink><span v-else>—</span></td><td><span class="security-copy">{{ site.securityStatus ?? 'Nog niet gecontroleerd' }}</span></td><td>{{ formatDate(site.lastScanAt) }}</td><td><RouterLink class="icon-button" :to="`/websites/${site.id}`" :aria-label="`${site.name} openen`"><ArrowRight :size="18" /></RouterLink></td></tr></tbody></table></div>
  </section>
</template>
