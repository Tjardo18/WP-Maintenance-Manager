<script setup lang="ts">
import { computed, ref } from "vue";
import { RouterLink } from "vue-router";
import { ArrowRight, CheckCircle2, CircleAlert, Globe2, Plus, RefreshCw, Search, ShieldAlert, WifiOff } from "@lucide/vue";
import StatusBadge from "../components/StatusBadge.vue";
import { useSitesStore } from "../stores/sites";
import { appApi } from "../services/tauri";
import { formatDate } from "../utils/format";

const store = useSitesStore();
const search = ref("");
const filter = ref("all");
const scanning = ref(false);
const completed = ref(0);
const currentNames = ref<string[]>([]);
const failures = ref<string[]>([]);
const filtered = computed(() => store.sites.filter((site) => (filter.value === "all" || site.status === filter.value) && `${site.name} ${site.url}`.toLowerCase().includes(search.value.toLowerCase())));
const count = (statuses: string[]) => store.sites.filter((site) => statuses.includes(site.status)).length;

async function scanAll() {
  scanning.value = true; completed.value = 0; failures.value = []; currentNames.value = [];
  const queue = [...store.sites];
  const worker = async () => {
    while (queue.length) {
      const site = queue.shift(); if (!site) break;
      currentNames.value.push(site.name);
      try { await appApi.scanSite(site.id); }
      catch { failures.value.push(site.name); }
      finally { currentNames.value = currentNames.value.filter((name) => name !== site.name); completed.value += 1; }
    }
  };
  await Promise.all(Array.from({ length: Math.min(4, queue.length) }, worker));
  await store.load(); scanning.value = false;
}
</script>

<template>
  <section class="page-heading">
    <div><h2>Goedemiddag</h2><p>Een actueel overzicht van al je WordPress-websites.</p></div>
    <div class="heading-actions"><RouterLink class="button secondary" to="/websites/toevoegen"><Plus :size="17" /> Website toevoegen</RouterLink><button class="button primary" :disabled="scanning || !store.sites.length" @click="scanAll"><RefreshCw :size="17" :class="{ spin: scanning }" /> Alle websites scannen</button></div>
  </section>

  <div v-if="scanning" class="progress-panel card">
    <div class="progress-copy"><span class="progress-icon"><RefreshCw :size="18" class="spin" /></span><div><strong>{{ completed }} van {{ store.sites.length }} websites gecontroleerd</strong><small v-if="currentNames.length">Nu bezig: {{ currentNames.join(", ") }}</small><small v-else>Resultaten verwerken…</small></div><span>{{ Math.round(completed / store.sites.length * 100) }}%</span></div>
    <div class="progress-track"><span :style="{ width: `${completed / store.sites.length * 100}%` }"></span></div>
    <p v-if="failures.length" class="inline-warning">Niet gelukt: {{ failures.join(", ") }}. Andere websites worden gewoon verder gecontroleerd.</p>
  </div>

  <div class="stat-grid">
    <button class="stat-card" @click="filter = 'all'"><span class="stat-icon blue"><Globe2 /></span><span><small>Websites</small><strong>{{ store.sites.length }}</strong></span></button>
    <button class="stat-card" @click="filter = 'healthy'"><span class="stat-icon green"><CheckCircle2 /></span><span><small>Gezond</small><strong>{{ count(['healthy']) }}</strong></span></button>
    <button class="stat-card" @click="filter = 'updates'"><span class="stat-icon amber"><CircleAlert /></span><span><small>Updates beschikbaar</small><strong>{{ count(['updates']) }}</strong></span></button>
    <button class="stat-card" @click="filter = 'attention'"><span class="stat-icon orange"><ShieldAlert /></span><span><small>Controle nodig</small><strong>{{ count(['attention', 'problem']) }}</strong></span></button>
    <button class="stat-card" @click="filter = 'unreachable'"><span class="stat-icon gray"><WifiOff /></span><span><small>Niet bereikbaar</small><strong>{{ count(['unreachable']) }}</strong></span></button>
  </div>

  <section class="card table-card">
    <div class="card-header"><div><h3>Alle websites</h3><p>Laatste bekende status en onderhoudsinformatie</p></div><div class="table-tools"><label class="search-box"><Search :size="17" /><input v-model="search" type="search" placeholder="Zoek website…" aria-label="Zoek website" /></label><select v-model="filter" aria-label="Filter op status"><option value="all">Alle statussen</option><option value="healthy">Gezond</option><option value="updates">Updates</option><option value="attention">Controle nodig</option><option value="unreachable">Niet bereikbaar</option><option value="unscanned">Niet gescand</option></select></div></div>
    <div v-if="store.loading" class="skeleton-list"><span v-for="i in 4" :key="i"></span></div>
    <div v-else-if="!store.sites.length" class="empty-state"><Globe2 :size="40" /><h3>Nog geen websites toegevoegd</h3><p>Voeg je eerste WordPress-website toe om te beginnen.</p><RouterLink class="button primary" to="/websites/toevoegen">Website toevoegen</RouterLink></div>
    <div v-else class="table-scroll"><table><thead><tr><th>Website</th><th>Status</th><th>WordPress / PHP</th><th>Updates</th><th>Securitystatus</th><th>Laatste scan</th><th><span class="sr-only">Acties</span></th></tr></thead><tbody><tr v-for="site in filtered" :key="site.id"><td><RouterLink class="site-name" :to="`/websites/${site.id}`"><span class="site-avatar">{{ site.name.slice(0, 2).toUpperCase() }}</span><span><strong>{{ site.name }}</strong><small>{{ site.url }}</small></span></RouterLink></td><td><StatusBadge :status="site.status" /></td><td><strong>{{ site.wordpressVersion ?? '—' }}</strong><small>PHP {{ site.phpVersion ?? '—' }}</small></td><td><span :class="['update-count', { active: site.updateCount }]">{{ site.updateCount }}</span></td><td><span class="security-copy">{{ site.securityStatus ?? 'Nog niet gecontroleerd' }}</span></td><td>{{ formatDate(site.lastScanAt) }}</td><td><RouterLink class="icon-button" :to="`/websites/${site.id}`" :aria-label="`${site.name} openen`"><ArrowRight :size="18" /></RouterLink></td></tr></tbody></table></div>
  </section>
</template>
