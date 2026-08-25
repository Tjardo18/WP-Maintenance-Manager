<script setup lang="ts">
import { computed, ref } from "vue";
import { RouterLink } from "vue-router";
import { ExternalLink, Plus, Search, Server } from "@lucide/vue";
import StatusBadge from "../components/StatusBadge.vue";
import ConfirmDialog from "../components/ConfirmDialog.vue";
import { useSitesStore } from "../stores/sites";
import { formatDate } from "../utils/format";
import { errorMessage } from "../utils/errors";

const store = useSitesStore();
const search = ref("");
const removing = ref<string>();
const busy = ref(false);
const error = ref<string>();
const filtered = computed(() => store.sites.filter((site) => `${site.name} ${site.url} ${site.sshHost}`.toLowerCase().includes(search.value.toLowerCase())));
async function confirmRemove() { if (!removing.value) return; busy.value = true; error.value = undefined; try { await store.remove(removing.value); removing.value = undefined; } catch (cause) { error.value = errorMessage(cause); } finally { busy.value = false; } }
</script>
<template>
  <section class="page-heading"><div><h2>Websites</h2><p>Beheer verbindingen en onderhoudsinstellingen.</p></div><RouterLink class="button primary" to="/websites/toevoegen"><Plus :size="17" /> Website toevoegen</RouterLink></section>
  <p v-if="error" class="error-banner">{{ error }}</p>
  <div class="toolbar card"><label class="search-box grow"><Search :size="17" /><input v-model="search" type="search" placeholder="Zoeken op naam, URL of server…" /></label><span>{{ filtered.length }} van {{ store.sites.length }}</span></div>
  <div v-if="filtered.length" class="site-grid">
    <article v-for="site in filtered" :key="site.id" class="site-card card">
      <div class="site-card-top"><span class="site-avatar large">{{ site.name.slice(0, 2).toUpperCase() }}</span><StatusBadge :status="site.status" /></div>
      <h3>{{ site.name }}</h3><span class="site-url">{{ site.url }} <ExternalLink :size="13" /></span>
      <dl><div><dt><Server :size="14" /> SSH-server</dt><dd>{{ site.sshUsername }}@{{ site.sshHost }}:{{ site.sshPort }}</dd></div><div><dt>WordPress</dt><dd>{{ site.wordpressVersion ?? 'Nog niet gedetecteerd' }}</dd></div><div><dt>Laatste scan</dt><dd>{{ formatDate(site.lastScanAt) }}</dd></div></dl>
      <div class="site-card-actions"><RouterLink class="button secondary grow" :to="`/websites/${site.id}`">Openen</RouterLink><RouterLink class="button ghost" :to="`/websites/${site.id}/bewerken`">Bewerken</RouterLink><button class="button danger-text" @click="removing = site.id">Verwijderen</button></div>
    </article>
  </div>
  <div v-else class="empty-state card"><Server :size="42" /><h3>Geen websites gevonden</h3><p>Pas de zoekopdracht aan of voeg een nieuwe website toe.</p></div>
  <ConfirmDialog v-if="removing" title="Website verwijderen?" confirm-label="Verwijderen" :busy="busy" @cancel="removing = undefined" @confirm="confirmRemove"><p>De lokale configuratie en historie van deze website worden verwijderd. De website zelf wordt niet gewijzigd.</p></ConfirmDialog>
</template>
