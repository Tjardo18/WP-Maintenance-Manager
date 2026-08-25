<script setup lang="ts">
import { onMounted, ref } from "vue";
import { CalendarDays, ChevronDown, History } from "@lucide/vue";
import StatusBadge from "../components/StatusBadge.vue";
import { appApi } from "../services/tauri";
import type { MaintenanceRun } from "../types";
import { formatDate, formatDuration } from "../utils/format";

const runs = ref<MaintenanceRun[]>([]); const expanded = ref<string>();
onMounted(async () => { runs.value = await appApi.listHistory(); });
</script>
<template>
  <section class="page-heading"><div><h2>Onderhoudshistorie</h2><p>Bekijk uitgevoerde stappen, backups en versieverschillen.</p></div></section>
  <section class="card table-card"><div class="card-header"><div><h3>Alle onderhoudsbeurten</h3><p>Lokale registratie, nieuwste eerst.</p></div><button class="button secondary"><CalendarDays :size="16" /> Periode kiezen</button></div>
    <div v-if="!runs.length" class="empty-state"><History :size="40" /><h3>Nog geen onderhoud uitgevoerd</h3><p>Voltooide en mislukte onderhoudsruns verschijnen hier.</p></div>
    <div v-else class="history-list"><article v-for="run in runs" :key="run.id" class="history-row"><button class="history-summary" @click="expanded = expanded === run.id ? undefined : run.id"><span><strong>{{ run.siteName ?? run.siteId }}</strong><small>{{ formatDate(run.startedAt) }}</small></span><StatusBadge :status="run.status" /><span><small>Duur</small><strong>{{ formatDuration(run.durationMs) }}</strong></span><ChevronDown :class="{ rotated: expanded === run.id }" /></button><div v-if="expanded === run.id" class="history-detail"><div class="version-compare"><div><small>Voor onderhoud</small><strong>{{ run.beforeVersions ?? 'Niet beschikbaar' }}</strong></div><span>→</span><div><small>Na onderhoud</small><strong>{{ run.afterVersions ?? 'Niet beschikbaar' }}</strong></div></div><ol class="step-list"><li v-for="step in run.steps" :key="step.key" :class="step.status"><span></span><strong>{{ step.label }}</strong><small>{{ step.detail }}</small></li></ol><p v-if="run.backupPath" class="backup-note">Databasebackup geregistreerd: <code>{{ run.backupPath }}</code></p></div></article></div>
  </section>
</template>
