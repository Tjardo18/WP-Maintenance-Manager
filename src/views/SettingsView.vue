<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from "vue";
import { DatabaseBackup, Gauge, Info, KeyRound, LoaderCircle, LockKeyhole, Maximize2, PlugZap, RefreshCw, Save, ShieldCheck, Trash2 } from "@lucide/vue";
import { appApi } from "../services/tauri";
import type { FilePreviewMode, MarkdownPreviewMode, VulnerabilityRefreshJobState, WordfenceIntegrationStatus } from "../types";
import { errorMessage } from "../utils/errors";
import { formatDate } from "../utils/format";
import { useAuthStore } from "../stores/auth";
import DatabaseCleanup from "../components/DatabaseCleanup.vue";

const auth = useAuthStore();
const concurrency = ref(4);
const filePreviewMode = ref<FilePreviewMode>("normal");
const markdownPreviewMode = ref<MarkdownPreviewMode>("raw");
const idleMinutes = ref(15);
const saved = ref(false);
const saving = ref(false);
const passwordBusy = ref(false);
const integrationBusy = ref<"save" | "remove" | "test" | "refresh">();
const currentPassword = ref("");
const newPassword = ref("");
const repeatedPassword = ref("");
const wordfenceApiKey = ref("");
const wordfence = ref<WordfenceIntegrationStatus>();
const refreshJob = ref<VulnerabilityRefreshJobState>();
const integrationMessage = ref<string>();
const error = ref<string>();

const wordfenceStatusLabel = computed(() => wordfence.value?.connectionStatus === "connected" ? "Verbonden" : wordfence.value?.configured ? "Ingesteld" : "Niet geconfigureerd");
const feedStatusLabel = computed(() => ({ missing: "Niet gedownload", current: "Actueel", stale: "Vernieuwing gewenst", refreshing: "Wordt bijgewerkt…", failed: "Vernieuwen mislukt" })[wordfence.value?.feedStatus ?? "missing"]);
const refreshPhaseLabel = computed(() => ({ download: "Downloaden", validate: "Controleren", process: "Verwerken", database: "Lokale websites herberekenen", complete: "Klaar" })[refreshJob.value?.phase ?? wordfence.value?.refreshPhase ?? "download"]);
let unlistenRefresh: (() => void) | undefined;

onMounted(async () => {
  idleMinutes.value = auth.idleTimeoutMinutes;
  try {
    const [settings, status, job] = await Promise.all([appApi.getSettings(), appApi.getWordfenceStatus(), appApi.getWordfenceFeedRefreshJob()]);
    concurrency.value = settings.scanConcurrency;
    filePreviewMode.value = settings.filePreviewMode;
    markdownPreviewMode.value = settings.markdownPreviewMode;
    wordfence.value = status;
    refreshJob.value = job;
    unlistenRefresh = await appApi.onWordfenceFeedRefreshUpdated(async (updated) => { refreshJob.value = updated; if (["completed", "failed"].includes(updated.status)) { integrationBusy.value = undefined; wordfence.value = await appApi.getWordfenceStatus(); } });
  } catch (cause) { error.value = errorMessage(cause); }
});
onBeforeUnmount(() => unlistenRefresh?.());

async function save() { saving.value = true; error.value = undefined; try { const settings = await appApi.saveSettings({ scanConcurrency: concurrency.value, filePreviewMode: filePreviewMode.value, markdownPreviewMode: markdownPreviewMode.value }); await auth.updateIdleTimeout(idleMinutes.value); concurrency.value = settings.scanConcurrency; filePreviewMode.value = settings.filePreviewMode; markdownPreviewMode.value = settings.markdownPreviewMode; saved.value = true; setTimeout(() => saved.value = false, 2000); } catch (cause) { error.value = errorMessage(cause); } finally { saving.value = false; } }
async function changePassword() { if (newPassword.value !== repeatedPassword.value || newPassword.value.length < 12) return; passwordBusy.value = true; error.value = undefined; try { await auth.changePassword(currentPassword.value, newPassword.value); } catch (cause) { error.value = errorMessage(cause); } finally { passwordBusy.value = false; } }
async function saveWordfenceKey() { integrationBusy.value = "save"; error.value = undefined; integrationMessage.value = undefined; try { wordfence.value = await appApi.saveWordfenceApiKey(wordfenceApiKey.value); wordfenceApiKey.value = ""; integrationMessage.value = "API-sleutel veilig opgeslagen. Test nu de verbinding."; } catch (cause) { error.value = errorMessage(cause); } finally { integrationBusy.value = undefined; } }
async function removeWordfenceKey() { integrationBusy.value = "remove"; error.value = undefined; integrationMessage.value = undefined; try { wordfence.value = await appApi.removeWordfenceApiKey(); wordfenceApiKey.value = ""; integrationMessage.value = "API-sleutel verwijderd. Een bestaande lokale database blijft behouden."; } catch (cause) { error.value = errorMessage(cause); } finally { integrationBusy.value = undefined; } }
async function testWordfenceConnection() { integrationBusy.value = "test"; error.value = undefined; integrationMessage.value = undefined; try { wordfence.value = await appApi.testWordfenceConnection(); integrationMessage.value = "Verbinding geslaagd. Wordfence Intelligence is bereikbaar en de API-sleutel is geldig."; } catch (cause) { error.value = errorMessage(cause); } finally { integrationBusy.value = undefined; } }
async function refreshWordfenceFeed() { integrationBusy.value = "refresh"; error.value = undefined; integrationMessage.value = undefined; try { refreshJob.value = await appApi.startWordfenceFeedRefresh(); wordfence.value = { ...wordfence.value!, refreshRunning: true, feedStatus: "refreshing" }; } catch (cause) { error.value = errorMessage(cause); integrationBusy.value = undefined; } }
</script>

<template>
  <section class="page-heading"><div><h2>Instellingen</h2><p>Veilige grenzen voor verbindingen, scans, integraties en lokale backups.</p></div></section>
  <div class="settings-grid">
    <section class="card form-card integration-card">
      <div class="section-heading"><span class="section-icon"><KeyRound /></span><div><small class="section-kicker">Integraties</small><h3>Wordfence Intelligence</h3><p>Controleer WordPress Core, plugins en thema's lokaal op bekende kwetsbaarheden.</p></div><span :class="['integration-status', { configured: wordfence?.configured }]">● {{ wordfenceStatusLabel }}</span></div>
      <div class="integration-body">
        <label><span>API-sleutel</span><input v-model="wordfenceApiKey" type="password" autocomplete="new-password" :placeholder="wordfence?.configured ? 'Nieuwe API-sleutel invoeren' : 'Plak hier je Wordfence API-sleutel'" maxlength="512" /><small>De sleutel gaat rechtstreeks naar de beveiligde opslag van Windows en wordt niet in SQLite of de interface bewaard.</small></label>
        <div class="integration-actions"><button class="button primary" :disabled="integrationBusy !== undefined || !wordfenceApiKey.trim()" @click="saveWordfenceKey"><Save :size="16" /> {{ integrationBusy === 'save' ? 'Opslaan…' : wordfence?.configured ? 'API-sleutel vervangen' : 'Opslaan' }}</button><button v-if="wordfence?.configured" class="button secondary" :disabled="integrationBusy !== undefined" @click="testWordfenceConnection"><PlugZap :size="16" /> {{ integrationBusy === 'test' ? 'Testen…' : 'Verbinding testen' }}</button><button v-if="wordfence?.configured" class="button danger-text" :disabled="integrationBusy !== undefined" @click="removeWordfenceKey"><Trash2 :size="16" /> {{ integrationBusy === 'remove' ? 'Verwijderen…' : 'API-sleutel verwijderen' }}</button></div>
        <p v-if="integrationMessage" class="saved-copy integration-message">{{ integrationMessage }}</p>
        <div class="feed-status-panel">
          <div><small>Vulnerability database</small><strong>{{ feedStatusLabel }}</strong></div><div><small>Laatste update</small><strong>{{ formatDate(wordfence?.lastSuccessfulUpdateAt) }}</strong></div><div><small>Volgende automatische update</small><strong>{{ formatDate(wordfence?.nextAutomaticUpdateAt) }}</strong></div><div><small>Vulnerabilities</small><strong>{{ wordfence?.vulnerabilityCount.toLocaleString('nl-NL') ?? 0 }}</strong></div>
        </div>
        <div v-if="wordfence?.refreshRunning || ['queued', 'running'].includes(refreshJob?.status ?? '')" class="feed-progress"><LoaderCircle class="spin" :size="17" /><span><strong>Wordfence database bijwerken…</strong><small>{{ refreshPhaseLabel }}<template v-if="refreshJob?.downloadedBytes"> · {{ (refreshJob.downloadedBytes / 1024 / 1024).toFixed(1) }} MB</template></small></span></div>
        <p v-if="wordfence?.lastError" class="inline-warning">{{ wordfence.lastError }} De vorige lokale database blijft beschikbaar.</p>
        <div class="integration-actions"><button class="button secondary" :disabled="!wordfence?.configured || wordfence.refreshRunning || integrationBusy !== undefined || Boolean(wordfence.cooldownRemainingSeconds)" @click="refreshWordfenceFeed"><RefreshCw :size="16" :class="{ spin: wordfence?.refreshRunning }" /> Database nu vernieuwen</button><small v-if="wordfence?.cooldownRemainingSeconds">Opnieuw vernieuwen mogelijk over {{ Math.ceil(wordfence.cooldownRemainingSeconds / 60) }} minuten.</small></div>
      </div>
    </section>
    <section class="card form-card"><div class="section-heading"><span class="section-icon"><Gauge /></span><div><h3>Verbindingen</h3><p>Voorkom dat de computer of hostingservers overbelast raken.</p></div></div><div class="form-grid"><label><span>Gelijktijdige scans</span><input v-model.number="concurrency" type="number" min="1" max="5" /><small>Rust dwingt altijd een maximum van 5 SSH-verbindingen af.</small></label><div class="notice"><Info :size="18" /><p>Iedere catalogusactie gebruikt een eigen veilige time-out op basis van het type controle of update.</p></div></div></section>
    <section class="card form-card"><div class="section-heading"><span class="section-icon"><Maximize2 /></span><div><h3>Bestandenpreview</h3><p>Kies hoe codebestanden en Markdown standaard worden geopend.</p></div></div><div class="form-grid"><label><span>Standaardweergave</span><select v-model="filePreviewMode"><option value="normal">Normaal</option><option value="fullscreen">Altijd fullscreen</option></select><small>Je kunt de weergave in iedere preview alsnog wisselen met de knop rechtsboven.</small></label><label><span>Markdown standaard openen</span><select v-model="markdownPreviewMode"><option value="raw">Altijd Raw openen</option><option value="preview">Altijd Preview openen</option></select><small>Deze keuze geldt alleen voor .md-bestanden en kan tijdens het bekijken worden gewijzigd.</small></label><div class="notice span-2"><Info :size="18" /><p>De keuzes worden lokaal bewaard en blijven na het opnieuw starten van de app behouden.</p></div></div></section>
    <section class="card form-card"><div class="section-heading"><span class="section-icon"><DatabaseBackup /></span><div><h3>Lokale backups</h3><p>Databasebackups staan buiten de website en worden lokaal als <code>.sql.gz</code> opgeslagen.</p></div></div><div class="form-grid"><div class="notice span-2"><Info :size="18" /><p>Windows-locatie: <code>%APPDATA%\nl.wpmaintenancemanager.desktop\backups\&lt;site-id&gt;\</code>. Het volledige pad van een gemaakte backup staat in de onderhoudshistorie; het bestand is dan al op deze computer opgeslagen.</p></div><div class="notice span-2"><Info :size="18" /><p>Backups worden niet automatisch verwijderd. De app heeft momenteel geen download-, openen- of herstelfunctie; herstel gebeurt handmatig met bijvoorbeeld WP-CLI, phpMyAdmin of hostinggereedschap.</p></div></div></section>
    <section class="card form-card"><div class="section-heading"><span class="section-icon"><LockKeyhole /></span><div><h3>Credentials</h3><p>Wachtwoorden, passphrases en API-sleutels staan in de beveiligde opslag van het besturingssysteem.</p></div></div><div class="notice safe"><LockKeyhole :size="18" /><p>De SQLite-database bevat geen geheime waarden. Credentials worden nooit teruggestuurd naar de interface.</p></div></section>
    <section class="card form-card"><div class="section-heading"><span class="section-icon"><ShieldCheck /></span><div><h3>Beveiliging</h3><p>De backend blokkeert sitegegevens en beheeracties zonder geldige sessie.</p></div></div><div class="form-grid"><label><span>Automatisch vergrendelen na</span><select v-model.number="idleMinutes"><option :value="5">5 minuten</option><option :value="10">10 minuten</option><option :value="15">15 minuten</option><option :value="30">30 minuten</option><option :value="60">1 uur</option></select></label><div class="notice"><Info :size="18" /><p>Na volledig afsluiten of herstarten moet je altijd opnieuw inloggen. Actieve muterende backendacties mogen bij vergrendeling veilig afronden.</p></div></div><form class="password-change" @submit.prevent="changePassword"><h4>Wachtwoord wijzigen</h4><div class="form-grid three"><label><span>Huidig wachtwoord</span><input v-model="currentPassword" type="password" autocomplete="current-password" required /></label><label><span>Nieuw wachtwoord</span><input v-model="newPassword" type="password" autocomplete="new-password" minlength="12" required /></label><label><span>Herhaal nieuw wachtwoord</span><input v-model="repeatedPassword" type="password" autocomplete="new-password" minlength="12" required /></label></div><p v-if="repeatedPassword && newPassword !== repeatedPassword" class="field-error">De nieuwe wachtwoorden zijn niet gelijk.</p><button class="button secondary" type="submit" :disabled="passwordBusy || newPassword.length < 12 || newPassword !== repeatedPassword">{{ passwordBusy ? 'Wijzigen…' : 'Wachtwoord wijzigen' }}</button></form><div class="security-lock-row"><p>Vergrendel direct en wis gevoelige UI-state.</p><button class="button danger-text" @click="auth.lock"><LockKeyhole :size="16" /> Nu vergrendelen</button></div></section>
    <DatabaseCleanup />
  </div>
  <p v-if="error" class="error-banner">{{ error }}</p>
  <div class="form-actions settings-save-actions"><span v-if="saved" class="saved-copy">Instellingen opgeslagen</span><button class="button primary" :disabled="saving || concurrency < 1 || concurrency > 5" @click="save"><Save :size="17" /> {{ saving ? 'Opslaan…' : 'Algemene instellingen opslaan' }}</button></div>
</template>

<style scoped>
.settings-save-actions { margin-top: 18px; }
</style>
