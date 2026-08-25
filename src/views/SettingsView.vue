<script setup lang="ts">
import { onMounted, ref } from "vue";
import { DatabaseBackup, Gauge, Info, LockKeyhole, Save } from "@lucide/vue";
import { appApi } from "../services/tauri";
import { errorMessage } from "../utils/errors";

const concurrency = ref(4);
const saved = ref(false);
const saving = ref(false);
const error = ref<string>();

onMounted(async () => { try { const settings = await appApi.getSettings(); concurrency.value = settings.scanConcurrency; } catch (cause) { error.value = errorMessage(cause); } });
async function save() { saving.value = true; error.value = undefined; try { const settings = await appApi.saveSettings({ scanConcurrency: concurrency.value }); concurrency.value = settings.scanConcurrency; saved.value = true; setTimeout(() => saved.value = false, 2000); } catch (cause) { error.value = errorMessage(cause); } finally { saving.value = false; } }
</script>
<template>
  <section class="page-heading"><div><h2>Instellingen</h2><p>Veilige grenzen voor verbindingen, scans en lokale backups.</p></div></section>
  <div class="settings-grid">
    <section class="card form-card"><div class="section-heading"><span class="section-icon"><Gauge /></span><div><h3>Verbindingen</h3><p>Voorkom dat de computer of hostingservers overbelast raken.</p></div></div><div class="form-grid"><label><span>Gelijktijdige scans</span><input v-model.number="concurrency" type="number" min="1" max="5" /><small>Rust dwingt altijd een maximum van 5 SSH-verbindingen af.</small></label><div class="notice"><Info :size="18" /><p>Iedere catalogusactie gebruikt een eigen veilige time-out op basis van het type controle of update.</p></div></div></section>
    <section class="card form-card"><div class="section-heading"><span class="section-icon"><DatabaseBackup /></span><div><h3>Lokale backups</h3><p>Databasebackups staan buiten de website en worden lokaal gecomprimeerd.</p></div></div><div class="notice"><Info :size="18" /><p>De backuplocatie wordt beheerd in de applicatiedatamap. Runtimebackups en databases worden nooit door Git gevolgd.</p></div></section>
    <section class="card form-card"><div class="section-heading"><span class="section-icon"><LockKeyhole /></span><div><h3>Credentials</h3><p>Wachtwoorden en passphrases staan in de beveiligde opslag van het besturingssysteem.</p></div></div><div class="notice safe"><LockKeyhole :size="18" /><p>De SQLite-database bevat uitsluitend onleesbare verwijzingen. Geheime waarden worden nooit teruggestuurd naar de interface.</p></div></section>
  </div>
  <p v-if="error" class="error-banner">{{ error }}</p>
  <div class="form-actions"><span v-if="saved" class="saved-copy">Instellingen opgeslagen</span><button class="button primary" :disabled="saving || concurrency < 1 || concurrency > 5" @click="save"><Save :size="17" /> {{ saving ? 'Opslaan…' : 'Opslaan' }}</button></div>
</template>
