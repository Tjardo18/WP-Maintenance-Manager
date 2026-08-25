<script setup lang="ts">
import { ref } from "vue";
import { DatabaseBackup, Gauge, Info, LockKeyhole, Save } from "@lucide/vue";
const concurrency = ref(4); const timeout = ref(30); const saved = ref(false);
function save() { saved.value = true; setTimeout(() => saved.value = false, 2000); }
</script>
<template>
  <section class="page-heading"><div><h2>Instellingen</h2><p>Veilige grenzen voor verbindingen, scans en lokale backups.</p></div></section>
  <div class="settings-grid"><section class="card form-card"><div class="section-heading"><span class="section-icon"><Gauge /></span><div><h3>Verbindingen</h3><p>Voorkom dat de computer of hostingservers overbelast raken.</p></div></div><div class="form-grid"><label><span>Gelijktijdige scans</span><input v-model.number="concurrency" type="number" min="1" max="5" /><small>Maximaal 5 gelijktijdige SSH-verbindingen.</small></label><label><span>Commandotime-out</span><div class="input-suffix"><input v-model.number="timeout" type="number" min="5" max="300" /><span>seconden</span></div></label></div></section>
    <section class="card form-card"><div class="section-heading"><span class="section-icon"><DatabaseBackup /></span><div><h3>Lokale backups</h3><p>Databasebackups staan buiten de website en worden lokaal gecomprimeerd.</p></div></div><div class="notice"><Info :size="18" /><p>De backuplocatie wordt beheerd in de applicatiedatamap. Runtimebackups en databases worden nooit door Git gevolgd.</p></div></section>
    <section class="card form-card"><div class="section-heading"><span class="section-icon"><LockKeyhole /></span><div><h3>Credentials</h3><p>Wachtwoorden en passphrases staan in de beveiligde opslag van het besturingssysteem.</p></div></div><div class="notice safe"><LockKeyhole :size="18" /><p>De SQLite-database bevat uitsluitend onleesbare verwijzingen. Geheime waarden worden nooit teruggestuurd naar de interface.</p></div></section></div>
  <div class="form-actions"><span v-if="saved" class="saved-copy">Instellingen opgeslagen</span><button class="button primary" @click="save"><Save :size="17" /> Opslaan</button></div>
</template>
