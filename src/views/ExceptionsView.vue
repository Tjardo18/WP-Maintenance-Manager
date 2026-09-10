<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { CheckCircle2, CircleAlert, FileQuestion, LoaderCircle, RotateCcw, ShieldCheck, Trash2 } from "@lucide/vue";
import { appApi } from "../services/tauri";
import type { FindingException, TrustedFile } from "../types";
import { errorMessage } from "../utils/errors";
import { formatDate } from "../utils/format";

const tab = ref<"ignored" | "trusted" | "expired">("ignored");
const exceptions = ref<FindingException[]>([]);
const trustedFiles = ref<TrustedFile[]>([]);
const loading = ref(true);
const busy = ref<string>();
const error = ref<string>();
const now = ref(Date.now());

const ignored = computed(() => exceptions.value.filter((item) => item.active && (!item.expiresAt || Date.parse(item.expiresAt) > now.value)));
const expired = computed(() => exceptions.value.filter((item) => item.active && item.expiresAt && Date.parse(item.expiresAt) <= now.value));
const trusted = computed(() => trustedFiles.value.filter((item) => item.active));

async function load() {
  loading.value = true; error.value = undefined;
  try { [exceptions.value, trustedFiles.value] = await Promise.all([appApi.listFindingExceptions(), appApi.listTrustedFiles()]); }
  catch (cause) { error.value = errorMessage(cause); }
  finally { loading.value = false; }
}

async function removeException(item: FindingException) {
  busy.value = item.id; error.value = undefined;
  try { await appApi.removeFindingException(item.id); item.active = false; }
  catch (cause) { error.value = errorMessage(cause); }
  finally { busy.value = undefined; }
}

async function revoke(item: TrustedFile) {
  busy.value = item.id; error.value = undefined;
  try { await appApi.revokeTrustedFile(item.id); item.active = false; }
  catch (cause) { error.value = errorMessage(cause); }
  finally { busy.value = undefined; }
}

async function retrust(item: TrustedFile) {
  busy.value = item.id; error.value = undefined;
  try { const result = await appApi.retrustFile(item.id); if (result.trustedFile) trustedFiles.value = trustedFiles.value.map((current) => current.id === item.id ? result.trustedFile! : current); }
  catch (cause) { error.value = errorMessage(cause); }
  finally { busy.value = undefined; }
}

function trustStatus(item: TrustedFile) {
  if (item.status === "trusted") return "Ongewijzigd";
  if (item.status === "changed") return "Gewijzigd";
  if (item.status === "missing") return "Niet meer aanwezig";
  return "Niet gecontroleerd";
}

onMounted(load);
</script>

<template>
  <div class="exceptions-page">
    <section class="page-intro"><div><h2>Uitzonderingen</h2><p>Beheer site-specifieke genegeerde meldingen en bestanden die op basis van hun SHA-256-fingerprint worden vertrouwd.</p></div></section>
    <p v-if="error" class="error-banner">{{ error }}</p>
    <nav class="tabs exception-tabs" aria-label="Soort uitzondering">
      <button :class="{ active: tab === 'ignored' }" @click="tab = 'ignored'">Genegeerde meldingen <span>{{ ignored.length }}</span></button>
      <button :class="{ active: tab === 'trusted' }" @click="tab = 'trusted'">Vertrouwde bestanden <span>{{ trusted.length }}</span></button>
      <button :class="{ active: tab === 'expired' }" @click="tab = 'expired'">Verlopen <span>{{ expired.length }}</span></button>
    </nav>
    <section class="card table-card">
      <div v-if="loading" class="empty-state compact"><LoaderCircle class="spin" :size="32" /><h3>Uitzonderingen laden…</h3></div>
      <template v-else-if="tab === 'ignored' || tab === 'expired'">
        <div v-if="!(tab === 'ignored' ? ignored : expired).length" class="empty-state compact"><CheckCircle2 :size="34" /><h3>{{ tab === 'expired' ? 'Geen verlopen uitzonderingen' : 'Geen genegeerde meldingen' }}</h3><p>Uitzonderingen die je vanuit een actuele securitymelding toevoegt, verschijnen hier.</p></div>
        <div v-else class="table-scroll"><table><thead><tr><th>Website</th><th>Controle / melding</th><th>Target</th><th>Aangemaakt</th><th>Verloopt</th><th>Notitie</th><th></th></tr></thead><tbody><tr v-for="item in (tab === 'ignored' ? ignored : expired)" :key="item.id"><td><strong>{{ item.siteName }}</strong></td><td><strong>{{ item.checkType }}</strong><small>{{ item.findingType }}</small></td><td><code>{{ item.target }}</code></td><td>{{ formatDate(item.createdAt) }}</td><td>{{ item.expiresAt ? formatDate(item.expiresAt) : 'Nooit' }}</td><td>{{ item.note || '—' }}</td><td><button class="button small danger-text" :disabled="!!busy" @click="removeException(item)"><LoaderCircle v-if="busy === item.id" class="spin" :size="14" /><Trash2 v-else :size="14" /> Niet meer negeren</button></td></tr></tbody></table></div>
      </template>
      <template v-else>
        <div v-if="!trusted.length" class="empty-state compact"><ShieldCheck :size="34" /><h3>Geen vertrouwde bestanden</h3><p>Vertrouw een bestaand bestand vanuit een actuele securitymelding.</p></div>
        <div v-else class="table-scroll"><table><thead><tr><th>Website</th><th>Bestand</th><th>Hashstatus</th><th>Vertrouwd op</th><th>Laatste controle</th><th>Notitie</th><th></th></tr></thead><tbody><tr v-for="item in trusted" :key="item.id"><td><strong>{{ item.siteName }}</strong></td><td><code>{{ item.relativePath }}</code><small>SHA-256 {{ item.trustedSha256.slice(0, 12) }}…</small></td><td><span :class="['trust-status', item.status]"><CheckCircle2 v-if="item.status === 'trusted'" :size="14" /><CircleAlert v-else-if="item.status === 'changed'" :size="14" /><FileQuestion v-else :size="14" /> {{ trustStatus(item) }}</span></td><td>{{ formatDate(item.trustedAt) }}</td><td>{{ formatDate(item.lastCheckedAt) }}</td><td>{{ item.note || '—' }}</td><td><div class="row-actions"><button v-if="item.status === 'changed'" class="button small secondary" :disabled="!!busy" @click="retrust(item)"><RotateCcw :size="14" /> Nieuwe versie vertrouwen</button><button class="button small danger-text" :disabled="!!busy" @click="revoke(item)"><LoaderCircle v-if="busy === item.id" class="spin" :size="14" /><Trash2 v-else :size="14" /> Vertrouwen intrekken</button></div></td></tr></tbody></table></div>
      </template>
    </section>
  </div>
</template>
