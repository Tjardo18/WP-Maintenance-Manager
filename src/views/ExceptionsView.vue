<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { CheckCircle2, CircleAlert, FileQuestion, LoaderCircle, RotateCcw, ShieldCheck, Trash2 } from "@lucide/vue";
import { appApi } from "../services/tauri";
import type { FindingException, TrustedFile } from "../types";
import { errorMessage } from "../utils/errors";
import { formatDate } from "../utils/format";
import ConfirmDialog from "../components/ConfirmDialog.vue";

const tab = ref<"ignored" | "trusted" | "expired">("ignored");
const exceptions = ref<FindingException[]>([]);
const trustedFiles = ref<TrustedFile[]>([]);
const loading = ref(true);
const busy = ref<string>();
const error = ref<string>();
const now = ref(Date.now());
const selectedExceptionIds = ref<string[]>([]);
const selectedTrustedIds = ref<string[]>([]);
const pendingAction = ref<
  { kind: "unignore" | "cleanup"; items: FindingException[] }
  | { kind: "revoke"; items: TrustedFile[] }
>();
let expiryTimer: number | undefined;

const ignored = computed(() => exceptions.value.filter((item) => item.active && (!item.expiresAt || Date.parse(item.expiresAt) > now.value)));
const expired = computed(() => exceptions.value.filter((item) => item.active && item.expiresAt && Date.parse(item.expiresAt) <= now.value));
const trusted = computed(() => trustedFiles.value.filter((item) => item.active));
const visibleExceptions = computed(() => tab.value === "expired" ? expired.value : ignored.value);
const selectedExceptions = computed(() => visibleExceptions.value.filter((item) => selectedExceptionIds.value.includes(item.id)));
const selectedTrusted = computed(() => trusted.value.filter((item) => selectedTrustedIds.value.includes(item.id)));
const allVisibleExceptionsSelected = computed(() => Boolean(visibleExceptions.value.length) && visibleExceptions.value.every((item) => selectedExceptionIds.value.includes(item.id)));
const allTrustedSelected = computed(() => Boolean(trusted.value.length) && trusted.value.every((item) => selectedTrustedIds.value.includes(item.id)));

async function load() {
  loading.value = true; error.value = undefined;
  try { [exceptions.value, trustedFiles.value] = await Promise.all([appApi.listFindingExceptions(), appApi.listTrustedFiles()]); }
  catch (cause) { error.value = errorMessage(cause); }
  finally { loading.value = false; }
}

function toggleException(id: string) {
  selectedExceptionIds.value = selectedExceptionIds.value.includes(id) ? selectedExceptionIds.value.filter((current) => current !== id) : [...selectedExceptionIds.value, id];
}

function toggleAllExceptions() {
  selectedExceptionIds.value = allVisibleExceptionsSelected.value ? [] : visibleExceptions.value.map((item) => item.id);
}

function toggleTrusted(id: string) {
  selectedTrustedIds.value = selectedTrustedIds.value.includes(id) ? selectedTrustedIds.value.filter((current) => current !== id) : [...selectedTrustedIds.value, id];
}

function toggleAllTrusted() {
  selectedTrustedIds.value = allTrustedSelected.value ? [] : trusted.value.map((item) => item.id);
}

async function executePendingAction() {
  const action = pendingAction.value;
  if (!action?.items.length) return;
  busy.value = "policy-action"; error.value = undefined;
  try {
    const ids = action.items.map((item) => item.id);
    if (action.kind === "unignore") await appApi.removeFindingExceptions(ids);
    else if (action.kind === "cleanup") await appApi.cleanupExpiredFindingExceptions(ids);
    else await appApi.revokeTrustedFiles(ids);
    pendingAction.value = undefined;
    selectedExceptionIds.value = [];
    selectedTrustedIds.value = [];
    await load();
  } catch (cause) { error.value = errorMessage(cause); }
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

function pendingTitle() {
  const action = pendingAction.value;
  if (!action) return "Actie bevestigen";
  if (action.kind === "unignore") return action.items.length === 1 ? "Melding niet meer negeren?" : `${action.items.length} meldingen niet meer negeren?`;
  if (action.kind === "cleanup") return action.items.length === 1 ? "Verlopen uitzondering opruimen?" : `${action.items.length} verlopen uitzonderingen opruimen?`;
  return action.items.length === 1 ? "Vertrouwen intrekken?" : `Vertrouwen voor ${action.items.length} bestanden intrekken?`;
}

function pendingConfirmLabel() {
  if (pendingAction.value?.kind === "cleanup") return "Opruimen";
  if (pendingAction.value?.kind === "revoke") return "Vertrouwen intrekken";
  return "Niet meer negeren";
}

watch(tab, () => { selectedExceptionIds.value = []; selectedTrustedIds.value = []; });
onMounted(() => {
  void load();
  expiryTimer = globalThis.setInterval(() => { now.value = Date.now(); }, 30_000);
});
onUnmounted(() => { if (expiryTimer !== undefined) globalThis.clearInterval(expiryTimer); });
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
        <template v-else>
          <div class="table-selection-toolbar"><label class="table-selection-toggle"><input type="checkbox" :checked="allVisibleExceptionsSelected" :disabled="!!busy" aria-label="Alle zichtbare uitzonderingen selecteren" @change="toggleAllExceptions" /><span>{{ selectedExceptionIds.length ? `${selectedExceptionIds.length} geselecteerd` : (tab === 'expired' ? 'Selecteer verlopen uitzonderingen om op te ruimen' : 'Selecteer meldingen voor een bulkactie') }}</span></label><button class="button small danger-text" :disabled="!!busy || !selectedExceptions.length" @click="pendingAction = { kind: tab === 'expired' ? 'cleanup' : 'unignore', items: selectedExceptions }"><Trash2 :size="14" /> {{ tab === 'expired' ? 'Geselecteerde opruimen' : 'Geselecteerde niet meer negeren' }}</button></div>
          <div class="table-scroll"><table><thead><tr><th class="table-select-cell"><span class="sr-only">Selecteren</span></th><th>Website</th><th>Controle / melding</th><th>Target</th><th>Aangemaakt</th><th>Verloopt</th><th>Notitie</th><th></th></tr></thead><tbody><tr v-for="item in visibleExceptions" :key="item.id"><td class="table-select-cell"><input type="checkbox" :checked="selectedExceptionIds.includes(item.id)" :aria-label="`${item.target} selecteren`" @change="toggleException(item.id)" /></td><td><strong>{{ item.siteName }}</strong></td><td><strong>{{ item.checkType }}</strong><small>{{ item.findingType }}</small></td><td><code>{{ item.target }}</code></td><td>{{ formatDate(item.createdAt) }}</td><td>{{ item.expiresAt ? formatDate(item.expiresAt) : 'Nooit' }}</td><td>{{ item.note || '—' }}</td><td><button class="button small danger-text" :disabled="!!busy" @click="pendingAction = { kind: tab === 'expired' ? 'cleanup' : 'unignore', items: [item] }"><Trash2 :size="14" /> {{ tab === 'expired' ? 'Opruimen' : 'Niet meer negeren' }}</button></td></tr></tbody></table></div>
        </template>
      </template>
      <template v-else>
        <div v-if="!trusted.length" class="empty-state compact"><ShieldCheck :size="34" /><h3>Geen vertrouwde bestanden</h3><p>Vertrouw een bestaand bestand vanuit een actuele securitymelding.</p></div>
        <template v-else>
          <div class="table-selection-toolbar"><label class="table-selection-toggle"><input type="checkbox" :checked="allTrustedSelected" :disabled="!!busy" aria-label="Alle vertrouwde bestanden selecteren" @change="toggleAllTrusted" /><span>{{ selectedTrustedIds.length ? `${selectedTrustedIds.length} geselecteerd` : 'Selecteer bestanden om het vertrouwen in bulk in te trekken' }}</span></label><button class="button small danger-text" :disabled="!!busy || !selectedTrusted.length" @click="pendingAction = { kind: 'revoke', items: selectedTrusted }"><Trash2 :size="14" /> Geselecteerd vertrouwen intrekken</button></div>
          <div class="table-scroll"><table><thead><tr><th class="table-select-cell"><span class="sr-only">Selecteren</span></th><th>Website</th><th>Bestand</th><th>Hashstatus</th><th>Vertrouwd op</th><th>Laatste controle</th><th>Notitie</th><th></th></tr></thead><tbody><tr v-for="item in trusted" :key="item.id"><td class="table-select-cell"><input type="checkbox" :checked="selectedTrustedIds.includes(item.id)" :aria-label="`${item.relativePath} selecteren`" @change="toggleTrusted(item.id)" /></td><td><strong>{{ item.siteName }}</strong></td><td><code>{{ item.relativePath }}</code><small>SHA-256 {{ item.trustedSha256.slice(0, 12) }}…</small></td><td><span :class="['trust-status', item.status]"><CheckCircle2 v-if="item.status === 'trusted'" :size="14" /><CircleAlert v-else-if="item.status === 'changed'" :size="14" /><FileQuestion v-else :size="14" /> {{ trustStatus(item) }}</span></td><td>{{ formatDate(item.trustedAt) }}</td><td>{{ formatDate(item.lastCheckedAt) }}</td><td>{{ item.note || '—' }}</td><td><div class="row-actions"><button v-if="item.status === 'changed'" class="button small secondary" :disabled="!!busy" @click="retrust(item)"><RotateCcw :size="14" /> Nieuwe versie vertrouwen</button><button class="button small danger-text" :disabled="!!busy" @click="pendingAction = { kind: 'revoke', items: [item] }"><Trash2 :size="14" /> Vertrouwen intrekken</button></div></td></tr></tbody></table></div>
        </template>
      </template>
    </section>

    <ConfirmDialog v-if="pendingAction" :title="pendingTitle()" :confirm-label="pendingConfirmLabel()" :busy="busy === 'policy-action'" danger @cancel="pendingAction = undefined" @confirm="executePendingAction">
      <p v-if="pendingAction.kind === 'unignore'">De geselecteerde meldingen worden direct weer normaal meegenomen in de actuele securitystatus.</p>
      <p v-else-if="pendingAction.kind === 'cleanup'">De verlopen registraties worden alleen uit deze beheerlijst verwijderd. De betreffende meldingen zijn al actief en worden niet opnieuw genegeerd.</p>
      <p v-else>De geselecteerde bestanden worden niet langer op basis van hun opgeslagen SHA-256-fingerprint vertrouwd.</p>
    </ConfirmDialog>
  </div>
</template>
