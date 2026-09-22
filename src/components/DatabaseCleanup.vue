<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { AlertTriangle, CheckCircle2, Database, Info, LoaderCircle, ShieldCheck, Trash2, X } from "@lucide/vue";
import { appApi } from "../services/tauri";
import { useSitesStore } from "../stores/sites";
import type { DatabaseCleanupOption, DatabaseCleanupResult } from "../types";
import { errorMessage } from "../utils/errors";
import ConfirmDialog from "./ConfirmDialog.vue";

const sites = useSitesStore();
const options = ref<DatabaseCleanupOption[]>([]);
const loading = ref(true);
const busy = ref(false);
const error = ref<string>();
const pending = ref<DatabaseCleanupOption>();
const infoOption = ref<DatabaseCleanupOption>();
const typedConfirmation = ref("");
const result = ref<DatabaseCleanupResult>();
const resultDetailsOpen = ref(false);

const confirmationValid = computed(() => {
  if (!pending.value) return false;
  return pending.value.confirmationMode === "dialog"
    || typedConfirmation.value === pending.value.confirmationPhrase;
});
const resultPrimaryImpact = computed(() => result.value?.impacts.find((impact) => impact.key === result.value?.tableName));
const visibleResultImpacts = computed(() => result.value?.impacts.filter((impact) => impact.count > 0) ?? []);

function formatCount(value: number) {
  return value.toLocaleString("nl-NL");
}

async function loadOptions() {
  loading.value = true;
  try {
    options.value = await appApi.listDatabaseCleanupOptions();
  } catch (cause) {
    error.value = errorMessage(cause);
  } finally {
    loading.value = false;
  }
}

function beginCleanup(option: DatabaseCleanupOption) {
  infoOption.value = undefined;
  pending.value = option;
  typedConfirmation.value = "";
  error.value = undefined;
}

function openInfo(option: DatabaseCleanupOption) {
  infoOption.value = option;
}

function cancelCleanup() {
  if (busy.value) return;
  pending.value = undefined;
  typedConfirmation.value = "";
  error.value = undefined;
}

async function confirmCleanup() {
  const option = pending.value;
  if (!option || !confirmationValid.value) return;
  busy.value = true;
  error.value = undefined;
  try {
    result.value = await appApi.cleanupDatabase({
      target: option.target,
      confirmation: option.confirmationMode === "typed"
        ? typedConfirmation.value
        : option.confirmationPhrase,
      previewToken: option.previewToken,
    });
    pending.value = undefined;
    resultDetailsOpen.value = false;
    typedConfirmation.value = "";
    await Promise.all([loadOptions(), sites.load()]);
  } catch (cause) {
    const cleanupError = errorMessage(cause);
    error.value = cleanupError;
    try {
      options.value = await appApi.listDatabaseCleanupOptions();
      pending.value = options.value.find((candidate) => candidate.target === option.target);
      typedConfirmation.value = "";
      error.value = cleanupError;
    } catch {
      // Keep the actionable cleanup error visible; the overview can be reloaded by reopening settings.
    }
  } finally {
    busy.value = false;
  }
}

onMounted(loadOptions);
</script>

<template>
  <section class="card form-card database-management-card">
    <header class="database-management-heading">
      <div class="section-heading">
        <span class="section-icon"><Database /></span>
        <div>
          <small class="section-kicker">Lokale opslag</small>
          <h3>Databasebeheer</h3>
          <p>Ruim geselecteerde lokale gegevens gecontroleerd op.</p>
        </div>
      </div>
      <div class="database-safety-summary">
        <ShieldCheck :size="18" />
        <span><strong>Alleen gecontroleerde acties</strong><small>Kritieke appgegevens zijn uitgesloten</small></span>
      </div>
    </header>

    <div v-if="result" :class="['database-cleanup-result', { warning: result.warnings.length }]" role="status">
      <CheckCircle2 v-if="!result.warnings.length" :size="20" />
      <AlertTriangle v-else :size="20" />
      <div>
        <strong>{{ result.warnings.length ? 'Opschonen afgerond met waarschuwingen' : 'Database succesvol opgeschoond' }}</strong>
        <p v-if="resultPrimaryImpact"><strong>{{ formatCount(resultPrimaryImpact.count) }}</strong> records uit <code>{{ result.tableName }}</code> verwijderd.</p>
      </div>
      <button class="button secondary compact" type="button" @click="resultDetailsOpen = true">Bekijk resultaat</button>
    </div>

    <div v-if="loading" class="database-cleanup-loading"><LoaderCircle class="spin" :size="19" /> Databasegegevens laden…</div>
    <div v-else class="database-cleanup-list">
      <article v-for="option in options" :key="option.target" class="database-cleanup-item">
        <header>
          <div class="database-table-identity">
            <span class="database-table-icon"><Database :size="17" /></span>
            <div><h4>{{ option.title }}</h4><code>{{ option.tableName }}</code></div>
          </div>
          <span class="database-record-count"><strong>{{ formatCount(option.recordCount) }}</strong><small>records</small></span>
        </header>
        <p class="database-cleanup-summary">{{ option.description }}</p>
        <div class="database-cleanup-meta">
          <span>{{ option.impacts.filter((impact) => impact.count > 0).length }} actuele gevolgen</span>
          <span v-if="option.confirmationMode === 'typed'">Extra bevestiging vereist</span>
        </div>
        <footer>
          <button class="button secondary compact database-more-info" type="button" @click="openInfo(option)"><Info :size="14" /> Meer info</button>
          <button class="button danger-text compact database-cleanup-action" type="button" :disabled="busy || option.recordCount === 0" @click="beginCleanup(option)"><Trash2 :size="14" /> {{ option.recordCount === 0 ? 'Geen records' : 'Opschonen' }}</button>
        </footer>
      </article>
    </div>
    <p v-if="error && !pending" class="error-banner">{{ error }}</p>
  </section>

  <div v-if="infoOption" class="modal-backdrop database-modal-backdrop" role="presentation" @click.self="infoOption = undefined">
    <section class="modal database-info-modal" role="dialog" aria-modal="true" :aria-label="`Informatie over ${infoOption.tableName}`">
      <button class="icon-button modal-close" type="button" aria-label="Sluiten" @click="infoOption = undefined"><X :size="18" /></button>
      <header class="database-modal-heading">
        <span class="database-modal-icon"><Info :size="21" /></span>
        <div><small>{{ infoOption.tableName }}</small><h2>{{ infoOption.title }}</h2><p>{{ infoOption.description }}</p></div>
        <span class="database-record-count large"><strong>{{ formatCount(infoOption.recordCount) }}</strong><small>records</small></span>
      </header>
      <div class="database-modal-body">
        <div class="database-detail-grid">
          <section><h3>Wat wordt hier bewaard?</h3><ul><li v-for="item in infoOption.storedData" :key="item">{{ item }}</li></ul></section>
          <section><h3>Gerelateerde gevolgen</h3><ul><li v-for="item in infoOption.dependencies" :key="item">{{ item }}</li></ul></section>
        </div>
        <section class="database-effect-panel"><strong>Bij het opschonen</strong><p>{{ infoOption.cleanupEffect }}</p></section>
      </div>
      <footer class="modal-actions">
        <button class="button secondary" type="button" @click="infoOption = undefined">Sluiten</button>
        <button class="button danger-text" type="button" :disabled="busy || infoOption.recordCount === 0" @click="beginCleanup(infoOption)"><Trash2 :size="14" /> {{ infoOption.recordCount === 0 ? 'Geen records' : 'Opschonen' }}</button>
      </footer>
    </section>
  </div>

  <ConfirmDialog
    v-if="pending"
    :title="`Tabel &quot;${pending.tableName}&quot; opschonen?`"
    confirm-label="Definitief opschonen"
    :busy="busy"
    danger
    wide
    :confirm-disabled="!confirmationValid"
    @confirm="confirmCleanup"
    @cancel="cancelCleanup"
  >
    <div class="database-confirm-lead"><strong>{{ formatCount(pending.recordCount) }}</strong><span>records uit <code>{{ pending.tableName }}</code> worden opgeschoond</span></div>
    <div class="database-confirm-context">
      <section><strong>Deze tabel bevat</strong><ul><li v-for="item in pending.storedData" :key="item">{{ item }}</li></ul></section>
      <section><strong>Wat er daarnaast gebeurt</strong><ul><li v-for="item in pending.dependencies" :key="item">{{ item }}</li></ul></section>
    </div>
    <section class="database-confirm-effects">
      <strong>Exacte gevolgen op dit moment</strong>
      <ul class="database-confirm-impact-list">
        <li v-for="impact in pending.impacts.filter((item) => item.count > 0)" :key="impact.key">
          <strong>{{ formatCount(impact.count) }}</strong><span>{{ impact.label }}</span><small>{{ impact.effect }}</small>
        </li>
      </ul>
    </section>
    <p class="database-confirm-summary">{{ pending.cleanupEffect }}</p>
    <p class="danger-notice"><AlertTriangle :size="16" /> Deze actie kan niet ongedaan worden gemaakt.</p>
    <label v-if="pending.confirmationMode === 'typed'" class="database-confirm-field">
      <span>Typ <strong>{{ pending.confirmationPhrase }}</strong> om door te gaan</span>
      <input v-model="typedConfirmation" autocomplete="off" spellcheck="false" :placeholder="pending.confirmationPhrase" />
    </label>
    <p v-if="error" class="error-banner">{{ error }}</p>
  </ConfirmDialog>

  <div v-if="result && resultDetailsOpen" class="modal-backdrop database-modal-backdrop" role="presentation" @click.self="resultDetailsOpen = false">
    <section class="modal database-info-modal database-result-modal" role="dialog" aria-modal="true" aria-label="Resultaat database opschonen">
      <button class="icon-button modal-close" type="button" aria-label="Sluiten" @click="resultDetailsOpen = false"><X :size="18" /></button>
      <header class="database-modal-heading">
        <span :class="['database-modal-icon', { warning: result.warnings.length }]"><CheckCircle2 v-if="!result.warnings.length" :size="21" /><AlertTriangle v-else :size="21" /></span>
        <div><small>{{ result.tableName }}</small><h2>Database opgeschoond</h2><p>De actie is {{ result.warnings.length ? 'met waarschuwingen' : 'succesvol' }} afgerond.</p></div>
      </header>
      <div class="database-modal-body">
        <ul class="database-result-impact-list">
          <li v-for="impact in visibleResultImpacts" :key="impact.key"><strong>{{ formatCount(impact.count) }}</strong><span>{{ impact.label }}</span><small>{{ impact.effect }}</small></li>
        </ul>
        <div v-if="result.warnings.length" class="database-result-warnings"><strong>Waarschuwingen</strong><p v-for="warning in result.warnings" :key="warning">{{ warning }}</p></div>
      </div>
      <footer class="modal-actions"><button class="button primary" type="button" @click="resultDetailsOpen = false">Sluiten</button></footer>
    </section>
  </div>
</template>

<style scoped>
.database-cleanup-summary { font-size: 10px; }
.database-cleanup-meta span { font-size: 9px; }
.database-table-identity h4 { font-size: 13px; }
.database-table-identity code { font-size: 10px; }
.database-record-count small { font-size: 8px; }
.button.compact { font-size: 11px; }
.database-safety-summary strong { font-size: 11px; }
.database-safety-summary small { font-size: 10px; }
.database-safety-summary svg { width: 20px; height: 20px; }
.database-modal-heading small { font-size: 9px; }
.database-modal-heading h2 { font-size: 16px; }
.database-modal-heading p { font-size: 10px; }
.database-detail-grid h3 { font-size: 12px; }
.database-detail-grid ul,
.database-confirm-context ul { font-size: 11px; }
.database-effect-panel strong { font-size: 10px; }
.database-effect-panel p { font-size: 10px; }
.database-confirm-lead span { font-size: 12px; }
.database-confirm-lead code { font-size: 11px; }
.database-confirm-context section > strong,
.database-confirm-effects > strong { font-size: 12px; }
.database-confirm-impact-list li > strong,
.database-result-impact-list li > strong { font-size: 12px; }
.database-confirm-impact-list li > span,
.database-result-impact-list li > span { font-size: 11px; }
.database-confirm-impact-list li > small,
.database-result-impact-list li > small { font-size: 10px; }
.database-confirm-summary { font-size: 11px; }
.database-confirm-field > span,
.database-confirm-field input,
.danger-notice { font-size: 11px; }
.database-result-warnings strong,
.database-result-warnings p { font-size: 10px; }
</style>
