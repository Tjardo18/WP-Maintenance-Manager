<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { ArrowRight, CheckCircle2, CircleAlert, GitCompare, ShieldAlert, Wrench } from "@lucide/vue";
import type { SiteChangeHistory, SnapshotChange, SnapshotMetadata, SnapshotSection, SnapshotValue } from "../types";
import { formatDate } from "../utils/format";

const props = defineProps<{ history?: SiteChangeHistory; snapshots?: SnapshotMetadata[]; loading?: boolean }>();
const emit = defineEmits<{ viewed: [snapshotId: string]; compare: [snapshotId: string]; baseline: [snapshotId: string] }>();
const filter = ref<SnapshotSection | "all">("all");
const comparisonChoice = ref("previous");

const sectionLabels: Record<SnapshotSection, string> = {
  core: "WordPress",
  plugins: "Plugins",
  themes: "Thema's",
  users: "Gebruikers",
  configuration: "Configuratie",
  cron: "Cron",
  files: "Bestanden",
};
const sections: SnapshotSection[] = ["core", "plugins", "themes", "users", "configuration", "cron", "files"];
const comparison = computed(() => props.history?.comparison ?? undefined);
const visibleChanges = computed(() => comparison.value?.changes.filter((change) => filter.value === "all" || change.category === filter.value) ?? []);
const unavailable = computed(() => comparison.value?.sections.filter((section) => section.status === "unavailable" && (filter.value === "all" || section.category === filter.value)) ?? []);
const baselineOnly = computed(() => Boolean(props.history?.latestSnapshot?.isBaseline && !comparison.value));
const relevantSections = computed(() => sections.filter((section) => (comparison.value?.changes.some((change) => change.category === section) ?? false) || (comparison.value?.sections.some((item) => item.category === section && item.status === "unavailable") ?? false)));
const comparisonOptions = computed(() => {
  const latestId = props.history?.latestSnapshot?.snapshotId;
  return (props.snapshots ?? []).filter((snapshot) => snapshot.snapshotId !== latestId);
});
const specificComparisonOptions = computed(() => comparisonOptions.value.filter((snapshot) =>
  snapshot.snapshotId !== props.history?.baselineSnapshot?.snapshotId
  && snapshot.snapshotId !== props.history?.latestSnapshot?.previousSnapshotId,
));
const comparisonLabel = computed(() => {
  const fromSnapshotId = comparison.value?.fromSnapshotId;
  if (!fromSnapshotId || fromSnapshotId === props.history?.latestSnapshot?.previousSnapshotId) return "Sinds vorige controle";
  if (fromSnapshotId === props.history?.baselineSnapshot?.snapshotId) return "Sinds baseline";
  const reference = comparisonOptions.value.find((snapshot) => snapshot.snapshotId === fromSnapshotId);
  return reference ? `Sinds ${formatDate(reference.createdAt)}` : "Geselecteerde vergelijking";
});

watch(
  () => props.history?.latestSnapshot?.snapshotId,
  () => { comparisonChoice.value = "previous"; },
);

watch(
  () => comparison.value?.toSnapshotId,
  (snapshotId) => {
    if (snapshotId && comparison.value?.changes.some((change) => !change.seen)) emit("viewed", snapshotId);
  },
  { immediate: true },
);

function count(section: SnapshotSection) {
  return comparison.value?.changes.filter((change) => change.category === section).length ?? 0;
}

function compareSelection() {
  emit("compare", comparisonChoice.value);
}

function metadataString(change: SnapshotChange, key: string) {
  const value = change.metadata[key];
  return value?.type === "string" ? value.value : undefined;
}

function entityName(change: SnapshotChange) {
  return metadataString(change, "name") ?? metadataString(change, "login") ?? metadataString(change, "hook") ?? change.entityKey.replace(/^[^:]+:/, "");
}

function changeTitle(change: SnapshotChange) {
  if (change.changeType === "version_changed" && change.category === "plugins") return `${entityName(change)} bijgewerkt`;
  if (change.changeType === "version_changed" && change.category === "themes") return `${entityName(change)} bijgewerkt`;
  return change.summary;
}

function roleLabel(value: string) {
  const labels: Record<string, string> = { administrator: "Administrator", editor: "Editor", author: "Auteur", contributor: "Schrijver", subscriber: "Abonnee", shop_manager: "Winkelmanager" };
  return value.split(",").filter(Boolean).map((role) => labels[role] ?? role.replace(/_/g, " ")).join(", ") || "Geen rol";
}

function valueLabel(value: SnapshotValue | null, change: SnapshotChange) {
  if (!value || value.type === "null") return "Niet ingesteld";
  if (value.type === "boolean") return value.value ? "Aan" : "Uit";
  if (change.field === "roles" && typeof value.value === "string") return roleLabel(value.value);
  if (change.field === "status" && typeof value.value === "string") return ({ active: "Actief", inactive: "Inactief" }[value.value] ?? value.value);
  return String(value.value);
}

function severityLabel(change: SnapshotChange) {
  return ({ info: "Informatie", attention: "Controle aanbevolen", warning: "Belangrijk", critical: "Kritiek" } as const)[change.severity];
}
</script>

<template>
  <section class="changes-page">
    <header class="card changes-header">
      <span class="section-icon"><GitCompare /></span>
      <div>
        <small>{{ comparisonLabel }}</small>
        <h3>Wijzigingen</h3>
        <p v-if="comparison">{{ comparison.changes.length }} {{ comparison.changes.length === 1 ? 'wijziging' : 'wijzigingen' }} · {{ formatDate(comparison.createdAt) }}</p>
        <p v-else>Belangrijke WordPress-toestand wordt na controles met eerdere momentopnames vergeleken.</p>
      </div>
      <span v-if="comparison" class="changes-total">{{ comparison.changes.length }}</span>
    </header>

    <section v-if="history?.latestSnapshot && comparisonOptions.length" class="card comparison-toolbar">
      <label><span>Vergelijk huidige controle met</span><select v-model="comparisonChoice" :disabled="loading" @change="compareSelection"><option value="previous">Vorige controle</option><option v-if="history.baselineSnapshot && history.baselineSnapshot.snapshotId !== history.latestSnapshot.snapshotId" value="baseline">Baseline · {{ formatDate(history.baselineSnapshot.createdAt) }}</option><option v-for="snapshot in specificComparisonOptions" :key="snapshot.snapshotId" :value="snapshot.snapshotId">{{ formatDate(snapshot.createdAt) }} · {{ snapshot.source.replace(/_/g, ' ') }}</option></select></label>
      <button v-if="!history.latestSnapshot.isBaseline" class="button small secondary" :disabled="loading" @click="emit('baseline', history.latestSnapshot.snapshotId)">Huidige als baseline instellen</button>
      <span v-else class="current-baseline"><CheckCircle2 :size="14" /> Huidige momentopname is de baseline</span>
    </section>

    <div v-if="loading" class="card empty-state compact"><h3>Wijzigingen laden…</h3></div>
    <div v-else-if="!history?.latestSnapshot" class="card empty-state">
      <GitCompare :size="38" /><h3>Nog geen momentopname</h3><p>Voer een volledige websitecontrole uit om de eerste baseline aan te maken.</p>
    </div>
    <div v-else-if="baselineOnly" class="card empty-state baseline-state">
      <CheckCircle2 :size="42" /><h3>Baseline aangemaakt</h3><p>Dit is de eerste betrouwbare momentopname van deze website. Vanaf de volgende volledige controle worden wijzigingen automatisch weergegeven.</p><small>{{ formatDate(history.latestSnapshot.createdAt) }}</small>
    </div>
    <div v-else-if="!comparison" class="card empty-state">
      <CircleAlert :size="38" /><h3>Momentopname opgeslagen</h3><p>Er is nog geen betrouwbare vergelijking beschikbaar. Een volgende volledige controle probeert opnieuw een baseline of vergelijking te maken.</p>
    </div>

    <template v-else>
      <nav class="change-filters" aria-label="Wijzigingen filteren">
        <button :class="{ active: filter === 'all' }" @click="filter = 'all'">Alles <span>{{ comparison.changes.length }}</span></button>
        <button v-for="section in relevantSections" :key="section" :class="{ active: filter === section }" @click="filter = section">{{ sectionLabels[section] }} <span>{{ count(section) }}</span></button>
      </nav>

      <div v-if="!visibleChanges.length && !unavailable.length" class="card empty-state">
        <CheckCircle2 :size="38" /><h3>Geen wijzigingen gevonden</h3><p>De website komt voor de gecontroleerde onderdelen overeen met de vorige momentopname.</p>
      </div>

      <div v-if="visibleChanges.length" class="change-list">
        <article v-for="change in visibleChanges" :key="change.id" :class="['card', 'change-card', change.severity]">
          <span class="change-severity-icon"><ShieldAlert v-if="['warning', 'critical'].includes(change.severity)" /><GitCompare v-else /></span>
          <div class="change-copy">
            <div class="change-title"><div><small>{{ sectionLabels[change.category] }}</small><h3>{{ changeTitle(change) }}</h3></div><span :class="['change-severity', change.severity]">{{ severityLabel(change) }}</span></div>
            <strong v-if="!changeTitle(change).includes(entityName(change))">{{ entityName(change) }}</strong>
            <div v-if="change.oldValue || change.newValue" class="change-values"><span>{{ valueLabel(change.oldValue, change) }}</span><ArrowRight :size="15" /><span>{{ valueLabel(change.newValue, change) }}</span></div>
            <p v-if="change.origin === 'maintenance'" class="change-origin"><Wrench :size="13" /> Uitgevoerd door onderhoud</p>
            <details><summary>Technische details</summary><dl><div><dt>Entiteit</dt><dd>{{ change.entityKey }}</dd></div><div><dt>Tijdstip</dt><dd>{{ formatDate(change.createdAt) }}</dd></div><div><dt>Van snapshot</dt><dd>{{ change.fromSnapshotId }}</dd></div><div><dt>Naar snapshot</dt><dd>{{ change.toSnapshotId }}</dd></div></dl></details>
          </div>
        </article>
      </div>

      <section v-if="unavailable.length" class="partial-comparisons">
        <article v-for="section in unavailable" :key="section.category" class="card partial-comparison"><CircleAlert :size="19" /><div><small>{{ sectionLabels[section.category] }}</small><h3>Vergelijking niet beschikbaar</h3><p>{{ section.reason ?? `${sectionLabels[section.category]} kon tijdens één van de controles niet volledig worden opgehaald.` }}</p></div></article>
      </section>
    </template>
  </section>
</template>
