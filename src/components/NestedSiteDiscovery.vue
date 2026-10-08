<script setup lang="ts">
import { computed, onMounted, ref } from "vue";
import { AlertTriangle, Check, FolderSearch, LoaderCircle, X } from "@lucide/vue";
import { appApi } from "../services/tauri";
import {
  availableNestedDirectories,
  buildNestedSiteProposal,
  joinWordpressPath,
  reconnectableNestedSite,
  rootSiteNameBase,
  type NestedSiteParentContext,
} from "../services/nestedSites";
import type { ConnectionTestResult, Site, SiteInput, SiteRelationType } from "../types";
import { errorMessage } from "../utils/errors";

type NestedSiteChoice = "unselected" | "none" | SiteRelationType;

interface Candidate {
  key: string;
  parentKey: string;
  depth: number;
  directory: string;
  choice: NestedSiteChoice;
  name: string;
  nameBase: string;
  url: string;
  wordpressPath: string;
  testGeneration: number;
  checking: boolean;
  verified: boolean;
  verifiedSignature?: string;
  result?: ConnectionTestResult;
  error?: string;
  saved?: boolean;
  savedId?: string;
  existingId?: string;
}

const props = defineProps<{ parent: Site; sites: Site[] }>();
const emit = defineEmits<{ close: []; saved: [site: Site] }>();
const discovering = ref(true);
const saving = ref(false);
const candidates = ref<Candidate[]>([]);
const discoveryResult = ref<ConnectionTestResult>();
const error = ref<string>();
const success = ref<string>();

function siteInput(name: string, url: string, wordpressPath: string, includeParentId: boolean): SiteInput {
  return {
    id: includeParentId ? props.parent.id : undefined,
    name,
    url,
    sshHost: props.parent.sshHost,
    sshPort: props.parent.sshPort,
    sshUsername: props.parent.sshUsername,
    authMethod: props.parent.authMethod,
    keyPath: props.parent.keyPath,
    wordpressPath,
    pinnedHostKey: props.parent.pinnedHostKey,
  };
}

function candidateSignature(candidate: Candidate) {
  return JSON.stringify([candidate.choice, candidate.url.trim(), candidate.wordpressPath]);
}

function contextFor(parentKey: string): NestedSiteParentContext | undefined {
  if (parentKey === "root") {
    return {
      key: props.parent.id,
      nameBase: rootSiteNameBase(props.parent.name, props.parent.url),
      url: props.parent.url,
      wordpressPath: props.parent.wordpressPath,
      isRoot: !props.parent.parentSiteId,
    };
  }
  const parentCandidate = candidates.value.find((candidate) => candidate.key === parentKey);
  if (!parentCandidate) return undefined;
  return {
    key: parentCandidate.key,
    nameBase: parentCandidate.nameBase,
    url: parentCandidate.url,
    wordpressPath: parentCandidate.wordpressPath,
    isRoot: false,
  };
}

function detectedDirectoryPath(candidate: Candidate) {
  const parent = contextFor(candidate.parentKey);
  return parent ? joinWordpressPath(parent.wordpressPath, candidate.directory) : candidate.directory;
}

function parentNameFor(candidate: Candidate) {
  if (candidate.parentKey === "root") return props.parent.name;
  return candidates.value.find((item) => item.key === candidate.parentKey)?.name ?? props.parent.name;
}

function descendantKeys(parentKey: string) {
  const keys = new Set<string>();
  let found = true;
  while (found) {
    found = false;
    for (const candidate of candidates.value) {
      if (!keys.has(candidate.key) && (candidate.parentKey === parentKey || keys.has(candidate.parentKey))) {
        keys.add(candidate.key);
        found = true;
      }
    }
  }
  return keys;
}

function removeDescendants(parentKey: string) {
  const keys = descendantKeys(parentKey);
  if (keys.size) candidates.value = candidates.value.filter((candidate) => !keys.has(candidate.key));
}

function addCandidates(parentKey: string, depth: number, directories: string[]) {
  const parent = contextFor(parentKey);
  if (!parent) return;
  const connection = {
    id: parentKey === "root" ? props.parent.id : parentKey,
    sshHost: props.parent.sshHost,
    sshPort: props.parent.sshPort,
    sshUsername: props.parent.sshUsername,
    authMethod: props.parent.authMethod,
    keyPath: props.parent.keyPath,
    wordpressPath: parent.wordpressPath,
  };
  const available = availableNestedDirectories(connection, directories, props.sites);
  const existingKeys = new Set(candidates.value.map((candidate) => candidate.key));
  const additions = available
    .map((directory) => ({ directory, key: `${parentKey}/${directory}`, existing: reconnectableNestedSite(connection, directory, props.sites) }))
    .filter(({ key }) => !existingKeys.has(key))
    .map(({ directory, key, existing }): Candidate => ({
      key,
      parentKey,
      depth,
      directory,
      choice: "unselected",
      name: existing?.name ?? "",
      nameBase: "",
      url: existing?.url ?? "",
      wordpressPath: joinWordpressPath(parent.wordpressPath, directory),
      testGeneration: 0,
      checking: false,
      verified: false,
      existingId: existing?.id,
    }));
  candidates.value = [...candidates.value, ...additions];
}

const orderedCandidates = computed(() => {
  const ordered: Candidate[] = [];
  const visit = (parentKey: string) => {
    for (const candidate of candidates.value.filter((item) => item.parentKey === parentKey)) {
      ordered.push(candidate);
      visit(candidate.key);
    }
  };
  visit("root");
  return ordered;
});

function invalidate(candidate: Candidate) {
  candidate.testGeneration += 1;
  candidate.checking = false;
  candidate.verified = false;
  candidate.verifiedSignature = undefined;
  candidate.result = undefined;
  candidate.error = undefined;
  removeDescendants(candidate.key);
}

async function discover() {
  discovering.value = true;
  error.value = undefined;
  success.value = undefined;
  try {
    const result = await appApi.testConnection(
      siteInput(props.parent.name, props.parent.url, props.parent.wordpressPath, true),
    );
    discoveryResult.value = result;
    if (!result.success) {
      error.value = result.error?.userMessage ?? "De extra WordPress-installaties konden niet worden gezocht.";
      candidates.value = [];
      return;
    }
    candidates.value = [];
    addCandidates("root", 0, result.unexpectedDirectories);
  } catch (cause) {
    error.value = errorMessage(cause);
    candidates.value = [];
  } finally {
    discovering.value = false;
  }
}

async function applyChoice(candidate: Candidate) {
  candidate.saved = false;
  candidate.savedId = undefined;
  invalidate(candidate);
  if (candidate.choice === "unselected" || candidate.choice === "none") {
    candidate.name = "";
    candidate.nameBase = "";
    candidate.url = "";
    candidate.wordpressPath = detectedDirectoryPath(candidate);
    return;
  }
  const parent = contextFor(candidate.parentKey);
  if (!parent) {
    candidate.error = "De bovenliggende website kon niet worden bepaald.";
    return;
  }
  const proposal = buildNestedSiteProposal(parent, candidate.directory, candidate.choice);
  const existing = props.sites.find((site) => site.id === candidate.existingId);
  Object.assign(candidate, {
    ...proposal,
    name: existing?.name ?? proposal.name,
    url: existing?.url ?? proposal.url,
  });
  await verifyCandidate(candidate);
}

async function verifyCandidate(candidate: Candidate) {
  if (candidate.choice !== "subdomain" && candidate.choice !== "subdirectory") return;
  const generation = candidate.testGeneration + 1;
  candidate.testGeneration = generation;
  candidate.checking = true;
  candidate.error = undefined;
  candidate.result = undefined;
  candidate.verified = false;
  removeDescendants(candidate.key);
  const signature = candidateSignature(candidate);
  try {
    const result = await appApi.testConnection(
      siteInput(candidate.name, candidate.url, candidate.wordpressPath, true),
    );
    if (generation !== candidate.testGeneration || signature !== candidateSignature(candidate)) return;
    candidate.result = result;
    candidate.verified = result.success;
    candidate.verifiedSignature = result.success ? signature : undefined;
    if (result.success) addCandidates(candidate.key, candidate.depth + 1, result.unexpectedDirectories);
  } catch (cause) {
    if (generation === candidate.testGeneration) candidate.error = errorMessage(cause);
  } finally {
    if (generation === candidate.testGeneration) candidate.checking = false;
  }
}

const selectedCandidates = computed(() => orderedCandidates.value.filter(
  (candidate) => candidate.choice === "subdomain" || candidate.choice === "subdirectory",
));
const allChoicesMade = computed(() => candidates.value.every((candidate) => candidate.choice !== "unselected"));
const candidatesVerified = computed(() => selectedCandidates.value.every(
  (candidate) => candidate.name.trim()
    && /^https?:\/\//.test(candidate.url)
    && candidate.verified
    && candidate.verifiedSignature === candidateSignature(candidate),
));
const uniqueTargets = computed(() => {
  const urls = new Set<string>();
  const paths = new Set<string>();
  for (const candidate of selectedCandidates.value.filter((item) => !item.saved)) {
    const url = candidate.url.trim().replace(/\/+$/g, "").toLowerCase();
    const path = candidate.wordpressPath.replace(/\/+$/g, "");
    if (urls.has(url) || paths.has(path) || props.sites.some((site) => site.id !== candidate.existingId
      && (site.url.trim().replace(/\/+$/g, "").toLowerCase() === url
        || (site.sshHost.toLowerCase() === props.parent.sshHost.toLowerCase()
          && site.sshPort === props.parent.sshPort
          && site.wordpressPath.replace(/\/+$/g, "") === path)))) return false;
    urls.add(url);
    paths.add(path);
  }
  return true;
});
const unsavedSelectedCandidates = computed(() => selectedCandidates.value.filter((candidate) => !candidate.saved));
const canSave = computed(() => allChoicesMade.value
  && candidatesVerified.value
  && uniqueTargets.value
  && !saving.value
  && unsavedSelectedCandidates.value.length > 0);

async function saveCandidates() {
  if (!canSave.value) return;
  saving.value = true;
  error.value = undefined;
  success.value = undefined;
  let savedCount = 0;
  let lastSaved: Site | undefined;
  try {
    for (const candidate of unsavedSelectedCandidates.value) {
      const relationType = candidate.choice as SiteRelationType;
      const parentSiteId = candidate.parentKey === "root"
        ? props.parent.id
        : candidates.value.find((item) => item.key === candidate.parentKey)?.savedId;
      if (!parentSiteId) throw new Error(`De parent van ${candidate.name} is nog niet opgeslagen.`);
      const saved = await appApi.saveSite({
        ...siteInput(candidate.name, candidate.url, candidate.wordpressPath, false),
        id: candidate.existingId,
        parentSiteId,
        relationType,
        parentDirectory: candidate.directory,
      });
      candidate.saved = true;
      candidate.savedId = saved.id;
      savedCount += 1;
      lastSaved = saved;
    }
    success.value = savedCount === 1
      ? "De extra WordPress-installatie is gekoppeld."
      : `${savedCount} extra WordPress-installaties zijn gekoppeld.`;
  } catch (cause) {
    error.value = errorMessage(cause);
  } finally {
    saving.value = false;
    if (lastSaved) emit("saved", lastSaved);
  }
}

onMounted(discover);
</script>

<template>
  <div class="modal-backdrop nested-discovery-backdrop" role="presentation" @click.self="!saving && emit('close')">
    <section class="modal nested-discovery-modal" role="dialog" aria-modal="true" aria-label="Zoeken naar subdomeinen en subdirectories">
      <button class="icon-button modal-close" type="button" aria-label="Sluiten" :disabled="saving" @click="emit('close')"><X :size="18" /></button>
      <div class="nested-discovery-heading"><span class="section-icon"><FolderSearch :size="21" /></span><div><h2>Zoeken naar subdomeinen/subdirectories</h2><p>Controleer mappen direct onder <strong>{{ parent.name }}</strong> en koppel nieuwe WordPress-installaties.</p></div></div>

      <div v-if="discovering" class="empty-state compact"><LoaderCircle class="spin" :size="31" /><h3>Mappen controleren…</h3><p>De opgeslagen SSH-verbinding van de parent wordt veilig hergebruikt.</p></div>
      <template v-else>
        <p v-if="discoveryResult?.unexpectedDirectoriesTruncated" class="nested-sites-warning"><AlertTriangle :size="15" />Alleen de eerste 200 gevonden mappen worden weergegeven.</p>
        <p v-if="error" class="error-banner">{{ error }}</p>
        <p v-if="success" class="nested-discovery-success"><Check :size="16" />{{ success }}</p>
        <div v-if="!candidates.length && !error" class="nested-sites-empty nested-discovery-empty"><Check :size="18" /><span>Geen nieuwe mogelijke child-installaties gevonden.</span></div>

        <div v-else class="nested-sites-list nested-discovery-list">
          <article v-for="candidate in orderedCandidates" :key="candidate.key" class="nested-site" :class="{ saved: candidate.saved }" :style="{ marginLeft: `${Math.min(candidate.depth, 5) * 18}px` }">
            <header><div><small>Gevonden map</small><strong>{{ candidate.directory }}</strong><code>{{ detectedDirectoryPath(candidate) }}</code></div><span v-if="candidate.saved" class="nested-level">Gekoppeld</span><span v-else-if="candidate.existingId" class="nested-level">Al geregistreerd</span><span v-else-if="candidate.depth" class="nested-level">Niveau {{ candidate.depth + 1 }}</span></header>
            <p v-if="candidate.existingId && !candidate.saved" class="nested-sites-help">Deze installatie staat al in de app. Koppelen hergebruikt de bestaande website en maakt geen duplicaat.</p>
            <fieldset :disabled="candidate.saved || saving">
              <legend>Wat is deze map?</legend>
              <div class="nested-choice-grid">
                <label :class="{ selected: candidate.choice === 'subdomain' }"><input v-model="candidate.choice" type="radio" value="subdomain" @change="applyChoice(candidate)" /><span><strong>Subdomein</strong><small>{{ candidate.directory }}.voorbeeld.nl</small></span></label>
                <label :class="{ selected: candidate.choice === 'subdirectory' }"><input v-model="candidate.choice" type="radio" value="subdirectory" @change="applyChoice(candidate)" /><span><strong>Subdirectory</strong><small>voorbeeld.nl/{{ candidate.directory }}</small></span></label>
                <label :class="{ selected: candidate.choice === 'none' }"><input v-model="candidate.choice" type="radio" value="none" @change="applyChoice(candidate)" /><span><strong>Geen aparte website</strong><small>Blijft onderdeel van de parent.</small></span></label>
              </div>
            </fieldset>

            <div v-if="candidate.choice === 'subdomain' || candidate.choice === 'subdirectory'" class="nested-site-details">
              <div class="form-grid">
                <label><span>Voorgestelde naam</span><input v-model.trim="candidate.name" required maxlength="100" :disabled="candidate.saved || saving" /></label>
                <label><span>Website-URL</span><input v-model.trim="candidate.url" required type="url" :disabled="candidate.saved || saving" @input="invalidate(candidate)" /></label>
                <label class="span-2"><span>WordPress-pad</span><input :value="candidate.wordpressPath" readonly /></label>
              </div>
              <div class="nested-verification">
                <span v-if="candidate.saved" class="verified"><Check :size="15" />Gekoppeld aan {{ parentNameFor(candidate) }}.</span>
                <span v-else-if="candidate.checking"><LoaderCircle class="spin" :size="15" />WordPress-installatie controleren…</span>
                <span v-else-if="candidate.verified" class="verified"><Check :size="15" />WordPress-installatie gecontroleerd.</span>
                <span v-else-if="candidate.result || candidate.error" class="failed"><AlertTriangle :size="15" />{{ candidate.result?.error?.userMessage ?? candidate.error ?? 'De installatie kon niet worden gecontroleerd.' }}</span>
                <span v-else>Controleer opnieuw nadat je de URL hebt aangepast.</span>
                <button v-if="!candidate.saved && !candidate.checking && !candidate.verified" class="button secondary small" type="button" :disabled="saving" @click="verifyCandidate(candidate)"><LoaderCircle v-if="candidate.checking" class="spin" :size="14" />Opnieuw controleren</button>
              </div>
              <p v-if="candidate.result?.unexpectedDirectoriesTruncated" class="nested-sites-warning"><AlertTriangle :size="15" />Niet alle onderliggende mappen konden worden getoond.</p>
            </div>
          </article>
        </div>

        <p v-if="candidates.length && !allChoicesMade" class="nested-sites-help">Maak voor iedere gevonden map een keuze.</p>
        <p v-if="!uniqueTargets" class="nested-sites-warning"><AlertTriangle :size="15" />Een voorgestelde URL of WordPress-installatie staat al in de app.</p>
      </template>

      <div class="modal-actions">
        <button class="button secondary" type="button" :disabled="saving" @click="emit('close')">Sluiten</button>
        <button v-if="candidates.length && unsavedSelectedCandidates.length" class="button primary" type="button" :disabled="!canSave" @click="saveCandidates"><LoaderCircle v-if="saving" class="spin" :size="15" />{{ saving ? 'Koppelen…' : `${unsavedSelectedCandidates.length} website${unsavedSelectedCandidates.length === 1 ? '' : 's'} koppelen` }}</button>
      </div>
    </section>
  </div>
</template>
