<script setup lang="ts">
import { computed, reactive, ref, watch, watchEffect } from "vue";
import { useRoute, useRouter, RouterLink } from "vue-router";
import {
  AlertTriangle,
  Check,
  ChevronDown,
  FileKey2,
  FolderTree,
  KeyRound,
  LoaderCircle,
  LockKeyhole,
  RefreshCw,
  Server,
  ShieldQuestion,
} from "@lucide/vue";
import { useSitesStore } from "../stores/sites";
import { appApi } from "../services/tauri";
import {
  buildNestedSiteProposal,
  joinWordpressPath,
  rootSiteNameBase,
  type NestedSiteParentContext,
} from "../services/nestedSites";
import type { ConnectionTestResult, SiteInput, SiteRelationType } from "../types";
import { errorMessage } from "../utils/errors";

type NestedSiteChoice = "unselected" | "none" | SiteRelationType;

interface NestedSiteCandidate {
  key: string;
  parentKey: string;
  depth: number;
  directory: string;
  choice: NestedSiteChoice;
  name: string;
  nameBase: string;
  url: string;
  wordpressPath: string;
  checking: boolean;
  verified: boolean;
  verifiedSignature?: string;
  result?: ConnectionTestResult;
  error?: string;
  savedId?: string;
  testGeneration: number;
}

const route = useRoute();
const router = useRouter();
const store = useSitesStore();
const form = reactive<SiteInput>({
  name: "",
  url: "https://",
  sshHost: "",
  sshPort: 7685,
  sshUsername: "",
  authMethod: "keyFile",
  keyPath: "",
  wordpressPath: "/home/<user>/domains/<domein.nl>/public_html",
  credentialSecret: "",
  pinnedHostKey: null,
  parentSiteId: null,
  relationType: null,
  parentDirectory: null,
});
const saving = ref(false);
const testing = ref(false);
const accepting = ref(false);
const result = ref<ConnectionTestResult>();
const error = ref<string>();
const candidates = ref<NestedSiteCandidate[]>([]);
const testedRootSignature = ref<string>();
const rootSavedId = ref<string>();
const loadedSiteId = ref<string>();
const editing = computed(() => typeof route.params.id === "string");

watchEffect(() => {
  const site = store.byId.get(String(route.params.id));
  if (!site || loadedSiteId.value === site.id) return;
  loadedSiteId.value = site.id;
  Object.assign(form, {
    id: site.id,
    name: site.name,
    url: site.url,
    sshHost: site.sshHost,
    sshPort: site.sshPort,
    sshUsername: site.sshUsername,
    authMethod: site.authMethod,
    keyPath: site.keyPath ?? "",
    wordpressPath: site.wordpressPath,
    credentialSecret: "",
    pinnedHostKey: site.pinnedHostKey ?? null,
    parentSiteId: site.parentSiteId ?? null,
    relationType: site.relationType ?? null,
    parentDirectory: site.parentDirectory ?? null,
  });
});

const valid = computed(() => Boolean(
  form.name.trim()
  && /^https?:\/\//.test(form.url)
  && form.sshHost.trim()
  && form.sshUsername.trim()
  && form.sshPort > 0
  && form.sshPort <= 65535
  && form.wordpressPath.startsWith("/")
  && (form.authMethod === "password" || form.keyPath),
));

function connectionSignature(input: SiteInput) {
  return JSON.stringify([
    input.url.trim(),
    input.sshHost.trim().toLowerCase(),
    input.sshPort,
    input.sshUsername.trim(),
    input.authMethod,
    input.keyPath ?? "",
    input.wordpressPath.replace(/\/+$/g, ""),
    input.credentialSecret ?? "",
    input.pinnedHostKey ?? "",
  ]);
}

const rootConnectionSignature = computed(() => connectionSignature(form));
const rootTestIsCurrent = computed(() => testedRootSignature.value === rootConnectionSignature.value);

watch(rootConnectionSignature, (signature) => {
  if (!testedRootSignature.value || testedRootSignature.value === signature) return;
  result.value = undefined;
  candidates.value = [];
  testedRootSignature.value = undefined;
});

function candidateSignature(candidate: NestedSiteCandidate) {
  return connectionSignature(candidateInput(candidate));
}

function candidateInput(candidate: NestedSiteCandidate): SiteInput {
  return {
    name: candidate.name,
    url: candidate.url,
    sshHost: form.sshHost,
    sshPort: form.sshPort,
    sshUsername: form.sshUsername,
    authMethod: form.authMethod,
    keyPath: form.keyPath,
    wordpressPath: candidate.wordpressPath,
    credentialSecret: form.credentialSecret,
    pinnedHostKey: form.pinnedHostKey,
  };
}

function parentContext(parentKey: string): NestedSiteParentContext | undefined {
  if (parentKey === "root") {
    return {
      key: "root",
      nameBase: rootSiteNameBase(form.name, form.url),
      url: form.url,
      wordpressPath: form.wordpressPath,
      isRoot: true,
    };
  }
  const parent = candidates.value.find((candidate) => candidate.key === parentKey);
  if (!parent) return undefined;
  return {
    key: parent.key,
    nameBase: parent.nameBase,
    url: parent.url,
    wordpressPath: parent.wordpressPath,
    isRoot: false,
  };
}

function detectedDirectoryPath(candidate: NestedSiteCandidate) {
  const parent = parentContext(candidate.parentKey);
  return parent ? joinWordpressPath(parent.wordpressPath, candidate.directory) : candidate.directory;
}

function addCandidates(parentKey: string, depth: number, directories: string[]) {
  const existingKeys = new Set(candidates.value.map((candidate) => candidate.key));
  const additions = directories
    .map((directory) => ({ directory, key: `${parentKey}/${directory}` }))
    .filter(({ key }) => !existingKeys.has(key))
    .map(({ directory, key }): NestedSiteCandidate => ({
      key,
      parentKey,
      depth,
      directory,
      choice: "unselected",
      name: "",
      nameBase: "",
      url: "",
      wordpressPath: "",
      checking: false,
      verified: false,
      testGeneration: 0,
    }));
  candidates.value = [...candidates.value, ...additions];
}

function setRootCandidates(connectionResult: ConnectionTestResult) {
  candidates.value = [];
  addCandidates("root", 0, connectionResult.unexpectedDirectories);
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

const orderedCandidates = computed(() => {
  const ordered: NestedSiteCandidate[] = [];
  const visit = (parentKey: string) => {
    for (const candidate of candidates.value.filter((item) => item.parentKey === parentKey)) {
      ordered.push(candidate);
      visit(candidate.key);
    }
  };
  visit("root");
  return ordered;
});

const selectedCandidates = computed(() => orderedCandidates.value.filter(
  (candidate) => candidate.choice === "subdomain" || candidate.choice === "subdirectory",
));
const candidatesComplete = computed(() => candidates.value.every((candidate) => {
  if (candidate.choice === "unselected") return false;
  if (candidate.choice === "none") return true;
  return Boolean(
    candidate.name.trim()
    && /^https?:\/\//.test(candidate.url)
    && candidate.verified
    && candidate.verifiedSignature === candidateSignature(candidate),
  );
}));
const uniqueCandidateTargets = computed(() => {
  const urls = new Set<string>([form.url.trim().replace(/\/+$/g, "").toLowerCase()]);
  const paths = new Set<string>([form.wordpressPath.replace(/\/+$/g, "")]);
  for (const candidate of selectedCandidates.value) {
    const url = candidate.url.trim().replace(/\/+$/g, "").toLowerCase();
    const path = candidate.wordpressPath.replace(/\/+$/g, "");
    if (urls.has(url) || paths.has(path)) return false;
    urls.add(url);
    paths.add(path);
  }
  return true;
});
const canSave = computed(() => {
  if (!valid.value || saving.value) return false;
  if (editing.value) return true;
  return Boolean(result.value?.success && rootTestIsCurrent.value && candidatesComplete.value && uniqueCandidateTargets.value);
});

async function chooseKey() {
  try {
    const { open } = await import("@tauri-apps/plugin-dialog");
    const selected = await open({ multiple: false, directory: false, title: "Kies een SSH private key" });
    if (selected) form.keyPath = selected;
  } catch {
    error.value = "Een sleutelbestand kiezen werkt alleen in de desktopapp.";
  }
}

async function test() {
  testing.value = true;
  error.value = undefined;
  result.value = undefined;
  candidates.value = [];
  const signature = rootConnectionSignature.value;
  try {
    const connectionResult = await appApi.testConnection({ ...form });
    result.value = connectionResult;
    testedRootSignature.value = signature;
    if (connectionResult.success && !editing.value) setRootCandidates(connectionResult);
  } catch (cause) {
    error.value = errorMessage(cause);
    testedRootSignature.value = signature;
  } finally {
    testing.value = false;
  }
}

async function acceptFingerprint() {
  if (!result.value?.fingerprint) return;
  accepting.value = true;
  error.value = undefined;
  try {
    form.pinnedHostKey = result.value.fingerprint;
    await test();
  } catch (cause) {
    error.value = errorMessage(cause);
  } finally {
    accepting.value = false;
  }
}

async function applyChoice(candidate: NestedSiteCandidate) {
  removeDescendants(candidate.key);
  candidate.error = undefined;
  candidate.result = undefined;
  candidate.verified = false;
  candidate.verifiedSignature = undefined;
  if (candidate.choice === "unselected" || candidate.choice === "none") {
    candidate.name = "";
    candidate.nameBase = "";
    candidate.url = "";
    candidate.wordpressPath = "";
    return;
  }

  const parent = parentContext(candidate.parentKey);
  if (!parent) {
    candidate.error = "De bovenliggende website kon niet worden bepaald.";
    return;
  }
  const proposal = buildNestedSiteProposal(parent, candidate.directory, candidate.choice);
  Object.assign(candidate, proposal);
  await testCandidate(candidate);
}

function invalidateCandidate(candidate: NestedSiteCandidate) {
  candidate.testGeneration += 1;
  candidate.checking = false;
  candidate.verified = false;
  candidate.verifiedSignature = undefined;
  candidate.result = undefined;
  candidate.error = undefined;
  removeDescendants(candidate.key);
}

async function testCandidate(candidate: NestedSiteCandidate) {
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
    const connectionResult = await appApi.testConnection(candidateInput(candidate));
    if (generation !== candidate.testGeneration || signature !== candidateSignature(candidate)) return;
    candidate.result = connectionResult;
    candidate.verified = connectionResult.success;
    candidate.verifiedSignature = connectionResult.success ? signature : undefined;
    if (connectionResult.success) {
      addCandidates(candidate.key, candidate.depth + 1, connectionResult.unexpectedDirectories);
    }
  } catch (cause) {
    if (generation === candidate.testGeneration) candidate.error = errorMessage(cause);
  } finally {
    if (generation === candidate.testGeneration) candidate.checking = false;
  }
}

async function save() {
  if (!canSave.value) return;
  saving.value = true;
  error.value = undefined;
  try {
    const rootSite = await appApi.saveSite({
      ...form,
      id: rootSavedId.value ?? form.id,
      credentialSecret: form.credentialSecret || undefined,
    });
    rootSavedId.value = rootSite.id;

    for (const candidate of selectedCandidates.value) {
      const parentId = candidate.parentKey === "root"
        ? rootSite.id
        : candidates.value.find((item) => item.key === candidate.parentKey)?.savedId;
      if (!parentId) throw new Error(`De parent van ${candidate.name} is nog niet opgeslagen.`);
      const saved = await appApi.saveSite({
        ...candidateInput(candidate),
        id: candidate.savedId,
        credentialSecret: form.credentialSecret || undefined,
        parentSiteId: parentId,
        relationType: candidate.choice as SiteRelationType,
        parentDirectory: candidate.directory,
      });
      candidate.savedId = saved.id;
    }

    await store.load();
    await router.push(`/websites/${rootSite.id}`);
  } catch (cause) {
    error.value = errorMessage(cause);
  } finally {
    saving.value = false;
  }
}
</script>

<template>
  <section class="page-heading">
    <div>
      <h2>{{ editing ? 'Website bewerken' : 'Nieuwe website' }}</h2>
      <p>Vul de verbindingsgegevens in. Wachtwoorden en passphrases worden niet in de lokale database opgeslagen.</p>
    </div>
    <RouterLink class="button ghost" to="/websites">Annuleren</RouterLink>
  </section>

  <form class="form-layout" @submit.prevent="save">
    <div class="card form-card">
      <div class="section-heading">
        <span class="section-icon"><Server :size="20" /></span>
        <div><h3>Website</h3><p>De herkenbare naam en het openbare adres.</p></div>
      </div>
      <div class="form-grid">
        <label><span>Naam</span><input v-model.trim="form.name" required maxlength="100" placeholder="Bijvoorbeeld Bakkerij De Molen" /></label>
        <label><span>Website-URL</span><input v-model.trim="form.url" required type="url" placeholder="https://voorbeeld.nl" /></label>
      </div>
    </div>

    <div class="card form-card">
      <div class="section-heading">
        <span class="section-icon"><KeyRound :size="20" /></span>
        <div><h3>SSH-verbinding</h3><p>Deze gegevens vind je in het hostingpaneel of bij je hostingprovider.</p></div>
      </div>
      <div class="form-grid three">
        <label class="span-2"><span>SSH host</span><input v-model.trim="form.sshHost" required placeholder="server.voorbeeld.nl" autocomplete="off" /></label>
        <label><span>Poort</span><input v-model.number="form.sshPort" required type="number" min="1" max="65535" /></label>
        <label><span>Gebruikersnaam</span><input v-model.trim="form.sshUsername" required autocomplete="username" /></label>
        <label class="span-2"><span>WordPress-pad</span><input v-model.trim="form.wordpressPath" required placeholder="/var/www/voorbeeld/public" /><small>Absoluut pad op de Linux-server.</small></label>
      </div>
      <fieldset>
        <legend>Authenticatiemethode</legend>
        <div class="choice-grid">
          <label :class="['choice-card', { selected: form.authMethod === 'keyFile' }]">
            <input v-model="form.authMethod" type="radio" value="keyFile" /><FileKey2 />
            <span><strong>SSH-sleutelbestand</strong><small>Aanbevolen. De app bewaart alleen het lokale pad.</small></span>
          </label>
          <label :class="['choice-card', { selected: form.authMethod === 'password' }]">
            <input v-model="form.authMethod" type="radio" value="password" /><LockKeyhole />
            <span><strong>Wachtwoord</strong><small>Veilig opgeslagen in het besturingssysteem.</small></span>
          </label>
        </div>
      </fieldset>
      <div v-if="form.authMethod === 'keyFile'" class="form-grid">
        <label class="span-2"><span>Private-keybestand</span><div class="input-button"><input v-model="form.keyPath" required readonly placeholder="Kies een bestand…" /><button class="button secondary" type="button" @click="chooseKey">Bladeren</button></div></label>
        <label class="span-2"><span>Passphrase <em>optioneel</em></span><input v-model="form.credentialSecret" type="password" autocomplete="new-password" :placeholder="editing ? 'Ongewijzigd laten' : 'Alleen als de sleutel beveiligd is'" /></label>
      </div>
      <div v-else class="form-grid">
        <label class="span-2"><span>SSH-wachtwoord</span><input v-model="form.credentialSecret" :required="!editing" type="password" autocomplete="new-password" :placeholder="editing ? 'Ongewijzigd laten' : 'Voer het SSH-wachtwoord in'" /></label>
      </div>
    </div>

    <div class="card test-card">
      <div><h3>Verbinding controleren</h3><p>We controleren SSH, de serveridentiteit, WP-CLI, WordPress, de database en mappen direct in de WordPress-root.</p></div>
      <button class="button secondary" type="button" :disabled="testing || !valid" @click="test">
        <LoaderCircle v-if="testing" class="spin" :size="17" /><ShieldQuestion v-else :size="17" />
        {{ testing ? 'Controleren…' : 'Verbinding testen' }}
      </button>
    </div>

    <div v-if="result" :class="['connection-result', result.success ? 'success-panel' : 'warning-panel']">
      <div class="result-heading">
        <Check v-if="result.success" /><ShieldQuestion v-else />
        <div>
          <strong>{{ result.success ? 'Verbinding geslaagd' : result.requiresHostKeyAcceptance ? 'Controleer de serveridentiteit' : (result.error?.userMessage ?? 'Verbinding niet voltooid') }}</strong>
          <small v-if="result.success">WordPress {{ result.wordpressVersion }} · PHP {{ result.phpVersion }} · WP-CLI {{ result.wpCliVersion }}</small>
          <small v-else-if="result.requiresHostKeyAcceptance">Vergelijk deze SHA-256-fingerprint zo mogelijk met je hostingprovider: {{ result.fingerprint }}</small>
        </div>
      </div>
      <ul><li v-for="step in result.steps" :key="step.key"><Check v-if="step.status === 'success'" :size="15" /><span v-else class="step-pending"></span>{{ step.label }}</li></ul>
      <div v-if="result.requiresHostKeyAcceptance" class="fingerprint-action">
        <p>Accepteer alleen wanneer je deze server verwacht. De app bewaart de fingerprint bij het opslaan en blokkeert latere wijzigingen.</p>
        <button class="button primary" type="button" :disabled="accepting" @click="acceptFingerprint">{{ accepting ? 'Controleren…' : 'Fingerprint accepteren en doorgaan' }}</button>
      </div>
      <details v-if="result.error?.technicalDetails"><summary>Technische details <ChevronDown :size="14" /></summary><pre>{{ result.error.technicalDetails }}</pre></details>
    </div>

    <section v-if="!editing && result?.success" class="card nested-sites-card">
      <div class="section-heading">
        <span class="section-icon"><FolderTree :size="20" /></span>
        <div>
          <h3>Mappen in de WordPress-root</h3>
          <p>Kies zelf of iedere onverwachte map een aparte WordPress-website is. De app bepaalt dit niet automatisch.</p>
        </div>
      </div>

      <div v-if="!candidates.length" class="nested-sites-empty"><Check :size="18" /><span>Geen onverwachte mappen gevonden.</span></div>
      <p v-if="result.unexpectedDirectoriesTruncated" class="nested-sites-warning"><AlertTriangle :size="15" />Er zijn meer mappen gevonden dan veilig in één keer getoond kunnen worden. Alleen de eerste 200 staan hieronder.</p>

      <div class="nested-sites-list">
        <article v-for="candidate in orderedCandidates" :key="candidate.key" class="nested-site" :style="{ marginLeft: `${Math.min(candidate.depth, 5) * 18}px` }">
          <header>
            <div><small>Gevonden map</small><strong>{{ candidate.directory }}</strong><code>{{ detectedDirectoryPath(candidate) }}</code></div>
            <span v-if="candidate.depth" class="nested-level">Niveau {{ candidate.depth + 1 }}</span>
          </header>

          <fieldset>
            <legend>Wat is deze map?</legend>
            <div class="nested-choice-grid">
              <label :class="{ selected: candidate.choice === 'subdomain' }"><input v-model="candidate.choice" type="radio" value="subdomain" @change="applyChoice(candidate)" /><span><strong>Subdomein</strong><small>Bijvoorbeeld {{ candidate.directory }}.voorbeeld.nl</small></span></label>
              <label :class="{ selected: candidate.choice === 'subdirectory' }"><input v-model="candidate.choice" type="radio" value="subdirectory" @change="applyChoice(candidate)" /><span><strong>Subdirectory</strong><small>Bijvoorbeeld voorbeeld.nl/{{ candidate.directory }}</small></span></label>
              <label :class="{ selected: candidate.choice === 'none' }"><input v-model="candidate.choice" type="radio" value="none" @change="applyChoice(candidate)" /><span><strong>Geen aparte website</strong><small>De map blijft onderdeel van de normale scan.</small></span></label>
            </div>
          </fieldset>

          <div v-if="candidate.choice === 'subdomain' || candidate.choice === 'subdirectory'" class="nested-site-details">
            <div class="form-grid">
              <label><span>Voorgestelde naam</span><input v-model.trim="candidate.name" required maxlength="100" /></label>
              <label><span>Website-URL</span><input v-model.trim="candidate.url" required type="url" @input="invalidateCandidate(candidate)" /></label>
              <label class="span-2"><span>WordPress-pad</span><input :value="candidate.wordpressPath" readonly /></label>
            </div>
            <div class="nested-verification">
              <span v-if="candidate.checking"><LoaderCircle class="spin" :size="15" />Installatie controleren…</span>
              <span v-else-if="candidate.verified" class="verified"><Check :size="15" />WordPress-installatie gecontroleerd.</span>
              <span v-else-if="candidate.result || candidate.error" class="failed"><AlertTriangle :size="15" />{{ candidate.result?.error?.userMessage ?? candidate.error ?? 'De installatie kon niet worden gecontroleerd.' }}</span>
              <span v-else>Controleer de installatie opnieuw nadat je de URL hebt aangepast.</span>
              <button v-if="!candidate.checking && !candidate.verified" class="button secondary small" type="button" @click="testCandidate(candidate)"><RefreshCw :size="14" />Opnieuw controleren</button>
            </div>
            <p v-if="candidate.result?.unexpectedDirectoriesTruncated" class="nested-sites-warning"><AlertTriangle :size="15" />Niet alle onderliggende mappen konden worden getoond.</p>
          </div>
        </article>
      </div>

      <p v-if="candidates.length && !candidatesComplete" class="nested-sites-help">Maak voor iedere map een keuze. Gekozen websites moeten succesvol gecontroleerd zijn voordat je alles kunt toevoegen.</p>
      <p v-if="!uniqueCandidateTargets" class="nested-sites-warning"><AlertTriangle :size="15" />Twee gekozen websites hebben dezelfde URL of hetzelfde WordPress-pad.</p>
    </section>

    <p v-if="error" class="error-banner">{{ error }}</p>
    <div class="form-actions">
      <RouterLink class="button secondary" to="/websites">Annuleren</RouterLink>
      <button class="button primary" type="submit" :disabled="!canSave">{{ saving ? 'Opslaan…' : (editing ? 'Wijzigingen opslaan' : selectedCandidates.length ? `Website en ${selectedCandidates.length} extra toevoegen` : 'Website toevoegen') }}</button>
    </div>
  </form>
</template>
