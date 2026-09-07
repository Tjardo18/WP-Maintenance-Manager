<script setup lang="ts">
import { computed, nextTick, onMounted, ref, watch } from "vue";
import { AlertTriangle, BookOpen, CheckCircle2, Eraser, LoaderCircle, Play, Server, SquareTerminal } from "@lucide/vue";
import type { Site, WpCliCatalog, WpCliCommandInspection, WpCliRisk, WpCliSuggestion } from "../types";
import { appApi } from "../services/tauri";
import { applyWpCliSuggestion, WpCliAutocompleteIndex } from "../services/wpCliAutocomplete";
import { appendWpCliOutput, getWpCliConsoleSession, loadWpCliCatalog, rememberWpCliCommand } from "../services/wpCliConsoleSession";
import { errorMessage } from "../utils/errors";
import ConfirmDialog from "./ConfirmDialog.vue";

const props = defineProps<{ site: Site }>();
const examples = ["wp core version", "wp plugin list", "wp theme list", "wp user list", "wp core verify-checksums --include-root"];
const session = getWpCliConsoleSession(props.site.id);
const input = ref<globalThis.HTMLInputElement>();
const outputPanel = ref<globalThis.HTMLElement>();
const catalog = ref<WpCliCatalog>();
const catalogLoadError = ref<string>();
const caret = ref(0);
const focused = ref(false);
const autocompleteDismissed = ref(false);
const selectedSuggestion = ref(0);
const historyPosition = ref(session.history.length);
const historyDraft = ref("");
const inspecting = ref(false);
const running = ref(false);
const runningStartedAt = ref<string>();
const pending = ref<{ command: string; inspection: WpCliCommandInspection }>();
const typedConfirmation = ref("");

const autocomplete = computed(() => catalog.value?.available ? new WpCliAutocompleteIndex(catalog.value) : undefined);
const autocompleteResult = computed(() => autocomplete.value?.suggest(session.command, caret.value));
const suggestions = computed(() => autocompleteResult.value?.suggestions ?? []);
const suggestionsOpen = computed(() => focused.value && !autocompleteDismissed.value && suggestions.value.length > 0);
const helpCommand = computed(() => autocompleteResult.value?.command);
const positionalParameters = computed(() => autocompleteResult.value?.parameters.filter((parameter) => parameter.positional) ?? []);
const optionParameters = computed(() => autocompleteResult.value?.parameters.filter((parameter) => !parameter.positional) ?? []);
const canRun = computed(() => !running.value && !inspecting.value && /^wp(?:\s|$)/.test(session.command.trim()));

onMounted(async () => {
  try { catalog.value = await loadWpCliCatalog(); }
  catch (cause) { catalogLoadError.value = errorMessage(cause); }
});

watch(() => session.command, () => {
  selectedSuggestion.value = 0;
  autocompleteDismissed.value = false;
});

function updateCaret() {
  caret.value = input.value?.selectionStart ?? session.command.length;
}

function fillCommand(command: string) {
  session.command = command;
  void nextTick(() => {
    input.value?.focus();
    input.value?.setSelectionRange(command.length, command.length);
    updateCaret();
  });
}

function chooseSuggestion(suggestion: WpCliSuggestion) {
  const applied = applyWpCliSuggestion(session.command, suggestion);
  session.command = applied.value;
  void nextTick(() => {
    input.value?.focus();
    input.value?.setSelectionRange(applied.cursor, applied.cursor);
    caret.value = applied.cursor;
  });
}

function navigateHistory(direction: -1 | 1) {
  if (!session.history.length) return;
  if (historyPosition.value === session.history.length && direction === -1) historyDraft.value = session.command;
  historyPosition.value = Math.max(0, Math.min(session.history.length, historyPosition.value + direction));
  fillCommand(historyPosition.value === session.history.length ? historyDraft.value : session.history[historyPosition.value]!);
}

function onKeydown(event: globalThis.KeyboardEvent) {
  if (event.key === "Enter" && event.ctrlKey) {
    event.preventDefault();
    void requestRun();
    return;
  }
  if (suggestionsOpen.value) {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const step = event.key === "ArrowDown" ? 1 : -1;
      selectedSuggestion.value = (selectedSuggestion.value + step + suggestions.value.length) % suggestions.value.length;
      return;
    }
    if (event.key === "Tab" || event.key === "Enter") {
      event.preventDefault();
      chooseSuggestion(suggestions.value[selectedSuggestion.value]!);
      return;
    }
    if (event.key === "Escape") {
      event.preventDefault();
      autocompleteDismissed.value = true;
      return;
    }
  }
  if (event.key === "Enter") {
    event.preventDefault();
    void requestRun();
  } else if (event.key === "ArrowUp" || event.key === "ArrowDown") {
    event.preventDefault();
    navigateHistory(event.key === "ArrowUp" ? -1 : 1);
  }
}

async function requestRun() {
  if (!canRun.value) return;
  const command = session.command.trim();
  inspecting.value = true;
  try {
    const inspection = await appApi.inspectWpCliCommand(props.site.id, command);
    if (inspection.requiresConfirmation) {
      typedConfirmation.value = "";
      pending.value = { command, inspection };
      return;
    }
    await executeCommand(command, inspection, false);
  } catch (cause) {
    appendError(command, "mutating", cause);
  } finally {
    inspecting.value = false;
  }
}

async function confirmRun() {
  if (!pending.value) return;
  const { command, inspection } = pending.value;
  if (inspection.requiresTypedConfirmation && typedConfirmation.value !== inspection.confirmationPhrase) return;
  pending.value = undefined;
  await executeCommand(command, inspection, true);
}

async function executeCommand(command: string, inspection: WpCliCommandInspection, confirmed: boolean) {
  if (running.value) return;
  running.value = true;
  const startedAt = new Date().toISOString();
  runningStartedAt.value = startedAt;
  rememberWpCliCommand(session, command);
  historyPosition.value = session.history.length;
  try {
    const result = await appApi.executeWpCliCommand(props.site.id, command, confirmed, confirmed ? typedConfirmation.value : undefined);
    appendWpCliOutput(session, { command, risk: result.risk, result, startedAt, finishedAt: result.finishedAt });
  } catch (cause) {
    appendError(command, inspection.risk, cause, startedAt);
  } finally {
    running.value = false;
    runningStartedAt.value = undefined;
    typedConfirmation.value = "";
    void scrollOutputToEnd();
  }
}

function appendError(command: string, risk: WpCliRisk, cause: unknown, startedAt = new Date().toISOString()) {
  appendWpCliOutput(session, { command, risk, error: errorMessage(cause), startedAt, finishedAt: new Date().toISOString() });
  void scrollOutputToEnd();
}

async function scrollOutputToEnd() {
  await nextTick();
  outputPanel.value?.scrollTo({ top: outputPanel.value.scrollHeight });
}

function formatTime(value: string) {
  return new Intl.DateTimeFormat("nl-NL", { hour: "2-digit", minute: "2-digit", second: "2-digit" }).format(new Date(value));
}

function riskLabel(risk: WpCliRisk) {
  return risk === "readOnly" ? "Alleen-lezen" : risk === "highRisk" ? "Hoog risico" : "Muterend";
}
</script>

<template>
  <div class="wpcli-page">
    <section class="card wpcli-context" aria-label="Actieve website">
      <span class="wpcli-context-icon"><SquareTerminal :size="21" /></span>
      <div class="wpcli-context-title"><small>WP-CLI Console · geselecteerde website</small><h3>{{ site.name }}</h3><a :href="site.url" target="_blank" rel="noreferrer">{{ site.url }}</a></div>
      <dl><div><dt>WordPress-pad</dt><dd>{{ site.wordpressPath }}</dd></div><div><dt>SSH-doel</dt><dd>{{ site.sshUsername }}@{{ site.sshHost }}:{{ site.sshPort }}</dd></div></dl>
      <span class="status-badge status-pending"><span class="status-dot"></span>Verbinding per commando</span>
    </section>

    <section v-if="!session.acknowledgedAdvancedWarning" class="wpcli-advanced-notice">
      <AlertTriangle :size="19" /><div><strong>Geavanceerde functie</strong><p>WP-CLI-commando's kunnen rechtstreeks wijzigingen aanbrengen in <b>{{ site.name }}</b>. Controleer het commando en de geselecteerde website voordat je het uitvoert.</p></div><button class="button small secondary" @click="session.acknowledgedAdvancedWarning = true">Begrepen</button>
    </section>

    <section v-if="catalogLoadError || catalog?.available === false" class="wpcli-catalog-warning">
      <AlertTriangle :size="18" /><div><strong>WP-CLI commandodatabase niet gevonden</strong><p>Commands uitvoeren blijft mogelijk. Plaats <code>wp-cli-commands.json</code> in <code>src-tauri/resources/wp-cli-commands.json</code> voor autocomplete en hulp.</p><details v-if="catalog?.technicalDetails || catalogLoadError"><summary>Technische details</summary><pre>{{ catalog?.technicalDetails ?? catalogLoadError }}</pre></details></div>
    </section>

    <div class="wpcli-layout">
      <section class="card wpcli-console-card">
        <header class="wpcli-console-header"><div><SquareTerminal :size="17" /><strong>Uitvoer</strong><span v-if="catalog?.available" class="wpcli-db-status">{{ catalog.totalCommandCount }} commands geladen</span></div><button class="button small ghost" :disabled="!session.outputs.length || running" @click="session.outputs.splice(0)"><Eraser :size="14" /> Console wissen</button></header>
        <div ref="outputPanel" class="wpcli-output" aria-live="polite">
          <div v-if="!session.outputs.length && !running" class="wpcli-empty"><SquareTerminal :size="34" /><strong>Begin met typen</strong><p>Typ <code>wp</code> om alle beschikbare commando's te zien, of kies een veilig voorbeeld.</p><div><button v-for="example in examples" :key="example" @click="fillCommand(example)">{{ example }}</button></div></div>
          <article v-for="entry in session.outputs" :key="entry.id" class="wpcli-output-entry">
            <header><code><span>&gt;</span> {{ entry.command }}</code><span :class="['wpcli-risk', entry.risk]">{{ riskLabel(entry.risk) }}</span></header>
            <pre v-if="entry.result?.stdout" class="console-stdout">{{ entry.result.stdout }}</pre>
            <pre v-if="entry.result?.stderr" class="console-stderr">{{ entry.result.stderr }}</pre>
            <p v-if="entry.error" class="console-error">{{ entry.error }}</p>
            <p v-if="entry.result?.truncated" class="console-truncated">Output afgekapt omdat deze te groot werd.</p>
            <footer :class="entry.result?.status ?? 'failed'"><CheckCircle2 v-if="entry.result?.status === 'success'" :size="13" /><AlertTriangle v-else :size="13" /><span>{{ entry.result?.status === 'success' ? 'Commando succesvol afgerond' : entry.result?.status === 'warning' ? 'Commando afgerond met waarschuwing' : 'Commando mislukt' }}</span><span v-if="entry.result">Exit code: {{ entry.result.exitCode }}</span><span v-if="entry.result">Duur: {{ entry.result.durationMs }} ms</span><span>{{ formatTime(entry.finishedAt) }}</span></footer>
          </article>
          <article v-if="running" class="wpcli-running"><LoaderCircle class="spin" :size="19" /><div><strong>Commando uitvoeren…</strong><small>Gestart om {{ formatTime(runningStartedAt!) }} · wacht op WP-CLI via SSH</small></div></article>
        </div>
        <div class="wpcli-command-area">
          <div class="wpcli-input-wrap">
            <span class="wpcli-prompt">&gt;</span>
            <input ref="input" v-model="session.command" data-testid="wpcli-input" type="text" spellcheck="false" autocomplete="off" aria-label="WP-CLI-commando" aria-autocomplete="list" :aria-expanded="suggestionsOpen" :disabled="running" placeholder="wp core version" @focus="focused = true; updateCaret()" @blur="focused = false" @click="updateCaret" @keyup="updateCaret" @input="updateCaret" @keydown="onKeydown" />
            <span class="wpcli-shortcut">Ctrl ↵</span>
            <div v-if="suggestionsOpen" class="wpcli-suggestions" role="listbox">
              <button v-for="(suggestion, index) in suggestions" :key="suggestion.id" :class="{ selected: index === selectedSuggestion }" role="option" :aria-selected="index === selectedSuggestion" @mousedown.prevent="chooseSuggestion(suggestion)" @mouseenter="selectedSuggestion = index">
                <span class="wpcli-suggestion-type">{{ suggestion.type === 'command' || suggestion.type === 'subcommand' ? 'Command' : suggestion.type === 'globalParameter' ? 'Globaal' : 'Parameter' }}</span><span class="wpcli-suggestion-copy"><code>{{ suggestion.label }}</code><small>{{ suggestion.description || 'Geen beschrijving beschikbaar.' }}</small></span><span v-if="suggestion.parameter?.takesValue" class="wpcli-value-hint">{{ suggestion.parameter.placeholder ? `&lt;${suggestion.parameter.placeholder}&gt;` : 'waarde' }}</span>
              </button>
            </div>
          </div>
          <button class="button primary wpcli-run" data-testid="wpcli-run" :disabled="!canRun" @click="requestRun"><LoaderCircle v-if="running || inspecting" class="spin" :size="15" /><Play v-else :size="15" /> {{ inspecting ? 'Controleren…' : 'Uitvoeren' }}</button>
        </div>
        <p class="wpcli-input-help">Alleen WP-CLI-commando's zijn toegestaan. Het opgeslagen WordPress-pad wordt door de backend gebruikt; <code>--path</code>, <code>--ssh</code>, <code>--http</code> en aliassen worden daarom niet geaccepteerd.</p>
      </section>

      <aside class="card wpcli-help">
        <header><BookOpen :size="17" /><div><strong>Command help</strong><small v-if="catalog?.available">Bron: {{ catalog.source }}</small></div></header>
        <div v-if="helpCommand" class="wpcli-help-content"><span class="wpcli-help-label">Command</span><h3><code>{{ helpCommand.fullCommand }}</code></h3><p>{{ helpCommand.description || 'Geen beschrijving beschikbaar.' }}</p>
          <template v-if="positionalParameters.length"><h4>Positionele argumenten</h4><dl><div v-for="parameter in positionalParameters" :key="parameter.rawSyntax"><dt><code>{{ parameter.displayText }}</code><span v-if="parameter.required">Verplicht</span><span v-if="parameter.repeatable">Herhaalbaar</span></dt><dd>{{ parameter.description || 'Geen beschrijving beschikbaar.' }}</dd></div></dl></template>
          <template v-if="optionParameters.length"><h4>Parameters</h4><dl><div v-for="parameter in optionParameters" :key="parameter.rawSyntax"><dt><code>{{ parameter.displayText }}</code><span v-if="parameter.required">Verplicht</span><span v-if="parameter.repeatable">Herhaalbaar</span></dt><dd>{{ parameter.description || 'Geen beschrijving beschikbaar.' }}</dd></div></dl></template>
          <details v-if="autocompleteResult?.globalParameters.length" class="wpcli-global-help"><summary>Globale WP-CLI parameters ({{ autocompleteResult.globalParameters.length }})</summary><dl><div v-for="parameter in autocompleteResult.globalParameters" :key="parameter.rawSyntax"><dt><code>{{ parameter.displayText }}</code></dt><dd>{{ parameter.description || 'Geen beschrijving beschikbaar.' }}</dd></div></dl></details>
        </div>
        <div v-else class="wpcli-help-empty"><BookOpen :size="30" /><strong>{{ autocompleteResult?.unknownCommand ? 'Custom command' : 'Hulp verschijnt hier' }}</strong><p>{{ autocompleteResult?.unknownCommand ? 'Dit commando staat niet in de helpdatabase, maar kan na backendcontrole wel worden uitgevoerd.' : 'Selecteer of typ een volledig command om parameters en uitleg te bekijken.' }}</p></div>
        <footer v-if="catalog?.available"><Server :size="14" /><span>{{ catalog.rootCommandCount }} hoofdcommando's · {{ catalog.totalCommandCount }} totaal · {{ catalog.globalParameterCount }} globale parameters<small v-if="catalog.scrapedAt">Gegenereerd: {{ catalog.scrapedAt }}</small></span></footer>
      </aside>
    </div>

    <ConfirmDialog v-if="pending" :title="pending.inspection.requiresTypedConfirmation ? 'Waarschuwing: destructief WP-CLI-commando' : 'WP-CLI-commando bevestigen'" :confirm-label="pending.inspection.requiresTypedConfirmation ? 'Toch uitvoeren' : 'Uitvoeren'" :danger="pending.inspection.requiresTypedConfirmation" :busy="running" :confirm-disabled="pending.inspection.requiresTypedConfirmation && typedConfirmation !== pending.inspection.confirmationPhrase" @cancel="pending = undefined; typedConfirmation = ''" @confirm="confirmRun">
      <p>{{ pending.inspection.summary }}</p><div class="wpcli-confirm-site"><strong>Geselecteerde website</strong><span>{{ site.name }}</span><code>{{ site.wordpressPath }}</code></div><div class="wpcli-confirm-command"><strong>Command</strong><code>{{ pending.command }}</code></div>
      <label v-if="pending.inspection.requiresTypedConfirmation" class="wpcli-confirm-input"><span>Typ <code>{{ pending.inspection.confirmationPhrase }}</code> om door te gaan</span><input v-model="typedConfirmation" autocomplete="off" spellcheck="false" /></label>
    </ConfirmDialog>
  </div>
</template>
