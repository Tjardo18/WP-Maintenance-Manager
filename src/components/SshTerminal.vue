<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref, watch } from "vue";
import { AlertTriangle, BookOpen, LoaderCircle, Plug, PlugZap, Server, SquareTerminal } from "@lucide/vue";
import { Terminal } from "@xterm/xterm";
import { FitAddon } from "@xterm/addon-fit";
import "@xterm/xterm/css/xterm.css";
import type { Site, TerminalOutputEvent, TerminalStatusEvent, WpCliCatalog, WpCliSuggestion } from "../types";
import { appApi } from "../services/tauri";
import { applyWpCliSuggestion, WpCliAutocompleteIndex } from "../services/wpCliAutocomplete";
import { loadWpCliCatalog } from "../services/wpCliConsoleSession";
import { completionKeystrokes, decodeTerminalPayload, isWpCliTerminalLine, updateTrackedTerminalLine } from "../services/terminalStream";
import { errorMessage } from "../utils/errors";

const props = defineProps<{ site: Site }>();
const terminalElement = ref<globalThis.HTMLElement>();
const catalog = ref<WpCliCatalog>();
const catalogLoadError = ref<string>();
const connectionStatus = ref<"disconnected" | "connecting" | "connected" | "failed">("disconnected");
const terminalSessionId = ref<string>();
const connectionError = ref<string>();
const currentLine = ref("");
const selectedSuggestion = ref(0);
const suggestionsDismissed = ref(false);
const acknowledged = ref(globalThis.localStorage?.getItem("wpmm:terminal-warning-v1") === "acknowledged");
let terminal: Terminal | undefined;
let fitAddon: FitAddon | undefined;
let resizeObserver: InstanceType<typeof globalThis.ResizeObserver> | undefined;
let stopOutput: (() => void) | undefined;
let stopStatus: (() => void) | undefined;
let dataDisposable: { dispose(): void } | undefined;
let resizeDisposable: { dispose(): void } | undefined;
let writeQueue = Promise.resolve();

const autocomplete = computed(() => catalog.value?.available ? new WpCliAutocompleteIndex(catalog.value) : undefined);
const wpInput = computed(() => currentLine.value.trimStart());
const autocompleteResult = computed(() => isWpCliTerminalLine(currentLine.value) ? autocomplete.value?.suggest(wpInput.value, wpInput.value.length) : undefined);
const suggestions = computed(() => suggestionsDismissed.value ? [] : autocompleteResult.value?.suggestions ?? []);
const helpCommand = computed(() => autocompleteResult.value?.command);
const positionalParameters = computed(() => autocompleteResult.value?.parameters.filter((parameter) => parameter.positional) ?? []);
const optionParameters = computed(() => autocompleteResult.value?.parameters.filter((parameter) => !parameter.positional) ?? []);
const connected = computed(() => connectionStatus.value === "connected" && Boolean(terminalSessionId.value));

watch(currentLine, () => {
  selectedSuggestion.value = 0;
  suggestionsDismissed.value = false;
});

onMounted(async () => {
  terminal = new Terminal({
    cursorBlink: true,
    disableStdin: true,
    fontFamily: '"Cascadia Mono", Consolas, Menlo, Monaco, "Liberation Mono", monospace',
    fontSize: 12,
    lineHeight: 1.25,
    scrollback: 5_000,
    tabStopWidth: 4,
    theme: { background: "#14201b", foreground: "#dce8e3", cursor: "#78c5a5", selectionBackground: "#44705f99", black: "#14201b", red: "#ef8d92", green: "#7ac2a3", yellow: "#e0b764", blue: "#75a9d4", magenta: "#c9a0dc", cyan: "#70c2c3", white: "#dce8e3" },
  });
  fitAddon = new FitAddon();
  terminal.loadAddon(fitAddon);
  terminal.open(terminalElement.value!);
  fitAddon.fit();
  terminal.writeln("\x1b[38;5;108mSSH Terminal — klik op Verbinden om een sessie te starten.\x1b[0m");
  dataDisposable = terminal.onData(handleTerminalInput);
  resizeDisposable = terminal.onResize(({ cols, rows }) => {
    if (terminalSessionId.value) void appApi.resizeTerminal(terminalSessionId.value, cols, rows).catch(handleConnectionFailure);
  });
  if (globalThis.ResizeObserver) {
    resizeObserver = new globalThis.ResizeObserver(() => fitAddon?.fit());
    resizeObserver.observe(terminalElement.value!);
  }
  stopOutput = await appApi.onTerminalOutput(handleOutput);
  stopStatus = await appApi.onTerminalStatus(handleStatus);
  try { catalog.value = await loadWpCliCatalog(); }
  catch (cause) { catalogLoadError.value = errorMessage(cause); }
});

onUnmounted(() => {
  const id = terminalSessionId.value;
  terminalSessionId.value = undefined;
  if (id) void appApi.closeTerminal(id).catch(() => undefined);
  stopOutput?.();
  stopStatus?.();
  dataDisposable?.dispose();
  resizeDisposable?.dispose();
  resizeObserver?.disconnect();
  terminal?.dispose();
});

function acknowledgeWarning() {
  acknowledged.value = true;
  globalThis.localStorage?.setItem("wpmm:terminal-warning-v1", "acknowledged");
}

async function connect() {
  if (!terminal || !fitAddon || connectionStatus.value === "connecting") return;
  connectionStatus.value = "connecting";
  connectionError.value = undefined;
  currentLine.value = "";
  terminal.clear();
  terminal.writeln(`\x1b[38;5;108mVerbinden met ${props.site.sshUsername}@${props.site.sshHost}:${props.site.sshPort}…\x1b[0m`);
  try {
    fitAddon.fit();
    const result = await appApi.openTerminal(props.site.id, terminal.cols, terminal.rows);
    terminalSessionId.value = result.sessionId;
    connectionStatus.value = "connected";
    terminal.options.disableStdin = false;
    terminal.focus();
  } catch (cause) {
    handleConnectionFailure(cause);
  }
}

async function disconnect() {
  const id = terminalSessionId.value;
  terminalSessionId.value = undefined;
  connectionStatus.value = "disconnected";
  currentLine.value = "";
  if (terminal) terminal.options.disableStdin = true;
  if (id) {
    try { await appApi.closeTerminal(id); }
    catch (cause) { connectionError.value = errorMessage(cause); }
  }
}

function handleOutput(payload: TerminalOutputEvent) {
  if (terminalSessionId.value ? payload.sessionId !== terminalSessionId.value : connectionStatus.value !== "connecting") return;
  terminal?.write(decodeTerminalPayload(payload.dataBase64));
}

function handleStatus(payload: TerminalStatusEvent) {
  if (terminalSessionId.value ? payload.sessionId !== terminalSessionId.value : connectionStatus.value !== "connecting") return;
  if (payload.status === "connected") return;
  terminalSessionId.value = undefined;
  connectionStatus.value = payload.status;
  if (terminal) terminal.options.disableStdin = true;
  if (payload.error || payload.message) connectionError.value = payload.error ? errorMessage(payload.error) : payload.message;
}

function handleConnectionFailure(cause: unknown) {
  terminalSessionId.value = undefined;
  connectionStatus.value = "failed";
  connectionError.value = errorMessage(cause);
  if (terminal) {
    terminal.options.disableStdin = true;
    terminal.writeln(`\r\n\x1b[31m${connectionError.value}\x1b[0m`);
  }
}

function queueInput(data: string) {
  const id = terminalSessionId.value;
  if (!id) return;
  writeQueue = writeQueue.then(() => appApi.writeTerminal(id, data)).catch(handleConnectionFailure);
}

function handleTerminalInput(data: string) {
  if (!connected.value) return;
  if (data === "\t" && suggestions.value.length) {
    chooseSuggestion(suggestions.value[selectedSuggestion.value]!);
    return;
  }
  if (data === "\u001b[B" || data === "\u001b[A") suggestionsDismissed.value = true;
  currentLine.value = updateTrackedTerminalLine(currentLine.value, data);
  queueInput(data);
}

function chooseSuggestion(suggestion: WpCliSuggestion) {
  if (!connected.value) return;
  const leading = currentLine.value.slice(0, currentLine.value.length - wpInput.value.length);
  const applied = applyWpCliSuggestion(wpInput.value, suggestion);
  const completed = leading + applied.value;
  queueInput(completionKeystrokes(currentLine.value, completed));
  currentLine.value = completed;
  suggestionsDismissed.value = true;
  terminal?.focus();
}

function sendExample(command: string) {
  if (!connected.value || currentLine.value) return;
  currentLine.value = command;
  queueInput(command);
  terminal?.focus();
}
</script>

<template>
  <div class="terminal-page">
    <section class="card terminal-context" aria-label="Actieve SSH-server">
      <span class="terminal-context-icon"><SquareTerminal :size="21" /></span>
      <div><small>SSH Terminal · SSH + WP-CLI</small><h3>{{ site.name }}</h3><a :href="site.url" target="_blank" rel="noreferrer">{{ site.url }}</a></div>
      <dl><div><dt>SSH-gebruiker</dt><dd>{{ site.sshUsername }}@{{ site.sshHost }}:{{ site.sshPort }}</dd></div><div><dt>Startpad</dt><dd>{{ site.wordpressPath }}</dd></div></dl>
      <span :class="['terminal-connection-status', connectionStatus]"><span></span>{{ connectionStatus === 'connected' ? 'Verbonden' : connectionStatus === 'connecting' ? 'Verbinden…' : connectionStatus === 'failed' ? 'Verbinding mislukt' : 'Niet verbonden' }}</span>
      <button v-if="connected" class="button small secondary" @click="disconnect"><PlugZap :size="14" /> Verbreken</button><button v-else class="button small primary" :disabled="connectionStatus === 'connecting' || !acknowledged" @click="connect"><LoaderCircle v-if="connectionStatus === 'connecting'" class="spin" :size="14" /><Plug v-else :size="14" /> Verbinden</button>
    </section>

    <section v-if="!acknowledged" class="terminal-warning"><AlertTriangle :size="19" /><div><strong>Geavanceerde terminal</strong><p>Commando's worden rechtstreeks op <b>{{ site.name }}</b> uitgevoerd met de rechten van het gekoppelde SSH-account. Controleer altijd de geselecteerde website voordat je wijzigingen uitvoert.</p></div><button class="button small secondary" @click="acknowledgeWarning">Begrepen</button></section>
    <p v-if="connectionError" class="error-banner">{{ connectionError }} <RouterLink to="/foutenlog">Open in foutenlog</RouterLink></p>
    <section v-if="catalogLoadError || catalog?.available === false" class="wpcli-catalog-warning"><AlertTriangle :size="18" /><div><strong>WP-CLI autocomplete niet beschikbaar</strong><p>De SSH-terminal blijft werken; alleen de hulp uit <code>wp-cli-commands.json</code> ontbreekt.</p></div></section>

    <div class="terminal-layout">
      <section class="card terminal-shell-card">
        <header><div><SquareTerminal :size="16" /><strong>Terminal</strong><span>PTY · xterm-256color</span></div><small>Ctrl+C onderbreekt het actieve remote proces</small></header>
        <div class="terminal-stage">
          <div ref="terminalElement" class="terminal-xterm" data-testid="terminal-xterm"></div>
          <div v-if="connected && suggestions.length" class="terminal-suggestions" role="listbox">
            <button v-for="(suggestion, index) in suggestions" :key="suggestion.id" :class="{ selected: index === selectedSuggestion }" role="option" @mousedown.prevent="chooseSuggestion(suggestion)" @mouseenter="selectedSuggestion = index"><span>{{ suggestion.type === 'command' || suggestion.type === 'subcommand' ? 'Command' : 'Parameter' }}</span><code>{{ suggestion.label }}</code><small>{{ suggestion.description || 'Geen beschrijving beschikbaar.' }}</small></button>
          </div>
        </div>
        <footer><span>De actieve shell bewaart de huidige directory en omgevingsstatus tot je de verbinding verbreekt.</span><div><button :disabled="!connected" @click="sendExample('pwd')">pwd</button><button :disabled="!connected" @click="sendExample('ls -lah')">ls -lah</button><button :disabled="!connected" @click="sendExample('wp plugin list')">wp plugin list</button></div></footer>
      </section>

      <aside class="card terminal-help">
        <header><BookOpen :size="17" /><div><strong>{{ isWpCliTerminalLine(currentLine) ? 'WP-CLI help' : 'Terminalcontext' }}</strong><small v-if="catalog?.available">{{ catalog.totalCommandCount }} WP-CLI commands geladen</small></div></header>
        <div v-if="helpCommand" class="terminal-help-content"><span>Command</span><h3><code>{{ helpCommand.fullCommand }}</code></h3><p>{{ helpCommand.description || 'Geen beschrijving beschikbaar.' }}</p><template v-if="positionalParameters.length"><h4>Argumenten</h4><dl><div v-for="parameter in positionalParameters" :key="parameter.rawSyntax"><dt><code>{{ parameter.displayText }}</code></dt><dd>{{ parameter.description }}</dd></div></dl></template><template v-if="optionParameters.length"><h4>Parameters</h4><dl><div v-for="parameter in optionParameters" :key="parameter.rawSyntax"><dt><code>{{ parameter.displayText }}</code></dt><dd>{{ parameter.description }}</dd></div></dl></template></div>
        <div v-else class="terminal-help-empty"><Server :size="30" /><strong>{{ connected ? 'Vrije SSH-shell' : 'Nog niet verbonden' }}</strong><p>{{ connected ? 'Typ een normaal Linux-commando. Alleen wanneer de nieuwe commandoregel met “wp” begint, verschijnt hier WP-CLI hulp.' : `Verbind met ${site.name} om in ${site.wordpressPath} te starten.` }}</p></div>
        <footer><AlertTriangle :size="14" /><span>Terminalcommando's worden niet in de lokale geschiedenis of het foutenlog opgeslagen. De remote shell kan zijn eigen historybeleid hebben.</span></footer>
      </aside>
    </div>
  </div>
</template>
