<script setup lang="ts">
import { computed, nextTick, onMounted, onUnmounted, ref, watch } from "vue";
import { AlertTriangle, BookOpen, Eye, EyeOff, KeyRound, LoaderCircle, LockKeyhole, PlugZap, Server, ShieldCheck, SquareTerminal } from "@lucide/vue";
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
const emit = defineEmits<{ cancel: [] }>();
type UnlockStep = "app" | "ssh" | "sshFailed" | "terminal";

const terminalElement = ref<globalThis.HTMLElement>();
const catalog = ref<WpCliCatalog>();
const catalogLoadError = ref<string>();
const unlockStep = ref<UnlockStep>("app");
const appPassword = ref("");
const sshPassword = ref("");
const showAppPassword = ref(false);
const showSshPassword = ref(false);
const challengeToken = ref<string>();
const challengeExpiresIn = ref(60);
const unlockBusy = ref(false);
const unlockError = ref<string>();
const connectionStatus = ref<"disconnected" | "connecting" | "connected" | "failed">("disconnected");
const terminalSessionId = ref<string>();
const terminalAuthorization = ref<string>();
const connectionError = ref<string>();
const currentLine = ref("");
const selectedSuggestion = ref(0);
const suggestionsDismissed = ref(false);
const acknowledged = ref(globalThis.localStorage?.getItem("wpmm:terminal-warning-v1") === "acknowledged");
const pendingOutput = new Array<TerminalOutputEvent>();
const queuedOutput = new Array<Uint8Array>();
let terminal: Terminal | undefined;
let fitAddon: FitAddon | undefined;
let resizeObserver: InstanceType<typeof globalThis.ResizeObserver> | undefined;
let stopOutput: (() => void) | undefined;
let stopStatus: (() => void) | undefined;
let dataDisposable: { dispose(): void } | undefined;
let resizeDisposable: { dispose(): void } | undefined;
let writeQueue = Promise.resolve();
let outputFrame: number | undefined;

const autocomplete = computed(() => catalog.value?.available ? new WpCliAutocompleteIndex(catalog.value) : undefined);
const wpInput = computed(() => currentLine.value.trimStart());
const autocompleteResult = computed(() => isWpCliTerminalLine(currentLine.value) ? autocomplete.value?.suggest(wpInput.value, wpInput.value.length) : undefined);
const suggestions = computed(() => suggestionsDismissed.value ? [] : autocompleteResult.value?.suggestions ?? []);
const helpCommand = computed(() => autocompleteResult.value?.command);
const positionalParameters = computed(() => autocompleteResult.value?.parameters.filter((parameter) => parameter.positional) ?? []);
const optionParameters = computed(() => autocompleteResult.value?.parameters.filter((parameter) => !parameter.positional) ?? []);
const connected = computed(() => connectionStatus.value === "connected" && Boolean(terminalSessionId.value) && Boolean(terminalAuthorization.value));

watch(currentLine, () => {
  selectedSuggestion.value = 0;
  suggestionsDismissed.value = false;
});

watch(() => props.site.id, (_siteId, previousSiteId) => {
  void closeAndReset(previousSiteId);
});

onMounted(async () => {
  stopOutput = await appApi.onTerminalOutput(handleOutput);
  stopStatus = await appApi.onTerminalStatus(handleStatus);
  try { catalog.value = await loadWpCliCatalog(); }
  catch (cause) { catalogLoadError.value = errorMessage(cause); }
});

onUnmounted(() => {
  clearPasswordFields();
  const id = terminalSessionId.value;
  const authorization = terminalAuthorization.value;
  const challenge = challengeToken.value;
  terminalSessionId.value = undefined;
  terminalAuthorization.value = undefined;
  challengeToken.value = undefined;
  if (id && authorization) void appApi.closeTerminal(id, authorization).catch(() => undefined);
  if (challenge) void appApi.cancelTerminalReauthentication(props.site.id, challenge).catch(() => undefined);
  stopOutput?.();
  stopStatus?.();
  teardownTerminal();
});

function acknowledgeWarning() {
  acknowledged.value = true;
  globalThis.localStorage?.setItem("wpmm:terminal-warning-v1", "acknowledged");
}

function errorCategory(cause: unknown): string {
  return typeof cause === "object" && cause !== null && "category" in cause
    ? String((cause as { category: unknown }).category)
    : "";
}

function clearPasswordFields() {
  appPassword.value = "";
  sshPassword.value = "";
  showAppPassword.value = false;
  showSshPassword.value = false;
}

async function submitAppPassword() {
  if (!appPassword.value || unlockBusy.value || !acknowledged.value) return;
  unlockBusy.value = true;
  unlockError.value = undefined;
  const submittedPassword = appPassword.value;
  appPassword.value = "";
  try {
    const challenge = await appApi.beginTerminalReauthentication(props.site.id, submittedPassword);
    challengeToken.value = challenge.challengeToken;
    challengeExpiresIn.value = challenge.expiresInSeconds;
    unlockStep.value = "ssh";
  } catch (cause) {
    if (errorCategory(cause) !== "app_session_revoked_reauth_failed") unlockError.value = errorMessage(cause);
  } finally {
    unlockBusy.value = false;
  }
}

async function submitSshPassword() {
  const challenge = challengeToken.value;
  if (!sshPassword.value || !challenge || unlockBusy.value) return;
  unlockBusy.value = true;
  unlockError.value = undefined;
  connectionError.value = undefined;
  connectionStatus.value = "connecting";
  const submittedPassword = sshPassword.value;
  sshPassword.value = "";
  challengeToken.value = undefined;
  try {
    const result = await appApi.openTerminal(props.site.id, challenge, submittedPassword, 100, 30);
    terminalSessionId.value = result.sessionId;
    terminalAuthorization.value = result.authorizationToken;
    connectionStatus.value = "connected";
    unlockStep.value = "terminal";
    await nextTick();
    initializeTerminal();
  } catch (cause) {
    terminalSessionId.value = undefined;
    terminalAuthorization.value = undefined;
    connectionStatus.value = "failed";
    if (!["locked", "session_expired", "invalid_session", "app_session_revoked_reauth_failed"].includes(errorCategory(cause))) {
      unlockError.value = errorMessage(cause);
      unlockStep.value = "sshFailed";
    }
  } finally {
    unlockBusy.value = false;
  }
}

async function cancelUnlock() {
  const challenge = challengeToken.value;
  challengeToken.value = undefined;
  clearPasswordFields();
  if (challenge) {
    try { await appApi.cancelTerminalReauthentication(props.site.id, challenge); }
    catch { /* Session errors are handled centrally by the API layer. */ }
  }
  emit("cancel");
}

function retryUnlock() {
  clearPasswordFields();
  unlockError.value = undefined;
  connectionError.value = undefined;
  connectionStatus.value = "disconnected";
  challengeToken.value = undefined;
  unlockStep.value = "app";
}

function initializeTerminal() {
  if (!terminalElement.value || !terminalSessionId.value || !terminalAuthorization.value) return;
  teardownTerminal();
  terminal = new Terminal({
    cursorBlink: true,
    disableStdin: false,
    fontFamily: '"Cascadia Mono", Consolas, Menlo, Monaco, "Liberation Mono", monospace',
    fontSize: 12,
    lineHeight: 1.25,
    scrollback: 5_000,
    tabStopWidth: 4,
    theme: { background: "#14201b", foreground: "#dce8e3", cursor: "#78c5a5", selectionBackground: "#44705f99", black: "#14201b", red: "#ef8d92", green: "#7ac2a3", yellow: "#e0b764", blue: "#75a9d4", magenta: "#c9a0dc", cyan: "#70c2c3", white: "#dce8e3" },
  });
  fitAddon = new FitAddon();
  terminal.loadAddon(fitAddon);
  terminal.open(terminalElement.value);
  fitAddon.fit();
  terminal.writeln(`\x1b[38;5;108mBeveiligd verbonden met ${props.site.sshUsername}@${props.site.sshHost}.\x1b[0m`);
  dataDisposable = terminal.onData(handleTerminalInput);
  resizeDisposable = terminal.onResize(({ cols, rows }) => {
    const id = terminalSessionId.value;
    const authorization = terminalAuthorization.value;
    if (id && authorization) void appApi.resizeTerminal(id, authorization, cols, rows).catch(handleConnectionFailure);
  });
  if (globalThis.ResizeObserver) {
    resizeObserver = new globalThis.ResizeObserver(() => fitAddon?.fit());
    resizeObserver.observe(terminalElement.value);
  }
  for (const payload of pendingOutput.splice(0)) {
    if (payload.sessionId === terminalSessionId.value) queueTerminalOutput(decodeTerminalPayload(payload.dataBase64));
  }
  const id = terminalSessionId.value;
  const authorization = terminalAuthorization.value;
  if (id && authorization) void appApi.resizeTerminal(id, authorization, terminal.cols, terminal.rows).catch(handleConnectionFailure);
  terminal.focus();
}

function teardownTerminal() {
  dataDisposable?.dispose();
  resizeDisposable?.dispose();
  resizeObserver?.disconnect();
  terminal?.dispose();
  dataDisposable = undefined;
  resizeDisposable = undefined;
  resizeObserver = undefined;
  fitAddon = undefined;
  terminal = undefined;
  pendingOutput.splice(0);
  queuedOutput.splice(0);
  if (outputFrame !== undefined) globalThis.cancelAnimationFrame?.(outputFrame);
  outputFrame = undefined;
  currentLine.value = "";
}

async function closeAndReset(challengeSiteId = props.site.id) {
  const id = terminalSessionId.value;
  const authorization = terminalAuthorization.value;
  const challenge = challengeToken.value;
  terminalSessionId.value = undefined;
  terminalAuthorization.value = undefined;
  challengeToken.value = undefined;
  connectionStatus.value = "disconnected";
  clearPasswordFields();
  teardownTerminal();
  if (id && authorization) {
    try { await appApi.closeTerminal(id, authorization); }
    catch (cause) { if (!["locked", "session_expired", "invalid_session"].includes(errorCategory(cause))) unlockError.value = errorMessage(cause); }
  }
  if (challenge) void appApi.cancelTerminalReauthentication(challengeSiteId, challenge).catch(() => undefined);
  unlockStep.value = "app";
}

function handleOutput(payload: TerminalOutputEvent) {
  if (terminalSessionId.value && payload.sessionId !== terminalSessionId.value) return;
  if (!terminal) {
    if (connectionStatus.value === "connecting" || payload.sessionId === terminalSessionId.value) pendingOutput.push(payload);
    return;
  }
  queueTerminalOutput(decodeTerminalPayload(payload.dataBase64));
}

function queueTerminalOutput(bytes: Uint8Array) {
  queuedOutput.push(bytes);
  if (outputFrame !== undefined) return;
  const schedule = globalThis.requestAnimationFrame ?? ((callback: (time: number) => void) => globalThis.setTimeout(() => callback(globalThis.performance.now()), 16));
  outputFrame = schedule(flushTerminalOutput);
}

function flushTerminalOutput() {
  outputFrame = undefined;
  if (!terminal || !queuedOutput.length) { queuedOutput.splice(0); return; }
  const chunks = queuedOutput.splice(0);
  const merged = new Uint8Array(chunks.reduce((total, chunk) => total + chunk.byteLength, 0));
  let offset = 0;
  for (const chunk of chunks) { merged.set(chunk, offset); offset += chunk.byteLength; }
  terminal.write(merged);
}

function handleStatus(payload: TerminalStatusEvent) {
  if (terminalSessionId.value ? payload.sessionId !== terminalSessionId.value : connectionStatus.value !== "connecting") return;
  if (payload.status === "connected") return;
  const id = terminalSessionId.value;
  const authorization = terminalAuthorization.value;
  terminalSessionId.value = undefined;
  terminalAuthorization.value = undefined;
  if (id && authorization) void appApi.closeTerminal(id, authorization).catch(() => undefined);
  connectionStatus.value = payload.status;
  if (terminal) terminal.options.disableStdin = true;
  if (payload.error || payload.message) connectionError.value = payload.error ? errorMessage(payload.error) : payload.message;
}

function handleConnectionFailure(cause: unknown) {
  const id = terminalSessionId.value;
  const authorization = terminalAuthorization.value;
  terminalSessionId.value = undefined;
  terminalAuthorization.value = undefined;
  if (id && authorization) void appApi.closeTerminal(id, authorization).catch(() => undefined);
  connectionStatus.value = "failed";
  connectionError.value = errorMessage(cause);
  if (terminal) {
    terminal.options.disableStdin = true;
    terminal.writeln(`\r\n\x1b[31m${connectionError.value}\x1b[0m`);
  }
}

function queueInput(data: string) {
  const id = terminalSessionId.value;
  const authorization = terminalAuthorization.value;
  if (!id || !authorization) return;
  writeQueue = writeQueue.then(() => appApi.writeTerminal(id, authorization, data)).catch(handleConnectionFailure);
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
    <section class="card terminal-context" aria-label="Geselecteerde SSH-server">
      <span class="terminal-context-icon"><SquareTerminal :size="21" /></span>
      <div><small>Interactieve Terminal · dubbele verificatie</small><h3>{{ site.name }}</h3><a :href="site.url" target="_blank" rel="noreferrer">{{ site.url }}</a></div>
      <dl><div><dt>SSH-gebruiker</dt><dd>{{ site.sshUsername }}@{{ site.sshHost }}:{{ site.sshPort }}</dd></div><div><dt>Startpad</dt><dd>{{ site.wordpressPath }}</dd></div></dl>
      <span :class="['terminal-connection-status', connectionStatus]"><span></span>{{ connected ? 'Verbonden' : unlockStep === 'terminal' && connectionStatus === 'failed' ? 'Verbinding verbroken' : 'Terminal 🔒' }}</span>
      <button v-if="unlockStep === 'terminal'" class="button small secondary" @click="closeAndReset()"><PlugZap :size="14" /> Sluiten</button>
    </section>

    <section v-if="!acknowledged && unlockStep !== 'terminal'" class="terminal-warning"><AlertTriangle :size="19" /><div><strong>Geavanceerde terminal</strong><p>Commando's worden rechtstreeks op <b>{{ site.name }}</b> uitgevoerd. Iedere opening vereist opnieuw je app-wachtwoord én het SSH-wachtwoord.</p></div><button class="button small secondary" @click="acknowledgeWarning">Begrepen</button></section>

    <section v-if="unlockStep !== 'terminal'" class="card terminal-unlock" aria-labelledby="terminal-unlock-title">
      <header><span><LockKeyhole :size="23" /></span><div><h2 id="terminal-unlock-title">Terminal ontgrendelen</h2><p>Om directe servertoegang te gebruiken moet je opnieuw bevestigen dat jij het bent.</p></div></header>
      <ol class="terminal-unlock-progress" aria-label="Voortgang Terminal-verificatie"><li :class="{ active: unlockStep === 'app', complete: unlockStep === 'ssh' || unlockStep === 'sshFailed' }"><span>1</span> App-verificatie</li><li :class="{ active: unlockStep === 'ssh' || unlockStep === 'sshFailed' }"><span>2</span> SSH-verificatie</li></ol>

      <form v-if="unlockStep === 'app'" class="terminal-unlock-form" data-testid="terminal-app-auth" @submit.prevent="submitAppPassword">
        <div><small>Stap 1 van 2</small><h3>WP Maintenance Manager-wachtwoord</h3><p>Dit wachtwoord wordt opnieuw door de beveiligde backend gecontroleerd.</p></div>
        <label><span>Wachtwoord</span><div class="terminal-password-input"><KeyRound :size="17" /><input v-model="appPassword" :type="showAppPassword ? 'text' : 'password'" autocomplete="off" autocapitalize="off" spellcheck="false" autofocus required /><button type="button" :aria-label="showAppPassword ? 'Wachtwoord verbergen' : 'Wachtwoord tonen'" @click="showAppPassword = !showAppPassword"><EyeOff v-if="showAppPassword" :size="16" /><Eye v-else :size="16" /></button></div></label>
        <p class="terminal-security-note"><ShieldCheck :size="14" /> Een fout app-wachtwoord beëindigt uit voorzorg de volledige applicatiesessie.</p>
        <p v-if="unlockError" class="error-banner">{{ unlockError }}</p>
        <footer><button type="button" class="button secondary" :disabled="unlockBusy" @click="cancelUnlock">Annuleren</button><button class="button primary" :disabled="!appPassword || unlockBusy || !acknowledged"><LoaderCircle v-if="unlockBusy" class="spin" :size="15" /> Doorgaan</button></footer>
      </form>

      <form v-else-if="unlockStep === 'ssh'" class="terminal-unlock-form" data-testid="terminal-ssh-auth" @submit.prevent="submitSshPassword">
        <div><small>Stap 2 van 2 · challenge verloopt na {{ challengeExpiresIn }} seconden</small><h3>SSH-authenticatie</h3><p>Voer het wachtwoord van de gekoppelde SSH-gebruiker in. Een opgeslagen key of credential wordt niet gebruikt.</p></div>
        <dl class="terminal-unlock-server"><div><dt>Website</dt><dd>{{ site.name }}</dd></div><div><dt>SSH-gebruiker</dt><dd>{{ site.sshUsername }}</dd></div><div><dt>Server</dt><dd>{{ site.sshHost }}:{{ site.sshPort }}</dd></div></dl>
        <label><span>SSH-wachtwoord</span><div class="terminal-password-input"><KeyRound :size="17" /><input v-model="sshPassword" :type="showSshPassword ? 'text' : 'password'" autocomplete="off" autocapitalize="off" spellcheck="false" autofocus required /><button type="button" :aria-label="showSshPassword ? 'SSH-wachtwoord verbergen' : 'SSH-wachtwoord tonen'" @click="showSshPassword = !showSshPassword"><EyeOff v-if="showSshPassword" :size="16" /><Eye v-else :size="16" /></button></div></label>
        <p v-if="unlockError" class="error-banner">{{ unlockError }}</p>
        <footer><button type="button" class="button secondary" :disabled="unlockBusy" @click="cancelUnlock">Annuleren</button><button class="button primary" :disabled="!sshPassword || unlockBusy"><LoaderCircle v-if="unlockBusy" class="spin" :size="15" /> Terminal verbinden</button></footer>
      </form>

      <div v-else class="terminal-unlock-form terminal-auth-failed" data-testid="terminal-ssh-failed">
        <span><AlertTriangle :size="22" /></span><div><small>Stap 2 van 2</small><h3>SSH-authenticatie mislukt</h3><p>{{ unlockError }}</p><p>Je blijft ingelogd in WP Maintenance Manager. Voor een nieuwe poging moeten beide wachtwoorden opnieuw worden bevestigd.</p></div>
        <footer><button type="button" class="button secondary" @click="cancelUnlock">Annuleren</button><button type="button" class="button primary" @click="retryUnlock">Opnieuw proberen</button></footer>
      </div>
    </section>

    <template v-else>
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
          <footer><span>Bij verlaten wordt deze shell en de aparte Terminal-autorisatie direct vernietigd.</span><div><button :disabled="!connected" @click="sendExample('pwd')">pwd</button><button :disabled="!connected" @click="sendExample('ls -lah')">ls -lah</button><button :disabled="!connected" @click="sendExample('wp plugin list')">wp plugin list</button></div></footer>
        </section>

        <aside class="card terminal-help">
          <header><BookOpen :size="17" /><div><strong>{{ isWpCliTerminalLine(currentLine) ? 'WP-CLI help' : 'Terminalcontext' }}</strong><small v-if="catalog?.available">{{ catalog.totalCommandCount }} WP-CLI commands geladen</small></div></header>
          <div v-if="helpCommand" class="terminal-help-content"><span>Command</span><h3><code>{{ helpCommand.fullCommand }}</code></h3><p>{{ helpCommand.description || 'Geen beschrijving beschikbaar.' }}</p><template v-if="positionalParameters.length"><h4>Argumenten</h4><dl><div v-for="parameter in positionalParameters" :key="parameter.rawSyntax"><dt><code>{{ parameter.displayText }}</code></dt><dd>{{ parameter.description }}</dd></div></dl></template><template v-if="optionParameters.length"><h4>Parameters</h4><dl><div v-for="parameter in optionParameters" :key="parameter.rawSyntax"><dt><code>{{ parameter.displayText }}</code></dt><dd>{{ parameter.description }}</dd></div></dl></template></div>
          <div v-else class="terminal-help-empty"><Server :size="30" /><strong>{{ connected ? 'Vrije SSH-shell' : 'Verbinding verbroken' }}</strong><p>{{ connected ? 'Typ een normaal Linux-commando. Alleen wanneer de nieuwe commandoregel met “wp” begint, verschijnt hier WP-CLI hulp.' : 'Sluit deze Terminal en doorloop beide beveiligingsstappen opnieuw om opnieuw te verbinden.' }}</p></div>
          <footer><AlertTriangle :size="14" /><span>Wachtwoorden, Terminalcommando's en output worden niet in de lokale database of het foutenlog opgeslagen. De remote shell kan zijn eigen historybeleid hebben.</span></footer>
        </aside>
      </div>
    </template>
  </div>
</template>
