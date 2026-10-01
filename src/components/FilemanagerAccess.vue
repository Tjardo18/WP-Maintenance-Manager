<script setup lang="ts">
import { onUnmounted, ref } from "vue";
import { LoaderCircle, LockKeyhole } from "@lucide/vue";
import { appApi } from "../services/tauri";
import type { FilemanagerContext } from "../types/filemanager";
import { errorMessage } from "../utils/errors";
import FilemanagerBrowser from "./FilemanagerBrowser.vue";

// Parent keys this component by website: every navigation starts a fresh gate.
const props = defineProps<{ context: FilemanagerContext }>();
const siteId = props.context.siteId;
const step = ref<"app" | "ssh" | "ready">("app");
const password = ref("");
const busy = ref(false);
const error = ref<string>();
const browser = ref<InstanceType<typeof FilemanagerBrowser>>();
async function reauthenticate() {
  if (await browser.value?.requestLeave() ?? true) reset();
}
let token: string | undefined;
let generation = 0;
let timer: ReturnType<typeof setTimeout> | undefined;

async function release(value?: string) {
  if (value) await appApi.closeFilemanager(siteId, value).catch(() => undefined);
}

function reset(message?: string) {
  generation += 1;
  globalThis.clearTimeout(timer);
  void release(token);
  token = undefined;
  password.value = "";
  step.value = "app";
  busy.value = false;
  error.value = message;
}

function expireAfter(seconds: number) {
  globalThis.clearTimeout(timer);
  timer = setTimeout(() => {
    if (step.value === "ready" && browser.value?.hasUnsavedChanges()) {
      void release(token);
      error.value = "De verificatie is verlopen. Niet-opgeslagen tekst blijft zichtbaar; kopieer deze indien nodig voordat je opnieuw verifieert.";
    } else reset("De verificatie is verlopen. Bevestig beide wachtwoorden opnieuw.");
  }, Math.max(0, seconds) * 1000);
}

async function submit() {
  if (busy.value || !password.value || step.value === "ready") return;
  busy.value = true;
  error.value = undefined;
  const request = generation;
  // Pass directly to IPC and clear the field immediately, not after the network call.
  const operation = step.value === "app"
    ? appApi.beginFilemanagerReauthentication(siteId, password.value)
    : appApi.openFilemanager(siteId, token!, password.value);
  password.value = "";
  try {
    const result = await operation;
    if ("challengeToken" in result) {
      if (request !== generation) { await release(result.challengeToken); return; }
      token = result.challengeToken;
      step.value = "ssh";
      expireAfter(result.expiresInSeconds);
    } else {
      if (request !== generation) return;
      // Never trust a frontend flag or open response alone: check the backend guard.
      const authorization = await appApi.getFilemanagerAuthorization(siteId, token!);
      if (request !== generation) return;
      if (result.siteId !== siteId || authorization.siteId !== siteId) throw new Error("De websiteverificatie komt niet overeen.");
      step.value = "ready";
      expireAfter(authorization.expiresInSeconds);
    }
  } catch (cause) {
    if (request === generation) reset(errorMessage(cause));
  } finally {
    if (request === generation) busy.value = false;
  }
}

onUnmounted(() => reset());
</script>

<template>
  <template v-if="step === 'ready' && token">
    <p v-if="error" class="error-banner" role="alert">{{ error }} <button class="button small secondary" @click="reauthenticate">Opnieuw verifiëren</button></p>
    <FilemanagerBrowser ref="browser" :context="context" :authorization-token="token" @expired="reset('De filemanagerverificatie is verlopen. Bevestig beide wachtwoorden opnieuw.')" />
  </template>
  <form v-else class="filemanager-auth" :aria-busy="busy" @submit.prevent="submit">
    <LockKeyhole :size="28" />
    <h3>{{ step === 'app' ? 'App-wachtwoord vereist' : 'SSH-wachtwoord vereist' }}</h3>
    <p v-if="step === 'app'">Bevestig je app-wachtwoord om de filemanager te openen.</p>
    <p v-else>App-wachtwoord geverifieerd. Voer het SSH-wachtwoord in voor deze website.</p>
    <p class="filemanager-auth-site">{{ context.siteName }} · {{ context.siteUrl }}</p>
    <p v-if="error" class="error-banner" role="alert">{{ error }}</p>
    <label :for="`filemanager-password-${siteId}`">{{ step === 'app' ? 'App-wachtwoord' : 'SSH-wachtwoord' }}</label>
    <input :id="`filemanager-password-${siteId}`" :key="step" v-model="password" type="password" autocomplete="off" :disabled="busy" required />
    <div class="filemanager-auth-actions">
      <button type="submit" class="button" :disabled="busy || !password"><LoaderCircle v-if="busy" class="spin" :size="16" />{{ busy ? 'Verificatie uitvoeren…' : step === 'app' ? 'Doorgaan' : 'Verbinden' }}</button>
      <button v-if="step === 'ssh'" type="button" class="button secondary" @click="reset()">Annuleren</button>
    </div>
    <p class="muted">Toegang geldt alleen voor deze website, maximaal 15 minuten en zolang de appsessie geldig is. Wachtwoorden worden niet opgeslagen.</p>
  </form>
</template>

<style scoped>
.filemanager-auth { display: flex; flex-direction: column; gap: 12px; max-width: 480px; margin: 20px auto; }
.filemanager-auth h3, .filemanager-auth p { margin: 0; }
.filemanager-auth-site { overflow-wrap: anywhere; }
.filemanager-auth-actions { display: flex; flex-wrap: wrap; gap: 12px; }
</style>
