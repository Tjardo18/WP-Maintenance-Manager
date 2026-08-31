<script setup lang="ts">
import { computed, ref } from "vue";
import { KeyRound, LoaderCircle, LockKeyhole, ShieldCheck } from "@lucide/vue";
import { useAuthStore } from "../stores/auth";
import { errorMessage } from "../utils/errors";

const auth = useAuthStore();
const password = ref("");
const repeatedPassword = ref("");
const busy = ref(false);
const error = ref<string>();
const longEnough = computed(() => password.value.length >= 12);
const canSubmit = computed(() => longEnough.value && (!auth.needsSetup || password.value === repeatedPassword.value) && !busy.value && auth.retryAfterSeconds === 0);

async function submit() {
  if (!canSubmit.value) return;
  busy.value = true;
  error.value = undefined;
  try {
    if (auth.needsSetup) await auth.setup(password.value);
    else await auth.login(password.value);
    password.value = "";
    repeatedPassword.value = "";
  } catch (cause) { error.value = errorMessage(cause); }
  finally { busy.value = false; }
}
</script>

<template>
  <main class="auth-shell">
    <section class="auth-panel" aria-labelledby="auth-title">
      <div class="auth-brand"><span><ShieldCheck :size="28" /></span><div><strong>WP Maintenance</strong><small>Manager</small></div></div>
      <div class="auth-icon"><LockKeyhole :size="26" /></div>
      <template v-if="auth.needsSetup">
        <h1 id="auth-title">Beveilig WP Maintenance Manager</h1>
        <p>Maak een wachtwoord aan om toegang tot je websites en beheeracties te beschermen.</p>
      </template>
      <template v-else>
        <h1 id="auth-title">Je websites zijn vergrendeld</h1>
        <p>Log lokaal in om WP Maintenance Manager te gebruiken.</p>
      </template>
      <form class="auth-form" @submit.prevent="submit">
        <label><span>Wachtwoord</span><div class="auth-input"><KeyRound :size="17" /><input v-model="password" type="password" autocomplete="current-password" autofocus required /></div></label>
        <label v-if="auth.needsSetup"><span>Herhaal wachtwoord</span><div class="auth-input"><KeyRound :size="17" /><input v-model="repeatedPassword" type="password" autocomplete="new-password" required /></div></label>
        <div v-if="auth.needsSetup" class="password-hint"><span :class="{ valid: longEnough }"></span><p>Gebruik minimaal 12 tekens. Een lange wachtwoordzin is toegestaan.</p></div>
        <p v-if="auth.needsSetup && repeatedPassword && password !== repeatedPassword" class="field-error">De wachtwoorden zijn niet gelijk.</p>
        <p v-if="error || auth.error" class="error-banner">{{ error ?? auth.error }}</p>
        <p v-if="auth.retryAfterSeconds" class="lock-delay">Opnieuw proberen over {{ auth.retryAfterSeconds }} seconden.</p>
        <button class="button primary auth-submit" type="submit" :disabled="!canSubmit"><LoaderCircle v-if="busy" class="spin" :size="17" />{{ busy ? 'Controleren…' : auth.needsSetup ? 'Wachtwoord instellen' : 'Inloggen' }}</button>
      </form>
      <p class="auth-footnote">De app start na volledig afsluiten altijd vergrendeld. Er is geen achterdeur waarmee het wachtwoord kan worden teruggelezen.</p>
    </section>
  </main>
</template>
