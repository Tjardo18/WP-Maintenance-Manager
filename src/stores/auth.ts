import { defineStore } from "pinia";
import { computed, ref } from "vue";
import { authApi } from "../services/tauri";
import { clearWpCliConsoleSessions } from "../services/wpCliConsoleSession";
import { errorMessage } from "../utils/errors";
import { useSitesStore } from "./sites";

const TOUCH_THROTTLE_MS = 20_000;

export const useAuthStore = defineStore("auth", () => {
  const initialized = ref(false);
  const configured = ref(false);
  const authenticated = ref(false);
  const idleTimeoutMinutes = ref(15);
  const error = ref<string>();
  const retryAfterSeconds = ref(0);
  let lastActivityAt = Date.now();
  let lastTouchAt = 0;
  let listenersStarted = false;

  const needsSetup = computed(() => initialized.value && !configured.value);

  async function initialize() {
    error.value = undefined;
    try {
      const status = await authApi.status();
      configured.value = status.configured;
      authenticated.value = status.authenticated;
      idleTimeoutMinutes.value = status.idleTimeoutMinutes;
      retryAfterSeconds.value = status.retryAfterSeconds;
    } catch (cause) { error.value = errorMessage(cause); }
    finally { initialized.value = true; startMonitoring(); }
  }

  async function setup(password: string) {
    const result = await authApi.setup(password);
    configured.value = true;
    authenticated.value = true;
    idleTimeoutMinutes.value = result.idleTimeoutMinutes;
    error.value = undefined;
    lastActivityAt = Date.now();
  }

  async function login(password: string) {
    const result = await authApi.login(password);
    authenticated.value = true;
    idleTimeoutMinutes.value = result.idleTimeoutMinutes;
    retryAfterSeconds.value = 0;
    error.value = undefined;
    lastActivityAt = Date.now();
  }

  async function lock() {
    let message: string | undefined;
    try { await authApi.lock(); }
    catch (cause) { message = errorMessage(cause); }
    finally { clearSession(message); }
  }

  function clearSession(message?: string) {
    authApi.setSessionToken();
    authenticated.value = false;
    error.value = message;
    clearWpCliConsoleSessions();
    useSitesStore().clear();
  }

  async function changePassword(currentPassword: string, newPassword: string) {
    await authApi.changePassword({ currentPassword, newPassword });
    clearSession("Het wachtwoord is gewijzigd. Log opnieuw in.");
  }

  async function updateIdleTimeout(minutes: number) {
    const status = await authApi.setIdleTimeout(minutes);
    idleTimeoutMinutes.value = status.idleTimeoutMinutes;
    lastActivityAt = Date.now();
  }

  function startMonitoring() {
    if (listenersStarted) return;
    listenersStarted = true;
    const recordActivity = () => {
      if (!authenticated.value) return;
      const now = Date.now();
      lastActivityAt = now;
      if (now - lastTouchAt >= TOUCH_THROTTLE_MS) {
        lastTouchAt = now;
        void authApi.touch().catch((cause) => clearSession(errorMessage(cause)));
      }
    };
    for (const event of ["pointerdown", "keydown", "mousemove", "scroll"]) {
      window.addEventListener(event, recordActivity, { passive: true });
    }
    window.addEventListener("wpmm:locked", ((event: CustomEvent<unknown>) => {
      clearSession(errorMessage(event.detail));
    }) as EventListener);
    window.setInterval(() => {
      if (authenticated.value && Date.now() - lastActivityAt >= idleTimeoutMinutes.value * 60_000) {
        void lock();
      }
      if (retryAfterSeconds.value > 0) retryAfterSeconds.value -= 1;
    }, 1_000);
  }

  return { initialized, configured, authenticated, idleTimeoutMinutes, error, retryAfterSeconds, needsSetup, initialize, setup, login, lock, changePassword, updateIdleTimeout };
});
