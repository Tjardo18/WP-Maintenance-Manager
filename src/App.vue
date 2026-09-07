<script setup lang="ts">
import { computed, onMounted, watch } from "vue";
import { useRoute, RouterLink, RouterView } from "vue-router";
import { Activity, CircleAlert, Globe2, History, LayoutDashboard, LoaderCircle, LockKeyhole, Settings, ShieldCheck } from "@lucide/vue";
import { useSitesStore } from "./stores/sites";
import { useAuthStore } from "./stores/auth";
import AuthView from "./views/AuthView.vue";

const route = useRoute();
const sites = useSitesStore();
const auth = useAuthStore();
const pageTitle = computed(() => String(route.meta.title ?? "WP Maintenance Manager"));

onMounted(() => {
  void auth.initialize();
  window.addEventListener("keydown", (event) => {
    if (event.ctrlKey && event.key.toLowerCase() === "l" && auth.authenticated) {
      event.preventDefault();
      void auth.lock();
    }
  });
});
watch(() => auth.authenticated, (unlocked) => { if (unlocked) void sites.load(); else sites.clear(); });
</script>

<template>
  <div v-if="!auth.initialized" class="auth-shell"><LoaderCircle class="spin" /></div>
  <AuthView v-else-if="!auth.authenticated" />
  <div v-else class="app-shell">
    <aside class="sidebar">
      <div class="brand">
        <span class="brand-mark"><ShieldCheck :size="23" /></span>
        <span><strong>WP Maintenance</strong><small>Manager</small></span>
      </div>
      <nav aria-label="Hoofdnavigatie">
        <RouterLink to="/"><LayoutDashboard :size="19" /> Dashboard</RouterLink>
        <RouterLink to="/websites"><Globe2 :size="19" /> Websites</RouterLink>
        <RouterLink to="/historie"><History :size="19" /> Onderhoudshistorie</RouterLink>
        <RouterLink to="/foutenlog"><CircleAlert :size="19" /> Foutenlog</RouterLink>
        <RouterLink to="/instellingen"><Settings :size="19" /> Instellingen</RouterLink>
      </nav>
      <div class="sidebar-footer">
        <span class="pulse-dot" aria-hidden="true"></span>
        <span><strong>Lokale applicatie</strong><small>Gegevens blijven op dit apparaat</small></span>
      </div>
    </aside>
    <main class="workspace">
      <header class="topbar">
        <div><p class="eyebrow">WordPress-beheer</p><h1>{{ pageTitle }}</h1></div>
        <div class="topbar-actions"><div class="topbar-state"><Activity :size="17" /><span>{{ sites.loading ? "Gegevens laden…" : `${sites.sites.length} websites` }}</span></div><button class="button secondary" title="Vergrendelen (Ctrl+L)" @click="auth.lock"><LockKeyhole :size="16" /> Vergrendelen</button></div>
      </header>
      <div class="page-container"><p v-if="sites.error" class="error-banner">{{ sites.error }}</p><RouterView /></div>
    </main>
  </div>
</template>
