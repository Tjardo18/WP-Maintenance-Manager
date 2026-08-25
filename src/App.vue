<script setup lang="ts">
import { computed, onMounted } from "vue";
import { useRoute, RouterLink, RouterView } from "vue-router";
import { Activity, Globe2, History, LayoutDashboard, Settings, ShieldCheck } from "@lucide/vue";
import { useSitesStore } from "./stores/sites";

const route = useRoute();
const sites = useSitesStore();
const pageTitle = computed(() => String(route.meta.title ?? "WP Maintenance Manager"));

onMounted(() => sites.load());
</script>

<template>
  <div class="app-shell">
    <aside class="sidebar">
      <div class="brand">
        <span class="brand-mark"><ShieldCheck :size="23" /></span>
        <span><strong>WP Maintenance</strong><small>Manager</small></span>
      </div>
      <nav aria-label="Hoofdnavigatie">
        <RouterLink to="/"><LayoutDashboard :size="19" /> Dashboard</RouterLink>
        <RouterLink to="/websites"><Globe2 :size="19" /> Websites</RouterLink>
        <RouterLink to="/historie"><History :size="19" /> Onderhoudshistorie</RouterLink>
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
        <div class="topbar-state"><Activity :size="17" /><span>{{ sites.loading ? "Gegevens laden…" : `${sites.sites.length} websites` }}</span></div>
      </header>
      <div class="page-container"><RouterView /></div>
    </main>
  </div>
</template>
