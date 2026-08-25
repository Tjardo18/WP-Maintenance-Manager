import { defineStore } from "pinia";
import { computed, ref } from "vue";
import { appApi } from "../services/tauri";
import type { Site, SiteInput } from "../types";

export const useSitesStore = defineStore("sites", () => {
  const sites = ref<Site[]>([]);
  const loading = ref(false);
  const error = ref<string>();
  const byId = computed(() => new Map(sites.value.map((site) => [site.id, site])));

  async function load() {
    loading.value = true;
    error.value = undefined;
    try { sites.value = await appApi.listSites(); }
    catch (cause) { error.value = cause instanceof Error ? cause.message : String(cause); }
    finally { loading.value = false; }
  }
  async function save(input: SiteInput) { const site = await appApi.saveSite(input); await load(); return site; }
  async function remove(id: string) { await appApi.deleteSite(id); await load(); }
  function replace(site: Site) { sites.value = sites.value.map((item) => item.id === site.id ? site : item); }
  return { sites, loading, error, byId, load, save, remove, replace };
});
