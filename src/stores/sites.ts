import { defineStore } from "pinia";
import { computed, ref, shallowRef } from "vue";
import { appApi } from "../services/tauri";
import type { Site, SiteInput } from "../types";
import { errorMessage } from "../utils/errors";

export const useSitesStore = defineStore("sites", () => {
  const sites = shallowRef<Site[]>([]);
  const loading = ref(false);
  const error = ref<string>();
  let loadPromise: Promise<void> | undefined;
  const byId = computed(() => new Map(sites.value.map((site) => [site.id, site])));

  async function load() {
    if (loadPromise) return loadPromise;
    loadPromise = (async () => {
      loading.value = true;
      error.value = undefined;
      try { sites.value = await appApi.listSites(); }
      catch (cause) { error.value = errorMessage(cause); }
      finally { loading.value = false; loadPromise = undefined; }
    })();
    return loadPromise;
  }
  async function save(input: SiteInput) { const site = await appApi.saveSite(input); await load(); return site; }
  async function remove(id: string) { await appApi.deleteSite(id); await load(); }
  function replace(site: Site) { sites.value = sites.value.map((item) => item.id === site.id ? site : item); }
  function clear() { sites.value = []; error.value = undefined; loading.value = false; }
  return { sites, loading, error, byId, load, save, remove, replace, clear };
});
