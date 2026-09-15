import { defineStore } from "pinia";
import { computed, ref, shallowRef } from "vue";
import { appApi } from "../services/tauri";
import type { Site, SiteChangeSummary, SiteInput } from "../types";
import { errorMessage } from "../utils/errors";

export const useSitesStore = defineStore("sites", () => {
  const sites = shallowRef<Site[]>([]);
  const loading = ref(false);
  const error = ref<string>();
  const changeSummaries = shallowRef(new Map<string, SiteChangeSummary>());
  let loadPromise: Promise<void> | undefined;
  const byId = computed(() => new Map(sites.value.map((site) => [site.id, site])));

  async function load() {
    if (loadPromise) return loadPromise;
    loadPromise = (async () => {
      loading.value = true;
      error.value = undefined;
      try {
        const [siteResult, summaryResult] = await Promise.allSettled([appApi.listSites(), appApi.listSiteChangeSummaries()]);
        if (siteResult.status === "rejected") throw siteResult.reason;
        sites.value = siteResult.value;
        changeSummaries.value = summaryResult.status === "fulfilled" ? new Map(summaryResult.value.map((summary) => [summary.siteId, summary])) : new Map();
      }
      catch (cause) { error.value = errorMessage(cause); }
      finally { loading.value = false; loadPromise = undefined; }
    })();
    return loadPromise;
  }
  async function save(input: SiteInput) { const site = await appApi.saveSite(input); await load(); return site; }
  async function remove(id: string) { await appApi.deleteSite(id); await load(); }
  function replace(site: Site) { sites.value = sites.value.map((item) => item.id === site.id ? site : item); }
  function clear() { sites.value = []; changeSummaries.value = new Map(); error.value = undefined; loading.value = false; }
  return { sites, changeSummaries, loading, error, byId, load, save, remove, replace, clear };
});
