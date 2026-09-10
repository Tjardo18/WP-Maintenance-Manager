import type { UnlistenFn } from "@tauri-apps/api/event";
import { defineStore } from "pinia";
import { computed, shallowRef } from "vue";
import { appApi } from "../services/tauri";
import type { ScanJobState } from "../types";

const isActive = (job: ScanJobState) => job.status === "queued" || job.status === "running";

export const useScanJobsStore = defineStore("scanJobs", () => {
  const jobs = shallowRef<Record<string, ScanJobState>>({});
  const initialized = shallowRef(false);
  let stopListening: UnlistenFn | undefined;

  const all = computed(() => Object.values(jobs.value).sort((a, b) => b.createdAt.localeCompare(a.createdAt)));
  const active = computed(() => all.value.filter(isActive));

  function upsert(job: ScanJobState) {
    jobs.value = { ...jobs.value, [job.id]: job };
  }

  function forSite(siteId: string) {
    return all.value.find((job) => job.siteId === siteId);
  }

  async function initialize() {
    if (initialized.value) return;
    const [loaded, unlisten] = await Promise.all([
      appApi.listScanJobs(),
      appApi.onScanJobUpdated(upsert),
    ]);
    jobs.value = { ...Object.fromEntries(loaded.map((job) => [job.id, job])), ...jobs.value };
    stopListening = unlisten;
    initialized.value = true;
  }

  async function start(siteId: string, modifiedDays = 30) {
    const job = await appApi.startSiteScan(siteId, modifiedDays);
    upsert(job);
    return job;
  }

  async function startAll(modifiedDays = 30) {
    const result = await appApi.startAllSiteScans(modifiedDays);
    result.jobs.forEach(upsert);
    return result.jobs;
  }

  async function cancel(jobId: string) {
    upsert(await appApi.cancelSiteScan(jobId));
  }

  async function cancelMany(jobIds: string[]) {
    const cancelled = await appApi.cancelScanJobs(jobIds);
    cancelled.forEach(upsert);
  }

  function clear() {
    stopListening?.();
    stopListening = undefined;
    jobs.value = {};
    initialized.value = false;
  }

  return { all, active, initialized, forSite, initialize, start, startAll, cancel, cancelMany, clear };
});
