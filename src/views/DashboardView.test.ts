import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ScanJobState, Site } from "../types";

const queuedJob: ScanJobState = {
  id: "job-a", jobType: "site_scan", siteId: "site-a", siteName: "Site A", status: "queued",
  createdAt: "2026-09-08T10:00:00.000Z", completedSteps: 0, totalSteps: 2,
  cancellationRequested: false, steps: [{ key: "ssh", label: "SSH", status: "pending" }, { key: "persist", label: "Opslaan", status: "pending" }],
};
const mockApi = vi.hoisted(() => ({
  startAllSiteScans: vi.fn(async () => ({ jobs: [queuedJob] })),
  listScanJobs: vi.fn(async () => []),
  onScanJobUpdated: vi.fn(async () => () => undefined),
  cancelScanJobs: vi.fn(async () => []),
}));
vi.mock("../services/tauri", () => ({ appApi: mockApi }));

import { useSitesStore } from "../stores/sites";
import DashboardView from "./DashboardView.vue";

const site: Site = {
  id: "site-a", name: "Site A", url: "https://site-a.test", sshHost: "ssh.site-a.test",
  sshPort: 22, sshUsername: "deploy", authMethod: "keyFile", wordpressPath: "/srv/site-a",
  status: "healthy", updateCount: 0, createdAt: "2026-09-08T10:00:00.000Z", updatedAt: "2026-09-08T10:00:00.000Z",
};

describe("dashboard background scans", () => {
  beforeEach(() => {
    for (const mock of Object.values(mockApi)) mock.mockClear();
  });

  it("shows queued progress without replacing or blocking the page", async () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    useSitesStore().sites = [site];
    const wrapper = mount(DashboardView, { global: { plugins: [pinia], stubs: { RouterLink: { template: "<a><slot /></a>" } } } });
    await wrapper.get(".page-heading .button.primary").trigger("click");
    await flushPromises();

    expect(mockApi.startAllSiteScans).toHaveBeenCalledOnce();
    expect(wrapper.find(".progress-panel").exists()).toBe(true);
    expect(wrapper.text()).toContain("Wacht op een beschikbare scanplek");
    expect(wrapper.find(".table-card").exists()).toBe(true);
    expect(wrapper.find(".site-name").exists()).toBe(true);
  });
});
