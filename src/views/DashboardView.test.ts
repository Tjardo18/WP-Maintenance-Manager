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
  vulnerabilitySummary: { criticalCount: 1, highCount: 2, mediumCount: 1, lowCount: 0, infoCount: 0, unknownCount: 0, lastCheckedAt: "2026-09-08T10:00:00.000Z", feedUpdatedAt: "2026-09-08T09:00:00.000Z", inventoryObservedAt: "2026-09-08T10:00:00.000Z", inventoryStale: false },
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

  it("prioritizes cached vulnerability counts and filters affected sites", async () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    useSitesStore().sites = [site, { ...site, id: "site-b", name: "Site B", vulnerabilitySummary: undefined }];
    const wrapper = mount(DashboardView, { global: { plugins: [pinia], stubs: { RouterLink: { template: "<a><slot /></a>" } } } });
    expect(wrapper.text()).toContain("Direct aandacht nodig");
    expect(wrapper.text()).toContain("1 kritiek · 2 hoog");
    const vulnerabilityCard = wrapper.findAll(".stat-card").find((card) => card.text().includes("Kwetsbaarheden"));
    expect(vulnerabilityCard?.text()).toContain("4");
    await vulnerabilityCard?.trigger("click");
    expect(wrapper.findAll(".table-card tbody tr")).toHaveLength(1);
    expect(wrapper.get(".table-card tbody").text()).toContain("Site A");
  });

  it("labels findings based on stale cached versions as possible and asks for a rescan", () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    useSitesStore().sites = [{ ...site, vulnerabilitySummary: { ...site.vulnerabilitySummary!, inventoryStale: true } }];
    const wrapper = mount(DashboardView, { global: { plugins: [pinia], stubs: { RouterLink: { template: "<a><slot /></a>" } } } });

    expect(wrapper.get(".vulnerability-priority").text()).toContain("Mogelijk · laatst bekende versies · scan opnieuw");
    expect(wrapper.get(".table-card tbody").text()).toContain("Mogelijk · scan opnieuw");
  });
});
