import { createPinia, setActivePinia } from "pinia";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ScanJobState } from "../types";

const callbacks = vi.hoisted(() => ({ updated: undefined as ((job: ScanJobState) => void) | undefined }));
const job = (): ScanJobState => ({
  id: "job-a", jobType: "site_scan", siteId: "site-a", siteName: "Site A",
  status: "queued", createdAt: "2026-09-08T10:00:00.000Z", completedSteps: 0,
  totalSteps: 2, cancellationRequested: false,
  steps: [{ key: "ssh", label: "SSH", status: "pending" }, { key: "persist", label: "Opslaan", status: "pending" }],
});
const mockApi = vi.hoisted(() => ({
  listScanJobs: vi.fn(async () => [] as ScanJobState[]),
  onScanJobUpdated: vi.fn(async (handler: (job: ScanJobState) => void) => { callbacks.updated = handler; return () => undefined; }),
  startSiteScan: vi.fn(async () => job()),
  startAllSiteScans: vi.fn(async () => ({ jobs: [job()] })),
  cancelSiteScan: vi.fn(async () => ({ ...job(), status: "cancelled" as const })),
  cancelScanJobs: vi.fn(async () => [{ ...job(), status: "cancelled" as const }]),
}));
vi.mock("../services/tauri", () => ({ appApi: mockApi }));

import { useScanJobsStore } from "./scanJobs";

describe("scan jobs store", () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    callbacks.updated = undefined;
    for (const mock of Object.values(mockApi)) mock.mockClear();
  });

  it("returns a queued job immediately and keeps progress outside a page component", async () => {
    const store = useScanJobsStore();
    await store.initialize();

    const started = await store.start("site-a");
    expect(started.status).toBe("queued");
    expect(store.forSite("site-a")?.id).toBe("job-a");

    callbacks.updated?.({ ...job(), status: "running", currentStep: "ssh", steps: [{ key: "ssh", label: "SSH", status: "running" }, { key: "persist", label: "Opslaan", status: "pending" }] });
    expect(store.forSite("site-a")?.status).toBe("running");
    expect(store.active).toHaveLength(1);
  });

  it("reuses the backend response for duplicate starts", async () => {
    const store = useScanJobsStore();
    await store.initialize();
    await Promise.all([store.start("site-a"), store.start("site-a")]);
    expect(store.all).toHaveLength(1);
  });
});
