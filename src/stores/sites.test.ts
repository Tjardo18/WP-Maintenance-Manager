import { createPinia, setActivePinia } from "pinia";
import { afterEach, describe, expect, it, vi } from "vitest";
import { appApi } from "../services/tauri";
import type { Site } from "../types";
import { useSitesStore } from "./sites";

const site: Site = {
  id: "11111111-1111-4111-8111-111111111111",
  name: "Testsite",
  url: "https://testsite.test",
  sshHost: "ssh.testsite.test",
  sshPort: 22,
  sshUsername: "deploy",
  authMethod: "keyFile",
  keyPath: "C:\\keys\\test",
  wordpressPath: "/var/www/testsite",
  status: "healthy",
  updateCount: 0,
  createdAt: "2026-08-25T10:00:00.000Z",
  updatedAt: "2026-08-25T10:00:00.000Z",
};

afterEach(() => vi.restoreAllMocks());

describe("sites store", () => {
  it("laadt websites en bouwt de id-index", async () => {
    vi.spyOn(appApi, "listSites").mockResolvedValue([site]);
    setActivePinia(createPinia());
    const store = useSitesStore();

    await store.load();

    expect(store.sites).toEqual([site]);
    expect(store.byId.get(site.id)?.name).toBe("Testsite");
    expect(store.loading).toBe(false);
  });

  it("toont de getypeerde backendmelding", async () => {
    vi.spyOn(appApi, "listSites").mockRejectedValue({ category: "storage", userMessage: "Database niet beschikbaar.", retryable: true });
    setActivePinia(createPinia());
    const store = useSitesStore();

    await store.load();

    expect(store.error).toBe("Database niet beschikbaar.");
  });
});
