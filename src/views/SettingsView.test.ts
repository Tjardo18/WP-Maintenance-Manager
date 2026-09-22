import { flushPromises, mount } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { AppSettings } from "../types";

const mockApi = vi.hoisted(() => ({
  getSettings: vi.fn(async () => ({ scanConcurrency: 4, filePreviewMode: "fullscreen" as const, markdownPreviewMode: "preview" as const })),
  saveSettings: vi.fn(async (settings: AppSettings) => settings),
  getWordfenceStatus: vi.fn(async () => ({ configured: false, connectionStatus: "not_tested", feedStatus: "missing", vulnerabilityCount: 0, softwareRecordCount: 0, refreshRunning: false, cooldownRemainingSeconds: 0 })),
  getWordfenceFeedRefreshJob: vi.fn(async () => undefined),
  onWordfenceFeedRefreshUpdated: vi.fn(async () => () => undefined),
  listDatabaseCleanupOptions: vi.fn(async () => []),
  cleanupDatabase: vi.fn(),
}));
const mockAuth = vi.hoisted(() => ({
  idleTimeoutMinutes: 15,
  updateIdleTimeout: vi.fn(async () => undefined),
  changePassword: vi.fn(async () => undefined),
  lock: vi.fn(),
}));

vi.mock("../services/tauri", () => ({ appApi: mockApi }));
vi.mock("../stores/auth", () => ({ useAuthStore: () => mockAuth }));
vi.mock("../stores/sites", () => ({ useSitesStore: () => ({ load: vi.fn(async () => undefined) }) }));

import SettingsView from "./SettingsView.vue";

describe("SettingsView file preview preference", () => {
  beforeEach(() => {
    for (const mock of Object.values(mockApi)) mock.mockClear();
    mockAuth.updateIdleTimeout.mockClear();
    mockAuth.changePassword.mockClear();
    mockAuth.lock.mockClear();
  });

  it("loads and saves the persistent file and Markdown preview modes", async () => {
    const wrapper = mount(SettingsView);
    await flushPromises();

    const select = wrapper.findAll("select").find((candidate) => candidate.element.value === "fullscreen");
    expect(select).toBeDefined();
    await select!.setValue("normal");
    const markdownSelect = wrapper.findAll("select").find((candidate) => candidate.element.value === "preview");
    expect(markdownSelect).toBeDefined();
    await markdownSelect!.setValue("raw");
    await wrapper.get(".form-actions .button.primary").trigger("click");
    await flushPromises();

    expect(mockApi.saveSettings).toHaveBeenCalledWith({ scanConcurrency: 4, filePreviewMode: "normal", markdownPreviewMode: "raw" });
    expect(wrapper.text()).toContain("Instellingen opgeslagen");
  });
});
