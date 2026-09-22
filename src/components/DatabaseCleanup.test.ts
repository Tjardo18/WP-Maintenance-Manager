import { flushPromises, mount } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { DatabaseCleanupOption, DatabaseCleanupResult } from "../types";

const sitesOption: DatabaseCleanupOption = {
  target: "sites",
  tableName: "sites",
  title: "Websites",
  description: "Alle websites die zijn toegevoegd.",
  storedData: ["Website- en SSH-configuratie."],
  dependencies: ["Scans, historie en uitzonderingen worden ook verwijderd."],
  cleanupEffect: "Alle websites en uitsluitend daaraan gekoppelde gegevens worden verwijderd.",
  recordCount: 24,
  impacts: [
    { key: "sites", label: "websites", count: 24, effect: "verwijderd" },
    { key: "scan_runs", label: "scans", count: 1842, effect: "verwijderd" },
  ],
  previewToken: "sites-preview",
  confirmationMode: "typed",
  confirmationPhrase: "VERWIJDEREN",
  irreversible: true,
};

const errorsOption: DatabaseCleanupOption = {
  target: "error_logs",
  tableName: "error_logs",
  title: "Foutenlog",
  description: "Alle technische fouten.",
  storedData: ["Fout-ID's en technische details."],
  dependencies: ["Geen afhankelijke tabellen."],
  cleanupEffect: "Alleen de foutregels worden verwijderd.",
  recordCount: 10,
  impacts: [{ key: "error_logs", label: "foutregels", count: 10, effect: "verwijderd" }],
  previewToken: "errors-preview",
  confirmationMode: "dialog",
  confirmationPhrase: "error_logs",
  irreversible: true,
};

const cleanupResult: DatabaseCleanupResult = {
  target: "sites",
  tableName: "sites",
  status: "success",
  impacts: sitesOption.impacts,
  warnings: [],
  completedAt: "2026-09-21T12:00:00Z",
};

const mockApi = vi.hoisted(() => ({
  listDatabaseCleanupOptions: vi.fn<() => Promise<DatabaseCleanupOption[]>>(),
  cleanupDatabase: vi.fn<() => Promise<DatabaseCleanupResult>>(),
}));
const loadSites = vi.hoisted(() => vi.fn(async () => undefined));

vi.mock("../services/tauri", () => ({ appApi: mockApi }));
vi.mock("../stores/sites", () => ({ useSitesStore: () => ({ load: loadSites }) }));

import DatabaseCleanup from "./DatabaseCleanup.vue";

describe("DatabaseCleanup", () => {
  beforeEach(() => {
    mockApi.listDatabaseCleanupOptions.mockReset();
    mockApi.cleanupDatabase.mockReset();
    loadSites.mockClear();
    mockApi.listDatabaseCleanupOptions.mockResolvedValue([sitesOption, errorsOption]);
    mockApi.cleanupDatabase.mockResolvedValue(cleanupResult);
  });

  it("shows exact impact counts and requires the typed phrase for sites", async () => {
    const wrapper = mount(DatabaseCleanup);
    await flushPromises();

    expect(wrapper.findAll(".database-record-count")[0]!.get("strong").text()).toBe("24");
    expect(wrapper.text()).not.toContain("Website- en SSH-configuratie.");
    await wrapper.findAll(".database-more-info")[0]!.trigger("click");
    expect(wrapper.text()).toContain("Wat wordt hier bewaard?");
    expect(wrapper.text()).toContain("Website- en SSH-configuratie.");
    await wrapper.get(".database-info-modal .modal-actions .button.secondary").trigger("click");
    await wrapper.findAll(".database-cleanup-action")[0]!.trigger("click");

    expect(wrapper.findAll(".database-confirm-impact-list li")[1]!.text()).toContain("1.842");
    expect(wrapper.findAll(".database-confirm-impact-list li")[1]!.text()).toContain("scans");
    expect(wrapper.findAll(".database-confirm-impact-list li")[1]!.text()).toContain("verwijderd");
    const confirm = wrapper.get(".modal-actions .button.danger");
    expect(confirm.attributes("disabled")).toBeDefined();
    await wrapper.get(".database-confirm-field input").setValue("sites");
    expect(confirm.attributes("disabled")).toBeDefined();
    await wrapper.get(".database-confirm-field input").setValue("VERWIJDEREN");
    expect(confirm.attributes("disabled")).toBeUndefined();
    await confirm.trigger("click");
    await flushPromises();

    expect(mockApi.cleanupDatabase).toHaveBeenCalledWith({
      target: "sites",
      confirmation: "VERWIJDEREN",
      previewToken: "sites-preview",
    });
    expect(loadSites).toHaveBeenCalledOnce();
    expect(wrapper.text()).toContain("Database succesvol opgeschoond");
    await wrapper.get(".database-cleanup-result .button").trigger("click");
    expect(wrapper.text()).toContain("Database opgeschoond");
    expect(wrapper.findAll(".database-result-impact-list li")).toHaveLength(2);
  });

  it("uses a concrete confirmation dialog for a normal cleanup action", async () => {
    const wrapper = mount(DatabaseCleanup);
    await flushPromises();
    await wrapper.findAll(".database-cleanup-action")[1]!.trigger("click");

    expect(wrapper.text()).toContain('Tabel "error_logs" opschonen?');
    expect(wrapper.find(".database-confirm-field").exists()).toBe(false);
    await wrapper.get(".modal-actions .button.danger").trigger("click");
    await flushPromises();

    expect(mockApi.cleanupDatabase).toHaveBeenCalledWith({
      target: "error_logs",
      confirmation: "error_logs",
      previewToken: "errors-preview",
    });
  });

  it("refreshes the confirmation counts after a stale preview is rejected", async () => {
    const refreshedErrors = {
      ...errorsOption,
      recordCount: 11,
      impacts: [{ key: "error_logs", label: "foutregels", count: 11, effect: "verwijderd" as const }],
      previewToken: "errors-preview-refreshed",
    };
    mockApi.listDatabaseCleanupOptions
      .mockResolvedValueOnce([sitesOption, errorsOption])
      .mockResolvedValueOnce([sitesOption, refreshedErrors]);
    mockApi.cleanupDatabase.mockRejectedValueOnce(new Error("De database is gewijzigd sinds deze aantallen zijn getoond."));

    const wrapper = mount(DatabaseCleanup);
    await flushPromises();
    await wrapper.findAll(".database-cleanup-action")[1]!.trigger("click");
    await wrapper.get(".modal-actions .button.danger").trigger("click");
    await flushPromises();

    expect(wrapper.text()).toContain("De database is gewijzigd sinds deze aantallen zijn getoond.");
    expect(wrapper.get(".database-confirm-lead strong").text()).toBe("11");
    expect(mockApi.listDatabaseCleanupOptions).toHaveBeenCalledTimes(2);
  });
});
