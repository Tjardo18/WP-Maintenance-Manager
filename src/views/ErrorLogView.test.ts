import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ErrorLogPage } from "../types";
import ErrorLogView from "./ErrorLogView.vue";

const errorPage: ErrorLogPage = {
  records: [
    {
      id: "ERR-AAAAAAAAAAAA", createdAt: "2026-09-07T11:42:18Z", severity: "error", category: "connection_timeout",
      siteId: "site-a", siteName: "voorbeeld.nl", action: "SSH verbinding testen", summary: "Server niet bereikbaar binnen de toegestane tijd",
      technicalDetails: "Connection timed out <script>alert('no')</script>", exitCode: undefined, causeChain: ["Caused by: TCP timeout"], durationMs: 15_000, retryable: true,
    },
    {
      id: "ERR-BBBBBBBBBBBB", createdAt: "2026-09-08T11:42:18Z", severity: "warning", category: "application",
      siteId: "site-b", siteName: "tweede.nl", action: "Securityscan uitvoeren", summary: "Controle vraagt aandacht",
      technicalDetails: undefined, exitCode: undefined, causeChain: [], durationMs: 800, retryable: false,
    },
  ],
  total: 2, limit: 25, offset: 0,
};

const mockApi = vi.hoisted(() => ({ listErrorLogs: vi.fn(async () => errorPage), deleteErrorLogs: vi.fn(async () => 1) }));
vi.mock("../services/tauri", () => ({ appApi: mockApi }));

describe("ErrorLogView", () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    mockApi.listErrorLogs.mockClear();
    mockApi.deleteErrorLogs.mockClear();
  });

  it("shows persisted incidents, filters and safe technical details", async () => {
    const wrapper = mount(ErrorLogView);
    await flushPromises();
    expect(wrapper.text()).toContain("voorbeeld.nl");
    expect(wrapper.text()).toContain("Server niet bereikbaar");
    expect(mockApi.listErrorLogs).toHaveBeenCalledWith(expect.objectContaining({ limit: 25, offset: 0 }));

    await wrapper.get(".error-log-table tbody tr").trigger("click");
    expect(wrapper.text()).toContain("ERR-AAAAAAAAAAAA");
    expect(wrapper.text()).toContain("Connection timed out <script>");
    expect(wrapper.find(".error-detail script").exists()).toBe(false);

    await wrapper.get('.error-log-search input').setValue("timeout");
    await wrapper.get(".error-log-filters").trigger("submit");
    await flushPromises();
    expect(mockApi.listErrorLogs).toHaveBeenLastCalledWith(expect.objectContaining({ query: "timeout", offset: 0 }));
  });

  it("confirms individual and bulk deletion", async () => {
    const wrapper = mount(ErrorLogView);
    await flushPromises();

    await wrapper.findAll(".error-log-table tbody .danger-text")[0]!.trigger("click");
    expect(wrapper.text()).toContain("Foutregel verwijderen?");
    await wrapper.get(".modal-actions .button.danger").trigger("click");
    await flushPromises();
    expect(mockApi.deleteErrorLogs).toHaveBeenLastCalledWith(["ERR-AAAAAAAAAAAA"]);

    const checkboxes = wrapper.findAll(".error-log-table tbody input[type='checkbox']");
    await checkboxes[0]!.setValue(true);
    await checkboxes[1]!.setValue(true);
    await wrapper.get(".table-selection-toolbar .danger-text").trigger("click");
    expect(wrapper.text()).toContain("2 foutregels verwijderen?");
    await wrapper.get(".modal-actions .button.danger").trigger("click");
    await flushPromises();
    expect(mockApi.deleteErrorLogs).toHaveBeenLastCalledWith(["ERR-AAAAAAAAAAAA", "ERR-BBBBBBBBBBBB"]);
  });
});
