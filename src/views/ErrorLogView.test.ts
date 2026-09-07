import { flushPromises, mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ErrorLogPage } from "../types";
import ErrorLogView from "./ErrorLogView.vue";

const errorPage: ErrorLogPage = {
  records: [{
    id: "ERR-ABC123", createdAt: "2026-09-07T11:42:18Z", severity: "error", category: "connection_timeout",
    siteId: "site-a", siteName: "voorbeeld.nl", action: "SSH verbinding testen", summary: "Server niet bereikbaar binnen de toegestane tijd",
    technicalDetails: "Connection timed out <script>alert('no')</script>", exitCode: undefined, causeChain: ["Caused by: TCP timeout"], durationMs: 15_000, retryable: true,
  }],
  total: 1, limit: 25, offset: 0,
};

const mockApi = vi.hoisted(() => ({ listErrorLogs: vi.fn(async () => errorPage) }));
vi.mock("../services/tauri", () => ({ appApi: mockApi }));

describe("ErrorLogView", () => {
  beforeEach(() => {
    setActivePinia(createPinia());
    mockApi.listErrorLogs.mockClear();
  });

  it("shows persisted incidents, filters and safe technical details", async () => {
    const wrapper = mount(ErrorLogView);
    await flushPromises();
    expect(wrapper.text()).toContain("voorbeeld.nl");
    expect(wrapper.text()).toContain("Server niet bereikbaar");
    expect(mockApi.listErrorLogs).toHaveBeenCalledWith(expect.objectContaining({ limit: 25, offset: 0 }));

    await wrapper.get(".error-log-table tbody tr").trigger("click");
    expect(wrapper.text()).toContain("ERR-ABC123");
    expect(wrapper.text()).toContain("Connection timed out <script>");
    expect(wrapper.find(".error-detail script").exists()).toBe(false);

    await wrapper.get('.error-log-search input').setValue("timeout");
    await wrapper.get(".error-log-filters").trigger("submit");
    await flushPromises();
    expect(mockApi.listErrorLogs).toHaveBeenLastCalledWith(expect.objectContaining({ query: "timeout", offset: 0 }));
  });
});
