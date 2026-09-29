import { flushPromises, mount } from "@vue/test-utils";
import { reactive } from "vue";
import { beforeEach, describe, expect, it, vi } from "vitest";
import FilemanagerView from "./FilemanagerView.vue";
import type { FilemanagerContext } from "../types/filemanager";

const api = vi.hoisted(() => ({ getFilemanagerContext: vi.fn(), beginFilemanagerReauthentication: vi.fn(), openFilemanager: vi.fn(), getFilemanagerAuthorization: vi.fn(), closeFilemanager: vi.fn(), listFilemanagerDirectory: vi.fn(), readFilemanagerFile: vi.fn(), getSettings: vi.fn() }));
const route = reactive({ params: { id: "site-a" } });
vi.mock("../services/tauri", () => ({ appApi: api }));
vi.mock("vue-router", () => ({ useRoute: () => route, RouterLink: { props: ["to"], template: '<a :href="to"><slot /></a>' } }));
const context = (id: string): FilemanagerContext => ({ siteId: id, siteName: id, siteUrl: `https://${id}.test` });

describe("Filemanager website context", () => {
  beforeEach(() => { vi.resetAllMocks(); route.params.id = "site-a"; });

  it("discards the previous site's delayed response after navigation", async () => {
    let resolveFirst!: (value: FilemanagerContext) => void;
    api.getFilemanagerContext.mockReturnValueOnce(new Promise((resolve) => { resolveFirst = resolve; })).mockResolvedValueOnce(context("site-b"));
    const wrapper = mount(FilemanagerView);
    route.params.id = "site-b";
    await flushPromises();
    resolveFirst(context("site-a"));
    await flushPromises();
    expect(wrapper.text()).toContain("site-b");
    expect(wrapper.text()).not.toContain("site-a");
    expect(wrapper.get('a').attributes('href')).toBe('/websites/site-b');
    wrapper.unmount();
  });

  it("clears old context when the next website is missing", async () => {
    api.getFilemanagerContext.mockResolvedValueOnce(context("site-a")).mockRejectedValueOnce(new Error("Website niet gevonden."));
    const wrapper = mount(FilemanagerView);
    await flushPromises();
    route.params.id = "missing";
    await flushPromises();
    expect(wrapper.get('[role="alert"]').text()).toContain("Website niet gevonden");
    expect(wrapper.text()).not.toContain("site-a");
    wrapper.unmount();
  });

  it("closes authorized site A and requires both passwords again for site B", async () => {
    api.getFilemanagerContext.mockImplementation(async (id: string) => context(id));
    api.beginFilemanagerReauthentication.mockResolvedValue({ challengeToken: "site-a-challenge", expiresInSeconds: 60 });
    api.openFilemanager.mockResolvedValue({ siteId: "site-a", expiresInSeconds: 900 });
    api.getFilemanagerAuthorization.mockResolvedValue({ siteId: "site-a", expiresInSeconds: 899 });
    api.closeFilemanager.mockResolvedValue(undefined);
    api.listFilemanagerDirectory.mockResolvedValue({ currentPath: "/", isRoot: true, parentPath: null, items: [], truncated: false });
    api.getSettings.mockResolvedValue({ scanConcurrency: 4, filePreviewMode: "normal", markdownPreviewMode: "raw" });
    const wrapper = mount(FilemanagerView);
    await flushPromises();
    for (let step = 0; step < 2; step += 1) {
      await wrapper.get('input').setValue(crypto.randomUUID());
      await wrapper.get('form').trigger('submit');
      await flushPromises();
    }
    expect(wrapper.text()).toContain("Deze map is leeg");
    route.params.id = "site-b";
    await flushPromises();
    expect(api.closeFilemanager).toHaveBeenCalledWith("site-a", "site-a-challenge");
    expect(wrapper.text()).toContain("App-wachtwoord vereist");
    expect(wrapper.text()).not.toContain("Deze map is leeg");
    expect(wrapper.text()).not.toContain("site-a");
    wrapper.unmount();
  });

  it("rejects mismatched context and safely ignores responses after unmount", async () => {
    api.getFilemanagerContext.mockResolvedValueOnce(context("site-b"));
    const wrapper = mount(FilemanagerView);
    await flushPromises();
    expect(wrapper.get('[role="alert"]').text()).toContain("komt niet overeen");
    expect(wrapper.text()).not.toContain("site-b");
    wrapper.unmount();
    let resolve!: (value: FilemanagerContext) => void;
    api.getFilemanagerContext.mockReturnValueOnce(new Promise((done) => { resolve = done; }));
    const second = mount(FilemanagerView);
    second.unmount();
    resolve(context("site-a"));
    await flushPromises();
  });
});
