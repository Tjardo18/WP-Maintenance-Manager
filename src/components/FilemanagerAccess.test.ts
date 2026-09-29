import { flushPromises, mount } from "@vue/test-utils";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import FilemanagerAccess from "./FilemanagerAccess.vue";

const api = vi.hoisted(() => ({ beginFilemanagerReauthentication: vi.fn(), openFilemanager: vi.fn(), getFilemanagerAuthorization: vi.fn(), closeFilemanager: vi.fn(), listFilemanagerDirectory: vi.fn(), readFilemanagerFile: vi.fn(), getSettings: vi.fn() }));
vi.mock("../services/tauri", () => ({ appApi: api }));
const context = { siteId: "site-a", siteName: "Website A", siteUrl: "https://a.test" };
const create = () => mount(FilemanagerAccess, { props: { context } });
type Wrapper = ReturnType<typeof create>;
async function submit(wrapper: Wrapper) {
  await wrapper.get('input').setValue(crypto.randomUUID());
  await wrapper.get('form').trigger('submit');
  await flushPromises();
}

describe("filemanager two-password gate", () => {
  beforeEach(() => {
    vi.resetAllMocks();
    api.beginFilemanagerReauthentication.mockResolvedValue({ challengeToken: "challenge-a", expiresInSeconds: 60 });
    api.openFilemanager.mockResolvedValue({ siteId: context.siteId, expiresInSeconds: 900 });
    api.getFilemanagerAuthorization.mockResolvedValue({ siteId: context.siteId, expiresInSeconds: 899 });
    api.closeFilemanager.mockResolvedValue(undefined);
    api.listFilemanagerDirectory.mockResolvedValue({ currentPath: "/", isRoot: true, parentPath: null, items: [], truncated: false });
    api.getSettings.mockResolvedValue({ scanConcurrency: 4, filePreviewMode: "normal", markdownPreviewMode: "raw" });
  });
  afterEach(() => { vi.useRealTimers(); });

  it("hides workspace until both checks and the server guard succeed, then closes on departure", async () => {
    const wrapper = create();
    expect(wrapper.text()).toContain("App-wachtwoord vereist");
    expect(wrapper.text()).not.toContain("Deze map is leeg");
    expect(wrapper.get('input').attributes('type')).toBe('password');
    await submit(wrapper);
    expect(wrapper.text()).toContain("SSH-wachtwoord vereist");
    expect(wrapper.get('input').element.value).toBe("");
    expect(api.openFilemanager).not.toHaveBeenCalled();
    await submit(wrapper);
    expect(api.openFilemanager).toHaveBeenCalledWith("site-a", "challenge-a", expect.any(String));
    expect(api.getFilemanagerAuthorization).toHaveBeenCalledWith("site-a", "challenge-a");
    expect(wrapper.text()).toContain("Deze map is leeg");
    wrapper.unmount();
    expect(api.closeFilemanager).toHaveBeenCalledWith("site-a", "challenge-a");
  });

  it("clears password immediately and prevents repeated submissions", async () => {
    let resolve!: (value: { challengeToken: string; expiresInSeconds: number }) => void;
    api.beginFilemanagerReauthentication.mockReturnValue(new Promise((done) => { resolve = done; }));
    const wrapper = create();
    await submit(wrapper);
    expect(wrapper.get('input').element.value).toBe("");
    expect(wrapper.get('input').attributes('disabled')).toBeDefined();
    await wrapper.get('form').trigger('submit');
    expect(api.beginFilemanagerReauthentication).toHaveBeenCalledOnce();
    wrapper.unmount();
    resolve({ challengeToken: "late", expiresInSeconds: 60 });
    await flushPromises();
    expect(api.closeFilemanager).toHaveBeenCalledWith("site-a", "late");
  });

  it("ignores successful SSH responses after cancellation", async () => {
    let resolve!: (value: { siteId: string; expiresInSeconds: number }) => void;
    api.openFilemanager.mockReturnValue(new Promise((done) => { resolve = done; }));
    const wrapper = create();
    await submit(wrapper);
    await submit(wrapper);
    await wrapper.get('button[type="button"]').trigger('click');
    resolve({ siteId: "site-a", expiresInSeconds: 900 });
    await flushPromises();
    expect(wrapper.text()).toContain("App-wachtwoord vereist");
    expect(api.getFilemanagerAuthorization).not.toHaveBeenCalled();
    expect(api.closeFilemanager).toHaveBeenCalledWith("site-a", "challenge-a");
    wrapper.unmount();
  });

  it.each(["app", "ssh", "guard"])("resets safely after %s failure", async (stage) => {
    const failure = new Error("Verificatie mislukt.");
    if (stage === "app") api.beginFilemanagerReauthentication.mockRejectedValueOnce(failure);
    if (stage === "ssh") api.openFilemanager.mockRejectedValueOnce(failure);
    if (stage === "guard") api.getFilemanagerAuthorization.mockRejectedValueOnce(failure);
    const wrapper = create();
    await submit(wrapper);
    if (stage !== "app") await submit(wrapper);
    expect(wrapper.get('[role="alert"]').text()).toContain("Verificatie mislukt");
    expect(wrapper.text()).not.toContain("Deze map is leeg");
    expect(wrapper.get('input').element.value).toBe("");
    wrapper.unmount();
  });

  it("rejects cross-site responses", async () => {
    api.getFilemanagerAuthorization.mockResolvedValueOnce({ siteId: "site-b", expiresInSeconds: 900 });
    const wrapper = create();
    await submit(wrapper); await submit(wrapper);
    expect(wrapper.get('[role="alert"]').text()).toContain("komt niet overeen");
    expect(wrapper.text()).not.toContain("Deze map is leeg");
    wrapper.unmount();
  });

  it.each([false, true])("expires pending/active access without renewing on a timer (active=%s)", async (active) => {
    vi.useFakeTimers();
    const wrapper = create();
    await submit(wrapper);
    if (active) await submit(wrapper);
    await vi.advanceTimersByTimeAsync(active ? 899000 : 60000);
    expect(wrapper.text()).toContain("App-wachtwoord vereist");
    expect(wrapper.text()).toContain("verlopen");
    expect(api.closeFilemanager).toHaveBeenCalledWith("site-a", "challenge-a");
    wrapper.unmount();
  });
});
