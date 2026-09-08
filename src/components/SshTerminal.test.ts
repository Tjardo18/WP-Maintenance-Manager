import { flushPromises, mount, type VueWrapper } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import SshTerminal from "./SshTerminal.vue";

const terminalMock = vi.hoisted(() => ({
  dataHandler: undefined as ((data: string) => void) | undefined,
  resizeHandler: undefined as ((size: { cols: number; rows: number }) => void) | undefined,
  writes: [] as Array<string | Uint8Array>,
  disposed: 0,
}));

vi.mock("@xterm/xterm", () => ({
  Terminal: class {
    cols = 80;
    rows = 24;
    options: Record<string, unknown> = {};
    loadAddon() {}
    open() {}
    writeln(value: string) { terminalMock.writes.push(value); }
    clear() {}
    focus() {}
    write(value: string | Uint8Array) { terminalMock.writes.push(value); }
    dispose() { terminalMock.disposed += 1; }
    onData(handler: (data: string) => void) { terminalMock.dataHandler = handler; return { dispose() {} }; }
    onResize(handler: (size: { cols: number; rows: number }) => void) { terminalMock.resizeHandler = handler; return { dispose() {} }; }
  },
}));
vi.mock("@xterm/addon-fit", () => ({ FitAddon: class { fit() {} } }));

const callbacks = vi.hoisted(() => ({
  output: undefined as ((event: { sessionId: string; dataBase64: string }) => void) | undefined,
  status: undefined as ((event: { sessionId: string; status: "connected" | "disconnected" | "failed" }) => void) | undefined,
}));
const mockApi = vi.hoisted(() => ({
  getWpCliCatalog: vi.fn(async () => ({ available: true, source: "test", rootCommandCount: 1, totalCommandCount: 2, globalParameterCount: 0, globalParameters: [], commands: [{ command: "core", fullCommand: "wp core", description: "Manage core", parameters: [], subcommands: [{ command: "version", fullCommand: "wp core version", description: "Version", parameters: [], subcommands: [] }] }] })),
  beginTerminalReauthentication: vi.fn(async () => ({ challengeToken: "challenge-1", expiresInSeconds: 60 })),
  cancelTerminalReauthentication: vi.fn(async () => undefined),
  openTerminal: vi.fn(async () => ({ sessionId: "terminal-1", authorizationToken: "authorization-1", siteId: "site-a", startPath: "/srv/www/site", columns: 100, rows: 30 })),
  writeTerminal: vi.fn(async () => undefined),
  resizeTerminal: vi.fn(async () => undefined),
  closeTerminal: vi.fn(async () => undefined),
  onTerminalOutput: vi.fn(async (handler: typeof callbacks.output) => { callbacks.output = handler; return () => undefined; }),
  onTerminalStatus: vi.fn(async (handler: typeof callbacks.status) => { callbacks.status = handler; return () => undefined; }),
}));
vi.mock("../services/tauri", () => ({ appApi: mockApi }));

const site = { id: "site-a", name: "Voorbeeld", url: "https://example.test", sshHost: "ssh.example.test", sshPort: 22, sshUsername: "deploy", authMethod: "keyFile" as const, wordpressPath: "/srv/www/site", status: "healthy" as const, updateCount: 0, createdAt: "2026-01-01T00:00:00Z", updatedAt: "2026-01-01T00:00:00Z" };

async function unlock(wrapper: VueWrapper) {
  await wrapper.get(".terminal-warning button").trigger("click");
  await wrapper.get('[data-testid="terminal-app-auth"] input').setValue("app-secret-never-store");
  await wrapper.get('[data-testid="terminal-app-auth"]').trigger("submit");
  await flushPromises();
  await wrapper.get('[data-testid="terminal-ssh-auth"] input').setValue("ssh-secret-never-store");
  await wrapper.get('[data-testid="terminal-ssh-auth"]').trigger("submit");
  await flushPromises();
}

describe("SshTerminal", () => {
  beforeEach(() => {
    const values = new Map<string, string>();
    Object.defineProperty(globalThis, "localStorage", { configurable: true, value: {
      clear: () => values.clear(),
      getItem: (key: string) => values.get(key) ?? null,
      setItem: (key: string, value: string) => values.set(key, value),
      removeItem: (key: string) => values.delete(key),
    } });
    globalThis.localStorage.clear();
    terminalMock.writes.length = 0;
    terminalMock.disposed = 0;
    terminalMock.dataHandler = undefined;
    callbacks.output = undefined;
    callbacks.status = undefined;
    for (const mock of Object.values(mockApi)) mock.mockClear();
  });

  it("requires both passwords before opening and authorizes every PTY call", async () => {
    const wrapper = mount(SshTerminal, { props: { site }, global: { stubs: { RouterLink: true } } });
    await flushPromises();
    expect(wrapper.text()).toContain("Terminal ontgrendelen");
    expect(wrapper.find('[data-testid="terminal-xterm"]').exists()).toBe(false);

    await unlock(wrapper);

    expect(mockApi.beginTerminalReauthentication).toHaveBeenCalledWith("site-a", "app-secret-never-store");
    expect(mockApi.openTerminal).toHaveBeenCalledWith("site-a", "challenge-1", "ssh-secret-never-store", 100, 30);
    expect(wrapper.find('[data-testid="terminal-xterm"]').exists()).toBe(true);
    expect(wrapper.text()).toContain("Verbonden");

    const output = new TextEncoder().encode("name     status\r\nplug-in  active\r\n\u001b[32m✓\u001b[0m");
    let binary = "";
    for (const byte of output) binary += String.fromCharCode(byte);
    callbacks.output!({ sessionId: "terminal-1", dataBase64: globalThis.btoa(binary) });
    expect(terminalMock.writes.slice(-1)[0]).toEqual(output);

    terminalMock.dataHandler!("\u0003");
    await flushPromises();
    expect(mockApi.writeTerminal).toHaveBeenCalledWith("terminal-1", "authorization-1", "\u0003");

    wrapper.unmount();
    expect(mockApi.closeTerminal).toHaveBeenCalledWith("terminal-1", "authorization-1");
  });

  it("shows WP autocomplete only for a new line beginning with wp", async () => {
    globalThis.localStorage.setItem("wpmm:terminal-warning-v1", "acknowledged");
    const wrapper = mount(SshTerminal, { props: { site }, global: { stubs: { RouterLink: true } } });
    await flushPromises();
    await wrapper.get('[data-testid="terminal-app-auth"] input').setValue("app-secret");
    await wrapper.get('[data-testid="terminal-app-auth"]').trigger("submit");
    await flushPromises();
    await wrapper.get('[data-testid="terminal-ssh-auth"] input').setValue("ssh-secret");
    await wrapper.get('[data-testid="terminal-ssh-auth"]').trigger("submit");
    await flushPromises();

    terminalMock.dataHandler!("wp");
    await wrapper.vm.$nextTick();
    expect(wrapper.text()).toContain("wp core");
    terminalMock.dataHandler!("\t");
    await flushPromises();
    expect(mockApi.writeTerminal).toHaveBeenCalledWith("terminal-1", "authorization-1", expect.stringContaining("core"));

    terminalMock.dataHandler!("\r");
    terminalMock.dataHandler!("ls -lah");
    await wrapper.vm.$nextTick();
    expect(wrapper.text()).toContain("Vrije SSH-shell");
    expect(wrapper.find(".terminal-suggestions").exists()).toBe(false);
  });

  it("clears the field and emits the global lock signal after a wrong app password", async () => {
    const revoked = { category: "app_session_revoked_reauth_failed", userMessage: "Sessie beëindigd", retryable: false };
    const lockListener = vi.fn();
    window.addEventListener("wpmm:locked", lockListener);
    mockApi.beginTerminalReauthentication.mockImplementationOnce(async () => {
      window.dispatchEvent(new CustomEvent("wpmm:locked", { detail: revoked }));
      throw revoked;
    });
    const wrapper = mount(SshTerminal, { props: { site }, global: { stubs: { RouterLink: true } } });
    await flushPromises();
    await wrapper.get(".terminal-warning button").trigger("click");
    const input = wrapper.get('[data-testid="terminal-app-auth"] input');
    await input.setValue("wrong-app-secret");
    await wrapper.get('[data-testid="terminal-app-auth"]').trigger("submit");
    await flushPromises();

    expect(lockListener).toHaveBeenCalledOnce();
    expect((input.element as HTMLInputElement).value).toBe("");
    expect(mockApi.openTerminal).not.toHaveBeenCalled();
    window.removeEventListener("wpmm:locked", lockListener);
  });

  it("keeps the app available after SSH failure and requires both checks for retry", async () => {
    mockApi.openTerminal.mockRejectedValueOnce({ category: "ssh_authentication", userMessage: "Het SSH-wachtwoord werd niet geaccepteerd.", retryable: false });
    const wrapper = mount(SshTerminal, { props: { site }, global: { stubs: { RouterLink: true } } });
    await flushPromises();
    await wrapper.get(".terminal-warning button").trigger("click");
    await wrapper.get('[data-testid="terminal-app-auth"] input').setValue("app-secret");
    await wrapper.get('[data-testid="terminal-app-auth"]').trigger("submit");
    await flushPromises();
    const sshInput = wrapper.get('[data-testid="terminal-ssh-auth"] input');
    await sshInput.setValue("wrong-ssh-secret");
    await wrapper.get('[data-testid="terminal-ssh-auth"]').trigger("submit");
    await flushPromises();

    expect(wrapper.get('[data-testid="terminal-ssh-failed"]').text()).toContain("SSH-authenticatie mislukt");
    expect((sshInput.element as HTMLInputElement).value).toBe("");
    expect(wrapper.find('[data-testid="terminal-xterm"]').exists()).toBe(false);
    await wrapper.get('[data-testid="terminal-ssh-failed"] .button.primary').trigger("click");
    expect(wrapper.find('[data-testid="terminal-app-auth"]').exists()).toBe(true);
  });

  it("cancels a live challenge and returns to the site", async () => {
    globalThis.localStorage.setItem("wpmm:terminal-warning-v1", "acknowledged");
    const wrapper = mount(SshTerminal, { props: { site }, global: { stubs: { RouterLink: true } } });
    await flushPromises();
    await wrapper.get('[data-testid="terminal-app-auth"] input').setValue("app-secret");
    await wrapper.get('[data-testid="terminal-app-auth"]').trigger("submit");
    await flushPromises();
    await wrapper.get('[data-testid="terminal-ssh-auth"] .button.secondary').trigger("click");
    await flushPromises();

    expect(mockApi.cancelTerminalReauthentication).toHaveBeenCalledWith("site-a", "challenge-1");
    expect(wrapper.emitted("cancel")).toHaveLength(1);
  });
});
