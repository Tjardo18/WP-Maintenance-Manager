import { flushPromises, mount } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import SshTerminal from "./SshTerminal.vue";

const terminalMock = vi.hoisted(() => ({
  dataHandler: undefined as ((data: string) => void) | undefined,
  resizeHandler: undefined as ((size: { cols: number; rows: number }) => void) | undefined,
  writes: [] as Array<string | Uint8Array>,
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
    dispose() {}
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
  openTerminal: vi.fn(async () => ({ sessionId: "terminal-1", siteId: "site-a", startPath: "/srv/www/site", columns: 80, rows: 24 })),
  writeTerminal: vi.fn(async () => undefined),
  resizeTerminal: vi.fn(async () => undefined),
  closeTerminal: vi.fn(async () => undefined),
  onTerminalOutput: vi.fn(async (handler: typeof callbacks.output) => { callbacks.output = handler; return () => undefined; }),
  onTerminalStatus: vi.fn(async (handler: typeof callbacks.status) => { callbacks.status = handler; return () => undefined; }),
}));
vi.mock("../services/tauri", () => ({ appApi: mockApi }));

const site = { id: "site-a", name: "Voorbeeld", url: "https://example.test", sshHost: "ssh.example.test", sshPort: 22, sshUsername: "deploy", authMethod: "keyFile" as const, wordpressPath: "/srv/www/site", status: "healthy" as const, updateCount: 0, createdAt: "2026-01-01T00:00:00Z", updatedAt: "2026-01-01T00:00:00Z" };

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
    terminalMock.dataHandler = undefined;
    callbacks.output = undefined;
    callbacks.status = undefined;
    for (const mock of Object.values(mockApi)) mock.mockClear();
  });

  it("connects an authenticated PTY, streams raw output and forwards Ctrl+C", async () => {
    const wrapper = mount(SshTerminal, { props: { site }, global: { stubs: { RouterLink: true } } });
    await flushPromises();
    expect(wrapper.text()).toContain("Geavanceerde terminal");
    await wrapper.get(".terminal-warning button").trigger("click");
    await wrapper.findAll(".terminal-context button").slice(-1)[0]!.trigger("click");
    await flushPromises();
    expect(mockApi.openTerminal).toHaveBeenCalledWith("site-a", 80, 24);
    expect(wrapper.text()).toContain("Verbonden");

    const output = new TextEncoder().encode("name     status\r\nplug-in  active\r\n\u001b[32m✓\u001b[0m");
    let binary = "";
    for (const byte of output) binary += String.fromCharCode(byte);
    callbacks.output!({ sessionId: "terminal-1", dataBase64: globalThis.btoa(binary) });
    expect(terminalMock.writes.slice(-1)[0]).toEqual(output);

    terminalMock.dataHandler!("\u0003");
    await flushPromises();
    expect(mockApi.writeTerminal).toHaveBeenCalledWith("terminal-1", "\u0003");
  });

  it("shows WP autocomplete only for a new line beginning with wp", async () => {
    globalThis.localStorage.setItem("wpmm:terminal-warning-v1", "acknowledged");
    const wrapper = mount(SshTerminal, { props: { site }, global: { stubs: { RouterLink: true } } });
    await flushPromises();
    await wrapper.findAll(".terminal-context button").slice(-1)[0]!.trigger("click");
    await flushPromises();

    terminalMock.dataHandler!("wp");
    await wrapper.vm.$nextTick();
    expect(wrapper.text()).toContain("wp core");
    terminalMock.dataHandler!("\t");
    await flushPromises();
    expect(mockApi.writeTerminal).toHaveBeenCalledWith("terminal-1", expect.stringContaining("core"));

    terminalMock.dataHandler!("\r");
    terminalMock.dataHandler!("ls -lah");
    await wrapper.vm.$nextTick();
    expect(wrapper.text()).toContain("Vrije SSH-shell");
    expect(wrapper.find(".terminal-suggestions").exists()).toBe(false);
  });
});
