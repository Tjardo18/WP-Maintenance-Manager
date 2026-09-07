import { flushPromises, mount } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { clearWpCliConsoleSessions } from "../services/wpCliConsoleSession";
import WpCliConsole from "./WpCliConsole.vue";

const mockApi = vi.hoisted(() => ({
  getWpCliCatalog: vi.fn(async () => ({
    available: true,
    source: "https://developer.wordpress.org/cli/commands/",
    scrapedAt: "2026-08-31",
    rootCommandCount: 1,
    totalCommandCount: 2,
    globalParameterCount: 1,
    globalParameters: [{ parameter: "[--debug]", description: "Show debug output." }],
    commands: [{
      command: "core", fullCommand: "wp core", description: "Manage WordPress core.", parameters: [],
      subcommands: [{ command: "version", fullCommand: "wp core version", description: "Show the WordPress version.", parameters: [], subcommands: [] }],
    }],
  })),
  inspectWpCliCommand: vi.fn(async () => ({ risk: "readOnly", commandFamily: "core", summary: "Alleen-lezen.", requiresConfirmation: false, requiresTypedConfirmation: false, confirmationPhrase: undefined as string | undefined })),
  executeWpCliCommand: vi.fn(async () => ({ status: "success", risk: "readOnly", commandFamily: "core", stdout: "<script>alert('xss')</script>\n", stderr: "", exitCode: 0, durationMs: 21, startedAt: "2026-01-01T00:00:00Z", finishedAt: "2026-01-01T00:00:00Z", truncated: false })),
}));

vi.mock("../services/tauri", () => ({ appApi: mockApi }));

const site = { id: "site-a", name: "Voorbeeld", url: "https://example.test", sshHost: "ssh.example.test", sshPort: 22, sshUsername: "deploy", authMethod: "keyFile" as const, wordpressPath: "/srv/www/example", status: "healthy" as const, updateCount: 0, createdAt: "2026-01-01T00:00:00Z", updatedAt: "2026-01-01T00:00:00Z" };

describe("WpCliConsole", () => {
  beforeEach(() => {
    clearWpCliConsoleSessions();
    mockApi.inspectWpCliCommand.mockResolvedValue({ risk: "readOnly", commandFamily: "core", summary: "Alleen-lezen.", requiresConfirmation: false, requiresTypedConfirmation: false, confirmationPhrase: undefined });
    mockApi.executeWpCliCommand.mockClear();
  });

  it("shows autocomplete and renders untrusted output as plain text", async () => {
    const wrapper = mount(WpCliConsole, { props: { site } });
    await flushPromises();
    const input = wrapper.get('[data-testid="wpcli-input"]');
    await input.setValue("wp");
    await input.trigger("focus");
    expect(wrapper.text()).toContain("wp core");

    await input.setValue("wp core version");
    await wrapper.get('[data-testid="wpcli-run"]').trigger("click");
    await flushPromises();

    expect(mockApi.executeWpCliCommand).toHaveBeenCalledWith("site-a", "wp core version", false, undefined);
    expect(wrapper.get(".console-stdout").text()).toBe("<script>alert('xss')</script>");
    expect(wrapper.find(".console-stdout script").exists()).toBe(false);
    expect(wrapper.html()).toContain("&lt;script&gt;");
  });

  it("requires the backend-provided phrase for a high-risk command", async () => {
    mockApi.inspectWpCliCommand.mockResolvedValueOnce({ risk: "highRisk", commandFamily: "db", summary: "Kan de database verwijderen.", requiresConfirmation: true, requiresTypedConfirmation: true, confirmationPhrase: "UITVOEREN" });
    const wrapper = mount(WpCliConsole, { props: { site } });
    await flushPromises();
    await wrapper.get('[data-testid="wpcli-input"]').setValue("wp db reset --yes");
    await wrapper.get('[data-testid="wpcli-run"]').trigger("click");
    await flushPromises();

    const confirm = wrapper.get(".modal-actions .danger");
    expect(confirm.attributes("disabled")).toBeDefined();
    await wrapper.get(".wpcli-confirm-input input").setValue("UITVOEREN");
    expect(wrapper.get(".modal-actions .danger").attributes("disabled")).toBeUndefined();
    await wrapper.get(".modal-actions .danger").trigger("click");
    await flushPromises();

    expect(mockApi.executeWpCliCommand).toHaveBeenCalledWith("site-a", "wp db reset --yes", true, "UITVOEREN");
  });
});
