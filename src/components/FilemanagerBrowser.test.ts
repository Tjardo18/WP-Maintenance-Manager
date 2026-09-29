import { flushPromises, mount } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import FilemanagerBrowser from "./FilemanagerBrowser.vue";
import type { FilemanagerDirectoryListing } from "../types/filemanager";

const api = vi.hoisted(() => ({ listFilemanagerDirectory: vi.fn(), readFilemanagerFile: vi.fn(), getSettings: vi.fn() }));
vi.mock("../services/tauri", () => ({ appApi: api }));
const context = { siteId: "site-a", siteName: "Website A", siteUrl: "https://a.test" };
const listing = (path: string, items: FilemanagerDirectoryListing["items"] = []): FilemanagerDirectoryListing => ({ currentPath: path, isRoot: path === "/", parentPath: path === "/" ? null : path.slice(0, path.lastIndexOf("/")) || "/", items, truncated: false });
const directory = (name: string, path: string) => ({ name, path, kind: "directory" as const, extension: null, size: null, permissions: "755", modifiedAt: "2026-09-29T08:30:00Z" });
const file = (name: string, path: string, extension: string | null = "php") => ({ name, path, kind: "file" as const, extension, size: 4300, permissions: "644", modifiedAt: "2026-09-29T08:30:00Z" });
const create = () => mount(FilemanagerBrowser, { props: { context, authorizationToken: "token-a" } });

describe("Filemanager directorybrowser", () => {
  beforeEach(() => { vi.resetAllMocks(); api.getSettings.mockResolvedValue({ scanConcurrency: 4, filePreviewMode: "normal", markdownPreviewMode: "raw" }); });

  it("loads the root once and shows directory and file metadata", async () => {
    api.listFilemanagerDirectory.mockResolvedValueOnce(listing("/", [directory("wp-content", "/wp-content"), file("index.php", "/index.php")]));
    const wrapper = create(); await flushPromises();
    expect(api.listFilemanagerDirectory).toHaveBeenCalledWith("site-a", "token-a", "/");
    expect(wrapper.text()).toContain("wp-content"); expect(wrapper.text()).toContain("index.php"); expect(wrapper.text()).toContain("Map"); expect(wrapper.text()).toContain("PHP"); expect(wrapper.text()).toContain("4,2 KB"); expect(wrapper.text()).toContain("755"); expect(wrapper.text()).toContain("644");
  });

  it("opens directories, supports up and back history without duplicate entries", async () => {
    api.listFilemanagerDirectory.mockResolvedValueOnce(listing("/", [directory("wp-content", "/wp-content")])).mockResolvedValueOnce(listing("/wp-content", [directory("plugins", "/wp-content/plugins")])).mockResolvedValueOnce(listing("/wp-content/plugins", [])).mockResolvedValueOnce(listing("/wp-content", [directory("plugins", "/wp-content/plugins")])).mockResolvedValueOnce(listing("/wp-content/plugins", []));
    const wrapper = create(); await flushPromises();
    await wrapper.get('button[title="Open wp-content"]').trigger("click"); await flushPromises(); await wrapper.get('button[title="Open plugins"]').trigger("click"); await flushPromises();
    expect(wrapper.text()).toContain("Huidige map: /wp-content/plugins");
    const up = wrapper.findAll('button').find((button) => button.text().includes("Omhoog")); await up!.trigger("click"); await flushPromises();
    expect(api.listFilemanagerDirectory).toHaveBeenLastCalledWith("site-a", "token-a", "/wp-content");
    const back = wrapper.findAll('button').find((button) => button.text().includes("Terug")); await back!.trigger("click"); await flushPromises();
    expect(api.listFilemanagerDirectory).toHaveBeenLastCalledWith("site-a", "token-a", "/wp-content/plugins"); expect(wrapper.text()).toContain("Huidige map: /wp-content/plugins");
  });

  it("navigates through safe breadcrumb paths and keeps root controls disabled", async () => {
    api.listFilemanagerDirectory.mockResolvedValueOnce(listing("/", [directory("wp-content", "/wp-content")])).mockResolvedValueOnce(listing("/wp-content", [directory("plugins", "/wp-content/plugins")])).mockResolvedValueOnce(listing("/wp-content/plugins", [directory("example", "/wp-content/plugins/example")])).mockResolvedValueOnce(listing("/wp-content/plugins/example", [file("plugin.php", "/wp-content/plugins/example/plugin.php")])).mockResolvedValueOnce(listing("/wp-content", []));
    const wrapper = create(); await flushPromises();
    await wrapper.get('button[title="Open wp-content"]').trigger("click"); await flushPromises(); await wrapper.get('button[title="Open plugins"]').trigger("click"); await flushPromises(); await wrapper.get('button[title="Open example"]').trigger("click"); await flushPromises();
    expect(wrapper.text()).toContain("wp-content"); expect(wrapper.text()).toContain("plugins"); expect(wrapper.text()).toContain("example");
    await wrapper.get('button[title="/wp-content"]').trigger("click"); await flushPromises(); expect(api.listFilemanagerDirectory).toHaveBeenLastCalledWith("site-a", "token-a", "/wp-content");
    api.listFilemanagerDirectory.mockResolvedValueOnce(listing("/", [])); await wrapper.get('button[title="Hoofdmap"]').trigger("click"); await flushPromises();
    const up = wrapper.findAll('button').find((button) => button.text().includes("Omhoog")); expect(up!.attributes("disabled")).toBeDefined();
  });

  it("shows empty and safe error states and resets to the authentication gate when access expires", async () => {
    api.listFilemanagerDirectory.mockResolvedValueOnce(listing("/", [])); const empty = create(); await flushPromises(); expect(empty.text()).toContain("Deze map is leeg"); empty.unmount();
    api.listFilemanagerDirectory.mockRejectedValueOnce({ category: "filemanager_permission_denied", userMessage: "Geen toegang tot deze map." }); const failure = create(); await flushPromises(); expect(failure.get('[role="alert"]').text()).toContain("Geen toegang"); failure.unmount();
    const expired = vi.fn(); api.listFilemanagerDirectory.mockRejectedValueOnce({ category: "filemanager_auth_required", userMessage: "Niet meer geldig." }); const unauthorized = mount(FilemanagerBrowser, { props: { context, authorizationToken: "token-a" }, attrs: { onExpired: expired } }); await flushPromises(); expect(expired).toHaveBeenCalledOnce(); expect(unauthorized.find('[role="alert"]').exists()).toBe(false);
  });

  it("never renders a previous site's response after unmounting and uses the next site's credentials", async () => {
    let resolveA!: (value: FilemanagerDirectoryListing) => void; api.listFilemanagerDirectory.mockReturnValueOnce(new Promise((resolve) => { resolveA = resolve; })); const first = create(); first.unmount();
    const secondContext = { siteId: "site-b", siteName: "Website B", siteUrl: "https://b.test" }; api.listFilemanagerDirectory.mockResolvedValueOnce(listing("/", [file("b.php", "/b.php")])); const second = mount(FilemanagerBrowser, { props: { context: secondContext, authorizationToken: "token-b" } }); await flushPromises();
    resolveA(listing("/", [file("a.php", "/a.php")])); await flushPromises(); expect(second.text()).toContain("b.php"); expect(second.text()).not.toContain("a.php"); expect(api.listFilemanagerDirectory).toHaveBeenNthCalledWith(2, "site-b", "token-b", "/");
  });

  it("opens text, dotfile, space and unicode names in the shared read-only preview", async () => {
    const items = [file("example.php", "/example.php"), file("my plugin.php", "/my plugin.php"), file(".htaccess", "/.htaccess", null), file("bestand-ë.php", "/bestand-ë.php")];
    api.listFilemanagerDirectory.mockResolvedValueOnce(listing("/", items));
    api.readFilemanagerFile.mockImplementation(async (_site: string, _token: string, path: string) => ({
      fileName: path.slice(1), relativePath: path, sizeBytes: 48, modifiedAt: "2026-09-29T08:30:00Z", fileType: "php-bestand", extension: path === "/.htaccess" ? undefined : "php", textContent: "<script>alert(1)</script>\n<?php echo '€ 中文';", binary: false, truncated: false,
    }));
    const wrapper = create(); await flushPromises();
    for (const item of items) {
      await wrapper.get(`button[aria-label="Bekijk ${item.name}"]`).trigger("click"); await flushPromises();
      expect(api.readFilemanagerFile).toHaveBeenLastCalledWith("site-a", "token-a", item.path);
      expect(wrapper.get('[aria-label="Bestandspreview"]').text()).toContain(item.name);
      expect(wrapper.get(".file-preview-line-numbers").text()).toContain("2");
      expect(wrapper.html()).not.toContain("<script>alert(1)</script>");
      await wrapper.get(".modal-actions .button.secondary").trigger("click");
      expect(wrapper.text()).toContain("Huidige map: /");
    }
  });

  it("keeps the newest file response, reports safe failures and expires invalid access", async () => {
    api.listFilemanagerDirectory.mockResolvedValueOnce(listing("/", [file("a.php", "/a.php"), file("b.php", "/b.php"), file("archive.zip", "/archive.zip", "zip")]));
    let resolveA!: (value: object) => void;
    api.readFilemanagerFile.mockReturnValueOnce(new Promise((resolve) => { resolveA = resolve; })).mockResolvedValueOnce({ fileName: "b.php", relativePath: "/b.php", sizeBytes: 4, fileType: "php-bestand", extension: "php", textContent: "B", binary: false, truncated: false });
    const expired = vi.fn();
    const wrapper = mount(FilemanagerBrowser, { props: { context, authorizationToken: "token-a" }, attrs: { onExpired: expired } }); await flushPromises();
    await wrapper.get('button[aria-label="Bekijk a.php"]').trigger("click");
    await wrapper.get('button[aria-label="Bekijk b.php"]').trigger("click"); await flushPromises();
    resolveA({ fileName: "a.php", relativePath: "/a.php", sizeBytes: 4, fileType: "php-bestand", extension: "php", textContent: "A", binary: false, truncated: false }); await flushPromises();
    expect(wrapper.text()).toContain("b.php"); expect(wrapper.text()).not.toContain("a.php/a.php");
    await wrapper.get(".modal-actions .button.secondary").trigger("click");

    api.readFilemanagerFile.mockRejectedValueOnce({ category: "filemanager_permission_denied", userMessage: "Geen toegang tot dit bestand." });
    await wrapper.get('button[aria-label="Bekijk archive.zip"]').trigger("click"); await flushPromises();
    expect(wrapper.get('[role="alert"]').text()).toContain("Geen toegang");
    api.readFilemanagerFile.mockRejectedValueOnce({ category: "filemanager_auth_required", userMessage: "Verlopen." });
    await wrapper.get('button[aria-label="Bekijk archive.zip"]').trigger("click"); await flushPromises();
    expect(expired).toHaveBeenCalledOnce();
  });

  it("renders unsupported binary content as binary instead of code", async () => {
    api.listFilemanagerDirectory.mockResolvedValueOnce(listing("/", [file("archive.zip", "/archive.zip", "zip")]));
    api.readFilemanagerFile.mockResolvedValueOnce({ fileName: "archive.zip", relativePath: "/archive.zip", sizeBytes: 128, fileType: "zip-bestand", extension: "zip", binary: true, truncated: false });
    const wrapper = create(); await flushPromises(); await wrapper.get('button[aria-label="Bekijk archive.zip"]').trigger("click"); await flushPromises();
    expect(wrapper.text()).toContain("Binair bestand");
    expect(wrapper.find(".file-preview-code").exists()).toBe(false);
  });
});
