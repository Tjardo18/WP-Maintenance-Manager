import { flushPromises, mount } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import FilemanagerBrowser from "./FilemanagerBrowser.vue";
import type { FilemanagerDirectoryListing } from "../types/filemanager";
import { createMemoryHistory, createRouter } from "vue-router";

const api = vi.hoisted(() => ({ listFilemanagerDirectory: vi.fn(), readFilemanagerFile: vi.fn(), saveFilemanagerFile: vi.fn(), createFilemanagerFile: vi.fn(), createFilemanagerDirectory: vi.fn(), deleteFilemanagerItem: vi.fn(), changeFilemanagerPermissions: vi.fn(), changeFilemanagerPermissionsBulk: vi.fn(), deleteFilemanagerBulk: vi.fn(), downloadFilemanagerItems: vi.fn(), getSettings: vi.fn() }));
vi.mock("../services/tauri", () => ({ appApi: api }));
const context = { siteId: "site-a", siteName: "Website A", siteUrl: "https://a.test" };
const listing = (path: string, items: FilemanagerDirectoryListing["items"] = []): FilemanagerDirectoryListing => ({ currentPath: path, isRoot: path === "/", parentPath: path === "/" ? null : path.slice(0, path.lastIndexOf("/")) || "/", items, truncated: false });
const directory = (name: string, path: string) => ({ name, path, kind: "directory" as const, extension: null, size: null, permissions: "755", modifiedAt: "2026-09-29T08:30:00Z" });
const file = (name: string, path: string, extension: string | null = "php") => ({ name, path, kind: "file" as const, extension, size: 4300, permissions: "644", modifiedAt: "2026-09-29T08:30:00Z" });
const create = () => mount(FilemanagerBrowser, { props: { context, authorizationToken: "token-a" } });

describe("Filemanager directorybrowser", () => {
  it("clears open mutation dialogs when the website changes", async () => {
    api.listFilemanagerDirectory.mockResolvedValue(listing('/', [file('a.php', '/a.php')]));
    const w = create(); await flushPromises();
    await w.get('[aria-label="Verwijder bestand a.php"]').trigger('click');
    await w.setProps({ context: { ...context, siteId: 'site-b' }, authorizationToken: 'token-b' });
    await flushPromises();
    expect(w.find('[aria-label="Bestand verwijderen?"]').exists()).toBe(false);
    expect(api.deleteFilemanagerItem).not.toHaveBeenCalled();
    w.unmount();
  });

  it("ignores a late create response after switching websites and back", async () => {
    api.listFilemanagerDirectory.mockResolvedValue(listing('/', []));
    let finish!: (value: unknown) => void;
    api.createFilemanagerFile.mockReturnValue(new Promise((resolve) => { finish = resolve; }));
    const w = create(); await flushPromises();
    await w.findAll('button').find((b) => b.text().includes('Nieuw bestand'))!.trigger('click');
    await w.get('#filemanager-new-name').setValue('old.php');
    await w.findAll('button').find((b) => b.text() === 'Aanmaken')!.trigger('click');
    await w.setProps({ context: { ...context, siteId: 'site-b' }, authorizationToken: 'token-b' }); await flushPromises();
    await w.setProps({ context, authorizationToken: 'new-token-a' }); await flushPromises();
    const calls = api.listFilemanagerDirectory.mock.calls.length;
    finish({ path: '/old.php', name: 'old.php', kind: 'file' }); await flushPromises();
    expect(api.listFilemanagerDirectory).toHaveBeenCalledTimes(calls);
    expect(w.text()).not.toContain('Bestand aangemaakt.');
    w.unmount();
  });
  it("saves with site-bound credentials, updates the preview and guards route changes", async () => {
    const router = createRouter({ history: createMemoryHistory(), routes: [{ path: '/:site', component: { template: '<div />' } }] });
    await router.push('/site-a');
    api.listFilemanagerDirectory.mockResolvedValue(listing('/', [file('edit.php', '/edit.php')]));
    const source = { fileName: 'edit.php', relativePath: '/edit.php', sizeBytes: 3, fileType: 'php', extension: 'php', textContent: 'old', binary: false, truncated: false, editVersion: 'a'.repeat(64) };
    api.readFilemanagerFile.mockResolvedValue(source);
    api.saveFilemanagerFile.mockResolvedValue({ ...source, textContent: 'new', editVersion: 'b'.repeat(64) });
    const w = mount(FilemanagerBrowser, { props: { context, authorizationToken: 'token-a' }, global: { plugins: [router] } });
    await flushPromises(); await w.get('[aria-label="Bekijk edit.php"]').trigger('click'); await flushPromises();
    const click = async (text: string) => { await w.findAll('button').find((b) => b.text() === text)!.trigger('click'); await flushPromises(); };
    await click('Bewerken'); await w.get('textarea').setValue('new'); await click('Opslaan');
    expect(api.saveFilemanagerFile).toHaveBeenCalledWith('site-a', 'token-a', { path: '/edit.php', content: 'new', expectedVersion: source.editVersion });
    expect(w.get('.file-preview-code').text()).toBe('new');
    await click('Bewerken'); await w.get('textarea').setValue('unsaved');
    const blocked = router.push('/site-b'); await flushPromises();
    expect(w.text()).toContain('Wijzigingen verwerpen?');
    await w.get('[aria-label="Wijzigingen verwerpen?"] .button.secondary').trigger('click'); await blocked;
    expect(router.currentRoute.value.path).toBe('/site-a');
    const allowed = router.push('/site-b'); await flushPromises(); await click('Verwerpen'); await allowed;
    expect(router.currentRoute.value.path).toBe('/site-b'); w.unmount();
  });
  beforeEach(() => { vi.resetAllMocks(); api.getSettings.mockResolvedValue({ scanConcurrency: 4, filePreviewMode: "normal", markdownPreviewMode: "raw" }); });

  it("downloads one server file directly and keeps the selection after a bulk archive", async () => {
    const items = [file("index.php", "/index.php"), directory("wp-content", "/wp-content")];
    api.listFilemanagerDirectory.mockResolvedValue(listing("/", items));
    api.downloadFilemanagerItems.mockResolvedValueOnce({ fileName: "index.php", bytes: 12, archived: false, savedTo: "C:\\Downloads\\index.php" }).mockResolvedValueOnce({ fileName: "filemanager-download.zip", bytes: 20, archived: true, savedTo: "C:\\Downloads\\filemanager-download.zip" });
    const wrapper = create(); await flushPromises();
    await wrapper.get('[aria-label="Download index.php"]').trigger("click"); await flushPromises();
    expect(api.downloadFilemanagerItems).toHaveBeenCalledWith("site-a", "token-a", { directory: "/", items: [{ path: "/index.php", expectedKind: "file" }] });
    expect(wrapper.text()).toContain("Download opgeslagen");
    await wrapper.get('[aria-label="Selecteer alle items in deze map"]').setValue(true);
    await wrapper.findAll(".filemanager-bulk-toolbar button").find((button) => button.text().includes("Downloaden"))!.trigger("click"); await flushPromises();
    expect(api.downloadFilemanagerItems).toHaveBeenLastCalledWith("site-a", "token-a", { directory: "/", items: [{ path: "/index.php", expectedKind: "file" }, { path: "/wp-content", expectedKind: "directory" }] });
    expect(wrapper.text()).toContain("2 items geselecteerd");
    expect(wrapper.text()).toContain("filemanager-download.zip");
  });

  it("shows download failures and disables duplicate requests while saving", async () => {
    api.listFilemanagerDirectory.mockResolvedValue(listing("/", [file("large.bin", "/large.bin", "bin")]));
    let reject!: (reason: unknown) => void;
    api.downloadFilemanagerItems.mockReturnValue(new Promise((_resolve, rejected) => { reject = rejected; }));
    const wrapper = create(); await flushPromises();
    await wrapper.get('[aria-label="Download large.bin"]').trigger("click"); await flushPromises();
    expect(wrapper.text()).toContain("Download voorbereiden");
    expect(wrapper.get('[aria-label="Download large.bin"]').attributes("disabled")).toBeDefined();
    reject({ category: "filemanager_download_write_failed", userMessage: "Onvoldoende schijfruimte." }); await flushPromises();
    expect(wrapper.get('[role="alert"]').text()).toContain("Onvoldoende schijfruimte");
  });

  it("downloads one directory as an archive and reports a server read failure", async () => {
    api.listFilemanagerDirectory.mockResolvedValue(listing("/", [directory("wp-content", "/wp-content")]));
    api.downloadFilemanagerItems.mockResolvedValueOnce({ fileName: "wp-content.zip", bytes: 12, archived: true, savedTo: "C:\\Downloads\\wp-content.zip" }).mockRejectedValueOnce({ category: "filemanager_file_read_failed", userMessage: "Een bestand kon niet worden gelezen." });
    const wrapper = create(); await flushPromises();
    await wrapper.get('[aria-label="Download wp-content"]').trigger("click"); await flushPromises();
    expect(api.downloadFilemanagerItems).toHaveBeenCalledWith("site-a", "token-a", { directory: "/", items: [{ path: "/wp-content", expectedKind: "directory" }] });
    expect(wrapper.text()).toContain("wp-content.zip");
    await wrapper.get('[aria-label="Download wp-content"]').trigger("click"); await flushPromises();
    expect(wrapper.get('[role="alert"]').text()).toContain("Een bestand kon niet worden gelezen");
  });

  it("selects the current listing, clears selection on navigation and changes one item's permissions", async () => {
    const items = [directory("uploads", "/uploads"), file("index.php", "/index.php")];
    api.listFilemanagerDirectory.mockResolvedValueOnce(listing("/", items)).mockResolvedValueOnce(listing("/", [{ ...items[0], permissions: "750" }, items[1]])).mockResolvedValueOnce(listing("/uploads", []));
    api.changeFilemanagerPermissions.mockResolvedValue(undefined);
    const wrapper = create(); await flushPromises();
    await wrapper.get('[aria-label="Selecteer uploads"]').setValue(true);
    expect(wrapper.text()).toContain("1 item geselecteerd");
    await wrapper.get('[aria-label="Selecteer alle items in deze map"]').setValue(true);
    expect(wrapper.text()).toContain("2 items geselecteerd");
    await wrapper.get('[aria-label="Permissions wijzigen van uploads"]').trigger("click");
    await wrapper.get("#filemanager-permissions").setValue("750");
    await wrapper.get('[aria-label="Permissions wijzigen"] .button.primary').trigger("click"); await flushPromises();
    expect(api.changeFilemanagerPermissions).toHaveBeenCalledWith("site-a", "token-a", { path: "/uploads", expectedKind: "directory", mode: "750" });
    expect(wrapper.get(".filemanager-table").text()).toContain("750");
    await wrapper.get('[title="Open uploads"]').trigger("click"); await flushPromises();
    expect(wrapper.text()).not.toContain("geselecteerd");
  });

  it("confirms bulk deletion and shows itemized partial failure", async () => {
    const items = [file("a.php", "/a.php"), file("b.php", "/b.php")];
    api.listFilemanagerDirectory.mockResolvedValueOnce(listing("/", items)).mockResolvedValueOnce(listing("/", [items[1]]));
    api.deleteFilemanagerBulk.mockResolvedValue({ requested: 2, succeeded: 1, failed: 1, failures: [{ path: "/b.php", reason: "Geen schrijfrechten." }] });
    const wrapper = create(); await flushPromises();
    await wrapper.get('[aria-label="Selecteer alle items in deze map"]').setValue(true);
    await wrapper.get(".filemanager-bulk-toolbar .button.danger").trigger("click");
    expect(wrapper.text()).toContain("deze 2 items wilt verwijderen");
    await wrapper.get('[aria-label="Geselecteerde items verwijderen?"] .button.secondary').trigger("click");
    expect(api.deleteFilemanagerBulk).not.toHaveBeenCalled();
    await wrapper.get(".filemanager-bulk-toolbar .button.danger").trigger("click");
    await wrapper.get('[aria-label="Geselecteerde items verwijderen?"] .button.danger').trigger("click"); await flushPromises();
    expect(api.deleteFilemanagerBulk).toHaveBeenCalledWith("site-a", "token-a", { directory: "/", items: [{ path: "/a.php", expectedKind: "file" }, { path: "/b.php", expectedKind: "file" }] });
    expect(wrapper.text()).toContain("1 van 2 items verwijderd");
    expect(wrapper.text()).toContain("Geen schrijfrechten");
  });

  it("drops selection when switching websites in the same browser instance", async () => {
    api.listFilemanagerDirectory.mockResolvedValueOnce(listing("/", [file("a.php", "/a.php")])).mockResolvedValueOnce(listing("/", [file("b.php", "/b.php")]));
    const wrapper = create(); await flushPromises();
    await wrapper.get('[aria-label="Selecteer a.php"]').setValue(true);
    expect(wrapper.text()).toContain("1 item geselecteerd");
    await wrapper.setProps({ context: { siteId: "site-b", siteName: "Website B", siteUrl: "https://b.test" }, authorizationToken: "token-b" }); await flushPromises();
    expect(api.listFilemanagerDirectory).toHaveBeenLastCalledWith("site-b", "token-b", "/");
    expect(wrapper.text()).toContain("b.php");
    expect(wrapper.text()).not.toContain("1 item geselecteerd");
  });

  it("ignores an in-flight listing from the previous website", async () => {
    let finishOld!: (value: FilemanagerDirectoryListing) => void;
    api.listFilemanagerDirectory.mockReturnValueOnce(new Promise((resolve) => { finishOld = resolve; })).mockResolvedValueOnce(listing("/", [file("b.php", "/b.php")]));
    const wrapper = create();
    await wrapper.setProps({ context: { siteId: "site-b", siteName: "Website B", siteUrl: "https://b.test" }, authorizationToken: "token-b" });
    await flushPromises();
    finishOld(listing("/", [file("a.php", "/a.php")])); await flushPromises();
    expect(wrapper.text()).toContain("b.php");
    expect(wrapper.text()).not.toContain("a.php");
  });

  it("does not bulk-delete an open file with unsaved edits without the discard guard", async () => {
    api.listFilemanagerDirectory.mockResolvedValue(listing("/", [file("edit.php", "/edit.php")]));
    api.readFilemanagerFile.mockResolvedValue({ fileName: "edit.php", relativePath: "/edit.php", sizeBytes: 3, fileType: "php", extension: "php", textContent: "old", binary: false, truncated: false, editVersion: "a".repeat(64) });
    const wrapper = create(); await flushPromises();
    await wrapper.get('[aria-label="Bekijk edit.php"]').trigger("click"); await flushPromises();
    await wrapper.findAll("button").find((button) => button.text() === "Bewerken")!.trigger("click");
    await wrapper.get("textarea").setValue("unsaved");
    await wrapper.get('[aria-label="Selecteer edit.php"]').setValue(true);
    await wrapper.get(".filemanager-bulk-toolbar .button.danger").trigger("click");
    await wrapper.get('[aria-label="Geselecteerde items verwijderen?"] .button.danger').trigger("click"); await flushPromises();
    expect(wrapper.text()).toContain("Wijzigingen verwerpen?");
    expect(api.deleteFilemanagerBulk).not.toHaveBeenCalled();
    await wrapper.get('[aria-label="Wijzigingen verwerpen?"] .button.secondary').trigger("click"); await flushPromises();
    expect(api.deleteFilemanagerBulk).not.toHaveBeenCalled();
  });

  it("creates a file in the current directory, refreshes and opens it", async () => {
    api.listFilemanagerDirectory.mockResolvedValueOnce(listing("/", [directory("wp-content", "/wp-content")])).mockResolvedValueOnce(listing("/wp-content", [])).mockResolvedValueOnce(listing("/wp-content", [file("test.php", "/wp-content/test.php")]));
    api.createFilemanagerFile.mockResolvedValue({ path: "/wp-content/test.php", name: "test.php", kind: "file" });
    api.readFilemanagerFile.mockResolvedValue({ fileName: "test.php", relativePath: "/wp-content/test.php", sizeBytes: 0, fileType: "php", extension: "php", textContent: "", binary: false, truncated: false, editVersion: "a".repeat(64) });
    const wrapper = create(); await flushPromises(); await wrapper.get('[title="Open wp-content"]').trigger("click"); await flushPromises();
    await wrapper.findAll("button").find((button) => button.text().includes("Nieuw bestand"))!.trigger("click");
    await wrapper.get("#filemanager-new-name").setValue("test.php"); await wrapper.findAll("button").find((button) => button.text() === "Aanmaken")!.trigger("click"); await flushPromises();
    expect(api.createFilemanagerFile).toHaveBeenCalledWith("site-a", "token-a", { directory: "/wp-content", name: "test.php" });
    expect(api.readFilemanagerFile).toHaveBeenCalledWith("site-a", "token-a", "/wp-content/test.php");
    expect(wrapper.text()).toContain("Bestand aangemaakt."); expect(wrapper.text()).toContain("Bewerken");
  });

  it("confirms delete, refreshes after success and keeps the item on cancellation/failure", async () => {
    const item = file("old.php", "/old.php");
    api.listFilemanagerDirectory.mockResolvedValueOnce(listing("/", [item])).mockResolvedValueOnce(listing("/", []));
    api.deleteFilemanagerItem.mockResolvedValue({ path: "/old.php", name: "old.php", kind: "file" });
    const wrapper = create(); await flushPromises();
    await wrapper.get('[aria-label="Verwijder bestand old.php"]').trigger("click");
    expect(wrapper.text()).toContain("Weet je zeker dat je old.php wilt verwijderen?");
    await wrapper.get('[aria-label="Bestand verwijderen?"] .button.secondary').trigger("click");
    expect(api.deleteFilemanagerItem).not.toHaveBeenCalled();
    await wrapper.get('[aria-label="Verwijder bestand old.php"]').trigger("click"); await wrapper.findAll("button").find((button) => button.text() === "Verwijderen")!.trigger("click"); await flushPromises();
    expect(api.deleteFilemanagerItem).toHaveBeenCalledWith("site-a", "token-a", { path: "/old.php", expectedKind: "file" });
    expect(wrapper.text()).toContain("Bestand verwijderd.");
    api.listFilemanagerDirectory.mockResolvedValueOnce(listing("/", [item])); api.deleteFilemanagerItem.mockRejectedValueOnce({ category: "filemanager_directory_not_empty", userMessage: "Deze map is niet leeg." });
  });

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

  it("uses the existing fullscreen and Markdown preview preferences", async () => {
    api.getSettings.mockResolvedValueOnce({ scanConcurrency: 4, filePreviewMode: "fullscreen", markdownPreviewMode: "preview" });
    api.listFilemanagerDirectory.mockResolvedValueOnce(listing("/", [file("README.md", "/README.md", "md")]));
    api.readFilemanagerFile.mockResolvedValueOnce({ fileName: "README.md", relativePath: "/README.md", sizeBytes: 10, fileType: "md-bestand", extension: "md", textContent: "# Titel", binary: false, truncated: false });
    const wrapper = create(); await flushPromises(); await wrapper.get('button[aria-label="Bekijk README.md"]').trigger("click"); await flushPromises();
    expect(wrapper.get(".preview-modal").classes()).toContain("fullscreen");
    expect(wrapper.get(".markdown-preview h1").text()).toBe("Titel");
    expect(wrapper.get('button[aria-pressed="true"]').text()).toContain("Preview");
  });
});
