import { flushPromises, mount } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ExceptionsView from "./ExceptionsView.vue";

const api = vi.hoisted(() => ({
  listFindingExceptions: vi.fn(), listTrustedFiles: vi.fn(), removeFindingExceptions: vi.fn(), cleanupExpiredFindingExceptions: vi.fn(), revokeTrustedFiles: vi.fn(), retrustFile: vi.fn(),
}));
vi.mock("../services/tauri", () => ({ appApi: api }));

describe("ExceptionsView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.removeFindingExceptions.mockResolvedValue(1);
    api.cleanupExpiredFindingExceptions.mockResolvedValue(1);
    api.revokeTrustedFiles.mockResolvedValue(1);
    api.listFindingExceptions.mockResolvedValue([
      { id: "exception-1", siteId: "site-1", siteName: "Voorbeeld", checkType: "core_checksum", findingType: "missing", target: "readme.html", scope: "site", reason: "Handmatig genegeerd", createdAt: "2026-09-10T08:00:00Z", active: true },
      { id: "exception-2", siteId: "site-1", siteName: "Voorbeeld", checkType: "php_uploads", findingType: "suspicious", target: "wp-content/uploads/test.php", scope: "site", reason: "Handmatig genegeerd", createdAt: "2026-09-10T08:00:00Z", expiresAt: "2099-09-11T08:00:00Z", active: true },
      { id: "expired-1", siteId: "site-1", siteName: "Voorbeeld", checkType: "core_checksum", findingType: "modified", target: "wp-includes/version.php", scope: "site", reason: "Tijdelijk genegeerd", createdAt: "2020-09-10T08:00:00Z", expiresAt: "2020-09-11T08:00:00Z", active: true },
      { id: "expired-2", siteId: "site-1", siteName: "Voorbeeld", checkType: "core_checksum", findingType: "modified", target: "wp-admin/about.php", scope: "site", reason: "Tijdelijk genegeerd", createdAt: "2020-09-10T08:00:00Z", expiresAt: "2020-09-12T08:00:00Z", active: true },
    ]);
    api.listTrustedFiles.mockResolvedValue([
      { id: "trusted-1", siteId: "site-1", siteName: "Voorbeeld", relativePath: "wp-content/custom-loader.php", trustedSha256: "a".repeat(64), currentSha256: "b".repeat(64), sizeBytes: 10, currentSizeBytes: 11, fileType: "regular", status: "changed", trustedAt: "2026-09-10T08:00:00Z", lastCheckedAt: "2026-09-10T09:00:00Z", active: true },
      { id: "trusted-2", siteId: "site-1", siteName: "Voorbeeld", relativePath: "wp-content/mu-plugins/loader.php", trustedSha256: "c".repeat(64), currentSha256: "c".repeat(64), sizeBytes: 10, currentSizeBytes: 10, fileType: "regular", status: "trusted", trustedAt: "2026-09-10T08:00:00Z", lastCheckedAt: "2026-09-10T09:00:00Z", active: true },
    ]);
  });

  it("shows ignored and changed trusted records with management actions", async () => {
    const wrapper = mount(ExceptionsView);
    await flushPromises();
    expect(wrapper.text()).toContain("readme.html");
    await wrapper.findAll(".exception-tabs button")[1]!.trigger("click");
    expect(wrapper.text()).toContain("wp-content/custom-loader.php");
    expect(wrapper.text()).toContain("Gewijzigd");
    expect(wrapper.text()).toContain("Nieuwe versie vertrouwen");
    expect(wrapper.text()).toContain("Vertrouwen intrekken");
    wrapper.unmount();
  });

  it("confirms individual and bulk actions for every list", async () => {
    const wrapper = mount(ExceptionsView);
    await flushPromises();

    await wrapper.findAll("tbody .danger-text")[0]!.trigger("click");
    expect(wrapper.text()).toContain("Melding niet meer negeren?");
    await wrapper.get(".modal-actions .button.danger").trigger("click");
    await flushPromises();
    expect(api.removeFindingExceptions).toHaveBeenLastCalledWith(["exception-1"]);

    const ignoredChecks = wrapper.findAll("tbody input[type='checkbox']");
    await ignoredChecks[0]!.setValue(true);
    await ignoredChecks[1]!.setValue(true);
    await wrapper.get(".table-selection-toolbar .danger-text").trigger("click");
    await wrapper.get(".modal-actions .button.danger").trigger("click");
    await flushPromises();
    expect(api.removeFindingExceptions).toHaveBeenLastCalledWith(["exception-1", "exception-2"]);

    await wrapper.findAll(".exception-tabs button")[1]!.trigger("click");
    const trustedChecks = wrapper.findAll("tbody input[type='checkbox']");
    await trustedChecks[0]!.setValue(true);
    await trustedChecks[1]!.setValue(true);
    await wrapper.get(".table-selection-toolbar .danger-text").trigger("click");
    await wrapper.get(".modal-actions .button.danger").trigger("click");
    await flushPromises();
    expect(api.revokeTrustedFiles).toHaveBeenLastCalledWith(["trusted-1", "trusted-2"]);

    await wrapper.findAll(".exception-tabs button")[2]!.trigger("click");
    expect(wrapper.text()).toContain("Opruimen");
    expect(wrapper.text()).not.toContain("Niet meer negeren");
    const expiredChecks = wrapper.findAll("tbody input[type='checkbox']");
    await expiredChecks[0]!.setValue(true);
    await expiredChecks[1]!.setValue(true);
    await wrapper.get(".table-selection-toolbar .danger-text").trigger("click");
    await wrapper.get(".modal-actions .button.danger").trigger("click");
    await flushPromises();
    expect(api.cleanupExpiredFindingExceptions).toHaveBeenLastCalledWith(["expired-1", "expired-2"]);
    wrapper.unmount();
  });
});
