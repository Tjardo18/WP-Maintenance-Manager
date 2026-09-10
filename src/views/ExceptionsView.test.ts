import { flushPromises, mount } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import ExceptionsView from "./ExceptionsView.vue";

const api = vi.hoisted(() => ({
  listFindingExceptions: vi.fn(), listTrustedFiles: vi.fn(), removeFindingException: vi.fn(), revokeTrustedFile: vi.fn(), retrustFile: vi.fn(),
}));
vi.mock("../services/tauri", () => ({ appApi: api }));

describe("ExceptionsView", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    api.listFindingExceptions.mockResolvedValue([{ id: "exception-1", siteId: "site-1", siteName: "Voorbeeld", checkType: "core_checksum", findingType: "missing", target: "readme.html", scope: "site", reason: "Handmatig genegeerd", createdAt: "2026-09-10T08:00:00Z", active: true }]);
    api.listTrustedFiles.mockResolvedValue([{ id: "trusted-1", siteId: "site-1", siteName: "Voorbeeld", relativePath: "wp-content/custom-loader.php", trustedSha256: "a".repeat(64), currentSha256: "b".repeat(64), sizeBytes: 10, currentSizeBytes: 11, fileType: "regular", status: "changed", trustedAt: "2026-09-10T08:00:00Z", lastCheckedAt: "2026-09-10T09:00:00Z", active: true }]);
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
  });
});
