import { enableAutoUnmount, flushPromises, mount } from "@vue/test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";
import ChecksumFilePreview from "./ChecksumFilePreview.vue";
import type { FileContentPreview } from "../types";
vi.mock("../services/tauri", () => ({ appApi: {} }));
enableAutoUnmount(afterEach);
const original: FileContentPreview = { fileName: "test.php", relativePath: "/test.php", fileType: "php", extension: "php", sizeBytes: 20, textContent: "\uFEFF<?php\r\necho 'é';\r\n", binary: false, truncated: false, editVersion: "a".repeat(64) };
const create = (saveFile = vi.fn().mockResolvedValue({ ...original, textContent: "new", editVersion: "b".repeat(64) })) => mount(ChecksumFilePreview, { props: { preview: { ...original }, saveFile } });
type Wrapper = ReturnType<typeof create>;
const click = async (w: Wrapper, text: string) => { await w.findAll("button").find((b) => b.text() === text)!.trigger("click"); await flushPromises(); };

describe("file editing", () => {
  it("requires explicit saving, preserves CRLF/BOM and refreshes preview from server response", async () => {
    const save = vi.fn().mockResolvedValue({ ...original, textContent: "saved", editVersion: "b".repeat(64) });
    const w = create(save); await click(w, "Bewerken");
    expect(w.findAll("button").find((b) => b.text() === "Opslaan")!.attributes("disabled")).toBeDefined();
    await w.get("textarea").setValue("<?php\necho '中文 🚀';\n");
    expect(save).not.toHaveBeenCalled();
    await click(w, "Opslaan");
    expect(save).toHaveBeenCalledWith("\uFEFF<?php\r\necho '中文 🚀';\r\n", original.editVersion);
    expect(w.emitted("saved")![0]![0]).toMatchObject({ textContent: "saved", editVersion: "b".repeat(64) });
    expect(w.text()).toContain("Bestand opgeslagen."); expect(w.find("textarea").exists()).toBe(false);
  });
  it("confirms Escape and cancel without writing, retaining draft when declined", async () => {
    const save = vi.fn(); const w = create(save); await click(w, "Bewerken"); await w.get("textarea").setValue("changed");
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" })); await flushPromises();
    expect(w.text()).toContain("Wijzigingen verwerpen?"); expect(w.emitted("close")).toBeUndefined();
    await w.get('[aria-label="Wijzigingen verwerpen?"] .button.secondary').trigger("click"); await flushPromises();
    expect((w.get("textarea").element as HTMLTextAreaElement).value).toBe("changed");
    await click(w, "Annuleren"); await click(w, "Verwerpen");
    expect(w.find("textarea").exists()).toBe(false); expect(save).not.toHaveBeenCalled();
    expect(w.get(".file-preview-code").text()).toContain("echo 'é'");
  });
  it("keeps failed/conflicting edits, blocks double saves and close during save", async () => {
    let reject!: (cause: Error) => void;
    const save = vi.fn(() => new Promise<FileContentPreview>((_resolve, fail) => { reject = fail; }));
    const w = create(save); await click(w, "Bewerken"); await w.get("textarea").setValue("<script>alert(1)</script>");
    await click(w, "Opslaan");
    window.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape" })); await flushPromises();
    expect(w.emitted("close")).toBeUndefined(); expect(w.get("textarea").attributes("disabled")).toBeDefined();
    expect(w.find("script").exists()).toBe(false); expect(save).toHaveBeenCalledOnce();
    reject(new Error("Dit bestand is gewijzigd. Herlaad het bestand.")); await flushPromises();
    expect(w.get('[role="alert"]').text()).toContain("gewijzigd");
    expect((w.get("textarea").element as HTMLTextAreaElement).value).toBe("<script>alert(1)</script>");
    expect(w.text()).not.toContain("Bestand opgeslagen.");
  });
  it("does not offer editing without a backend version, for binary or truncated files", async () => {
    for (const change of [{ editVersion: undefined }, { binary: true }, { truncated: true }]) {
      const w = create(); await w.setProps({ preview: { ...original, ...change } });
      expect(w.text()).not.toContain("Bewerken"); w.unmount();
    }
  });
});
