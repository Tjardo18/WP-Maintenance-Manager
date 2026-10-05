import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";
import ConfirmDialog from "./ConfirmDialog.vue";

describe("ConfirmDialog", () => {
  it("cannot be dismissed while an operation is active", async () => {
    const wrapper = mount(ConfirmDialog, { props: { title: "Bezig", busy: true } });
    await wrapper.get(".modal-close").trigger("click");
    await wrapper.get(".modal-backdrop").trigger("click");
    expect(wrapper.emitted("cancel")).toBeUndefined();
    expect(wrapper.get(".modal-close").attributes("disabled")).toBeDefined();
    wrapper.unmount();
  });

  it("still emits cancel when the dialog is idle", async () => {
    const wrapper = mount(ConfirmDialog, { props: { title: "Bevestigen" } });
    await wrapper.get(".modal-close").trigger("click");
    expect(wrapper.emitted("cancel")).toHaveLength(1);
    wrapper.unmount();
  });
});

describe("confirmation dialog keyboard navigation", () => {
  it("contains Tab focus, restores the opener and leaves media keys untouched", async () => {
    const opener = document.createElement("button");
    document.body.append(opener);
    opener.focus();
    const wrapper = mount(ConfirmDialog, { props: { title: "Verwijderen" }, attachTo: document.body });
    try {
      const buttons = wrapper.findAll("button");
      expect(document.activeElement).toBe(buttons[0].element);
      await buttons[0].trigger("keydown", { key: "Tab", shiftKey: true });
      expect(document.activeElement).toBe(buttons[2].element);
      await buttons[2].trigger("keydown", { key: "Tab" });
      expect(document.activeElement).toBe(buttons[0].element);
      const media = new KeyboardEvent("keydown", { key: "MediaPlayPause", bubbles: true, cancelable: true });
      buttons[0].element.dispatchEvent(media);
      expect(media.defaultPrevented).toBe(false);
      expect(wrapper.emitted("cancel")).toBeUndefined();
      await buttons[0].trigger("keydown", { key: "Escape" });
      expect(wrapper.emitted("cancel")).toHaveLength(1);
      await wrapper.setProps({ busy: true });
      await wrapper.get('[role="dialog"]').trigger("keydown", { key: "Escape" });
      expect(wrapper.emitted("cancel")).toHaveLength(1);
    } finally {
      wrapper.unmount();
      expect(document.activeElement).toBe(opener);
      opener.remove();
    }
  });
});
