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
  });

  it("still emits cancel when the dialog is idle", async () => {
    const wrapper = mount(ConfirmDialog, { props: { title: "Bevestigen" } });

    await wrapper.get(".modal-close").trigger("click");

    expect(wrapper.emitted("cancel")).toHaveLength(1);
  });
});
