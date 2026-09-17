import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";
import ScanStepList from "./ScanStepList.vue";

describe("ScanStepList", () => {
  it("shows a distinct icon and label for every scan status", () => {
    const wrapper = mount(ScanStepList, { props: { steps: [
      { key: "pending", label: "Wachtend", status: "pending" },
      { key: "running", label: "Bezig", status: "running" },
      { key: "success", label: "Geslaagd", status: "success", durationMs: 42 },
      { key: "warning", label: "Waarschuwing", status: "warning", durationMs: 51 },
      { key: "failed", label: "Mislukt", status: "failed", durationMs: 60 },
      { key: "skipped", label: "Overgeslagen", status: "skipped" },
    ] } });

    expect(wrapper.get('[data-step-status="pending"]').attributes("aria-label")).toBe("Nog niet uitgevoerd");
    expect(wrapper.get('[data-step-status="running"] svg').classes()).toContain("lucide-loader-circle");
    expect(wrapper.get('[data-step-status="success"] svg').classes()).toContain("lucide-check");
    expect(wrapper.get('[data-step-status="warning"] svg').classes()).toContain("lucide-triangle-alert");
    expect(wrapper.get('[data-step-status="failed"] svg').classes()).toContain("lucide-x");
    expect(wrapper.get('[data-step-status="skipped"] svg').classes()).toContain("lucide-minus");
  });

  it("only displays a finite non-negative execution time", () => {
    const wrapper = mount(ScanStepList, { props: { steps: [
      { key: "pending", label: "Wachtend", status: "pending", durationMs: null },
      { key: "missing", label: "Nog geen tijd", status: "pending" },
      { key: "invalid", label: "Ongeldig", status: "failed", durationMs: Number.NaN },
      { key: "zero", label: "Direct", status: "success", durationMs: 0 },
    ] } });

    expect(wrapper.text()).not.toContain("null ms");
    expect(wrapper.text()).not.toContain("NaN ms");
    expect(wrapper.text()).toContain("0 ms");
    expect(wrapper.findAll("small")).toHaveLength(1);
  });
});
