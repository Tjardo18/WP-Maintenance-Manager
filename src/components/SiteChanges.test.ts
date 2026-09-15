import { mount } from "@vue/test-utils";
import { describe, expect, it } from "vitest";
import SiteChanges from "./SiteChanges.vue";
import { demoChanges } from "../services/fixtures";

describe("SiteChanges", () => {
  it("explains the first baseline without reporting existing entities as new", () => {
    const baseline = structuredClone(demoChanges);
    baseline.latestSnapshot = baseline.baselineSnapshot;
    baseline.comparison = null;
    const wrapper = mount(SiteChanges, { props: { history: baseline } });
    expect(wrapper.text()).toContain("Baseline aangemaakt");
    expect(wrapper.findAll(".change-card")).toHaveLength(0);
  });

  it("shows friendly values, maintenance context, filters and partial sections", async () => {
    const history = structuredClone(demoChanges);
    history.comparison!.changes[0]!.origin = "maintenance";
    const wrapper = mount(SiteChanges, { props: { history } });
    expect(wrapper.text()).toContain("WooCommerce bijgewerkt");
    expect(wrapper.text()).toContain("9.8.1");
    expect(wrapper.text()).toContain("Uit");
    expect(wrapper.text()).toContain("Aan");
    expect(wrapper.text()).toContain("Uitgevoerd door onderhoud");
    expect(wrapper.text()).toContain("Vergelijking niet beschikbaar");
    expect(wrapper.emitted("viewed")?.[0]).toEqual(["snapshot-current"]);

    const userFilter = wrapper.findAll(".change-filters button").find((button) => button.text().includes("Gebruikers"));
    await userFilter!.trigger("click");
    expect(wrapper.findAll(".change-card")).toHaveLength(1);
    expect(wrapper.text()).toContain("Nieuwe administrator");
    expect(wrapper.text()).not.toContain("WooCommerce bijgewerkt");
  });

  it("uses a clear no-change state for identical comparable snapshots", () => {
    const history = structuredClone(demoChanges);
    history.comparison!.changes = [];
    history.comparison!.sections = history.comparison!.sections.map((section) => ({ ...section, status: "compared", reason: null }));
    const wrapper = mount(SiteChanges, { props: { history } });
    expect(wrapper.text()).toContain("Geen wijzigingen gevonden");
  });
});
