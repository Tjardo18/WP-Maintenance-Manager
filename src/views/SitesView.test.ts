import { mount } from "@vue/test-utils";
import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it } from "vitest";
import type { Site } from "../types";
import { useSitesStore } from "../stores/sites";
import SitesView from "./SitesView.vue";

const site: Site = {
  id: "site-a", name: "Site A", url: "https://site-a.test", sshHost: "ssh.site-a.test",
  sshPort: 22, sshUsername: "deploy", authMethod: "keyFile", wordpressPath: "/srv/site-a",
  status: "healthy", wordpressVersion: "6.8.2", wpCliVersion: "WP-CLI 2.12.0",
  wpCliVersionCheckedAt: "2026-09-17T10:00:00.000Z", updateCount: 0,
  createdAt: "2026-09-17T10:00:00.000Z", updatedAt: "2026-09-17T10:00:00.000Z",
};

describe("website cards", () => {
  it("shows the WP-CLI version between WordPress and the last scan", () => {
    const pinia = createPinia();
    setActivePinia(pinia);
    useSitesStore().sites = [site];
    const wrapper = mount(SitesView, { global: { plugins: [pinia], stubs: { RouterLink: { template: "<a><slot /></a>" } } } });
    const labels = wrapper.findAll(".site-card dl dt").map((item) => item.text());

    expect(labels).toEqual(["SSH-server", "WordPress", "WP-CLI-versie", "Laatste scan"]);
    expect(wrapper.get(".site-card dl").text()).toContain("WP-CLI 2.12.0");
  });
});
