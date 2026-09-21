import { flushPromises, mount } from "@vue/test-utils";
import { beforeEach, describe, expect, it, vi } from "vitest";
import type { ConnectionTestResult, Site } from "../types";
import NestedSiteDiscovery from "./NestedSiteDiscovery.vue";

const mockApi = vi.hoisted(() => ({
  testConnection: vi.fn(),
  saveSite: vi.fn(),
}));

vi.mock("../services/tauri", () => ({ appApi: mockApi }));

const parent: Site = {
  id: "dd81a778-5707-4465-a18a-5af955fa9e88",
  name: "Yellowbrand",
  url: "https://yellowbrand.nl/",
  sshHost: "ssh.yellowbrand.nl",
  sshPort: 22,
  sshUsername: "yellowbrand",
  authMethod: "password",
  wordpressPath: "/home/yellowbrand/domains/yellowbrand.nl/public_html/",
  pinnedHostKey: "SHA256:trusted-parent-key",
  status: "healthy",
  updateCount: 0,
  createdAt: "2026-09-21T10:00:00Z",
  updatedAt: "2026-09-21T10:00:00Z",
};

function connectionResult(unexpectedDirectories: string[] = []): ConnectionTestResult {
  return {
    success: true,
    requiresHostKeyAcceptance: false,
    unexpectedDirectories,
    unexpectedDirectoriesTruncated: false,
    steps: [],
  };
}

describe("NestedSiteDiscovery", () => {
  beforeEach(() => {
    mockApi.testConnection.mockReset();
    mockApi.saveSite.mockReset();
  });

  it("discovers directories through the saved parent connection", async () => {
    mockApi.testConnection.mockResolvedValue(connectionResult(["dev"]));

    const wrapper = mount(NestedSiteDiscovery, { props: { parent, sites: [parent] } });
    await flushPromises();

    expect(mockApi.testConnection).toHaveBeenCalledTimes(1);
    expect(mockApi.testConnection).toHaveBeenCalledWith(expect.objectContaining({
      id: parent.id,
      sshHost: parent.sshHost,
      wordpressPath: parent.wordpressPath,
      pinnedHostKey: parent.pinnedHostKey,
    }));
    expect(mockApi.testConnection.mock.calls[0]?.[0]).not.toHaveProperty("credentialSecret");
    expect(wrapper.text()).toContain("dev");
    expect(wrapper.text()).toContain("/home/yellowbrand/domains/yellowbrand.nl/public_html/dev");
  });

  it("verifies and saves an editable child with its parent relation", async () => {
    mockApi.testConnection
      .mockResolvedValueOnce(connectionResult(["academy"]))
      .mockResolvedValueOnce(connectionResult());
    const savedChild: Site = {
      ...parent,
      id: "a1eb5b5c-8fa7-41aa-a0a1-e2ccb5576795",
      name: "Academy platform",
      url: "https://yellowbrand.nl/academy/",
      wordpressPath: "/home/yellowbrand/domains/yellowbrand.nl/public_html/academy",
      parentSiteId: parent.id,
      relationType: "subdirectory",
      parentDirectory: "academy",
    };
    mockApi.saveSite.mockResolvedValue(savedChild);

    const wrapper = mount(NestedSiteDiscovery, { props: { parent, sites: [parent] } });
    await flushPromises();
    await wrapper.get('input[type="radio"][value="subdirectory"]').setValue();
    await flushPromises();

    const inputs = wrapper.findAll(".nested-site-details input");
    expect((inputs[0]?.element as HTMLInputElement).value).toBe("academy yellowbrand");
    expect((inputs[1]?.element as HTMLInputElement).value).toBe("https://yellowbrand.nl/academy/");
    expect((inputs[2]?.element as HTMLInputElement).value).toBe(
      "/home/yellowbrand/domains/yellowbrand.nl/public_html/academy",
    );
    expect(mockApi.testConnection).toHaveBeenLastCalledWith(expect.objectContaining({
      id: parent.id,
      url: "https://yellowbrand.nl/academy/",
      wordpressPath: "/home/yellowbrand/domains/yellowbrand.nl/public_html/academy",
    }));

    await inputs[0]?.setValue("Academy platform");
    await wrapper.get("button.primary").trigger("click");
    await flushPromises();

    expect(mockApi.saveSite).toHaveBeenCalledWith(expect.objectContaining({
      name: "Academy platform",
      url: "https://yellowbrand.nl/academy/",
      wordpressPath: "/home/yellowbrand/domains/yellowbrand.nl/public_html/academy",
      parentSiteId: parent.id,
      relationType: "subdirectory",
      parentDirectory: "academy",
    }));
    expect(mockApi.saveSite.mock.calls[0]?.[0]).not.toHaveProperty("credentialSecret");
    expect(wrapper.emitted("saved")?.[0]).toEqual([savedChild]);
    expect(wrapper.text()).toContain("De extra WordPress-installatie is gekoppeld.");
  });

  it("discovers and saves subdirectories on multiple levels in parent-first order", async () => {
    mockApi.testConnection
      .mockResolvedValueOnce(connectionResult(["academy"]))
      .mockResolvedValueOnce(connectionResult(["course"]))
      .mockResolvedValueOnce(connectionResult());
    const academy: Site = {
      ...parent,
      id: "a1eb5b5c-8fa7-41aa-a0a1-e2ccb5576795",
      name: "academy yellowbrand",
      url: "https://yellowbrand.nl/academy/",
      wordpressPath: "/home/yellowbrand/domains/yellowbrand.nl/public_html/academy",
      parentSiteId: parent.id,
      relationType: "subdirectory",
      parentDirectory: "academy",
    };
    const course: Site = {
      ...academy,
      id: "91b9b7f3-0776-4744-bffe-ab154bec4dba",
      name: "course yellowbrand",
      url: "https://yellowbrand.nl/academy/course/",
      wordpressPath: "/home/yellowbrand/domains/yellowbrand.nl/public_html/academy/course",
      parentSiteId: academy.id,
      parentDirectory: "course",
    };
    mockApi.saveSite.mockResolvedValueOnce(academy).mockResolvedValueOnce(course);

    const wrapper = mount(NestedSiteDiscovery, { props: { parent, sites: [parent] } });
    await flushPromises();
    await wrapper.get('input[type="radio"][value="subdirectory"]').setValue();
    await flushPromises();

    expect(wrapper.findAll(".nested-site")).toHaveLength(2);
    expect(wrapper.text()).toContain("Niveau 2");
    const nestedChoice = wrapper.findAll('input[type="radio"][value="subdirectory"]')[1];
    await nestedChoice?.setValue();
    await flushPromises();

    const nestedInputs = wrapper.findAll(".nested-site")[1]?.findAll(".nested-site-details input") ?? [];
    expect((nestedInputs[0]?.element as HTMLInputElement).value).toBe("course yellowbrand");
    expect((nestedInputs[1]?.element as HTMLInputElement).value).toBe("https://yellowbrand.nl/academy/course/");
    expect((nestedInputs[2]?.element as HTMLInputElement).value).toBe(
      "/home/yellowbrand/domains/yellowbrand.nl/public_html/academy/course",
    );

    await wrapper.get("button.primary").trigger("click");
    await flushPromises();

    expect(mockApi.saveSite).toHaveBeenNthCalledWith(1, expect.objectContaining({
      parentSiteId: parent.id,
      parentDirectory: "academy",
    }));
    expect(mockApi.saveSite).toHaveBeenNthCalledWith(2, expect.objectContaining({
      parentSiteId: academy.id,
      parentDirectory: "course",
    }));
    expect(wrapper.emitted("saved")?.[0]).toEqual([course]);
    expect(wrapper.text()).toContain("2 extra WordPress-installaties zijn gekoppeld.");
  });
});
