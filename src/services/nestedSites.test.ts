import { describe, expect, it } from "vitest";
import type { Site } from "../types";
import { availableNestedDirectories, buildNestedSiteProposal, joinWordpressPath, reconnectableNestedSite, rootSiteNameBase } from "./nestedSites";

const root = {
  key: "root",
  nameBase: "yellowbrand",
  url: "https://yellowbrand.nl/",
  wordpressPath: "/home/yellowbrand/domains/yellowbrand.nl/public_html/",
  isRoot: true,
};

const storedRoot: Site = {
  id: "root-id",
  name: "Yellowbrand",
  url: root.url,
  sshHost: "host.example.test",
  sshPort: 22,
  sshUsername: "deploy",
  authMethod: "keyFile",
  wordpressPath: root.wordpressPath,
  status: "healthy",
  updateCount: 0,
  createdAt: "2026-09-21T10:00:00Z",
  updatedAt: "2026-09-21T10:00:00Z",
};

describe("nested site proposals", () => {
  it("builds a subdomain from the root hostname", () => {
    expect(buildNestedSiteProposal(root, "dev", "subdomain")).toEqual({
      name: "dev yellowbrand",
      nameBase: "dev",
      url: "https://dev.yellowbrand.nl/",
      wordpressPath: "/home/yellowbrand/domains/yellowbrand.nl/public_html/dev",
    });
  });

  it("builds a subdirectory under the root", () => {
    expect(buildNestedSiteProposal(root, "academy", "subdirectory")).toEqual({
      name: "academy yellowbrand",
      nameBase: "yellowbrand",
      url: "https://yellowbrand.nl/academy/",
      wordpressPath: "/home/yellowbrand/domains/yellowbrand.nl/public_html/academy",
    });
  });

  it("uses the subdomain name for a nested subdirectory title", () => {
    const dev = buildNestedSiteProposal(root, "dev", "subdomain");
    expect(buildNestedSiteProposal({ ...dev, key: "dev", isRoot: false }, "manon", "subdirectory")).toEqual({
      name: "manon dev",
      nameBase: "dev",
      url: "https://dev.yellowbrand.nl/manon/",
      wordpressPath: "/home/yellowbrand/domains/yellowbrand.nl/public_html/dev/manon",
    });
  });

  it("keeps ports and safely appends URL path segments", () => {
    const proposal = buildNestedSiteProposal({ ...root, url: "https://example.test:8443/base/" }, "my site", "subdirectory");
    expect(proposal.url).toBe("https://example.test:8443/base/my%20site/");
    expect(proposal.wordpressPath).toBe("/home/yellowbrand/domains/yellowbrand.nl/public_html/my site");
  });

  it("turns a directory name into a valid editable subdomain proposal", () => {
    const proposal = buildNestedSiteProposal(root, "Klant Omgeving!", "subdomain");
    expect(proposal.url).toBe("https://klant-omgeving.yellowbrand.nl/");
    expect(proposal.name).toBe("Klant Omgeving! yellowbrand");
  });

  it("derives a root title base and joins paths without duplicate separators", () => {
    expect(rootSiteNameBase("Fallback", "https://www.yellowbrand.nl/")).toBe("yellowbrand");
    expect(rootSiteNameBase("Fallback", "not a url")).toBe("Fallback");
    expect(joinWordpressPath("/var/www/root///", "/dev/")).toBe("/var/www/root/dev");
  });

  it.each([
    "/home/ctlvu/domains/ctl-vu.nl/public_html",
    "/home/ctlvu/domains/ctl-vu.nl/public_html/",
  ])("joins a detected level-one directory to parent path %s", (parentPath) => {
    expect(joinWordpressPath(parentPath, "edudatabase")).toBe(
      "/home/ctlvu/domains/ctl-vu.nl/public_html/edudatabase",
    );
  });

  it("uses the same normalized join at deeper detection levels", () => {
    expect(joinWordpressPath("/home/ctlvu/domains/ctl-vu.nl/public_html/edudatabase/", "portal")).toBe(
      "/home/ctlvu/domains/ctl-vu.nl/public_html/edudatabase/portal",
    );
  });

  it("hides installations that already exist on the same server and path", () => {
    const existingChild: Site = {
      ...storedRoot,
      id: "dev-id",
      name: "dev yellowbrand",
      url: "https://dev.yellowbrand.nl/",
      wordpressPath: "/home/yellowbrand/domains/yellowbrand.nl/public_html/dev/",
      parentSiteId: storedRoot.id,
      relationType: "subdomain",
      parentDirectory: "dev",
    };
    expect(
      availableNestedDirectories(storedRoot, ["dev", "academy", "academy"], [storedRoot, existingChild]),
    ).toEqual(["academy"]);
  });

  it("offers a detached existing child for reconnection without offering linked or incompatible sites", () => {
    const detached: Site = {
      ...storedRoot,
      id: "portal-id",
      url: "https://yellowbrand.nl/portal/",
      wordpressPath: "/home/yellowbrand/domains/yellowbrand.nl/public_html/portal/",
    };
    expect(availableNestedDirectories(storedRoot, ["portal"], [storedRoot, detached])).toEqual(["portal"]);
    expect(reconnectableNestedSite(storedRoot, "portal", [storedRoot, detached])?.id).toBe("portal-id");
    const incompatible = { ...detached, sshUsername: "other-user" };
    expect(availableNestedDirectories(storedRoot, ["portal"], [storedRoot, incompatible])).toEqual([]);
    expect(reconnectableNestedSite(storedRoot, "portal", [storedRoot, incompatible])).toBeUndefined();
  });
});
