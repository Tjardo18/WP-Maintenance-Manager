import { describe, expect, it } from "vitest";
import { buildNestedSiteProposal, joinWordpressPath, rootSiteNameBase } from "./nestedSites";

const root = {
  key: "root",
  nameBase: "yellowbrand",
  url: "https://yellowbrand.nl/",
  wordpressPath: "/home/yellowbrand/domains/yellowbrand.nl/public_html/",
  isRoot: true,
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
});
