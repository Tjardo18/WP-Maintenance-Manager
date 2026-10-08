import type { Site, SiteRelationType } from "../types";

export interface NestedSiteParentContext {
  key: string;
  nameBase: string;
  url: string;
  wordpressPath: string;
  isRoot: boolean;
}

export interface NestedSiteProposal {
  name: string;
  nameBase: string;
  url: string;
  wordpressPath: string;
}

type NestedSiteConnection = Pick<Site, "id" | "sshHost" | "sshPort" | "sshUsername" | "authMethod" | "keyPath" | "wordpressPath">;

function normalizedDirectory(directory: string) {
  return directory.trim().replace(/^\/+|\/+$/g, "");
}

function subdomainLabel(directory: string) {
  const label = directory
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 63)
    .replace(/-+$/g, "");
  return label || "site";
}

export function joinWordpressPath(parentPath: string, directory: string) {
  return `${parentPath.replace(/\/+$/g, "")}/${normalizedDirectory(directory)}`;
}

export function reconnectableNestedSite(
  parent: NestedSiteConnection,
  directory: string,
  sites: Site[],
) {
  const childPath = joinWordpressPath(parent.wordpressPath, directory);
  return sites.find((site) => site.id !== parent.id
    && !site.parentSiteId && !site.relationType && !site.parentDirectory
    && site.sshHost.toLowerCase() === parent.sshHost.toLowerCase()
    && site.sshPort === parent.sshPort
    && site.sshUsername === parent.sshUsername
    && site.authMethod === parent.authMethod
    && (site.keyPath ?? "") === (parent.keyPath ?? "")
    && site.wordpressPath.replace(/\/+$/g, "") === childPath);
}

export function availableNestedDirectories(
  parent: NestedSiteConnection,
  directories: string[],
  sites: Site[],
) {
  const knownPaths = new Set(
    sites
      .filter((site) => site.id !== parent.id)
      .filter((site) => site.sshHost.toLowerCase() === parent.sshHost.toLowerCase() && site.sshPort === parent.sshPort)
      .map((site) => site.wordpressPath.replace(/\/+$/g, "")),
  );
  return [...new Set(directories)]
    .filter((directory) => !knownPaths.has(joinWordpressPath(parent.wordpressPath, directory))
      || Boolean(reconnectableNestedSite(parent, directory, sites)))
    .sort((left, right) => left.localeCompare(right));
}

export function rootSiteNameBase(name: string, url: string) {
  try {
    const hostname = new URL(url).hostname.replace(/^www\./i, "");
    const firstLabel = hostname.split(".")[0]?.trim();
    if (firstLabel) return firstLabel;
  } catch {
    // The form validation reports an invalid URL; the name remains a useful fallback.
  }
  return name.trim() || "website";
}

export function buildNestedSiteProposal(
  parent: NestedSiteParentContext,
  directory: string,
  relationType: SiteRelationType,
): NestedSiteProposal {
  const cleanDirectory = normalizedDirectory(directory);
  const target = new URL(parent.url);

  if (relationType === "subdomain") {
    target.hostname = `${subdomainLabel(cleanDirectory)}.${target.hostname.replace(/^www\./i, "")}`;
    target.pathname = "/";
    target.search = "";
    target.hash = "";
  } else {
    const parentPath = target.pathname.replace(/\/+$/g, "");
    target.pathname = `${parentPath}/${encodeURIComponent(cleanDirectory)}/`;
    target.search = "";
    target.hash = "";
  }

  return {
    name: `${cleanDirectory} ${parent.nameBase}`.trim(),
    nameBase: relationType === "subdomain" ? cleanDirectory : parent.nameBase,
    url: target.toString(),
    wordpressPath: joinWordpressPath(parent.wordpressPath, cleanDirectory),
  };
}
