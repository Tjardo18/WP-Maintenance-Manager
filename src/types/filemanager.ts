/** Local display metadata, not an authenticated remote file session. */
import type { FileContentPreview } from "../types";

export interface FilemanagerContext {
  siteId: string;
  siteName: string;
  siteUrl: string;
}

export interface FilemanagerAuthorization {
  siteId: string;
  expiresInSeconds: number;
}

/** Paths are virtual POSIX paths relative to the backend-owned WordPress root. */
export interface FilemanagerDirectoryItem {
  name: string;
  path: string;
  kind: "directory" | "file" | "symlink" | "other";
  extension: string | null;
  size: number | null;
  permissions: string | null;
  modifiedAt: string | null;
}

export interface FilemanagerDirectoryListing {
  currentPath: string;
  isRoot: boolean;
  parentPath: string | null;
  items: FilemanagerDirectoryItem[];
  truncated: boolean;
}

export type FilemanagerFilePreview = FileContentPreview;
