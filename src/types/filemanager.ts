/** Local display metadata, not an authenticated remote file session. */
export interface FilemanagerContext {
  siteId: string;
  siteName: string;
  siteUrl: string;
}

export interface FilemanagerAuthorization {
  siteId: string;
  expiresInSeconds: number;
}
