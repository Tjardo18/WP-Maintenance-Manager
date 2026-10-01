import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.hoisted(() => vi.fn());
const listenMock = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));
vi.mock("@tauri-apps/api/event", () => ({ listen: listenMock }));

import { appApi, authApi, systemInputApi } from "./tauri";

describe("Tauri authentication boundary", () => {
  beforeEach(() => {
    Object.defineProperty(window, "__TAURI_INTERNALS__", { configurable: true, value: {} });
    invokeMock.mockReset();
    listenMock.mockReset();
    listenMock.mockResolvedValue(() => undefined);
    authApi.setSessionToken("active-app-session");
  });

  afterEach(() => {
    delete (window as Window & { __TAURI_INTERNALS__?: unknown }).__TAURI_INTERNALS__;
    authApi.setSessionToken();
  });

  it("clears frontend authentication after backend terminal reauthentication revocation", async () => {
    const revoked = {
      category: "app_session_revoked_reauth_failed",
      userMessage: "Sessie beëindigd. Log opnieuw in.",
      retryable: false,
    };
    invokeMock.mockRejectedValueOnce(revoked);
    const lockListener = vi.fn();
    window.addEventListener("wpmm:locked", lockListener);

    await expect(
      appApi.beginTerminalReauthentication("site-a", "never-store-this-password"),
    ).rejects.toEqual(revoked);
    await expect(appApi.listSites()).rejects.toMatchObject({ category: "locked" });
    expect(invokeMock).toHaveBeenCalledTimes(1);
    expect(lockListener).toHaveBeenCalledOnce();
    expect(lockListener.mock.calls[0]?.[0]).toBeInstanceOf(CustomEvent);

    window.removeEventListener("wpmm:locked", lockListener);
  });

  it("opens external URLs through the native system-browser command", async () => {
    invokeMock.mockResolvedValueOnce(undefined);

    await appApi.openExternalUrl("https://example.test/path");

    expect(invokeMock).toHaveBeenCalledWith("open_vulnerability_reference", {
      url: "https://example.test/path",
      sessionToken: "active-app-session",
    });
  });

  it("requires an app session for filemanager metadata and sends only the site selector", async () => {
    invokeMock.mockResolvedValueOnce({ siteId: "site-a", siteName: "A", siteUrl: "https://a.test" });
    await appApi.getFilemanagerContext("site-a");
    expect(invokeMock).toHaveBeenCalledWith("get_filemanager_context", { siteId: "site-a", sessionToken: "active-app-session" });
    authApi.setSessionToken();
    await expect(appApi.getFilemanagerContext("site-b")).rejects.toMatchObject({ category: "locked" });
    expect(invokeMock).toHaveBeenCalledTimes(1);
  });

  it("sends source as authenticated structured input, never a shell command or URL", async () => {
    const input = { path: "/my plugin.php", content: "<?php echo '$HOME ; 中文';", expectedVersion: "a".repeat(64) };
    invokeMock.mockResolvedValueOnce({ textContent: input.content });
    await appApi.saveFilemanagerFile("site-a", "access-a", input);
    expect(invokeMock).toHaveBeenCalledWith("save_filemanager_file", { siteId: "site-a", authorizationToken: "access-a", input, sessionToken: "active-app-session" });
    authApi.setSessionToken();
    await expect(appApi.saveFilemanagerFile("site-a", "access-a", input)).rejects.toMatchObject({ category: "locked" });
    expect(invokeMock).toHaveBeenCalledOnce();
  });

  it("uses site-bound structured mutations for named create and individual delete", async () => {
    const token = "access-a";
    invokeMock.mockResolvedValue({});
    await appApi.createFilemanagerFile("site-a", token, { directory: "/plugins", name: "test $; 中文.php" });
    await appApi.createFilemanagerDirectory("site-a", token, { directory: "/plugins", name: ".cache" });
    await appApi.deleteFilemanagerItem("site-a", token, { path: "/plugins/test $; 中文.php", expectedKind: "file" });
    expect(invokeMock).toHaveBeenNthCalledWith(1, "create_filemanager_file", { siteId: "site-a", authorizationToken: token, input: { directory: "/plugins", name: "test $; 中文.php" }, sessionToken: "active-app-session" });
    expect(invokeMock).toHaveBeenNthCalledWith(2, "create_filemanager_directory", { siteId: "site-a", authorizationToken: token, input: { directory: "/plugins", name: ".cache" }, sessionToken: "active-app-session" });
    expect(invokeMock).toHaveBeenNthCalledWith(3, "delete_filemanager_item", { siteId: "site-a", authorizationToken: token, input: { path: "/plugins/test $; 中文.php", expectedKind: "file" }, sessionToken: "active-app-session" });
  });

  it("uses dedicated site-bound filemanager endpoints and requires the app session on each", async () => {
    const password = crypto.randomUUID();
    const token = crypto.randomUUID();
    invokeMock.mockResolvedValue(undefined);
    await appApi.beginFilemanagerReauthentication("site-a", password);
    await appApi.openFilemanager("site-a", token, password);
    await appApi.getFilemanagerAuthorization("site-a", token);
    await appApi.closeFilemanager("site-a", token);
    expect(invokeMock).toHaveBeenNthCalledWith(1, "begin_filemanager_reauthentication", { siteId: "site-a", appPassword: password, sessionToken: "active-app-session" });
    expect(invokeMock).toHaveBeenNthCalledWith(2, "open_filemanager", { siteId: "site-a", challengeToken: token, sshPassword: password, sessionToken: "active-app-session" });
    expect(invokeMock).toHaveBeenNthCalledWith(3, "get_filemanager_authorization", { siteId: "site-a", authorizationToken: token, sessionToken: "active-app-session" });
    expect(invokeMock).toHaveBeenNthCalledWith(4, "close_filemanager", { siteId: "site-a", authorizationToken: token, sessionToken: "active-app-session" });
    authApi.setSessionToken();
    await expect(appApi.beginFilemanagerReauthentication("site-a", password)).rejects.toMatchObject({ category: "locked" });
    await expect(appApi.openFilemanager("site-a", token, password)).rejects.toMatchObject({ category: "locked" });
    await expect(appApi.getFilemanagerAuthorization("site-a", token)).rejects.toMatchObject({ category: "locked" });
    await expect(appApi.closeFilemanager("site-a", token)).rejects.toMatchObject({ category: "locked" });
    expect(invokeMock).toHaveBeenCalledTimes(4);
  });

  it("invalidates the app session when filemanager app-password verification fails", async () => {
    invokeMock.mockRejectedValueOnce({ category: "app_session_revoked_reauth_failed", userMessage: "Log opnieuw in." });
    await expect(appApi.beginFilemanagerReauthentication("site-a", crypto.randomUUID())).rejects.toMatchObject({ category: "app_session_revoked_reauth_failed" });
    await expect(appApi.getFilemanagerAuthorization("site-a", crypto.randomUUID())).rejects.toMatchObject({ category: "locked" });
    expect(invokeMock).toHaveBeenCalledOnce();
  });

  it("lists a virtual directory through authenticated IPC without accepting a root or SSH configuration", async () => {
    const authorizationToken = crypto.randomUUID();
    invokeMock.mockResolvedValueOnce({ currentPath: "/wp-content", parentPath: "/", isRoot: false, items: [], truncated: false });
    await appApi.listFilemanagerDirectory("site-a", authorizationToken, "/wp-content");
    expect(invokeMock).toHaveBeenCalledWith("list_filemanager_directory", { siteId: "site-a", authorizationToken, requestedPath: "/wp-content", sessionToken: "active-app-session" });
    authApi.setSessionToken();
    await expect(appApi.listFilemanagerDirectory("site-b", authorizationToken)).rejects.toMatchObject({ category: "locked" });
    expect(invokeMock).toHaveBeenCalledOnce();
  });

  it("forwards a media key without exposing or requiring the app session", async () => {
    invokeMock.mockResolvedValueOnce(undefined);

    await systemInputApi.forwardMediaKey("play-pause");

    expect(invokeMock).toHaveBeenCalledWith("forward_media_key", {
      command: "play-pause",
    });
  });

  it("keeps database cleanup behind the authenticated IPC boundary", async () => {
    invokeMock.mockResolvedValueOnce([]).mockResolvedValueOnce({
      target: "error_logs",
      tableName: "error_logs",
      status: "success",
      impacts: [],
      warnings: [],
      completedAt: "2026-09-21T12:00:00Z",
    });

    await appApi.listDatabaseCleanupOptions();
    await appApi.cleanupDatabase({ target: "error_logs", confirmation: "error_logs", previewToken: "preview" });

    expect(invokeMock).toHaveBeenNthCalledWith(1, "list_database_cleanup_options", {
      sessionToken: "active-app-session",
    });
    expect(invokeMock).toHaveBeenNthCalledWith(2, "cleanup_database", {
      request: { target: "error_logs", confirmation: "error_logs", previewToken: "preview" },
      sessionToken: "active-app-session",
    });
  });

  it("correlates a bulk file deletion with its progress operation", async () => {
    invokeMock.mockResolvedValueOnce({
      requested: 2,
      deleted: 2,
      deletedPaths: ["one.php", "two.php"],
      failures: [],
    });

    await appApi.deleteChecksumFindings("site-a", ["finding-a", "finding-b"], "operation-a");

    expect(invokeMock).toHaveBeenCalledWith("delete_checksum_findings", {
      siteId: "site-a",
      findingIds: ["finding-a", "finding-b"],
      operationId: "operation-a",
      sessionToken: "active-app-session",
    });
  });

  it("forwards live bulk deletion progress events", async () => {
    const handler = vi.fn();
    await appApi.onChecksumDeleteProgress(handler);
    const eventHandler = listenMock.mock.calls[0]?.[1] as ((event: { payload: unknown }) => void) | undefined;
    const progress = { operationId: "operation-a", siteId: "site-a", phase: "deleting", processed: 1, total: 2, deleted: 1, failed: 0 };

    eventHandler?.({ payload: progress });

    expect(listenMock).toHaveBeenCalledWith("checksum-delete-progress", expect.any(Function));
    expect(handler).toHaveBeenCalledWith(progress);
  });
});
