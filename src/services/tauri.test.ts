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
