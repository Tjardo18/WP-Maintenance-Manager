import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const invokeMock = vi.hoisted(() => vi.fn());
vi.mock("@tauri-apps/api/core", () => ({ invoke: invokeMock }));
vi.mock("@tauri-apps/api/event", () => ({ listen: vi.fn() }));

import { appApi, authApi } from "./tauri";

describe("Tauri authentication boundary", () => {
  beforeEach(() => {
    Object.defineProperty(window, "__TAURI_INTERNALS__", { configurable: true, value: {} });
    invokeMock.mockReset();
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
});
