import { beforeEach, describe, expect, it } from "vitest";
import { appendWpCliOutput, clearWpCliConsoleSessions, getWpCliConsoleSession, rememberWpCliCommand } from "./wpCliConsoleSession";

describe("WP-CLI in-memory console sessions", () => {
  beforeEach(() => clearWpCliConsoleSessions());

  it("keeps commands per site and removes sensitive state on lock", () => {
    const siteA = getWpCliConsoleSession("site-a");
    const siteB = getWpCliConsoleSession("site-b");
    siteA.command = "wp option update api_key secret";
    rememberWpCliCommand(siteA, siteA.command);
    appendWpCliOutput(siteA, { command: siteA.command, risk: "mutating", error: "test", startedAt: "2026-01-01T00:00:00Z", finishedAt: "2026-01-01T00:00:01Z" });

    expect(siteB.history).toEqual([]);
    clearWpCliConsoleSessions();

    expect(siteA.command).toBe("");
    expect(siteA.history).toEqual([]);
    expect(siteA.outputs).toEqual([]);
  });

  it("does not duplicate consecutive history entries", () => {
    const session = getWpCliConsoleSession("site-a");
    rememberWpCliCommand(session, "wp core version");
    rememberWpCliCommand(session, "wp core version");
    expect(session.history).toEqual(["wp core version"]);
  });
});
