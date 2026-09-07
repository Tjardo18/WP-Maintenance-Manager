import { describe, expect, it } from "vitest";
import { completionKeystrokes, decodeTerminalPayload, isWpCliTerminalLine, updateTrackedTerminalLine } from "./terminalStream";

describe("terminal stream", () => {
  it("preserves table whitespace, tabs, ANSI, Unicode and progress controls byte-for-byte", () => {
    const fixture = "name             status\tupdate\r\nwoocommerce      active\tnone\r\n\u001b[32m✓ gereed\u001b[0m\rVoortgang 50%\rVoortgang 100%\n";
    const bytes = new TextEncoder().encode(fixture);
    let binary = "";
    for (const byte of bytes) binary += String.fromCharCode(byte);
    const decoded = decodeTerminalPayload(globalThis.btoa(binary));

    expect(decoded).toEqual(bytes);
    expect(new TextDecoder().decode(decoded)).toBe(fixture);
    expect(new TextDecoder().decode(decoded)).toContain("             ");
    expect(new TextDecoder().decode(decoded)).toContain("\t");
    expect(new TextDecoder().decode(decoded)).toContain("\u001b[32m");
  });

  it("tracks simple new command lines and activates help only for WP-CLI", () => {
    expect(updateTrackedTerminalLine("", "wp cor")).toBe("wp cor");
    expect(updateTrackedTerminalLine("wp cor", "\u007fe")).toBe("wp coe");
    expect(updateTrackedTerminalLine("wp core", "\r")).toBe("");
    expect(isWpCliTerminalLine("wp core verify-checksums --")).toBe(true);
    expect(isWpCliTerminalLine("ls -lah")).toBe(false);
    expect(isWpCliTerminalLine("cd wp-content && wp plugin list")).toBe(false);
  });

  it("builds remote completion input without resending an existing prefix", () => {
    expect(completionKeystrokes("wp cor", "wp core ")).toBe("e ");
    expect(completionKeystrokes("wp plx", "wp plugin ")).toBe("\u007fugin ");
  });
});
