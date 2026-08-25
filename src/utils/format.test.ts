import { describe, expect, it } from "vitest";
import { formatDuration, statusLabel } from "./format";
describe("Nederlandse formatters", () => {
  it("vertaalt statussen zonder veiligheid te overdrijven", () => { expect(statusLabel("attention")).toBe("Controle nodig"); expect(statusLabel("healthy")).toBe("Gezond"); });
  it("formatteert een onderhoudsduur", () => { expect(formatDuration(125_000)).toBe("2 min 5 sec"); expect(formatDuration()).toBe("—"); });
});
