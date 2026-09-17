import { describe, expect, it } from "vitest";
import { formatDuration, formatModifiedFileDetail, formatWpCliVersion, statusLabel } from "./format";
describe("Nederlandse formatters", () => {
  it("vertaalt statussen zonder veiligheid te overdrijven", () => { expect(statusLabel("attention")).toBe("Controle nodig"); expect(statusLabel("healthy")).toBe("Gezond"); });
  it("formatteert een onderhoudsduur", () => { expect(formatDuration(125_000)).toBe("2 min 5 sec"); expect(formatDuration()).toBe("—"); });
  it("zet historische Unix-bestandstijden om zonder de herhaalde uitleg", () => {
    expect(formatModifiedFileDetail("Gewijzigd op Unix-tijd 1789627074.9670225510 met permissiemodus 644. Een recente wijziging is niet automatisch kwaadaardig."))
      .toBe("Gewijzigd op 17 september 2026 om 08:37 uur en heeft permissies 644.");
    expect(formatModifiedFileDetail("Andere melding")).toBe("Andere melding");
  });
  it("toont een volledige WP-CLI-versie en een duidelijke fallback", () => {
    expect(formatWpCliVersion("2.12.0")).toBe("WP-CLI 2.12.0");
    expect(formatWpCliVersion("WP-CLI 2.12.0")).toBe("WP-CLI 2.12.0");
    expect(formatWpCliVersion(undefined, "2026-09-17T10:00:00Z")).toBe("WP-CLI niet beschikbaar");
    expect(formatWpCliVersion()).toBe("WP-CLI nog niet gecontroleerd");
  });
});
