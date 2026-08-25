import { describe, expect, it } from "vitest";
import { errorMessage } from "./errors";

describe("errorMessage", () => {
  it("leest een getypeerde backendmelding", () => {
    expect(errorMessage({ category: "timeout", userMessage: "De server reageert niet.", retryable: true })).toBe("De server reageert niet.");
  });

  it("lekt geen willekeurige objectinhoud naar de interface", () => {
    expect(errorMessage({ secret: "niet tonen" })).toBe("Er is een onverwachte fout opgetreden.");
  });
});
