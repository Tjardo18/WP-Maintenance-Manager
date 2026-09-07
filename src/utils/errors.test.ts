import { describe, expect, it } from "vitest";
import { errorMessage } from "./errors";

describe("errorMessage", () => {
  it("leest een getypeerde backendmelding", () => {
    expect(errorMessage({ category: "timeout", userMessage: "De server reageert niet.", retryable: true })).toBe("De server reageert niet.");
  });

  it("lekt geen willekeurige objectinhoud naar de interface", () => {
    expect(errorMessage({ secret: "niet tonen" })).toBe("Er is een onverwachte fout opgetreden.");
  });

  it("toont het persistente fout-id bij een gelogde backendfout", () => {
    expect(errorMessage({ errorId: "ERR-ABC123", category: "timeout", userMessage: "De server reageert niet.", retryable: true })).toBe("De server reageert niet. (Fout-ID: ERR-ABC123)");
  });
});
