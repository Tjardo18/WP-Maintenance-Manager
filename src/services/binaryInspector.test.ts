import { describe, expect, it } from "vitest";
import { inspectBinaryImage } from "./binaryInspector";

function encode(bytes: Uint8Array) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return window.btoa(binary);
}

function pngWithTrailingPayload(payload = "") {
  const signature = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  const iend = [0, 0, 0, 0, 0x49, 0x45, 0x4e, 0x44, 0, 0, 0, 0];
  return new Uint8Array([...signature, ...iend, ...Array.from(payload, (character) => character.charCodeAt(0))]);
}

describe("binary image inspector", () => {
  it("shows readable exploit code and flags data appended after PNG IEND", () => {
    const payload = "<?php eval(base64_decode($payload)); ?>";
    const inspection = inspectBinaryImage(encode(pngWithTrailingPayload(payload)));

    expect(inspection?.readableText).toContain(payload);
    expect(inspection?.suspiciousMatches.map((match) => match.label)).toContain("PHP-openingstag");
    expect(inspection?.suspiciousMatches.map((match) => match.label)).toContain("Dynamische code-uitvoering");
    expect(inspection?.suspiciousMatches.some((match) => match.label.includes("extra bytes na PNG IEND"))).toBe(true);
    expect(inspection?.hexDump).toContain("3C 3F 70 68 70");
  });

  it("includes suspicious regions from the middle of a large file in the bounded hex dump", () => {
    const bytes = new Uint8Array(80_000);
    const payload = new TextEncoder().encode("shell_exec($_GET['cmd'])");
    bytes.set(payload, 40_000);
    const inspection = inspectBinaryImage(encode(bytes));

    expect(inspection?.suspiciousMatches.some((match) => match.offset === 40_000)).toBe(true);
    expect(inspection?.hexDump).toContain("shell_exec");
    expect(inspection?.hexDumpTruncated).toBe(true);
  });

  it("fails closed for missing or invalid Base64 data", () => {
    expect(inspectBinaryImage()).toBeUndefined();
    expect(inspectBinaryImage("%%%not-base64%%%")).toBeUndefined();
  });
});
