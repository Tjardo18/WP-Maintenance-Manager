export interface BinarySuspiciousMatch {
  label: string;
  offset: number;
  offsetLabel: string;
  snippet: string;
}

export interface BinaryInspection {
  byteLength: number;
  suspiciousMatches: BinarySuspiciousMatch[];
  readableText: string;
  readableTextTruncated: boolean;
  hexDump: string;
  hexDumpTruncated: boolean;
}

const suspiciousPatterns = [
  ["PHP-openingstag", "<?php"],
  ["Korte PHP-openingstag", "<?="],
  ["Script-element", "<script"],
  ["JavaScript-URL", "javascript:"],
  ["Eventhandler", "onerror="],
  ["Eventhandler", "onload="],
  ["Dynamische code-uitvoering", "eval("],
  ["PHP Base64-decodering", "base64_decode"],
  ["PHP-decompressie", "gzinflate"],
  ["Shell-opdracht", "shell_exec"],
  ["Shell-opdracht", "passthru("],
  ["Systeemopdracht", "system("],
  ["Procesuitvoering", "exec("],
  ["Dynamische assertie", "assert("],
  ["Documentinjectie", "document.write"],
  ["PowerShell-opdracht", "powershell"],
  ["Windows-opdrachtprompt", "cmd.exe"],
] as const;

const maxSuspiciousMatches = 50;
const maxReadableCharacters = 128 * 1024;
const maxReadableSegmentCharacters = 8 * 1024;
const hexEdgeBytes = 16 * 1024;
const suspiciousHexContextBytes = 256;
const maxSuspiciousHexSections = 12;

function decodeBase64(dataBase64: string): Uint8Array | undefined {
  try {
    const binary = window.atob(dataBase64);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    return bytes;
  } catch {
    return undefined;
  }
}

function offsetLabel(offset: number) {
  return `0x${offset.toString(16).toUpperCase().padStart(8, "0")}`;
}

function printableSnippet(bytes: Uint8Array, offset: number, length: number) {
  const start = Math.max(0, offset - 56);
  const end = Math.min(bytes.length, offset + length + 96);
  let snippet = "";
  for (let index = start; index < end; index += 1) {
    const byte = bytes[index];
    snippet += byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126) ? String.fromCharCode(byte) : "·";
  }
  return snippet.replace(/\s+/g, " ").trim();
}

function trailingDataEnd(bytes: Uint8Array): { format: string; end: number } | undefined {
  const has = (...expected: number[]) => expected.every((value, index) => bytes[index] === value);
  if (has(0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a)) {
    let offset = 8;
    while (offset + 12 <= bytes.length) {
      const length = ((bytes[offset] << 24) | (bytes[offset + 1] << 16) | (bytes[offset + 2] << 8) | bytes[offset + 3]) >>> 0;
      const chunkEnd = offset + 12 + length;
      if (chunkEnd > bytes.length) break;
      if (bytes[offset + 4] === 0x49 && bytes[offset + 5] === 0x45 && bytes[offset + 6] === 0x4e && bytes[offset + 7] === 0x44) {
        return { format: "PNG IEND", end: chunkEnd };
      }
      offset = chunkEnd;
    }
  }
  if (has(0xff, 0xd8)) {
    for (let offset = 2; offset + 1 < bytes.length; offset += 1) {
      if (bytes[offset] === 0xff && bytes[offset + 1] === 0xd9) return { format: "JPEG EOI", end: offset + 2 };
    }
  }
  if (bytes.length >= 12 && has(0x52, 0x49, 0x46, 0x46) && bytes[8] === 0x57 && bytes[9] === 0x45 && bytes[10] === 0x42 && bytes[11] === 0x50) {
    const declaredSize = bytes[4] | (bytes[5] << 8) | (bytes[6] << 16) | (bytes[7] << 24);
    return { format: "WebP RIFF", end: (declaredSize >>> 0) + 8 };
  }
  if (bytes.length >= 6 && has(0x42, 0x4d)) {
    const declaredSize = bytes[2] | (bytes[3] << 8) | (bytes[4] << 16) | (bytes[5] << 24);
    return { format: "BMP-bestandseinde", end: declaredSize >>> 0 };
  }
  return gifDataEnd(bytes);
}

function skipGifSubBlocks(bytes: Uint8Array, start: number): number | undefined {
  let offset = start;
  while (offset < bytes.length) {
    const size = bytes[offset];
    offset += 1;
    if (size === 0) return offset;
    if (offset + size > bytes.length) return undefined;
    offset += size;
  }
  return undefined;
}

function gifDataEnd(bytes: Uint8Array): { format: string; end: number } | undefined {
  const header = String.fromCharCode(...bytes.subarray(0, Math.min(6, bytes.length)));
  if (header !== "GIF87a" && header !== "GIF89a" || bytes.length < 13) return undefined;
  const packed = bytes[10];
  let offset = 13 + ((packed & 0x80) === 0 ? 0 : 3 * (2 ** ((packed & 0x07) + 1)));
  while (offset < bytes.length) {
    const marker = bytes[offset];
    if (marker === 0x3b) return { format: "GIF-trailer", end: offset + 1 };
    if (marker === 0x21) {
      offset = skipGifSubBlocks(bytes, offset + 2) ?? bytes.length;
      continue;
    }
    if (marker === 0x2c && offset + 10 <= bytes.length) {
      const imagePacked = bytes[offset + 9];
      offset += 10 + ((imagePacked & 0x80) === 0 ? 0 : 3 * (2 ** ((imagePacked & 0x07) + 1)));
      if (offset >= bytes.length) return undefined;
      offset = skipGifSubBlocks(bytes, offset + 1) ?? bytes.length;
      continue;
    }
    return undefined;
  }
  return undefined;
}

function suspiciousMatches(bytes: Uint8Array): BinarySuspiciousMatch[] {
  const text = new window.TextDecoder("latin1").decode(bytes);
  const normalized = text.toLowerCase();
  const matches: BinarySuspiciousMatch[] = [];
  for (const [label, needle] of suspiciousPatterns) {
    let offset = normalized.indexOf(needle);
    while (offset >= 0 && matches.length < maxSuspiciousMatches) {
      matches.push({ label, offset, offsetLabel: offsetLabel(offset), snippet: printableSnippet(bytes, offset, needle.length) });
      offset = normalized.indexOf(needle, offset + needle.length);
    }
  }

  const base64Pattern = /[A-Za-z0-9+/]{80,}={0,2}/g;
  for (const match of text.matchAll(base64Pattern)) {
    if (matches.length >= maxSuspiciousMatches) break;
    const offset = match.index;
    matches.push({ label: "Lange Base64-achtige reeks", offset, offsetLabel: offsetLabel(offset), snippet: printableSnippet(bytes, offset, Math.min(match[0].length, 128)) });
  }

  const dataEnd = trailingDataEnd(bytes);
  if (dataEnd && dataEnd.end < bytes.length && matches.length < maxSuspiciousMatches) {
    const trailingLength = bytes.length - dataEnd.end;
    matches.push({
      label: `${trailingLength} extra bytes na ${dataEnd.format}`,
      offset: dataEnd.end,
      offsetLabel: offsetLabel(dataEnd.end),
      snippet: printableSnippet(bytes, dataEnd.end, Math.min(trailingLength, 128)),
    });
  }

  return matches.sort((left, right) => left.offset - right.offset || left.label.localeCompare(right.label));
}

function readableStrings(bytes: Uint8Array): { text: string; truncated: boolean } {
  const sections: string[] = [];
  let outputLength = 0;
  let start = -1;
  let truncated = false;

  const append = (end: number) => {
    if (start < 0 || end - start < 4) {
      start = -1;
      return;
    }
    const originalLength = end - start;
    const visibleEnd = Math.min(end, start + maxReadableSegmentCharacters);
    let value = new window.TextDecoder("ascii").decode(bytes.subarray(start, visibleEnd));
    if (!value.trim()) {
      start = -1;
      return;
    }
    if (visibleEnd < end) value += `\n… ${originalLength - (visibleEnd - start)} tekens uit deze reeks weggelaten …`;
    const section = `[${offsetLabel(start)}]\n${value}`;
    if (outputLength + section.length > maxReadableCharacters) {
      truncated = true;
      start = -1;
      return;
    }
    sections.push(section);
    outputLength += section.length + 2;
    start = -1;
  };

  for (let index = 0; index <= bytes.length; index += 1) {
    const byte = bytes[index];
    const printable = index < bytes.length && (byte === 9 || byte === 10 || byte === 13 || (byte >= 32 && byte <= 126));
    if (printable && start < 0) start = index;
    if (!printable && start >= 0) append(index);
    if (truncated) break;
  }
  return { text: sections.join("\n\n"), truncated };
}

interface HexRange { start: number; end: number }

function hexDump(bytes: Uint8Array, matches: BinarySuspiciousMatch[]): { text: string; truncated: boolean } {
  const ranges: HexRange[] = [];
  const addRange = (start: number, end: number) => {
    const alignedStart = Math.max(0, Math.floor(start / 16) * 16);
    const alignedEnd = Math.min(bytes.length, Math.ceil(end / 16) * 16);
    if (alignedEnd > alignedStart) ranges.push({ start: alignedStart, end: alignedEnd });
  };
  addRange(0, Math.min(bytes.length, hexEdgeBytes));
  for (const match of matches.slice(0, maxSuspiciousHexSections)) addRange(match.offset - suspiciousHexContextBytes, match.offset + suspiciousHexContextBytes);
  if (bytes.length > hexEdgeBytes) addRange(bytes.length - hexEdgeBytes, bytes.length);
  ranges.sort((left, right) => left.start - right.start);

  const merged: HexRange[] = [];
  for (const range of ranges) {
    const previous = merged[merged.length - 1];
    if (previous && range.start <= previous.end) previous.end = Math.max(previous.end, range.end);
    else merged.push({ ...range });
  }

  const output: string[] = [];
  let previousEnd = 0;
  for (const range of merged) {
    if (range.start > previousEnd) output.push(`… ${range.start - previousEnd} bytes weggelaten …`);
    for (let offset = range.start; offset < range.end; offset += 16) {
      const row = bytes.subarray(offset, Math.min(offset + 16, range.end));
      const hex = Array.from(row, (byte) => byte.toString(16).toUpperCase().padStart(2, "0")).join(" ").padEnd(47, " ");
      const ascii = Array.from(row, (byte) => byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : ".").join("");
      output.push(`${offsetLabel(offset)}  ${hex}  |${ascii}|`);
    }
    previousEnd = range.end;
  }
  if (previousEnd < bytes.length) output.push(`… ${bytes.length - previousEnd} bytes weggelaten …`);
  const displayedBytes = merged.reduce((total, range) => total + range.end - range.start, 0);
  return { text: output.join("\n"), truncated: displayedBytes < bytes.length };
}

export function inspectBinaryImage(dataBase64?: string): BinaryInspection | undefined {
  if (!dataBase64) return undefined;
  const bytes = decodeBase64(dataBase64);
  if (!bytes) return undefined;
  const matches = suspiciousMatches(bytes);
  const readable = readableStrings(bytes);
  const hex = hexDump(bytes, matches);
  return {
    byteLength: bytes.length,
    suspiciousMatches: matches,
    readableText: readable.text,
    readableTextTruncated: readable.truncated,
    hexDump: hex.text,
    hexDumpTruncated: hex.truncated,
  };
}
