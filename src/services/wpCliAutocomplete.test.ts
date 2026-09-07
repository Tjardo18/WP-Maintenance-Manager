import { describe, expect, it } from "vitest";
import type { WpCliCatalog, WpCliCommandNode } from "../types";
import { WpCliAutocompleteIndex, analyzeWpCliInput, applyWpCliSuggestion, parseWpCliParameter } from "./wpCliAutocomplete";

const leaf = (command: string, parent = "wp", parameters: WpCliCommandNode["parameters"] = []): WpCliCommandNode => ({
  command,
  fullCommand: `${parent} ${command}`,
  description: `${command} description`,
  parameters,
  subcommands: [],
});

function fixture(): WpCliCatalog {
  const core = leaf("core");
  core.subcommands = [
    leaf("check-update", "wp core"), leaf("download", "wp core"), leaf("install", "wp core"),
    leaf("install-network", "wp core"), leaf("is-installed", "wp core"), leaf("multisite-convert", "wp core"),
    leaf("multisite-install", "wp core"), leaf("update", "wp core"), leaf("update-db", "wp core"),
    leaf("upgrade", "wp core"),
    leaf("verify-checksums", "wp core", [
      { parameter: "[--include-root]", description: "Include root" },
      { parameter: "[--version=<version>]", description: "Version" },
      { parameter: "[--locale=<locale>]", description: "Locale" },
      { parameter: "[--insecure]", description: "Insecure" },
      { parameter: "[--exclude=<files>]", description: "Exclude" },
      { parameter: "[--format=<format>]", description: "Format" },
    ]),
    leaf("version", "wp core"),
  ];
  const roots = ["cache", "cap", "cli", "comment", "config", "cron"].map((command) => leaf(command));
  roots.push(core);
  return {
    available: true,
    rootCommandCount: roots.length,
    totalCommandCount: roots.length + core.subcommands.length,
    globalParameterCount: 3,
    globalParameters: [
      { parameter: "[--debug]", description: "Debug" },
      { parameter: "[--url=<url>]", description: "URL" },
      { parameter: "[--insecure]", description: "Duplicate for test" },
    ],
    commands: roots,
  };
}

describe("WP-CLI parameter syntax", () => {
  it("normalizes flags, valued options and positional arguments", () => {
    expect(parseWpCliParameter({ parameter: "[--include-root]", description: "" }).insertText).toBe("--include-root");
    const version = parseWpCliParameter({ parameter: "[--version=<version>]", description: "" });
    expect(version.insertText).toBe("--version=");
    expect(version.placeholder).toBe("version");
    expect(version.optional).toBe(true);
    const id = parseWpCliParameter({ parameter: "<id>…", description: "" });
    expect(id.positional).toBe(true);
    expect(id.repeatable).toBe(true);
    expect(id.displayText).toBe("<id>");
    const optionalValue = parseWpCliParameter({ parameter: "[--foo[=<value>]]", description: "" });
    expect(optionalValue.valueOptional).toBe(true);
    expect(optionalValue.takesValue).toBe(true);
  });
});

describe("WP-CLI autocomplete", () => {
  const index = new WpCliAutocompleteIndex(fixture());

  it("shows all root commands for wp and prioritizes prefixes", () => {
    expect(index.suggest("wp").suggestions).toHaveLength(7);
    expect(index.suggest("wp c").suggestions.map((item) => item.label)).toEqual([
      "wp cache", "wp cap", "wp cli", "wp comment", "wp config", "wp cron", "wp core",
    ]);
    expect(index.suggest("wp cor").suggestions[0]?.label).toBe("wp core");
  });

  it("resolves recursive subcommands", () => {
    expect(index.suggest("wp core").suggestions.map((item) => item.label)).toContain("wp core verify-checksums");
    expect(index.suggest("wp core v").suggestions.map((item) => item.label)).toEqual([
      "wp core verify-checksums", "wp core version",
    ]);
  });

  it("offers local and global parameters and hides used non-repeatable options", () => {
    const direct = index.suggest("wp core verify-checksums");
    expect(direct.suggestions.map((item) => item.label)).toContain("--include-root");
    const options = index.suggest("wp core verify-checksums --");
    expect(options.suggestions.map((item) => item.label)).toContain("--debug");
    expect(options.suggestions.filter((item) => item.label === "--insecure")).toHaveLength(1);
    expect(index.suggest("wp core verify-checksums --i").suggestions.map((item) => item.label)).toEqual(["--include-root", "--insecure"]);
    const afterUsed = index.suggest("wp core verify-checksums --include-root --");
    expect(afterUsed.suggestions.map((item) => item.label)).not.toContain("--include-root");
    expect(afterUsed.suggestions.map((item) => item.label)).toContain("--format=<format>");
  });

  it("is cursor-aware and suppresses suggestions inside quoted data", () => {
    const input = "wp core vers trailing";
    const result = index.suggest(input, "wp core vers".length);
    expect(result.suggestions[0]?.label).toBe("wp core version");
    expect(analyzeWpCliInput("wp db query \"SELECT 1;\"", 18).cursorInQuote).toBe(true);
    expect(index.suggest("wp db query \"SELECT * FROM posts\"").suggestions).toEqual([]);
  });

  it("inserts only the selected token and positions the cursor after equals", () => {
    const suggestion = index.suggest("wp cor").suggestions[0]!;
    expect(applyWpCliSuggestion("wp cor", suggestion)).toEqual({ value: "wp core ", cursor: 8 });
    const valued = index.suggest("wp core verify-checksums --v").suggestions[0]!;
    expect(applyWpCliSuggestion("wp core verify-checksums --v", valued)).toEqual({
      value: "wp core verify-checksums --version=",
      cursor: 35,
    });
  });
});
