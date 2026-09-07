import type { ParsedWpCliParameter, WpCliCatalog, WpCliCommandNode, WpCliParameterDoc, WpCliSuggestion } from "../types";

export interface WpCliInputToken {
  value: string;
  start: number;
  end: number;
}

export interface WpCliInputAnalysis {
  tokens: WpCliInputToken[];
  currentToken?: WpCliInputToken;
  currentPrefix: string;
  replaceStart: number;
  replaceEnd: number;
  cursorInQuote: boolean;
}

export interface WpCliAutocompleteResult {
  suggestions: WpCliSuggestion[];
  command?: WpCliCommandNode;
  parameters: ParsedWpCliParameter[];
  globalParameters: ParsedWpCliParameter[];
  unknownCommand: boolean;
}

interface CommandLevel {
  parent?: WpCliCommandNode;
  children: WpCliCommandNode[];
}

export function parseWpCliParameter(doc: WpCliParameterDoc): ParsedWpCliParameter {
  const rawSyntax = doc.parameter.trim();
  const optional = hasOuterBrackets(rawSyntax);
  let displayText = optional ? rawSyntax.slice(1, -1).trim() : rawSyntax;
  const repeatable = /(?:…|\.\.\.)$/.test(displayText);
  displayText = displayText.replace(/(?:…|\.\.\.)$/, "");
  const positional = displayText.startsWith("<");
  const valueOptional = !positional && /\[=<[^>]+>\]$/.test(displayText);
  const requiredValueMatch = !positional ? displayText.match(/=<([^>]+)>/) : undefined;
  const optionalValueMatch = !positional ? displayText.match(/\[=<([^>]+)>\]/) : undefined;
  const positionalMatch = positional ? displayText.match(/^<([^>]+)>/) : undefined;
  const placeholder = (requiredValueMatch ?? optionalValueMatch ?? positionalMatch)?.[1];
  const takesValue = positional || Boolean(requiredValueMatch || optionalValueMatch);
  let insertText = displayText;
  if (positional) insertText = "";
  else if (requiredValueMatch) insertText = displayText.slice(0, requiredValueMatch.index! + 1);
  else if (valueOptional) insertText = displayText.replace(/\[=<[^>]+>\]$/, "");
  return {
    rawSyntax,
    displayText,
    insertText,
    required: !optional,
    optional,
    repeatable,
    takesValue,
    valueOptional,
    placeholder,
    positional,
    description: doc.description.trim(),
  };
}

function hasOuterBrackets(value: string): boolean {
  if (!value.startsWith("[") || !value.endsWith("]")) return false;
  let depth = 0;
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] === "[") depth += 1;
    if (value[index] === "]") depth -= 1;
    if (depth === 0 && index < value.length - 1) return false;
  }
  return depth === 0;
}

export function analyzeWpCliInput(input: string, cursor = input.length): WpCliInputAnalysis {
  const safeCursor = Math.max(0, Math.min(cursor, input.length));
  const tokens = tokenizeWpCliInput(input);
  const currentToken = tokens.find((token) => safeCursor >= token.start && safeCursor <= token.end);
  const cursorInQuote = quoteAtCursor(input, safeCursor) !== undefined;
  let currentPrefix = "";
  if (currentToken) {
    currentPrefix = unquoteFragment(input.slice(currentToken.start, safeCursor));
  }
  return {
    tokens,
    currentToken,
    currentPrefix,
    replaceStart: currentToken?.start ?? safeCursor,
    replaceEnd: currentToken?.end ?? safeCursor,
    cursorInQuote,
  };
}

export function tokenizeWpCliInput(input: string): WpCliInputToken[] {
  const tokens: WpCliInputToken[] = [];
  let index = 0;
  while (index < input.length) {
    while (index < input.length && /\s/.test(input[index]!)) index += 1;
    if (index >= input.length) break;
    const start = index;
    let value = "";
    let quote: "'" | '"' | undefined;
    while (index < input.length) {
      const character = input[index]!;
      if (!quote && /\s/.test(character)) break;
      if (character === "\\" && quote !== "'") {
        if (index + 1 < input.length) {
          value += input[index + 1]!;
          index += 2;
          continue;
        }
        value += character;
        index += 1;
        continue;
      }
      if (character === "'" || character === '"') {
        if (!quote) quote = character;
        else if (quote === character) quote = undefined;
        else value += character;
        index += 1;
        continue;
      }
      value += character;
      index += 1;
    }
    tokens.push({ value, start, end: index });
  }
  return tokens;
}

function quoteAtCursor(input: string, cursor: number): "'" | '"' | undefined {
  let quote: "'" | '"' | undefined;
  for (let index = 0; index < cursor; index += 1) {
    const character = input[index]!;
    if (character === "\\" && quote !== "'") {
      index += 1;
      continue;
    }
    if (character === "'" || character === '"') {
      if (!quote) quote = character;
      else if (quote === character) quote = undefined;
    }
  }
  return quote;
}

function unquoteFragment(fragment: string): string {
  return tokenizeWpCliInput(fragment)[0]?.value ?? "";
}

export class WpCliAutocompleteIndex {
  private readonly fullCommandIndex = new Map<string, WpCliCommandNode>();
  private readonly globalParameters: ParsedWpCliParameter[];

  constructor(private readonly catalog: WpCliCatalog) {
    this.globalParameters = deduplicateParameters(catalog.globalParameters.map(parseWpCliParameter));
    this.indexNodes(catalog.commands);
  }

  get commandCount(): number { return this.fullCommandIndex.size; }

  findCommand(fullCommand: string): WpCliCommandNode | undefined {
    return this.fullCommandIndex.get(normalizeCommand(fullCommand));
  }

  suggest(input: string, cursor = input.length): WpCliAutocompleteResult {
    const analysis = analyzeWpCliInput(input, cursor);
    const empty = { suggestions: [], parameters: [], globalParameters: this.globalParameters, unknownCommand: false };
    if (analysis.cursorInQuote) return empty;

    const first = analysis.tokens[0];
    if (!first) return empty;
    if (first.value !== "wp") {
      if (analysis.currentToken === first && "wp".startsWith(analysis.currentPrefix.toLowerCase())) {
        return { ...empty, suggestions: [this.commandSuggestion(undefined, { command: "wp", fullCommand: "wp", description: "WP-CLI", parameters: [], subcommands: [] }, analysis, "command")] };
      }
      return empty;
    }

    const currentIndex = analysis.currentToken ? analysis.tokens.indexOf(analysis.currentToken) : analysis.tokens.length;
    const firstIsCurrent = currentIndex === 0;
    const endsAtExactWp = firstIsCurrent && analysis.currentPrefix === "wp";
    let level: CommandLevel = { children: this.catalog.commands };
    let resolved: WpCliCommandNode | undefined;
    let unresolvedCommand = false;
    const argumentsBeforeCurrent = analysis.tokens.slice(1, currentIndex);
    for (const token of argumentsBeforeCurrent) {
      if (token.value.startsWith("-")) continue;
      const child = level.children.find((candidate) => candidate.command === token.value);
      if (child && !unresolvedCommand) {
        resolved = child;
        level = { parent: child, children: child.subcommands };
      } else {
        unresolvedCommand = true;
      }
    }

    let prefix = endsAtExactWp ? "" : analysis.currentPrefix;
    let replaceStart = endsAtExactWp ? cursor : analysis.replaceStart;
    let replaceEnd = endsAtExactWp ? cursor : analysis.replaceEnd;
    const currentIsOption = prefix.startsWith("-");
    if (!currentIsOption && prefix && !unresolvedCommand) {
      const exact = level.children.find((candidate) => candidate.command === prefix);
      if (exact) {
        resolved = exact;
        level = { parent: exact, children: exact.subcommands };
        prefix = "";
        replaceStart = cursor;
        replaceEnd = cursor;
      }
    }

    const currentCommand = resolved;
    const commandParameters = deduplicateParameters((currentCommand?.parameters ?? []).map(parseWpCliParameter));
    if (!currentIsOption && level.children.length && !unresolvedCommand) {
      const suggestions = rankByPrefix(level.children, prefix).map((node) =>
        this.commandSuggestion(level.parent, node, { ...analysis, replaceStart, replaceEnd }, level.parent ? "subcommand" : "command"),
      );
      return { suggestions, command: currentCommand, parameters: commandParameters, globalParameters: this.globalParameters, unknownCommand: false };
    }

    if (!currentCommand) {
      return { ...empty, unknownCommand: analysis.tokens.length > 1 };
    }
    if (!currentIsOption && prefix) {
      return { suggestions: [], command: currentCommand, parameters: commandParameters, globalParameters: this.globalParameters, unknownCommand: false };
    }
    const usedOptions = new Set(analysis.tokens.map((token) => optionName(token.value)).filter((value): value is string => Boolean(value)));
    const parameterPrefix = currentIsOption ? prefix : "";
    const localSuggestions = parameterSuggestions(commandParameters, usedOptions, parameterPrefix, analysis, "parameter");
    const localNames = new Set(commandParameters.map((parameter) => optionName(parameter.displayText)).filter(Boolean));
    const globalSuggestions = parameterSuggestions(
      this.globalParameters.filter((parameter) => !localNames.has(optionName(parameter.displayText))),
      usedOptions,
      parameterPrefix,
      analysis,
      "globalParameter",
    );
    return {
      suggestions: [...localSuggestions, ...globalSuggestions],
      command: currentCommand,
      parameters: commandParameters,
      globalParameters: this.globalParameters,
      unknownCommand: false,
    };
  }

  private indexNodes(nodes: WpCliCommandNode[]) {
    for (const node of nodes) {
      this.fullCommandIndex.set(normalizeCommand(node.fullCommand), node);
      this.indexNodes(node.subcommands);
    }
  }

  private commandSuggestion(parent: WpCliCommandNode | undefined, node: WpCliCommandNode, analysis: Pick<WpCliInputAnalysis, "replaceStart" | "replaceEnd">, type: "command" | "subcommand"): WpCliSuggestion {
    return {
      id: `${type}:${node.fullCommand}`,
      type,
      label: node.fullCommand,
      description: node.description,
      insertText: `${parent || node.command !== "wp" ? node.command : "wp"} `,
      replaceStart: analysis.replaceStart,
      replaceEnd: analysis.replaceEnd,
      command: node,
    };
  }
}

function parameterSuggestions(
  parameters: ParsedWpCliParameter[],
  usedOptions: Set<string>,
  prefix: string,
  analysis: Pick<WpCliInputAnalysis, "replaceStart" | "replaceEnd">,
  type: "parameter" | "globalParameter",
): WpCliSuggestion[] {
  return parameters
    .filter((parameter) => !parameter.positional)
    .filter((parameter) => parameter.repeatable || !usedOptions.has(optionName(parameter.displayText) ?? ""))
    .filter((parameter) => parameter.displayText.toLowerCase().startsWith(prefix.toLowerCase()))
    .map((parameter) => ({
      id: `${type}:${parameter.rawSyntax}`,
      type,
      label: parameter.displayText,
      description: parameter.description,
      insertText: parameter.takesValue && !parameter.valueOptional ? parameter.insertText : `${parameter.insertText} `,
      replaceStart: analysis.replaceStart,
      replaceEnd: analysis.replaceEnd,
      parameter,
    }));
}

function deduplicateParameters(parameters: ParsedWpCliParameter[]): ParsedWpCliParameter[] {
  const seen = new Set<string>();
  return parameters.filter((parameter) => {
    const key = parameter.rawSyntax.trim();
    if (!key || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function optionName(value: string): string | undefined {
  if (!value.startsWith("--")) return undefined;
  return value.split(/[=[]/, 1)[0];
}

function rankByPrefix(nodes: WpCliCommandNode[], prefix: string): WpCliCommandNode[] {
  const normalized = prefix.toLowerCase();
  const prefixMatches = nodes.filter((node) => node.command.toLowerCase().startsWith(normalized));
  if (prefixMatches.length || !normalized) return prefixMatches;
  return nodes.filter((node) => node.command.toLowerCase().includes(normalized));
}

function normalizeCommand(command: string): string {
  return command.trim().replace(/\s+/g, " ").toLowerCase();
}

export function applyWpCliSuggestion(input: string, suggestion: WpCliSuggestion): { value: string; cursor: number } {
  const value = `${input.slice(0, suggestion.replaceStart)}${suggestion.insertText}${input.slice(suggestion.replaceEnd)}`;
  return { value, cursor: suggestion.replaceStart + suggestion.insertText.length };
}
