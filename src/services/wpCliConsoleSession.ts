import { reactive } from "vue";
import type { WpCliCatalog, WpCliExecutionResult, WpCliRisk } from "../types";
import { appApi } from "./tauri";

export interface WpCliConsoleOutput {
  id: number;
  command: string;
  risk: WpCliRisk;
  result?: WpCliExecutionResult;
  error?: string;
  startedAt: string;
  finishedAt: string;
}

export interface WpCliConsoleSession {
  command: string;
  history: string[];
  outputs: WpCliConsoleOutput[];
  acknowledgedAdvancedWarning: boolean;
}

const MAX_HISTORY_ITEMS = 100;
const MAX_OUTPUT_ITEMS = 20;
const sessions = new Map<string, WpCliConsoleSession>();
let nextOutputId = 1;
let catalogPromise: Promise<WpCliCatalog> | undefined;

export function getWpCliConsoleSession(siteId: string): WpCliConsoleSession {
  const existing = sessions.get(siteId);
  if (existing) return existing;
  const session = reactive<WpCliConsoleSession>({ command: "", history: [], outputs: [], acknowledgedAdvancedWarning: false });
  sessions.set(siteId, session);
  return session;
}

export function rememberWpCliCommand(session: WpCliConsoleSession, command: string) {
  if (session.history[session.history.length - 1] === command) return;
  session.history.push(command);
  if (session.history.length > MAX_HISTORY_ITEMS) session.history.splice(0, session.history.length - MAX_HISTORY_ITEMS);
}

export function appendWpCliOutput(session: WpCliConsoleSession, output: Omit<WpCliConsoleOutput, "id">) {
  session.outputs.push({ ...output, id: nextOutputId++ });
  if (session.outputs.length > MAX_OUTPUT_ITEMS) session.outputs.splice(0, session.outputs.length - MAX_OUTPUT_ITEMS);
}

export function clearWpCliConsoleSessions() {
  for (const session of sessions.values()) {
    session.command = "";
    session.history.splice(0);
    session.outputs.splice(0);
    session.acknowledgedAdvancedWarning = false;
  }
  sessions.clear();
}

export function loadWpCliCatalog(): Promise<WpCliCatalog> {
  if (!catalogPromise) {
    catalogPromise = appApi.getWpCliCatalog().catch((cause) => {
      catalogPromise = undefined;
      throw cause;
    });
  }
  return catalogPromise;
}
