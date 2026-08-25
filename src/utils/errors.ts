import type { TechnicalError } from "../types";

export function errorMessage(cause: unknown): string {
  if (cause instanceof Error) return cause.message;
  if (typeof cause === "object" && cause !== null && "userMessage" in cause) {
    const message = (cause as Partial<TechnicalError>).userMessage;
    if (typeof message === "string" && message.trim()) return message;
  }
  if (typeof cause === "string") return cause;
  return "Er is een onverwachte fout opgetreden.";
}
