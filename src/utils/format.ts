import type { SiteStatus, StepStatus } from "../types";

export const statusLabel = (status: SiteStatus | StepStatus) => ({ healthy: "Gezond", updates: "Updates beschikbaar", attention: "Controle nodig", problem: "Probleem", unreachable: "Niet bereikbaar", unscanned: "Nog niet gescand", pending: "Wachtend", running: "Bezig", success: "Geslaagd", warning: "Waarschuwing", failed: "Mislukt", skipped: "Overgeslagen" }[status]);
export const formatDate = (value?: string | null) => value ? new Intl.DateTimeFormat("nl-NL", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)) : "Nog niet";
export const formatDuration = (milliseconds?: number) => milliseconds == null ? "—" : milliseconds < 60_000 ? `${Math.round(milliseconds / 1000)} sec` : `${Math.floor(milliseconds / 60_000)} min ${Math.round((milliseconds % 60_000) / 1000)} sec`;
export const formatWpCliVersion = (value?: string | null, checkedAt?: string | null) => {
  const version = value?.trim();
  if (version) return version.startsWith("WP-CLI ") ? version : `WP-CLI ${version}`;
  return checkedAt ? "WP-CLI niet beschikbaar" : "WP-CLI nog niet gecontroleerd";
};
