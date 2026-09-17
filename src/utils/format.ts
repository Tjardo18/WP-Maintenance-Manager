import type { SiteStatus, StepStatus } from "../types";

export const statusLabel = (status: SiteStatus | StepStatus) => ({ healthy: "Gezond", updates: "Updates beschikbaar", attention: "Controle nodig", problem: "Probleem", unreachable: "Niet bereikbaar", unscanned: "Nog niet gescand", pending: "Wachtend", running: "Bezig", success: "Geslaagd", warning: "Waarschuwing", failed: "Mislukt", skipped: "Overgeslagen" }[status]);
export const formatDate = (value?: string | null) => value ? new Intl.DateTimeFormat("nl-NL", { dateStyle: "medium", timeStyle: "short" }).format(new Date(value)) : "Nog niet";
export const formatDuration = (milliseconds?: number) => milliseconds == null ? "—" : milliseconds < 60_000 ? `${Math.round(milliseconds / 1000)} sec` : `${Math.floor(milliseconds / 60_000)} min ${Math.round((milliseconds % 60_000) / 1000)} sec`;
export const formatModifiedFileDetail = (value: string) => {
  const legacy = value.match(/^Gewijzigd op Unix-tijd (-?\d+(?:\.\d+)?) met permissiemodus ([0-7]{3,4})\. Een recente wijziging is niet automatisch kwaadaardig\.$/);
  if (!legacy) return value;
  const date = new Date(Number(legacy[1]) * 1000);
  if (Number.isNaN(date.getTime())) return `Gewijzigd op een onbekend tijdstip en heeft permissies ${legacy[2]}.`;
  const dateLabel = new Intl.DateTimeFormat("nl-NL", { day: "numeric", month: "long", year: "numeric", timeZone: "Europe/Amsterdam" }).format(date);
  const timeLabel = new Intl.DateTimeFormat("nl-NL", { hour: "2-digit", minute: "2-digit", hourCycle: "h23", timeZone: "Europe/Amsterdam" }).format(date);
  return `Gewijzigd op ${dateLabel} om ${timeLabel} uur en heeft permissies ${legacy[2]}.`;
};
export const formatWpCliVersion = (value?: string | null, checkedAt?: string | null) => {
  const version = value?.trim();
  if (version) return version.startsWith("WP-CLI ") ? version : `WP-CLI ${version}`;
  return checkedAt ? "WP-CLI niet beschikbaar" : "WP-CLI nog niet gecontroleerd";
};
