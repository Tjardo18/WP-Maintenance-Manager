import type { MaintenanceRun, ScanResult, Site, UpdateItem } from "../types";

const now = new Date();
const isoAgo = (hours: number) => new Date(now.getTime() - hours * 3_600_000).toISOString();

export const demoSites: Site[] = [
  { id: "demo-1", name: "Bakkerij De Molen", url: "https://example.test", sshHost: "server.example.test", sshPort: 22, sshUsername: "deploy", authMethod: "keyFile", keyPath: "C:\\Users\\demo\\.ssh\\id_ed25519", wordpressPath: "/var/www/example/public", pinnedHostKey: "SHA256:demo", status: "updates", wordpressVersion: "6.8.1", phpVersion: "8.3.12", updateCount: 4, securityStatus: "Geen aandachtspunten gevonden", lastScanAt: isoAgo(3), lastMaintenanceAt: isoAgo(168), createdAt: isoAgo(720), updatedAt: isoAgo(3) },
  { id: "demo-2", name: "Studio Noord", url: "https://studio.example.test", sshHost: "studio.example.test", sshPort: 22, sshUsername: "wordpress", authMethod: "password", wordpressPath: "/srv/www/site", pinnedHostKey: "SHA256:demo2", status: "healthy", wordpressVersion: "6.8.2", phpVersion: "8.2.24", updateCount: 0, securityStatus: "Geen aandachtspunten gevonden", lastScanAt: isoAgo(8), lastMaintenanceAt: isoAgo(240), createdAt: isoAgo(1200), updatedAt: isoAgo(8) },
  { id: "demo-3", name: "Museum Collectie", url: "https://museum.example.test", sshHost: "offline.example.test", sshPort: 22, sshUsername: "beheer", authMethod: "keyFile", wordpressPath: "/home/museum/public_html", status: "unreachable", updateCount: 0, securityStatus: "Scan mislukt", lastScanAt: isoAgo(30), createdAt: isoAgo(2000), updatedAt: isoAgo(30) },
];

export const demoUpdates: UpdateItem[] = [
  { kind: "core", slug: "wordpress", name: "WordPress", currentVersion: "6.8.1", newVersion: "6.8.2", status: "available" },
  { kind: "plugin", slug: "wordpress-seo", name: "Yoast SEO", currentVersion: "24.1", newVersion: "24.3", status: "available" },
  { kind: "plugin", slug: "woocommerce", name: "WooCommerce", currentVersion: "9.8.1", newVersion: "9.9.0", status: "available" },
  { kind: "theme", slug: "twentytwentyfive", name: "Twenty Twenty-Five", currentVersion: "1.1", newVersion: "1.2", status: "available" },
];

export const demoScan: ScanResult = {
  id: "scan-demo", siteId: "demo-1", startedAt: isoAgo(3), finishedAt: isoAgo(3), status: "updates", truncated: false,
  checks: [
    { key: "core_checksum", label: "WordPress core", status: "warning", summary: "Gewijzigd: 0 · Ontbreekt: 0 · Hoort niet aanwezig te zijn: 1 · Scanmeldingen: 0", findings: [{ id: "27f602cb-a50e-4b86-8220-a4f05b09a83a", category: "wordpress-core-unexpected", severity: "attention", title: "Hoort niet aanwezig te zijn", detail: "File should not exist", path: "wp-admin/cache-old.php", checksumStatus: "unexpected", observedAt: isoAgo(3) }] },
    { key: "users", label: "Gebruikersaccounts", status: "success", summary: "5 accounts gevonden, waarvan 2 beheerders.", findings: [] },
    { key: "php_uploads", label: "PHP in uploads", status: "warning", summary: "1 bestand vraagt aandacht.", findings: [{ category: "uploads", severity: "attention", title: "PHP-bestand gevonden in uploads", detail: "PHP-bestanden horen normaal niet in de uploadmap. Controleer het bestand voordat je actie onderneemt.", path: "wp-content/uploads/cache/legacy.php" }] },
    { key: "permissions", label: "Bestandsrechten", status: "success", summary: "Geen world-writable bestanden gevonden.", findings: [] },
    { key: "database", label: "Database", status: "success", summary: "Databasecontrole voltooid zonder fouten.", findings: [] },
  ],
};

export const demoHistory: MaintenanceRun[] = [{
  id: "maintenance-demo", siteId: "demo-1", siteName: "Bakkerij De Molen", startedAt: isoAgo(168), finishedAt: isoAgo(167.9), durationMs: 362000, status: "success", backupPath: "backups/demo-1/2026-08-18.sql.gz", beforeVersions: "WordPress 6.8.0 · 3 pluginupdates", afterVersions: "WordPress 6.8.1 · alles bijgewerkt",
  steps: ["Preflight", "Voorcontrole", "Databasebackup", "WordPress bijwerken", "Plugins bijwerken", "Thema's bijwerken", "Vertalingen", "Database", "Nacontrole", "Homepage bereikbaar"].map((label, index) => ({ key: String(index), label, status: "success" })),
}];
