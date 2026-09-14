import type { MaintenanceRun, ScanResult, Site, UpdateItem, WordPressUsersData } from "../types";

const now = new Date();
const isoAgo = (hours: number) => new Date(now.getTime() - hours * 3_600_000).toISOString();

export const demoSites: Site[] = [
  { id: "demo-1", name: "Bakkerij De Molen", url: "https://example.test", sshHost: "server.example.test", sshPort: 22, sshUsername: "deploy", authMethod: "keyFile", keyPath: "C:\\Users\\demo\\.ssh\\id_ed25519", wordpressPath: "/var/www/example/public", pinnedHostKey: "SHA256:demo", status: "attention", wordpressVersion: "6.8.1", phpVersion: "8.3.12", updateCount: 4, securityStatus: "Aandacht nodig", lastScanAt: isoAgo(3), lastMaintenanceAt: isoAgo(168), createdAt: isoAgo(720), updatedAt: isoAgo(3), vulnerabilitySummary: { criticalCount: 0, highCount: 1, mediumCount: 0, lowCount: 0, infoCount: 0, unknownCount: 0, lastCheckedAt: isoAgo(3), feedUpdatedAt: isoAgo(8), inventoryObservedAt: isoAgo(3), inventoryStale: false } },
  { id: "demo-2", name: "Studio Noord", url: "https://studio.example.test", sshHost: "studio.example.test", sshPort: 22, sshUsername: "wordpress", authMethod: "password", wordpressPath: "/srv/www/site", pinnedHostKey: "SHA256:demo2", status: "healthy", wordpressVersion: "6.8.2", phpVersion: "8.2.24", updateCount: 0, securityStatus: "Geen aandachtspunten gevonden", lastScanAt: isoAgo(8), lastMaintenanceAt: isoAgo(240), createdAt: isoAgo(1200), updatedAt: isoAgo(8) },
  { id: "demo-3", name: "Museum Collectie", url: "https://museum.example.test", sshHost: "offline.example.test", sshPort: 22, sshUsername: "beheer", authMethod: "keyFile", wordpressPath: "/home/museum/public_html", status: "unreachable", updateCount: 0, securityStatus: "Scan mislukt", lastScanAt: isoAgo(30), createdAt: isoAgo(2000), updatedAt: isoAgo(30) },
];

export const demoUpdates: UpdateItem[] = [
  { kind: "core", slug: "wordpress", name: "WordPress", currentVersion: "6.8.1", newVersion: "6.8.2", status: "available" },
  { kind: "plugin", slug: "wordpress-seo", name: "Yoast SEO", currentVersion: "24.1", newVersion: "24.3", status: "available" },
  { kind: "plugin", slug: "woocommerce", name: "WooCommerce", currentVersion: "9.8.1", newVersion: "9.9.0", status: "available" },
  { kind: "theme", slug: "twentytwentyfive", name: "Twenty Twenty-Five", currentVersion: "1.1", newVersion: "1.2", status: "available" },
];

export const demoUsers: WordPressUsersData = {
  multisite: true,
  roles: [{ role: "administrator", name: "Administrator" }, { role: "editor", name: "Editor" }, { role: "author", name: "Auteur" }, { role: "subscriber", name: "Abonnee" }, { role: "shop_manager", name: "Winkelmanager" }],
  users: [
    { id: 1, username: "admin", displayName: "Sitebeheerder", email: "admin@example.test", roles: ["administrator"], registeredAt: "2020-01-12 09:30:00" },
    { id: 8, username: "redactie", displayName: "Redactie", email: "redactie@example.test", roles: ["editor", "shop_manager"], registeredAt: "2023-05-18 14:12:00" },
    { id: 14, username: "auteur", displayName: "Webredacteur", email: "auteur@example.test", roles: ["author"], registeredAt: "2025-11-04 11:45:00" },
  ],
};

export const demoScan: ScanResult = {
  id: "scan-demo", siteId: "demo-1", startedAt: isoAgo(3), finishedAt: isoAgo(3), status: "updates", truncated: false,
  checks: [
    { key: "core_checksum", label: "WordPress core", status: "warning", summary: "Gewijzigd: 0 · Ontbreekt: 0 · Hoort niet aanwezig te zijn: 1 · Scanmeldingen: 0", findings: [{ id: "27f602cb-a50e-4b86-8220-a4f05b09a83a", category: "wordpress-core-unexpected", severity: "attention", title: "Hoort niet aanwezig te zijn", detail: "File should not exist", path: "wp-admin/cache-old.php", checksumStatus: "unexpected", observedAt: isoAgo(3) }] },
    { key: "users", label: "Gebruikersaccounts", status: "success", summary: "5 accounts gevonden, waarvan 2 beheerders.", findings: [] },
    { key: "php_uploads", label: "PHP in uploads", status: "warning", summary: "1 bestand vraagt aandacht.", findings: [{ category: "uploads", severity: "attention", title: "PHP-bestand gevonden in uploads", detail: "PHP-bestanden horen normaal niet in de uploadmap. Controleer het bestand voordat je actie onderneemt.", path: "wp-content/uploads/cache/legacy.php" }] },
    { key: "permissions", label: "Bestandsrechten", status: "success", summary: "Geen world-writable bestanden gevonden.", findings: [] },
    { key: "database", label: "Database", status: "success", summary: "Databasecontrole voltooid zonder fouten.", findings: [] },
    { key: "vulnerabilities", label: "Kwetsbaarheden", status: "warning", summary: "1 bekende kwetsbaarheid gevonden in 12 componenten.", technicalDetails: `Bron: Wordfence Intelligence · Feed bijgewerkt: ${isoAgo(8)} · Exacte type/slug-matches: 11/12`, findings: [{
      id: "d42e42c4-e004-45c6-82d9-0b467cbb11aa", category: "vulnerability", severity: "warning", title: "WooCommerce: Demo vulnerability", detail: "Geïnstalleerde versie 9.8.1 valt binnen <= 9.8.1.", observedAt: isoAgo(3), disposition: "active", policyTarget: "wordfence:fixture:plugin:woocommerce:9.8.1",
      vulnerability: { provider: "wordfence", vulnerabilityId: "e48d8536-eefa-4639-a8b8-cbb06cfa5347", title: "Authenticated Stored Cross-Site Scripting", description: "Een beheerder met specifieke rechten kan opgeslagen inhoud manipuleren. Dit is uitsluitend demonstratiedata voor de lokale browserweergave.", informational: false, cve: "CVE-2026-12345", cveLink: "https://www.cve.org/CVERecord?id=CVE-2026-12345", published: isoAgo(72), updated: isoAgo(24), cvssVector: "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", cvssScore: 7.2, cvssRating: "High", cweId: 79, cweName: "Cross-site Scripting", cweDescription: "Improper neutralization of input", researchers: ["Demo Researcher"], references: ["https://www.wordfence.com/threat-intel/vulnerabilities/"], copyrights: { mitre: { notice: "CVE data is subject to the record-specific terms.", license_url: "https://www.cve.org/Legal/TermsOfUse" } }, softwareType: "plugin", softwareSlug: "woocommerce", softwareName: "WooCommerce", affectedRanges: [{ label: "<= 9.8.1", fromVersion: "*", fromInclusive: true, toVersion: "9.8.1", toInclusive: true }], patched: true, patchedVersions: ["9.9.0"], remediation: "Update naar versie 9.9.0 of een aantoonbaar veilige nieuwere versie.", installedVersion: "9.8.1", installedStatus: "active", updateVersion: "9.9.0", matchedRanges: ["<= 9.8.1"] },
    }] },
  ],
};

export const demoHistory: MaintenanceRun[] = [{
  id: "maintenance-demo", siteId: "demo-1", siteName: "Bakkerij De Molen", startedAt: isoAgo(168), finishedAt: isoAgo(167.9), durationMs: 362000, status: "success", backupPath: "backups/demo-1/2026-08-18.sql.gz", beforeVersions: "WordPress 6.8.0 · 3 pluginupdates", afterVersions: "WordPress 6.8.1 · alles bijgewerkt",
  steps: ["Preflight", "Voorcontrole", "Databasebackup", "WordPress bijwerken", "Plugins bijwerken", "Thema's bijwerken", "Vertalingen", "Database", "Nacontrole", "Homepage bereikbaar"].map((label, index) => ({ key: String(index), label, status: "success" })),
}];
