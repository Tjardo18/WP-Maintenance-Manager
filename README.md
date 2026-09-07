# WP Maintenance Manager

[![CI](https://github.com/Tjardo18/WP-Maintenance-Manager/actions/workflows/ci.yml/badge.svg)](https://github.com/Tjardo18/WP-Maintenance-Manager/actions/workflows/ci.yml)

Een lokale, Nederlandstalige Windows-desktopapp voor veilig beheer en onderhoud van meerdere WordPress-websites via SSH en WP-CLI. Dagelijks beheer gebruikt vooraf gedefinieerde acties; voor beheerders is per website daarnaast een afgeschermde Advanced WP-CLI Console beschikbaar. Dit is geen algemene SSH-shell.

> Status: functionele MVP. Applicatielogin, secure SSH, root-checksums, begrensd checksum-bestandsbeheer, WordPress-gebruikersbeheer, core-reparatie, updates, lokale databasebackups, historie en de Advanced WP-CLI Console zijn aangesloten. Mockdata verschijnt uitsluitend wanneer de interface los in een browser draait en kan nooit een echte productiescan of remote command rapporteren.

## Ondersteunde omgeving

- Desktop: Windows 10/11 (architectuur blijft waar mogelijk cross-platform).
- Remote hosting: Linux/POSIX, SSH, PHP, WordPress en WP-CLI.
- Node.js 22 of nieuwer, npm 10 of nieuwer.
- Rust stable met de MSVC-toolchain.
- Microsoft C++ Build Tools en WebView2 Runtime (zie de Tauri 2 Windows-prerequisites).

## Ontwikkelen

```powershell
npm install
npm run dev
```

De losse Vite-interface gebruikt uitsluitend developmentfixtures. Start de echte desktopapp met:

```powershell
npm run tauri dev
```

Kwaliteitscontroles:

```powershell
npm run lint
npm run typecheck
npm run test
npm run build
# of alle frontendcontroles in één keer:
npm run check
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml
```

Een productie-installatiepakket maken:

```powershell
npm run tauri build
```

Op Windows verschijnen daarna een MSI en NSIS-installer onder `src-tauri/target/release/bundle/`. Lokale builds zijn niet digitaal ondertekend; voor publieke distributie hoort daar een vertrouwd code-signingcertificaat bij.

## WP-CLI autocomplete database

Autocomplete en ingebouwde command help worden gevoed door één bestand met exact deze naam en locatie:

```text
WP Maintenance Manager/
└── src-tauri/
    └── resources/
        └── wp-cli-commands.json
```

Installeren of vervangen:

1. Verkrijg of genereer `wp-cli-commands.json` met de beschreven WP-CLI-structuur (`source`, `scraped_at`, `global_parameters` en een recursieve `commands`-boom).
2. Plaats het bestand als `src-tauri/resources/wp-cli-commands.json` vóór `npm run tauri dev` of `npm run tauri build`.
3. Open na het inloggen een website en kies de tab **WP-CLI**. De status onder **Command help** toont bron, generatiedatum en de afgeleide aantallen hoofdcommando's, totale commands en globale parameters.

Tauri bundelt de volledige `resources`-map mee. In development zoekt de backend ook in dezelfde projectlocatie. Ontbreekt het bestand of is de JSON corrupt of ongeldig, dan crasht de app niet: de console toont **WP-CLI commandodatabase niet gevonden** en vrije, geldige `wp`-commands blijven uitvoerbaar zonder autocomplete/help. De database is alleen helpdata en vormt geen securitygrens; Rust valideert en classificeert ieder command afzonderlijk.

## Lokale gegevens

Productiedata komt in de app-datamap die Tauri voor `nl.wpmaintenancemanager.desktop` levert. SQLite bevat voor de applicatielogin alleen een gezouten Argon2id-hash, nooit het leesbare wachtwoord. SSH-wachtwoorden en key-passphrases worden via de credential store van het besturingssysteem opgeslagen. Databasebackups komen in een aparte `backups`-submap, buiten een website-documentroot. Databases, backups, keys en lokale logs zijn door `.gitignore` uitgesloten.

## Huidige functies

- First-run applicatiewachtwoord met Argon2id, één willekeurige geheugensessie, backend-autorisatie, login-rate-limiting, handmatige lock en instelbare idle lock (standaard 15 minuten).
- Dashboard voor tientallen websites met status, zoeken en filters.
- Website toevoegen/bewerken/verwijderen en veilige authenticatiekeuze.
- Persistente SQLite-siteopslag met UUID's, UTC-timestamps en cascading historie-tabellen.
- OS-credentialopslag voor wachtwoorden/passphrases; secrets komen nooit in SQLite of IPC-responses.
- SSH key/password-authenticatie met time-outs, SHA-256-host-key-pinning en een blokkerende mismatchmelding.
- Centrale Rust-commandcatalogus met pad-, slug- en dagenvalidatie en begrensde remote output.
- Securityscan met vanuit de WordPress-root uitgevoerde `--include-root`-corechecksums, getypeerde modified/missing/unexpected-resultaten, accounts, PHP-inventaris, PHP in uploads, recente bestanden, world-writable permissions, geselecteerde configuratie en databasecheck.
- Preview en individuele/bulkverwijdering van uitsluitend `unexpected` bestanden uit de nieuwste checksumscan. SFTP, finding-id's, canonieke padcontrole, symlinkweigering, 256-KB-previewlimiet en automatische nacontrole begrenzen deze flow.
- WordPress-gebruikers bekijken, weergavenaam/e-mail/rol wijzigen en verwijderen met expliciete contenttoewijzing of contentverwijdering. De laatste Administrator is backendmatig beschermd en Multisite-acties blijven bij de huidige site.
- WordPress-, plugin- en thema-updatecontrole via getypeerde JSON-parsers; teruggestuurde slugs worden opnieuw gevalideerd.
- Afzonderlijke coreacties: de huidige officiële versie veilig opnieuw installeren met `--force --skip-content`, of naar de vooraf gedetecteerde doelversie bijwerken. Beide vereisen een databasebackup, doen post-checks en komen in de onderhoudshistorie.
- Bevestigde plugin-, thema-, taal- en database-updates; status en versies worden na afloop opnieuw uitgelezen.
- Volledige onderhoudspipeline met preflight, voorcontrole, verplichte databasebackup, updates, nacontrole en begrensde HTTP-homepagecheck.
- Live onderhoudsstappen en persistente rapporten met voor/na-versies, waarschuwingen, failures en backupregistratie.
- Laatste scanresultaten en findings worden na een app-herstart uit SQLite hersteld. Mislukte deelcontroles bewaren begrensde, geredigeerde technische details die in de UI inklapbaar zijn.
- Detailweergave met Updates, Security, Gebruikers, Bestanden, Database, Onderhoud en Historie.
- Advanced WP-CLI-tab met recursieve JSON-autocomplete, cursor- en quote-awareness, command help, muis/toetsenbordbediening en sessiegebonden command history/output per site.
- Vrije WP-CLI-uitvoering via een geauthenticeerde backendparser: uitsluitend executable `wp`, geen shell chaining/redirects/substitution, backend-bepaald sitepad, afzonderlijk POSIX-gequote argumenten en een conservatieve risicoclassificatie met extra bevestiging.
- Bevestigingsdialogen voor iedere muterende actie.
- Backend-bulkscans met live voortgang, foutisolatie per site, veilig stoppen en persistent instelbare paralleliteit (1–5 taken).
- Developmentfixtures voor beoordeling zonder productiecredentials.
- Restrictieve Tauri-capability en CSP zonder remote JavaScript.

Zie [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md) en [docs/REMOTE_COMMANDS.md](docs/REMOTE_COMMANDS.md) voor ontwerp- en veiligheidsdetails.

## Bekende beperkingen

Versie 1 ondersteunt alleen WordPress op Linux/POSIX-hosting via SSH. Backups vóór onderhoud en coreacties zijn databasebackups; er is nog geen volledige bestandsbackup of automatische rollback. De bestandsflow is bewust geen filemanager en kan alleen actuele `unexpected` checksumfindings openen/verwijderen. Een core-reparatie verwijdert onbekende bestanden niet. Userverwijdering op Multisite is alleen voor de huidige site, nooit netwerkbreed. Custom WP-CLI-output verschijnt in deze versie na completion en streamt nog niet live; een lopend SSH-command heeft geen onveilige stopknop.

Een geslaagde homepagecheck of securityscan is geen garantie dat een complete website foutloos of volledig veilig is. Een reeds geautoriseerde backendactie mag na een lock veilig afronden; de lock start geen rollback. De applicatielogin beperkt ongewenst gebruik via de app, maar beschermt niet tegen volledige controle over het Windows-account, procesgeheugen of bestandssysteem. Automatische malwareverwijdering, quarantaine, database-optimalisatie en digitaal ondertekende publieke installers vallen buiten versie 1.
