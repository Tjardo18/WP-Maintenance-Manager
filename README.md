# WP Maintenance Manager

Een lokale, Nederlandstalige Windows-desktopapp voor veilig beheer en onderhoud van meerdere WordPress-websites via SSH en WP-CLI. De gebruiker kiest alleen vooraf gedefinieerde acties; de interface bevat geen terminal of vrij commandoveld.

> Status: actieve MVP-ontwikkeling. Sitebeheer gebruikt in de desktopapp echte SQLite-migrations en de Windows Credential Manager; SSH/scans worden in de volgende milestones aangesloten. Mockdata verschijnt uitsluitend wanneer de interface los in een browser draait en kan nooit een echte productiescan rapporteren.

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
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml
```

Een productie-installatiepakket maken:

```powershell
npm run tauri build
```

## Lokale gegevens

Productiedata komt in de app-datamap die Tauri voor `nl.wpmaintenancemanager.app` levert. SQLite bevat nooit wachtwoorden of passphrases. Secrets worden via de credential store van het besturingssysteem opgeslagen. Databasebackups komen in een aparte `backups`-submap, buiten een website-documentroot. Databases, backups, keys en lokale logs zijn door `.gitignore` uitgesloten.

## Huidige functies

- Dashboard voor tientallen websites met status, zoeken en filters.
- Website toevoegen/bewerken/verwijderen en veilige authenticatiekeuze.
- Persistente SQLite-siteopslag met UUID's, UTC-timestamps en cascading historie-tabellen.
- OS-credentialopslag voor wachtwoorden/passphrases; secrets komen nooit in SQLite of IPC-responses.
- Detailweergave met Updates, Security, Gebruikers, Bestanden, Database, Onderhoud en Historie.
- Bevestigingsdialogen voor iedere muterende actie.
- Begrensde bulkscaninterface (maximaal vier gelijktijdige taken).
- Developmentfixtures voor beoordeling zonder productiecredentials.
- Restrictieve Tauri-capability en CSP zonder remote JavaScript.

Zie [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md) en [docs/REMOTE_COMMANDS.md](docs/REMOTE_COMMANDS.md) voor ontwerp- en veiligheidsdetails.

## Bekende beperkingen

Versie 1 ondersteunt alleen WordPress op Linux/POSIX-hosting via SSH. Een geslaagde homepagecheck of securityscan is geen garantie dat een complete website foutloos of volledig veilig is. Automatische malwareverwijdering, rollback en volledige bestandsbackups vallen bewust buiten versie 1.
