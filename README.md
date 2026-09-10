# WP Maintenance Manager

[![CI](https://github.com/Tjardo18/WP-Maintenance-Manager/actions/workflows/ci.yml/badge.svg)](https://github.com/Tjardo18/WP-Maintenance-Manager/actions/workflows/ci.yml)

Een lokale, Nederlandstalige Windows-desktopapp voor beheer en onderhoud van meerdere WordPress-websites via SSH en WP-CLI. Dagelijks beheer gebruikt vooraf gedefinieerde acties; voor beheerders is per website daarnaast een geavanceerde interactieve SSH-terminal beschikbaar.

> Status: functionele MVP. Applicatielogin, secure SSH, root-checksums, intelligente PHP-classificatie, begrensd checksum-bestandsbeheer, WordPress-gebruikersbeheer, core-reparatie, updates, lokale databasebackups, foutenlog, historie en de interactieve SSH-terminal zijn aangesloten. Mockdata verschijnt uitsluitend wanneer de interface los in een browser draait en kan nooit een echte productiescan of remote command rapporteren.

Websitecontroles en bulkscans draaien als begrensde achtergrondtaken. Cached pagina's en navigatie blijven daardoor tijdens een scan bruikbaar, terwijl echte stapvoortgang en annulering beschikbaar blijven.

## Uitzonderingen

Bekende of operationeel onbelangrijke meldingen kunnen per website permanent of tijdelijk worden genegeerd. De backend matcht exact op website, controle, meldingstype en target: een genegeerde ontbrekende `readme.html` verbergt dus geen latere gewijzigde `readme.html`. Informatieve ontbrekende distributiebestanden zoals `readme.html` en `license.txt` tellen standaard niet als websitewaarschuwing. De Security-tab toont standaard alleen actieve meldingen; genegeerde, vertrouwde en verlopen records blijven via filters en de centrale pagina **Uitzonderingen** beschikbaar.

## Vertrouwde bestanden

Een bestaand bestand kan na bewuste beoordeling worden vertrouwd. De Rust-backend leest het bestand alleen via veilige SFTP-controles en bewaart uitsluitend een streaming berekende SHA-256-fingerprint en minimale metadata, nooit de inhoud. Bij iedere volgende scan wordt die fingerprint opnieuw berekend. Een gelijke versie telt niet als actief probleem; gewijzigde inhoud wordt als **Vertrouwd bestand is gewijzigd** opnieuw actief, en een verdwenen bestand blijft in het beheeroverzicht staan. Vertrouwen is site- en inhoudsspecifiek en is geen malwaregarantie.

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

Op Windows verschijnen daarna een MSI en NSIS-installer onder `src-tauri/target/release/bundle/`. De app- en pakketversie is `0.9.0-beta.1`; omdat Windows Installer geen tekstuele prerelease-identifiers accepteert, gebruikt uitsluitend de interne WiX/MSI-productversie de equivalente numerieke waarde `0.9.0.1`. Lokale builds zijn niet digitaal ondertekend; voor publieke distributie hoort daar een vertrouwd code-signingcertificaat bij.

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
3. Open na het inloggen een website en kies de tab **Terminal**. Doorloop de extra app- en SSH-wachtwoordcontrole. Typ daarna aan een nieuwe prompt `wp`; het zijpaneel toont de bijbehorende command help en suggesties.

Tauri bundelt de volledige `resources`-map mee. In development zoekt de backend ook in dezelfde projectlocatie. Ontbreekt het bestand of is de JSON corrupt of ongeldig, dan crasht de app niet: de terminal blijft werken, alleen WP-CLI autocomplete/help ontbreekt. De database is alleen helpdata en vormt geen securitygrens.

## Terminal beveiliging

Iedere keer dat de interactieve Terminal wordt geopend, vraagt de app opnieuw om twee afzonderlijke wachtwoorden:

1. het WP Maintenance Manager-wachtwoord, opnieuw gecontroleerd tegen dezelfde Argon2id-hash als de normale login;
2. het SSH-wachtwoord van de aan de geselecteerde website gekoppelde SSH-gebruiker.

Na de eerste controle geeft de backend een cryptografisch willekeurige, site- en appsessiegebonden challenge uit. Deze is 60 seconden geldig en kan maar één keer worden gebruikt. Pas na expliciete SSH-passwordauthenticatie en de bestaande host-keycontrole wordt een nieuwe PTY geopend. De Terminal gebruikt hierbij nooit stil een opgeslagen SSH-key, agent of credential als fallback.

Een fout Maintenance Manager-wachtwoord tijdens deze extra controle wordt behandeld als mogelijke ongeautoriseerde toegang: de volledige backend-appsessie wordt ingetrokken, alle terminalkanalen worden gesloten, gevoelige frontendstate wordt gewist en het algemene loginscherm verschijnt. Een fout SSH-wachtwoord houdt alleen de Terminal gesloten; de gewone app blijft beschikbaar. SSH-pogingen worden bij herhaalde failures kort vertraagd.

Het ingevoerde SSH-wachtwoord geldt uitsluitend voor deze ene verbindingspoging en wordt niet opgeslagen in SQLite, localStorage, de OS-credentialstore, logs of terminalhistory. De tijdelijke challenge, aparte Terminal-autorisatie, shell en lokale scrollback verdwijnen bij annuleren, sluiten, tabwissel, sitewissel, app-lock, idle lock, wachtwoordwijziging of procesafsluiting. Opnieuw openen vereist altijd opnieuw beide wachtwoorden.

Een server met `PasswordAuthentication no`, of een server die alleen public-key/keyboard-interactive authenticatie aanbiedt, kan volgens deze policy geen interactieve Terminal openen. Managed scans, updates en onderhoud blijven wel hun afzonderlijk opgeslagen key of credential gebruiken.

## Terminalfuncties

De tab **Terminal** bevat een geavanceerde SSH-terminal met een echte persistente PTY/shell. De sessie start in de ingestelde WordPress-root. Een `cd wp-content` beïnvloedt daardoor een volgende `pwd`, zoals bij een normale SSH-login. Vrije Linux-commando's zoals `ls`, `grep`, `chmod`, `mkdir`, `find`, `git`, `composer` en `wp` worden rechtstreeks uitgevoerd met de rechten van het gekoppelde SSH-account.

De renderer is xterm.js met `xterm-256color`. Whitespace, tabs, ANSI-sequenties, carriage returns en lange WP-CLI-tabellen blijven terminalgetrouw; de terminal schaalt de remote PTY mee en stuurt Ctrl+C als interrupt. Wanneer een nieuwe commandoregel met `wp` begint, blijft autocomplete uit `wp-cli-commands.json` actief. Complexe shell-chaining zoals `cd wp-content && wp ...` wordt wel door de shell uitgevoerd, maar activeert in deze versie geen WP-autocomplete voor het tweede commando.

Dit is bewust een advanced functie. Terminalcommando's en output worden niet in de lokale database opgeslagen; de remote shell bepaalt zelf of zij server-side history bijhoudt.

## Lokale gegevens

Productiedata komt in de app-datamap die Tauri voor `nl.wpmaintenancemanager.desktop` levert. SQLite bevat voor de applicatielogin alleen een gezouten Argon2id-hash, nooit het leesbare wachtwoord. SSH-wachtwoorden en key-passphrases voor managed functies worden via de credential store van het besturingssysteem opgeslagen. Het handmatig ingevoerde Terminal-SSH-wachtwoord wordt daar niet aan toegevoegd. Het SQLite-foutenlog bewaart maximaal 30 dagen en 10.000 geredigeerde records. Databasebackups komen in een aparte `backups`-submap, buiten een website-documentroot. Databases, backups, keys en lokale logs zijn door `.gitignore` uitgesloten.

## Huidige functies

- First-run applicatiewachtwoord met Argon2id, één willekeurige geheugensessie, backend-autorisatie, login-rate-limiting, handmatige lock en instelbare idle lock (standaard 15 minuten).
- Dashboard voor tientallen websites met status, zoeken en filters.
- Website toevoegen/bewerken/verwijderen en veilige authenticatiekeuze.
- Persistente SQLite-siteopslag met UUID's, UTC-timestamps en cascading historie-tabellen.
- OS-credentialopslag voor wachtwoorden/passphrases; secrets komen nooit in SQLite of IPC-responses.
- SSH key/password-authenticatie met time-outs, SHA-256-host-key-pinning en een blokkerende mismatchmelding.
- Centrale Rust-commandcatalogus met pad-, slug- en dagenvalidatie en begrensde remote output.
- Securityscan met vanuit de WordPress-root uitgevoerde `--include-root`-corechecksums, getypeerde modified/missing/unexpected-resultaten, accounts, intelligente statische PHP-classificatie, PHP in uploads, recente bestanden, world-writable permissions, geselecteerde configuratie en databasecheck. Normale plugin-/theme-PHP blijft standaard verborgen; opvallende locatie-, naam- en inhoudscombinaties worden met redenen getoond.
- Centrale severity- en statuspolicy met site-specifieke exacte uitzonderingen, tijdelijke verloopdata en filters voor actief, genegeerd, vertrouwd en alles.
- Hash-based vertrouwde bestanden via streaming SHA-256/SFTP, met hernieuwde waarschuwing bij gewijzigde inhoud, beheerbare status bij verwijdering en auditbare trustintrekking of -vernieuwing.
- Preview en individuele/bulkverwijdering van uitsluitend `unexpected` bestanden uit de nieuwste checksumscan. SFTP, finding-id's, canonieke padcontrole, symlinkweigering, 256-KB-previewlimiet en automatische nacontrole begrenzen deze flow.
- WordPress-gebruikers bekijken, weergavenaam/e-mail/rol wijzigen en verwijderen met expliciete contenttoewijzing of contentverwijdering. De laatste Administrator is backendmatig beschermd en Multisite-acties blijven bij de huidige site.
- WordPress-, plugin- en thema-updatecontrole via getypeerde JSON-parsers; teruggestuurde slugs worden opnieuw gevalideerd.
- Afzonderlijke coreacties: de huidige officiële versie veilig opnieuw installeren met `--force --skip-content`, of naar de vooraf gedetecteerde doelversie bijwerken. Beide vereisen een databasebackup, doen post-checks en komen in de onderhoudshistorie.
- Bevestigde plugin-, thema-, taal- en database-updates; status en versies worden na afloop opnieuw uitgelezen.
- Volledige onderhoudspipeline met preflight, voorcontrole, verplichte databasebackup, updates, nacontrole en begrensde HTTP-homepagecheck.
- Live onderhoudsstappen en persistente rapporten met voor/na-versies, waarschuwingen, failures en backupregistratie.
- Laatste scanresultaten en findings worden na een app-herstart uit SQLite hersteld. Mislukte deelcontroles bewaren begrensde, geredigeerde technische details die in de UI inklapbaar zijn.
- Compacte Security-detailweergave met samenvatting, accordions, standaard alleen opvallende PHP, zoeken, categoriefilters en paginering van 25/50/100 resultaten.
- Persistent, filterbaar SQLite-foutenlog met `ERR-…`-correlatie-ID, categorie, site, actie, veilige technische details, cause-chain, duur, exitcode en retry-indicatie. Retentie voorkomt onbeperkte groei.
- Interactieve Terminal-tab met verplichte app-reauthenticatie, expliciete SSH-passwordauthenticatie, single-use challenge, aparte sitegebonden Terminal-autorisatie, persistente PTY/shell, live streaming, Ctrl+C, resize, vrije shellcommands en automatisch sluiten bij verlaten of lock.
- WP-CLI-autocomplete en command help binnen de terminal voor eenvoudige nieuwe regels die met `wp` beginnen.
- Bevestigingsdialogen voor iedere muterende actie.
- Centrale achtergrondjobs voor losse en bulk-scans, met echte stapvoortgang, één SSH-sessie per scan, foutisolatie, veilig stoppen en persistent instelbare paralleliteit (1–5 sites).
- Developmentfixtures voor beoordeling zonder productiecredentials.
- Restrictieve Tauri-capability en CSP zonder remote JavaScript.

Zie [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md), [docs/PERFORMANCE.md](docs/PERFORMANCE.md) en [docs/REMOTE_COMMANDS.md](docs/REMOTE_COMMANDS.md) voor ontwerp-, performance- en veiligheidsdetails.

## Bekende beperkingen

Versie 1 ondersteunt alleen WordPress op Linux/POSIX-hosting via SSH. Interactieve Terminaltoegang vereist dat de server gewone SSH-passwordauthenticatie aanbiedt; `PasswordAuthentication no` blokkeert deze specifieke functie zonder fallback naar de opgeslagen key. Backups vóór onderhoud en coreacties zijn databasebackups; er is nog geen volledige bestandsbackup of automatische rollback. De bestandsflow is bewust geen filemanager en kan alleen actuele `unexpected` checksumfindings openen/verwijderen. Trust kan ook andere actuele findings met een bestaand site-relatief bestand hashen, maar biedt geen algemene bestandsbrowser. Een site met actieve trustregistraties gebruikt tijdens een scan één aanvullende gebundelde SFTP-sessie voor fingerprintcontrole. Een core-reparatie verwijdert onbekende bestanden niet. Userverwijdering op Multisite is alleen voor de huidige site, nooit netwerkbreed. Full-screen interactieve programma's zijn afhankelijk van de remote shell/hosting; de primaire dekking is normale shellinvoer, `cd`, WP-CLI, streaming en interrupts. WP-autocomplete parseert nog geen complexe shell-AST of chained `wp`-commando's.

Een geslaagde homepagecheck of securityscan is geen garantie dat een complete website foutloos of volledig veilig is. Een reeds geautoriseerde backendactie mag na een lock veilig afronden; de lock start geen rollback. De applicatielogin beperkt ongewenst gebruik via de app, maar beschermt niet tegen volledige controle over het Windows-account, procesgeheugen of bestandssysteem. Automatische malwareverwijdering, quarantaine, database-optimalisatie en digitaal ondertekende publieke installers vallen buiten versie 1.
