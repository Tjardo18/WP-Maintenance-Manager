# Architectuur

## Grenzen en execution modes

```text
Vue UI → typed TypeScript service → authenticated Tauri commands
                                      ├─ Managed Commands → stored credential → SSH exec/WP-CLI
                                      ├─ Terminal gate → app reauth → single-use challenge
                                      │                  → password-only SSH → authorized PTY/shell
                                      └─ Error reporting → redactie/retentie → SQLite error_logs

SQLite repositories ← application services → scans / users / core / maintenance
OS credential store ← SSH adapter         ↘ begrensde SFTP / HTTP health check
```

De app heeft bewust twee verschillende remote execution modes:

1. **Managed Commands** voor scans, updates, checksums, users, backups en onderhoud. Deze acties zijn typed, vooraf gedefinieerd, backend-gevalideerd en begrensd.
2. **Interactive SSH Terminal** voor advanced beheer. Dit is een vrije, sitegebonden SSH-shell met een persistente PTY. De remote Linux-accountrechten zijn hier de uiteindelijke autorisatiegrens.

De terminal maakt de managed commandcatalogus niet vrijer. Omgekeerd legt de catalogus geen allowlist op aan terminalinvoer.

## Frontend

Vue 3, Vue Router, Pinia en TypeScript vormen de interface. `src/services/tauri.ts` is de enige IPC-toegang. Een gewone browser gebruikt duidelijk fictieve `.test`-fixtures; Tauri gebruikt die nooit voor productieacties.

De Security-interface toont een compacte samenvatting en een accordion per check. De volledige PHP-inventaris blijft in het scanresultaat beschikbaar, maar `php_files` filtert standaard op `attention`/`problem`. Grote lijsten krijgen zoek-/categoriefilters en frontendpaginering van maximaal 100 DOM-items per geopende sectie. Remote inventarisatie zelf is backendmatig op 5.000 records plus een truncatiesignaal begrensd.

De Terminal toont vóór iedere shell een lokale tweestaps-gate. Passwordvelden staan alleen in het component, gaan nooit door Pinia, URL-state of localStorage en worden direct na submit/cancel geleegd. xterm.js en FitAddon worden pas na succesvolle dubbele backendverificatie opgebouwd; verlaten disposeert de terminal en scrollback. Remote bytes gaan als base64-event over IPC en daarna als `Uint8Array` naar xterm, zodat spaces, tabs, newlines, Unicode, ANSI, carriage returns en progressoutput niet door HTML-layout worden gewijzigd. Invoer wordt in volgorde naar de backend verstuurd. De frontend houdt alleen de eenvoudige actuele regel bij om WP-CLI-autocomplete te tonen; er wordt geen lokale terminalhistory persistent gemaakt.

De WP-CLI autocomplete-index wordt één keer uit de recursieve resource opgebouwd en vervolgens lokaal geraadpleegd. Alleen een eenvoudige nieuwe regel die met `wp` begint activeert suggesties en help. De JSON is nooit een uitvoerautorisatiebron.

## Backend

De Rust-backend is opgesplitst in domeinmodellen, SQLite-repositories, runtime-authenticatie, credentialopslag, SSH-adapter, managed commandcatalogus, interactieve terminalmanager, centrale error-logservice, checksum-bestandsservice, userservice, scan-/update-engine en maintenance-/core-orchestratie. De normale SSH-executor is een trait zodat managed flows mocks kunnen gebruiken.

### Managed Commands

- Ieder dynamisch pad, slug, ID, aantal dagen, versie en locale wordt vóór commandbouw gevalideerd.
- De uiteindelijke remote commandstring wordt alleen in Rust gebouwd en heeft per actie een timeout en outputlimiet.
- De afzonderlijke gecontroleerde WP-CLI argv-executor accepteert alleen `wp`, quote argumenten opnieuw en kent read-only/mutating/high-risk bevestigingsbeleid. Dit endpoint is niet de interactieve Terminal.
- Checksum-preview/delete gebruikt SFTP zonder vrij pad-IPC. Root/doel worden gecanonicaliseerd; symlinks, niet-reguliere bestanden, configuratie en `wp-content` worden geweigerd.
- Core repair/update en onderhoud stoppen vóór mutaties wanneer preflight of verplichte databasebackup faalt.

### Interactive SSH Terminal

`begin_terminal_reauthentication` autoriseert eerst de normale appsessie en verifieert het opnieuw ingevoerde app-wachtwoord tegen de bestaande Argon2id-hash. Een fout wachtwoord sluit alle terminals, wist challenges en trekt de appsessie in. Bij succes geeft `TerminalAccessManager` een random, alleen-in-memory challenge met een TTL van 60 seconden uit. De opgeslagen record bevat alleen token- en sessiehash, site-id en vervaltijd.

`open_terminal` vereist daarna dezelfde appsessie, dezelfde site, de single-use challenge en een handmatig SSH-wachtwoord. De challenge wordt bij de poging geconsumeerd. De SSH-adapter voert eerst de bestaande gepinde host-keycontrole uit, eist dat de server de gewone `password`-methode aanbiedt en roept uitsluitend `userauth_password` aan. De interactieve flow haalt geen opgeslagen credential op en valt nooit terug naar key-, agent- of managed authenticatie. Na succes bezit één named workerthread gedurende de sessie:

```text
één TCP/SSH-session → één channel_session → request xterm-256color PTY → shell()
                                         ↕ raw input/output events
                               resize / Ctrl+C / close controls
```

De shell ontvangt direct een veilig gequote `cd -- <wordpress-root>`. De directory is vooraf met dezelfde SSH-session gecontroleerd; een ontbrekend pad resulteert in een fout, niet in een stille fallback. Alle volgende bytes — inclusief arbitrary Linux commands en shelloperators — gaan naar hetzelfde channel. Daarom blijft de working directory behouden.

De manager genereert per verbinding een apart random TerminalAuthorization-token en bewaart daarvan alleen de hash, samen met de hash van de app-sessie en de site-id. Iedere input-, resize- en close-call moet terminal-id, app-sessie en TerminalAuthorization combineren. De manager houdt maximaal één actieve terminal per site in deze app-instantie. Sluiten, remote disconnect-cleanup, tab/site verlaten, site verwijderen, manual/idle lock, wachtwoordwijziging en procesafsluiting sluiten het kanaal en verwijderen het record. Oude terminal-id's of authorizations zijn niet herbruikbaar; opnieuw openen begint weer bij app-reauthenticatie.

Het app-wachtwoord en SSH-wachtwoord komen in Rust direct in `zeroize::Zeroizing<String>`. Het SSH-wachtwoord wordt meteen na de authenticatiepoging overschreven. Geen van beide komt in database-, audit- of errorlogvelden. Door eigenschappen van IPC, JavaScript en het OS is dit best-effort memory hygiene en geen garantie tegen een debugger of volledig gecompromitteerd systeem.

### Error reporting

Operationele fouten lopen door een centrale classifier naar vaste categorieën zoals `connection_timeout`, `ssh_authentication`, `ssh_host_key`, `ssh_channel`, `wp_cli`, `database`, `backup`, `update`, `parse` en `unknown`. `persist_error` maakt een `ERR-…`-ID, voegt de sitesnapshot/actie/duur/exitcode/retry-indicatie toe en bewaart alleen begrensde, geredigeerde details.

`error_logs` heeft indexes voor tijd, site en categorie. Iedere insert verwijdert records ouder dan 30 dagen en alles buiten de nieuwste 10.000. De UI vraagt gefilterde pagina's van maximaal 100 records op. Ruwe terminalcommandtekst en terminaloutput worden nooit onderdeel van dit record.

## Overige beslissingen

- Tauri 2 zonder lokale shell-plugin: alleen Rust beheert remote verbindingen.
- De applicatielogin gebruikt een Argon2id-hash in SQLite en één random sessie in backendgeheugen. Ieder niet-publiek Tauri-command autoriseert opnieuw; restart, idle lock, manual lock en wachtwoordwijziging wissen de sessie.
- SQLite gebruikt oplopende migrations, foreign keys, WAL en een busy timeout. UTC/RFC 3339 wordt lokaal in Vue geformatteerd.
- SSH-passwords/passphrases voor managed functies staan in de OS credential store; een keybestand blijft op zijn bestaande lokale pad. Het handmatig ingevoerde Terminalwachtwoord wordt uitsluitend voor de huidige password-authenticatiepoging gebruikt en niet opgeslagen.
- Host-key-pinning is verplicht vóór authenticatie. Een gewijzigde fingerprint blokkeert verbinding en terminal.
- PHP-bestanden worden alleen statisch gelezen, nooit uitgevoerd. Locatie-, naam- en gecombineerde inhoudsindicatoren bepalen een conservatieve score met concrete redenen; één los risicokeyword in normale plugin-/themecode is onvoldoende.
- Scanruns blijven in SQLite bewaard; de detailweergave kan de 50 recentste scans met checks en findings heropenen.
- Audit-events registreren authenticatie en expliciete destructieve GUI-acties zonder credentials of commandinhoud. Het foutenlog is een aparte operationele diagnosebron.
- Database-export gebruikt een backend-gegenereerde `/tmp/wpmm-XXXXXXXX.sql`, streamt via SFTP naar een gzipbestand buiten de documentroot en valideert remote cleanup opnieuw.
- Bulkscans starten maximaal 1–5 workers. Annuleren voorkomt nieuwe read-only scans; actieve scans mogen afronden en een sitespecifieke fout blokkeert andere sites niet.
