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

De Security-interface toont een compacte samenvatting en een accordion per check. De PHP-parser telt de volledige begrensde inventaris, maar bewaart en verstuurt standaard alleen opvallende `attention`/`problem`-resultaten. Grote lijsten krijgen een zoekdebounce van 200 ms, zoek-/categoriefilters en paginering van maximaal 100 DOM-items per geopende sectie. Remote inventarisatie zelf is backendmatig op 5.000 records plus een truncatiesignaal begrensd.

De Terminal toont vóór iedere shell een lokale tweestaps-gate. Passwordvelden staan alleen in het component, gaan nooit door Pinia, URL-state of localStorage en worden direct na submit/cancel geleegd. xterm.js en FitAddon worden pas na succesvolle dubbele backendverificatie opgebouwd; verlaten disposeert de terminal en scrollback. Remote bytes gaan als base64-event over IPC en worden per animatieframe tot één `Uint8Array` samengevoegd voordat xterm schrijft. Zo blijven terminalsemantiek en hoge outputdoorvoer behouden zonder een Vue-update per chunk. Invoer wordt in volgorde naar de backend verstuurd. De frontend houdt alleen de eenvoudige actuele regel bij om WP-CLI-autocomplete te tonen; er wordt geen lokale terminalhistory persistent gemaakt.

De WP-CLI autocomplete-index wordt één keer uit de recursieve resource opgebouwd en vervolgens lokaal geraadpleegd. Alleen een eenvoudige nieuwe regel die met `wp` begint activeert suggesties en help. De JSON is nooit een uitvoerautorisatiebron.

## Backend

De Rust-backend is opgesplitst in domeinmodellen, SQLite-repositories, runtime-authenticatie, credentialopslag, SSH-adapter, managed commandcatalogus, interactieve terminalmanager, centrale error-logservice, checksum-bestandsservice, userservice, scan-/update-engine en maintenance-/core-orchestratie. De normale SSH-executor is een trait zodat managed flows mocks kunnen gebruiken.

## Wordfence Intelligence V3

```text
Wordfence Intelligence V3 Production Feed
        ↓ Authorization: Bearer via geverifieerde HTTPS
Streaming download → backend-tempfile → JSON-validatie
        ↓                                  ↓ failure: oude dataset blijft actief
Atomaire SQLite-transactie → genormaliseerde actieve vulnerabilitydataset
        ↓
Index op provider + software type + exacte slug
        ↓
Lokale numerieke/prerelease version-range matcher
        ↓
Gecachete WordPress Core/plugin/theme-inventaris
        ↓
Typed Security Findings → uitzonderingen/severity
        ↓
Gecachete sitesamenvatting → Dashboard + Security UI
```

`WordfenceIntelligenceProvider` implementeert de providergrens voor een streaming complete-feeddownload. Alleen de V3 Production Feed is nu actief; de service- en opslaggrenzen laten een latere provider toe zonder multi-providerlogica in de huidige UI te introduceren. De API key komt uit de OS credential store en gaat alleen als Bearer-header naar `www.wordfence.com`. De request bevat geen site- of klantgegevens.

De verbindingstest en de eerste refresh delen één backend-download: een volledig ontvangen testfeed wordt maximaal 24 uur als staged bestand in de app-cache gehouden en door de databasejob atomair geclaimd. Nieuwe downloads worden naar een unieke tempfile gestreamd. `serde_json::Deserializer` leest via `BufReader` rechtstreeks de root-map; vulnerabilities, softwarekoppelingen, ranges en attributie worden binnen één transactie ingevoegd. Alleen na een complete geldige import wisselt `vulnerability_feed_state.active_dataset_id`; daarna verdwijnen records uit de vorige complete dataset coherent. Mislukking rolt de nieuwe transactie terug en laat de actieve cache ongemoeid.

`vulnerable_software` is geïndexeerd op provider, softwaretype en slug. Plugins en thema's matchen uitsluitend op exact type plus exacte slug. Core gebruikt daadwerkelijk als `type=core` aangeleverde records en verzint geen provider-slug. De matcher vergelijkt numerieke dotted versies en bekende prereleasestadia, respecteert `*` plus inclusieve/exclusieve grenzen en maakt bij onbekende notatie een typed vergelijkingsmelding in plaats van een veilige of kwetsbare uitkomst te gokken. Een normale sitescan downloadt nooit een feed.

Feedrefresh is een onafhankelijke named worker met korte jobstate-locks en fases voor download, validatie, verwerking en lokale database-update. Bij appstart start alleen een ontbrekende of minstens 24 uur oude feed op de achtergrond; een lokale 30-minutencooldown en server-`429` verhinderen retrylussen. Na succesvolle import worden alle aanwezige `software_inventory`-snapshots lokaal opnieuw gematcht, zonder SSH. De tabel `site_vulnerability_state` bewaart de actuele afgeleide check en overschrijft alleen de nieuwste Security-weergave; historische scanrecords en finding-snapshots blijven intact. `sites` bevat compacte severitytellingen voor het Dashboard, zodat daar geen feedjoin of grote reactieve array nodig is. Een inventorysnapshot ouder dan zeven dagen wordt als mogelijk verouderd gemarkeerd.

## Site snapshots and baseline foundation

```text
SiteScanResult
      ↓
SnapshotBuilder
      ↓
Normalized SiteSnapshot (schema v1 + section completeness)
      ↓
SnapshotRepository
      ↓
Previous/Baseline Snapshot
      ↓
SnapshotDiffEngine
      ↓
SnapshotChange[]
      ↓
Transactional persistence → UI / History / future features
```

Het snapshotdomein gebruikt gedeelde typed Rust-modellen en overeenkomstige TypeScript-contracten voor Core, plugins, thema's, users, een expliciete configuratie-allowlist, cronmetadata en begrensde relevante bestandsmetadata. Iedere sectie draagt afzonderlijk `complete`, `failed` of `not_collected`. Alleen `complete` aan beide kanten is vergelijkbaar; een ontbrekende partial sectie kan daardoor nooit als massale verwijdering worden geïnterpreteerd. De eerste geschikte scan wordt zonder changes als expliciete baseline vastgelegd. Een baseline is een vertrouwd vergelijkingspunt, terwijl `previous_snapshot_id` de chronologisch vorige geschikte controle aanduidt.

De opslag is bewust hybride. Relationele `site_snapshots`-metadata en geïndexeerde `snapshot_diffs`, sectiestatussen en change records ondersteunen snelle historie-, categorie- en unseen-queries. De complete genormaliseerde payload blijft één versioned backend-object in een BLOB met een expliciete encoding; v1 gebruikt UTF-8 JSON en reserveert een gzip-encoding zonder compressie nu verplicht te maken. Hiermee hoeven snapshot-entiteiten niet over veel tabellen te worden herhaald, terwijl schema-upgrades en deterministisch herbouwen van diffs mogelijk blijven. `site_snapshot_state` bevat uitsluitend pointers en compacte UI-samenvattingen. De standaardretentie wordt honderd snapshots per site; een expliciete baseline en gekoppelde pre/post-maintenance snapshots zijn beschermd.

Vulnerability intelligence hoort niet in de websitebaseline: een feedwijziging verandert de website zelf niet. De opgeslagen Core-, plugin- en themaversies kunnen wel opnieuw lokaal tegen Wordfence worden gematcht. Snapshot changes blijven daarnaast een ander concept dan security findings en uitzonderingen. Toekomstige gebruikersbewaking, configuration drift, plugin hygiene, rapportage en prioritering bouwen op dezelfde `SnapshotDiffEngine` in plaats van eigen vergelijkingslogica.

## Background Jobs and Responsiveness

Een normale site- of bulkscan loopt niet meer binnen de levensduur van een lang Tauri-request:

```text
Vue/Pinia → start_site_scan → ScanJobManager → begrensde blocking worker
                 ↓ direct       ↓ korte locks        ↓ één SSH-session, sequentiële channels
              jobstate ← scan-job-updated events ← echte stapstatus/timings
                                                      ↓
                                         SQLite transaction → gerichte eindrefresh
```

`start_site_scan` valideert de appsessie en site, maakt of hergebruikt een job en retourneert daarna direct. De blocking `ssh2`, remote commands, parsing, HTTP-check en persistence draaien op een named workerthread. Alle Tauri-commands gebruiken bovendien Tauri's asynchrone dispatchcontext, zodat ook incidentele verbindingstests, updates, onderhoud, credentialstore- en SQLite-acties niet rechtstreeks op de WebView/UI-eventloop draaien. De oude synchrone `scan_site`- en `scan_all_sites`-IPC-endpoints zijn verwijderd. Jobstate is backend-owned en leeft daarom door wanneer een Vue-route unmount; `list_scan_jobs` herstelt de actuele state bij terugkeer. Events bevatten één immutable typed jobsnapshot per echte stapovergang, niet per bestand of voortgangstick.

Per site bestaat maximaal één actieve scan. `ScanJobManager` bewaart korte mutexsecties rond statewijzigingen en houdt nooit een lock vast tijdens SSH-, HTTP- of database-I/O. Een cancellation-token wordt vóór iedere nieuwe stap en tijdens wachten op de globale gate gecontroleerd. Een reeds lopend niet-muterend SSH-command rondt veilig af; daarna wordt de job `cancelled` en wordt de RAII-concurrencypermit altijd vrijgegeven.

De globale, instelbare limiet is 1–5 sites tegelijk (standaard 4). Binnen één site is de remote concurrency bewust 1: één geauthenticeerde libssh2-session wordt hergebruikt voor opeenvolgende commandchannels. Daarmee daalt een gewone scan zonder trustregistraties van circa 16 volledige SSH-handshakes/authenticaties naar één, zonder een `Session` onveilig tussen gelijktijdige commands te delen of de server met parallelle filesystemscans te belasten. Heeft een site vertrouwde bestanden, dan volgt bewust één extra geauthenticeerde SFTP-sessie waarin alle actieve fingerprints gebundeld en streaming worden gecontroleerd. Bulkscans gebruiken dezelfde jobs, gate en limiet als losse scans.

De detailroute toont eerst cached SQLite-data. Updates worden daaruit weergegeven en alleen op de Updates-tab live vernieuwd; WordPress-gebruikers worden pas op de Gebruikers-tab opgehaald. Het Dashboard gebruikt uitsluitend de lokale sitesamenvatting. Pinia bewaart scanjobs centraal en dedupliceert gelijktijdige site-list-requests. Na completion volgt één gecontroleerde refresh; tussenliggende events vervangen alleen de betrokken jobstate.

Elke scan rapporteert afzonderlijke timings voor connectie, WordPress-detectie/informatie, checksum, users, PHP/uploads, modified files, permissions, database, core/plugin/theme-updates, HTTP en persistence. Parserduur wordt zonder payload of secrets apart naar de developmentlog geschreven. De TypeScript IPC-laag logt in development alleen commandonaam, totale IPC-duur, responsgrootte en frontend-verwerkingstijd en waarschuwt boven 1 MiB. De detailpagina toont voor een afgeronde scan development-only de timings per stap.

SQLite blijft bij de duurzame defaults, met `foreign_keys=ON`, WAL en een busy timeout van 5 seconden. WAL past hier omdat achtergrondscans kunnen schrijven terwijl de UI cached data leest. Scan en finding-inserts gebruiken één transactie plus hergebruikte prepared statements. De historiequery gebruikt drie gebonden batchqueries in plaats van queries per scan en per check. Extra indexes dekken scan-checks, findings, maintenance-stappen en cached updates; er is bewust geen `synchronous=OFF`-achtige durabilityverlaging.

### Finding policy, uitzonderingen en trust

De effectieve securitystatus is volledig backend-owned en doorloopt één centrale policyflow:

```text
Raw scan finding
        ↓
Severity policy
        ↓
Site exception (exact: site + check + type + target)
        ↓
Trusted file fingerprint (SHA-256 + file type)
        ↓
Effective FindingDisposition
        ↓
Site status en security summary
        ↓
Vue-filters en beheeracties
```

`finding_exceptions` en `trusted_files` zijn sitegebonden SQLite-records met samengestelde lookupindexes. Een scan laadt beide verzamelingen eenmaal; matching doet geen query per finding. `FindingDisposition` onderscheidt actief, genegeerd, vertrouwd, verlopen uitzondering, gewijzigd vertrouwd bestand en verdwenen vertrouwd bestand. `FindingSeverity` bevat info, attention, warning en critical, naast de bestaande problemwaarde voor backwards compatibility. Alleen relevante actieve warning/attention-findings maken de site `attention`; actieve critical/problem-findings maken haar `problem`. Info, ignored, gelijk gebleven trusted en verdwenen trusted records houden de site gezond. Connectiefouten blijven via de bestaande aparte flow `unreachable`.

Een ignore/trust-mutatie haalt de finding uitsluitend uit de nieuwste scan van dezelfde site, berekent target en type backend-side en past de policy direct opnieuw op dat scanresultaat toe. De UI stuurt dus geen vrij exceptiontarget of hash in. Hashing gebruikt SFTP, 64-KB-blokken, canonieke containment, regular-file/typecontrole en metadata vóór/open/na de read. De centrale beheerpagina leest dezelfde typed records; verwijderen deactiveert records zodat oude auditcontext behouden blijft.

De reproduceerbare vóór/na-metingen, performancebudgetten en beperkingen staan in [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

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
- Scanruns blijven in SQLite bewaard; de detailweergave kan de 20 recentste scans met checks en findings heropenen.
- Audit-events registreren authenticatie en expliciete destructieve GUI-acties zonder credentials of commandinhoud. Het foutenlog is een aparte operationele diagnosebron.
- Database-export gebruikt een backend-gegenereerde `/tmp/wpmm-XXXXXXXX.sql`, streamt via SFTP naar een gzipbestand buiten de documentroot en valideert remote cleanup opnieuw.
- Site- en bulkscans gebruiken dezelfde globale queue/gate met maximaal 1–5 actieve sites. Annuleren voorkomt nieuwe stappen; het huidige read-only command mag veilig afronden en een sitespecifieke fout blokkeert andere sites niet.
