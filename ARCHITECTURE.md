# Architectuur

Het geïsoleerde filemanagerfundament en de hergebruikspunten voor volgende fases staan in [docs/FILEMANAGER.md](docs/FILEMANAGER.md). Fase 1 biedt uitsluitend lokale websitecontext en een placeholderpagina; er zijn nog geen remote filemanageracties.

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

De globale toetsenbordafhandeling is allowlist-gebaseerd: alleen exact `Ctrl+L` activeert de app-lock. Op Windows start het hoofdvenster WebView2 bovendien met `HardwareMediaKeyHandling` uitgeschakeld, naast de door Wry standaard uitgeschakelde Edge-componenten. Omdat WebView2 low-level keyboardhooks van keypadsoftware alsnog kan passeren wanneer het venster focus heeft, herkent de capture-handler uitsluitend de gestandaardiseerde media-keynamen, bijbehorende fysieke codes en Windows virtual-keycodes. Alleen echte, vertrouwde Play/Pauze-, Volgende-, Vorige-, Stop- en volume-events krijgen `preventDefault()` en gaan zonder appsessietoken naar een strikt gevalideerde native allowlist. De backend zet ze om in `WM_APPCOMMAND` voor Windows; willekeurige toetsen of opdrachten zijn niet mogelijk. Alle onbekende events blijven onaangeroerd.

De Security-interface toont een compacte samenvatting en een accordion per check. De PHP-parser telt de volledige begrensde inventaris, maar bewaart en verstuurt standaard alleen opvallende `attention`/`problem`-resultaten. Grote lijsten krijgen een zoekdebounce van 200 ms, zoek-/categoriefilters en paginering van maximaal 100 DOM-items per geopende sectie. Remote inventarisatie zelf is backendmatig op 5.000 records plus een truncatiesignaal begrensd.

De Terminal toont vóór iedere shell een lokale tweestaps-gate. Passwordvelden staan alleen in het component, gaan nooit door Pinia, URL-state of localStorage en worden direct na submit/cancel geleegd. xterm.js en FitAddon worden pas na succesvolle dubbele backendverificatie opgebouwd; verlaten disposeert de terminal en scrollback. Remote bytes gaan als base64-event over IPC en worden per animatieframe tot één `Uint8Array` samengevoegd voordat xterm schrijft. Zo blijven terminalsemantiek en hoge outputdoorvoer behouden zonder een Vue-update per chunk. Invoer wordt in volgorde naar de backend verstuurd. De frontend houdt alleen de eenvoudige actuele regel bij om WP-CLI-autocomplete te tonen; er wordt geen lokale terminalhistory persistent gemaakt.

De WP-CLI autocomplete-index wordt één keer uit de recursieve resource opgebouwd en vervolgens lokaal geraadpleegd. Alleen een eenvoudige nieuwe regel die met `wp` begint activeert suggesties en help. De JSON is nooit een uitvoerautorisatiebron.

De bestandspreview ontvangt uitsluitend een backend-opgebouwd `FilePreview` voor een actuele toegestane finding. Tekst gebruikt een begrensde editorweergave met regelnummers en geregistreerde highlight.js-talen; PHP gebruikt de templategrammar zodat PHP, HTML, CSS, JavaScript en JSON binnen één bestand gescheiden blijven. Markdown-rendering schakelt raw HTML uit en opent alleen HTTP(S)-links via de gevalideerde backendopener. SVG-rendering verwijdert actieve/externe inhoud voordat een data-URL ontstaat. Binaire afbeeldingen krijgen geen kunstmatige syntax highlighting: Raw gebruikt een begrensde byte-inspector en Preview uitsluitend een allowlist van lokale image-MIME-types. Fullscreen en Markdownstandaard zijn lokale persistente app-instellingen.

## Backend

De Rust-backend is opgesplitst in domeinmodellen, SQLite-repositories, runtime-authenticatie, credentialopslag, SSH-adapter, managed commandcatalogus, interactieve terminalmanager, centrale error-logservice, checksum-bestandsservice, userservice, scan-/update-engine en maintenance-/core-orchestratie. De normale SSH-executor is een trait zodat managed flows mocks kunnen gebruiken.

### Gecontroleerd databasebeheer

`database_cleanup` gebruikt een gesloten enum met exact zes ondersteunde targets. Tabelnamen komen nooit als vrije SQL-input uit de UI. De preview en uitvoering delen dezelfde backendmetadata en tellen de primaire plus alle gerelateerde effecten rechtstreeks in SQLite. `auth_config`, `app_settings`, `schema_migrations`, de globale Wordfence-feedtabellen en overige interne tabellen zijn niet bereikbaar via deze beheerfunctie.

Iedere uitvoering valideert opnieuw de targetspecifieke bevestiging. `sites` vereist de letterlijke frase `VERWIJDEREN`; de overige acties vereisen na hun concrete UI-dialoog de exacte backend-owned tabelidentiteit. Conflicterende actieve scan- en Wordfence-jobs blokkeren relevante acties. Sitescleanup sluit bovendien alle sitegebonden terminals en trekt openstaande terminalchallenges in voordat de data verdwijnt.

De backend telt de impact en voert alle SQLite-wijzigingen binnen dezelfde transactie uit. Cascades verwijderen onderliggende scan-, snapshot-, maintenance- en policyrecords; aanvullende `SET NULL`-effecten en samenvattingsresets worden expliciet getoond. Vóór commit moet de gekozen hoofdtabel leeg zijn en `PRAGMA foreign_key_check` geen overtreding opleveren. Een fout bevat de mislukte fase en laat de transactie terugrollen. Na commit wordt een WAL-checkpoint plus `VACUUM` geprobeerd. OS-credentialverwijdering kan niet onderdeel zijn van een SQLite-transactie en gebeurt daarom direct erna; een mislukte credential- of compactiestap levert een zichtbare `completed_with_warnings`-uitkomst op zonder een succesvolle databaseactie verkeerd als rollback te presenteren.

### Geneste WordPress-installaties

Een geslaagde verbindingstest voert na WordPress- en databasevalidatie een begrensde, read-only inventarisatie uit van directe niet-standaardmappen in de WordPress-root. De UI classificeert niets automatisch: iedere map blijft onbeslist totdat de gebruiker haar als subdomein, subdirectory of geen aparte site markeert. Voor iedere gekozen installatie wordt de volledige verbinding opnieuw getest; zowel gekozen subdomeinen als subdirectories leveren vervolgens hun volgende maplaag op. De root en alle gecontroleerde children worden parent-vóór-child opgeslagen.

De detailpagina kan deze inventarisatie later opnieuw uitvoeren voor iedere opgeslagen site, inclusief een bestaande child. Zij gebruikt het site-id van de oorspronkelijke opgeslagen site alleen om backend-side diens credential op te halen; secrets worden niet opnieuw naar Vue gestuurd. Bekende installaties op dezelfde SSH-host, poort en genormaliseerde root worden per niveau uit de voorstellen gefilterd. Iedere gekozen kandidaat wordt opnieuw volledig getest en kan direct een volgende laag opleveren. Bij opslaan wordt de geordende boom parent-vóór-child verwerkt, zodat iedere diepere installatie naar de zojuist opgeslagen directe parent verwijst.

`sites.parent_site_id`, `relation_type` en `parent_directory` vormen de duurzame relatie. De commandlaag vereist een bestaande parent, dezelfde SSH-host/poort/gebruiker/authenticatiemethode/key, de gepinde hostidentiteit van de parent en exact `<parent-root>/<directe-map>`. Cirkelvorming, incomplete relaties en duplicaten op host+poort+WordPress-pad of genormaliseerde URL worden geweigerd. Het wijzigen van verbinding/root van een parent met children wordt geblokkeerd om stille relatiebreuk te voorkomen; verwijderen van een parent maakt children zelfstandig en wist hun relatiemetadata.

Een achteraf aangemaakte child zonder nieuw aangeleverd secret erft uitsluitend de opaque credentialreferentie van de parent. De secretbytes blijven in de OS credential store en komen niet via IPC. Omdat zo'n referentie gedeeld kan zijn, verwijdert siteverwijdering de credential pas wanneer geen andere site die referentie nog gebruikt.

Voor iedere normale, onderhouds- en core-scan haalt de backend de bevestigde directe childmappen van de parent uit SQLite. De officiële WP-CLI-checksum draait zonder `--include-root`, zodat WP-CLI niet recursief alle willekeurige rootmappen betreedt. Een afzonderlijke begrensde rootbestandscontrole slaat `wp-content`, de coremappen en bevestigde directe childmappen over voordat een directory wordt gelezen; overige niet-standaard rootbestanden blijven `unexpected` findings. Backendfiltering van onverwachte childpaden blijft als defense-in-depth aanwezig. Mappen die als geen aparte website zijn aangemerkt krijgen geen opgeslagen relatie en dus geen uitzondering. Een childscan gebruikt de eigen opgeslagen WordPress-root en wordt hierdoor niet beperkt.

### Databaseback-ups

Onderhoud, core-update en core-reparatie gebruiken dezelfde `create_database_backup`-service. De catalogus maakt met `wp db export` een backend-benoemd `/tmp/wpmm-XXXXXXXX.sql`-bestand buiten de documentroot. De SSH-adapter streamt maximaal 20 GiB brondata via SFTP naar een lokale gzipencoder onder `<app-data>/backups/<site-id>/<UTC>-<uuid>.sql.gz`; de export wordt niet volledig in geheugen geladen. Daarna verwijdert een afzonderlijke streng gevalideerde catalogusactie de tijdelijke serverkopie. Download en cleanup moeten beide slagen voordat de mutatie doorgaat.

Na succes worden absoluut lokaal pad, gecomprimeerde grootte en SHA-256 samen met de onderhoudsrun in `backup_records` opgeslagen. De bytes staan niet in SQLite. Er bestaat geen backuprepository voor listing, retentie, openen of restore: historie leest alleen het nieuwste geregistreerde pad per run, lokale bestanden worden niet automatisch verwijderd en siteverwijdering ruimt de fysieke map niet op. Zie [docs/BACKUPS.md](docs/BACKUPS.md) voor de gebruikersgerichte werkwijze.

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

## Site snapshots en baselines

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

`SnapshotBuilder` ontvangt de al getypeerde sectieresultaten uit de background scan; Core, plugins, thema's, users en configuratie worden niet opnieuw via SSH opgehaald. Alleen cron had een aanvullende begrensde read-only verzameling nodig. De builder normaliseert slugs, rollen, paden, booleans en UTC-tijden, weigert dubbele stabiele identiteiten voor unieke entiteiten en gebruikt uitsluitend een expliciete configuratie-allowlist. WordPress mag dezelfde logische croninstantie op meerdere timestamps bewaren: gelijke hook-, argument- en schedulevarianten worden daarom samengevoegd met de vroegste `next_run_at`, terwijl verschillende schedules een deterministische secundaire identiteit krijgen. Arbitrary cronargumenten verlaten de backend niet: alleen een SHA-256-fingerprint kan onderdeel van de stabiele cronidentiteit worden.

Iedere sectie draagt afzonderlijk `complete`, `failed` of `not_collected`. `SnapshotDiffEngine` vergelijkt een sectie alleen wanneer beide kanten `complete` zijn; een mislukte user- of cronverzameling kan daardoor nooit als massale verwijdering verschijnen. Plugin- en themaslugs, WordPress user-id's, toegestane configkeys, genormaliseerde cronidentiteiten en site-relatieve bestandspaden vormen de stabiele entity keys. De centrale diffpolicy negeert volatiele waarden zoals de normale volgende cronruntijd, kent specifieke change types en severity toe en sorteert deterministisch. Frontendmodules tonen deze uitkomst en implementeren geen eigen vergelijkingsregels.

De eerste geschikte scan wordt zonder changes als expliciete baseline vastgelegd. `previous_snapshot_id` wijst naar de meest recente geschikte voorganger en is de standaardvergelijking; de losse baselinepointer is een expliciet vertrouwd referentiepunt. Een gebruiker kan de huidige snapshot als nieuwe baseline markeren zonder historie te verwijderen. De repository kan daarnaast willekeurige snapshot-id's backend-side vergelijken. Alleen de standaarddiff na scan/onderhoud wordt relationeel gecachet; een handmatige vergelijking vervuilt de actuele change-telling niet.

De opslag is bewust hybride. Relationele `site_snapshots`-metadata en geïndexeerde `snapshot_diffs`, sectiestatussen en `snapshot_changes` ondersteunen snelle historie-, categorie-, severity- en unseen-queries. De complete genormaliseerde payload blijft één versioned backend-object in een BLOB. Kleine payloads gebruiken UTF-8 JSON; vanaf 4 KiB gebruikt de repository gzip wanneer dat daadwerkelijk kleiner is. Zowel opgeslagen als uitgepakte payload is begrensd op 16 MiB. Metadata-, dashboard- en historiequeries decoderen de payload niet. `site_snapshot_state` bevat uitsluitend pointers en compacte UI-samenvattingen.

Snapshot en standaarddiff worden binnen dezelfde SQLite-transactie opgeslagen, waarna state en retention coherent worden bijgewerkt. Migratie `0013_site_snapshots.sql` maakt het schema en de foreign keys; `0014_snapshot_performance.sql` voegt indexen voor diff- en belangrijke-changelezingen toe. De standaardretentie is 100 snapshots per site en verwijdert in één SQL-operatie de oudste normale snapshots met cascade-cleanup. Een expliciete baseline en gekoppelde pre-/post-maintenance snapshots zijn beschermd; wanneer alleen beschermde records overblijven mag het totaal daarom boven de zachte grens uitkomen.

Pre- en post-maintenance snapshots dragen `maintenance_run_id` en produceren changes met origin `maintenance`. Het Dashboard leest één compacte batch met telling, ongezien aantal, laatste tijd en hoogst belangrijke ongeziene samenvatting. De detail-UI haalt alleen metadata en relationele changes op; de volledige payload gaat niet via IPC naar Vue.

Vulnerability intelligence hoort niet in de websitebaseline: een feedwijziging verandert de website zelf niet. De opgeslagen Core-, plugin- en themaversies kunnen wel opnieuw lokaal tegen Wordfence worden gematcht. Snapshot changes blijven daarnaast een ander concept dan security findings, acknowledgements en uitzonderingen. Toekomstige gebruikersbewaking, configuration drift, plugin hygiene, rapportage en prioritering bouwen op dezelfde `SnapshotDiffEngine` in plaats van eigen vergelijkingslogica.

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

`finding_exceptions` en `trusted_files` zijn sitegebonden SQLite-records met samengestelde lookupindexes. Een scan laadt beide verzamelingen eenmaal; matching doet geen query per finding. `FindingDisposition` onderscheidt actief, genegeerd, vertrouwd, verlopen uitzondering, gewijzigd vertrouwd bestand en verdwenen vertrouwd bestand. `FindingSeverity` bevat info, attention, warning en critical, naast de bestaande problemwaarde voor backwards compatibility. Alleen relevante actieve warning/attention-findings maken de site `attention`; actieve critical/problem-findings maken haar `problem`. Info, ignored, gelijk gebleven trusted en verdwenen trusted records houden de site gezond. Connectiefouten blijven via de bestaande aparte flow `unreachable`. De UTC-verlooptijd wordt tijdens iedere policytoepassing opnieuw beoordeeld: een verstreken tijdelijke uitzondering krijgt `expired_exception`, telt weer als actief en beïnvloedt zonder handmatige tussenstap opnieuw check- en sitestatus.

De `modified_files`-sectie is inventaris: de centrale severitypolicy zet recencyfindings altijd op `info`, ongeacht pad of aantal. De Vue-weergave correleert zo'n regel alleen voor presentatie met de zwaarste actieve finding voor exact hetzelfde genormaliseerde pad uit een andere controle en sorteert critical/problem, warning/attention en gewijzigde trust vóór informatieve regels. Alleen de oorspronkelijke backendfinding uit die andere controle beïnvloedt de persistente check- en sitestatus.

Een ignore/trust-mutatie haalt de finding uitsluitend uit de nieuwste scan van dezelfde site, berekent target en type backend-side en past de policy direct opnieuw op dat scanresultaat toe. De UI stuurt dus geen vrij exceptiontarget of hash in. Hashing gebruikt SFTP, 64-KB-blokken, canonieke containment, regular-file/typecontrole en metadata vóór/open/na de read. De centrale beheerpagina leest dezelfde typed records. Individuele en bulkintrekking gebruiken dezelfde backendvalidatie; actuele uitzonderingen en trustregistraties worden atomair gedeactiveerd zodat hun auditcontext behouden blijft. De afzonderlijke cleanup voor verlopen uitzonderingen accepteert uitsluitend nog actieve records met een aantoonbaar verstreken RFC 3339-eindtijd en verwijdert die registraties atomair. Daarna wordt de policy eenmaal per betrokken site opnieuw toegepast, zonder de finding te onderdrukken.

De reproduceerbare vóór/na-metingen, performancebudgetten en beperkingen staan in [docs/PERFORMANCE.md](docs/PERFORMANCE.md).

### Managed Commands

- Ieder dynamisch pad, slug, ID, aantal dagen, versie en locale wordt vóór commandbouw gevalideerd.
- De uiteindelijke remote commandstring wordt alleen in Rust gebouwd en heeft per actie een timeout en outputlimiet.
- De afzonderlijke gecontroleerde WP-CLI argv-executor accepteert alleen `wp`, quote argumenten opnieuw en kent read-only/mutating/high-risk bevestigingsbeleid. Dit endpoint is niet de interactieve Terminal.
- Bestandspreview en checksum-delete gebruiken SFTP zonder vrij pad-IPC. Preview is beperkt tot actuele bestaande `modified`/`unexpected` core-, PHP-in-uploads- en modified-files-findings; `missing` en `scan_error` hebben geen bestand om te openen. Delete blijft uitsluitend voor actuele `unexpected` corebestanden. Root/doel worden gecanonicaliseerd en symlinks en niet-reguliere bestanden worden geweigerd; delete weigert daarnaast configuratie en heel `wp-content`.
- Core repair/update en onderhoud stoppen vóór mutaties wanneer een kritieke preflight of verplichte databasebackup faalt. Een betrouwbaar gemeten tekort aan schijfruimte is kritisch; wanneer `df`, PHP `disk_free_space()` en de WP-CLI-fallback allemaal niet beschikbaar zijn, blijft de preflight met een expliciete waarschuwing doorgaan.

### Interactive SSH Terminal

`begin_terminal_reauthentication` autoriseert eerst de normale appsessie en verifieert het opnieuw ingevoerde app-wachtwoord tegen de bestaande Argon2id-hash. Een fout wachtwoord sluit alle terminals, wist challenges en trekt de appsessie in. Bij succes geeft `TerminalAccessManager` een random, alleen-in-memory challenge met een TTL van 60 seconden uit. De opgeslagen record bevat alleen token- en sessiehash, site-id en vervaltijd.

`open_terminal` vereist daarna dezelfde appsessie, dezelfde site, de single-use challenge en een handmatig SSH-wachtwoord. De challenge wordt bij de poging geconsumeerd. De SSH-adapter voert eerst de bestaande gepinde host-keycontrole uit, eist dat de server de gewone `password`-methode aanbiedt en roept uitsluitend `userauth_password` aan. De interactieve flow haalt geen opgeslagen credential op en valt nooit terug naar key-, agent- of managed authenticatie. Na succes bezit één named workerthread gedurende de sessie:

```text
één TCP/SSH-session → één channel_session → request xterm-256color PTY → shell()
                                         ↕ raw input/output events
                               resize / Ctrl+C / close controls
```

De shell ontvangt direct een veilig gequote `cd -- <wordpress-root>`. De directory is vooraf met dezelfde SSH-session gecontroleerd; een ontbrekend pad resulteert in een fout, niet in een stille fallback. Alle volgende bytes — inclusief arbitrary Linux commands en shelloperators — gaan naar hetzelfde channel. Daarom blijft de working directory behouden.

De manager genereert per verbinding een apart random TerminalAuthorization-token en bewaart daarvan alleen de hash, samen met de hash van de app-sessie en de site-id. Iedere input-, resize- en close-call moet terminal-id, app-sessie en TerminalAuthorization combineren. De manager houdt maximaal één actieve terminal per site in deze app-instantie. Sluiten, een normale remote EOF zoals `exit`, remote disconnect-cleanup, tab/site verlaten, site verwijderen, manual/idle lock, wachtwoordwijziging en procesafsluiting sluiten het kanaal en verwijderen het record. De frontend verwerkt zo'n remote afsluiting via hetzelfde sluit- en resetpad als de knop **Sluiten**. Oude terminal-id's of authorizations zijn niet herbruikbaar; opnieuw openen begint weer bij app-reauthenticatie.

Het app-wachtwoord en SSH-wachtwoord komen in Rust direct in `zeroize::Zeroizing<String>`. Het SSH-wachtwoord wordt meteen na de authenticatiepoging overschreven. Geen van beide komt in database-, audit- of errorlogvelden. Door eigenschappen van IPC, JavaScript en het OS is dit best-effort memory hygiene en geen garantie tegen een debugger of volledig gecompromitteerd systeem.

### Error reporting

Operationele fouten lopen door een centrale classifier naar vaste categorieën zoals `connection_timeout`, `ssh_authentication`, `ssh_host_key`, `ssh_channel`, `wp_cli`, `database`, `backup`, `update`, `parse` en `unknown`. `persist_error` maakt een `ERR-…`-ID, voegt de sitesnapshot/actie/duur/exitcode/retry-indicatie toe en bewaart alleen begrensde, geredigeerde details.

`error_logs` heeft indexes voor tijd, site en categorie. Iedere insert verwijdert records ouder dan 30 dagen en alles buiten de nieuwste 10.000. De UI vraagt gefilterde pagina's van maximaal 100 records op. Gericht verwijderen accepteert 1–1.000 unieke, strikt gevormde `ERR-`-ID's en voert de volledige selectie in één SQLite-transactie uit. Ruwe terminalcommandtekst en terminaloutput worden nooit onderdeel van dit record.

## Overige beslissingen

- Tauri 2 zonder lokale shell-plugin: alleen Rust beheert remote verbindingen.
- De applicatielogin gebruikt een Argon2id-hash in SQLite en één random sessie in backendgeheugen. Ieder niet-publiek Tauri-command autoriseert opnieuw; restart, idle lock, manual lock en wachtwoordwijziging wissen de sessie.
- SQLite gebruikt oplopende migrations, foreign keys, WAL en een busy timeout. UTC/RFC 3339 wordt lokaal in Vue geformatteerd.
- SSH-passwords/passphrases voor managed functies staan in de OS credential store; een keybestand blijft op zijn bestaande lokale pad. Het handmatig ingevoerde Terminalwachtwoord wordt uitsluitend voor de huidige password-authenticatiepoging gebruikt en niet opgeslagen.
- Host-key-pinning is verplicht vóór authenticatie. Een gewijzigde fingerprint blokkeert verbinding en terminal.
- PHP-bestanden worden alleen statisch gelezen, nooit uitgevoerd. Locatie-, naam- en gecombineerde inhoudsindicatoren bepalen een conservatieve score met concrete redenen; één los risicokeyword in normale plugin-/themecode is onvoldoende.
- Scanruns blijven in SQLite bewaard; de detailweergave kan de 20 recentste scans met checks en findings heropenen.
- Audit-events registreren authenticatie en de security- en beheeracties waarvoor een auditcategorie is gedefinieerd, zonder credentials of commandinhoud. Het foutenlog is een aparte operationele diagnosebron en kan daarom zelf gericht worden opgeschoond.
- Database-export gebruikt een backend-gegenereerde `/tmp/wpmm-XXXXXXXX.sql`, streamt via SFTP naar een gzipbestand buiten de documentroot en valideert remote cleanup opnieuw.
- Site- en bulkscans gebruiken dezelfde globale queue/gate met maximaal 1–5 actieve sites. Annuleren voorkomt nieuwe stappen; het huidige read-only command mag veilig afronden en een sitespecifieke fout blokkeert andere sites niet.
