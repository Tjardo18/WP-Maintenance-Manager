# Remote command catalog

Alle remote uitvoering loopt via Rust. Voorgedefinieerde beheeracties gebruiken onderstaande catalogus; de afzonderlijke interactieve Terminal gebruikt bewust een vrije SSH-PTY/shell. Algemene cataloguslimieten voor managed acties: pad maximaal 4096 bytes, slugs maximaal 200 ASCII-tekens, dagen 1–365 en scanresultaten standaard maximaal 5000 records.

| Actie | Doel | Muterend | Parameters/validatie | Output | Standaardtimeout | Risico |
|---|---|---:|---|---|---:|---|
| TestWordPressPath | Controleren of het ingestelde pad bestaat | Nee | absoluut POSIX-pad | exitstatus | 20 s | laag |
| DetectWordPress | Installatie en database detecteren | Nee | absoluut POSIX-pad | exitstatus | 60 s | laag |
| GetWordPressVersion | Coreversie ophalen | Nee | pad | tekst | 60 s | laag |
| GetPhpVersion | PHP-versie ophalen | Nee | geen | tekst | 20 s | laag |
| GetWpCliVersion | WP-CLI-versie ophalen | Nee | geen | tekst | 20 s | laag |
| GetSiteUrl | Canonieke WordPress-site-URL ophalen | Nee | pad | tekst | 60 s | laag |
| ListUnexpectedRootDirectories | Directe niet-standaardmappen in de WordPress-root inventariseren | Nee | absoluut gevalideerd rootpad; vaste uitsluiting van WordPress-coremappen | gesorteerde JSON met maximaal 200 gevalideerde mapnamen en truncatievlag | 60 s | tijdens verbindingstest en latere herdetectie; remote namen blijven onbetrouwbaar en worden opnieuw backend-side gevalideerd |
| GetCoreLocale | Actieve WordPress-locale bepalen | Nee | vaste PHP-expressie | locale | 60 s | geen userinput |
| CheckDiskSpace | Vrije ruimte op filesystem van WordPress-root | Nee | gevalideerd rootpad | `df`-KB, PHP-bytes of expliciete unavailable-status | 60 s | probeert `df`, daarna PHP `disk_free_space()` en WP-CLI; gemeten tekort blokkeert, volledig ontbreken geeft een niet-blokkerende waarschuwing |
| VerifyCoreChecksums | Officiële WordPress-corechecksums | Nee | expliciet pad, `core is-installed`; bewust zonder `--include-root` | JSON + exitstatus | 120 s | willekeurige rootmappen worden niet recursief doorlopen; alleen bij werkelijk incompatibele JSON-output volgt de plain fallback |
| VerifyCoreChecksumsPlain | Compatibiliteitsfallback voor oudere WP-CLI | Nee | hetzelfde gevalideerde pad; bewust zonder `--include-root` | vaste Warning/Success/Error-regels + exitstatus | 120 s | alleen bij incompatibele/onleesbare gestructureerde uitvoer; echte uitvoerfouten worden niet blind opnieuw uitgevoerd |
| FindUnexpectedRootFiles | Aanvullende onverwachte bestanden buiten standaard WordPress-mappen vinden | Nee | absoluut rootpad plus gevalideerde directe childmapnamen uit backendopslag | JSON; maximaal 5.000 bestanden, 20.000 bekeken items of 20 s remote werktijd | 30 s | `wp-admin`, `wp-includes`, `wp-content` en bevestigde children worden vóór traversal overgeslagen; symlinks worden niet gevolgd |
| ListUsers | Accounts en rollen | Nee | pad, vaste velden | JSON | 60 s | privacy; niet loggen |
| ListRoles | Toegestane rollen van de huidige site | Nee | vaste velden `role,name` | JSON | 60 s | custom roles toegestaan na validatie |
| DetectMultisite | Multisite-status bepalen | Nee | vaste PHP-expressie | `0` of `1` | 60 s | alleen status, geen userinput |
| UpdateUser | Weergavenaam/e-mail en optioneel rol wijzigen | Ja | numerieke user-id, gevalideerde waarden, live role-allowlist | exitstatus | 60 s | rechtenwijziging; laatste admin beschermd |
| DeleteUser | Gebruiker van huidige site verwijderen | Ja | numerieke user-id en optionele numerieke reassign-id | exitstatus | 60 s | destructief; nooit `--network` |
| FindPhpFiles | PHP-inventaris in wp-content | Nee | pad, vaste limiet via PHP-streamfilter | NUL-records | 120 s | grote output; geen GNU `head -z` vereist |
| FindPhpInUploads | PHP in uploads | Nee | pad, vaste limiet via PHP-streamfilter | NUL-paden | 120 s | grote output; geen GNU `head -z` vereist |
| FindModifiedFiles | Recent gewijzigd | Nee | dagen 1–365, vaste limiet via PHP-streamfilter | NUL-records | 120 s | grote output; geen GNU `head -z` vereist |
| CheckUnsafePermissions | World-writable objecten | Nee | pad, vaste limiet via PHP-streamfilter | NUL-paden | 120 s | grote output; geen GNU `head -z` vereist |
| CheckSelectedWpConfigConstants | Geselecteerde niet-geheime instellingen | Nee | vaste allowlist; effectief omgevingstype via WordPress API | JSON | 60 s | geen secrets opvragen; niet ingestelde omgeving wordt als WordPress-standaard `production` uitgelegd |
| ListCronEvents | Begrensde WordPress-cronmetadata verzamelen | Nee | vaste PHP-expressie, maximaal 5.000 events | JSON | 60 s | argumenten worden later alleen gefingerprint en niet opgeslagen |
| CheckCoreUpdates | Coreupdates | Nee | pad | JSON | 60 s | netwerk op server |
| ListPluginUpdates | Pluginupdates | Nee | pad, vaste velden | JSON | 60 s | netwerk op server |
| ListThemeUpdates | Themaupdates | Nee | pad, vaste velden | JSON | 60 s | netwerk op server |
| CheckDatabase | Database-integriteit | Nee | pad | tekst/exitstatus | 180 s | serverbelasting |
| DatabaseSizes | Grootste tabellen | Nee | pad | JSON | 120 s | serverbelasting |
| CreateDatabaseBackup | Export naar veilige tempdir | Ja | pad, backendnaam | temp-pad | 600 s | gevoelige data/schijf |
| DeleteTemporaryBackup | Remote tempbestand opruimen | Ja | exact door backend gemaakt pad | exitstatus | 30 s | verwijderactie |
| UpdateCore | WordPress core bijwerken | Ja | pad; alleen binnen de volledige maintenanceflow | JSON/exitstatus | 600 s | directe `run_update`-IPC voor core/all wordt geweigerd |
| UpdateCoreTo | WordPress naar vooraf gedetecteerde doelversie bijwerken | Ja | gevalideerde expliciete versie, nooit `latest` | JSON/exitstatus | 600 s | sitewijziging |
| RepairCore | Officiële huidige coreversie opnieuw downloaden | Ja | gedetecteerde versie + locale, `--force --skip-content` | tekst/exitstatus | 600 s | overschrijft alleen distributiebestanden |
| UpdatePlugin | Eén plugin bijwerken | Ja | gevalideerde slug | JSON | 300 s | sitewijziging |
| UpdateAllPlugins | Alle plugins bijwerken | Ja | pad | JSON | 900 s | sitewijziging |
| UpdateTheme | Eén thema bijwerken | Ja | gevalideerde slug | JSON | 300 s | sitewijziging |
| UpdateAllThemes | Alle thema's bijwerken | Ja | pad | JSON | 600 s | sitewijziging |
| UpdateLanguages | Vertalingen bijwerken | Ja | pad | tekst | 300 s | sitewijziging |
| UpdateCoreLanguages | Alleen corevertalingen bijwerken | Ja | pad | tekst | 300 s | sitewijziging |
| UpdateDatabase | WordPress databaseschema | Ja | pad | tekst | 300 s | databasewijziging |

Commands draaien met `LC_ALL=C` voor stabiele parsing. Stderr en exitstatus blijven gescheiden. Niet-nul exitcodes worden typed failures; onleesbare, ongeldige of te grote output faalt gesloten. `CheckDiskSpace` vormt één bewuste uitzondering: providerstatussen worden intern verzameld zodat ontbrekende `df`/PHP-tools als expliciete niet-blokkerende unavailable-status kunnen terugkomen. SSH-/kanaalfouten blijven wel hard falen. Time-outs sluiten het kanaal en iedere SSH-sessie wordt altijd opgeruimd.

`CreateDatabaseBackup` exporteert ongecomprimeerde SQL naar de servertempdir; de app downloadt dit pad daarna via SFTP en schrijft lokaal direct gzipgecomprimeerd. `DeleteTemporaryBackup` kan uitsluitend het gevalideerde tijdelijke patroon verwijderen. De onderhoudsmutatie start pas wanneer overdracht én cleanup slagen. Er is geen omgekeerde upload/importactie in de catalogus en dus geen beheerde restoreflow. Zie [BACKUPS.md](BACKUPS.md) voor opslag, retentie en handmatig herstel.

## Gecontroleerde WP-CLI-executor

`execute_wp_cli_command` blijft een afzonderlijk gecontroleerd WP-CLI-endpoint en is geen shell. De frontend stuurt uitsluitend een geldige app-sessietoken, `site_id`, commandtekst en eventuele bevestiging. Host, SSH-configuratie, credentials en WordPress-root zijn niet overschrijfbaar vanuit deze payload. Dit endpoint is architectonisch gescheiden van de interactieve Terminal.

De backend:

1. autoriseert de app-sessie en laadt de opgeslagen site plus credential;
2. tokeniseert maximaal 64 KB naar maximaal 1024 argv-items van elk maximaal 32 KB;
3. vereist exact `wp` als eerste token en weigert ongequote shelloperators, redirects, substitution en newline-chaining;
4. weigert usergestuurde `--path`, `--ssh`, `--http` en aliassen;
5. classificeert het volledige command conservatief als read-only, muterend of high-risk en controleert de vereiste bevestiging opnieuw;
6. construeert uitsluitend uit backenddata `LC_ALL=C wp --no-color --path='<opgeslagen root>'` en voegt ieder gevalideerd argument afzonderlijk POSIX-gequote toe;
7. voert via dezelfde gepinde SSH-adapter uit met 180 s (read-only), 600 s (muterend) of 900 s (high-risk) timeout en maximaal 2 MB weergegeven output.

De adapter draint eventuele resterende bytes zodat grote output het proces niet onbeperkt in geheugen laat groeien; het resultaat krijgt dan `truncated=true`. ANSI- en overige controlcodes worden verwijderd, stdout/stderr blijven gescheiden en de UI rendert beide uitsluitend als tekst. Audit schrijft alleen `wp:<family>`, risico, status, exitcode, duur en truncatie — nooit commandtekst of output.

## Interactieve SSH-terminal

De commands `open_terminal`, `write_terminal`, `resize_terminal` en `close_terminal` beheren een sitegebonden SSH-session met `xterm-256color` PTY. Elk endpoint controleert de applicatiesessie. `open_terminal` haalt host, credential en WordPress-root uitsluitend uit backendopslag, verifieert de host key, controleert de startdirectory en start één persistent shellkanaal.

`write_terminal` accepteert daarna bewust raw terminalinvoer tot 256 KiB per IPC-bericht. Er is geen commandparser of allowlist: shellsyntax, normale Linux-programma's en WP-CLI zijn toegestaan met de rechten van de remote SSH-user. Invoer gaat steeds naar hetzelfde kanaal, waardoor `cd` en environment behouden blijven. `resize_terminal` begrenst kolommen/regels en stuurt de nieuwe PTY-grootte door; Ctrl+C is gewone inputbyte `0x03`.

Uitvoer streamt als base64-bytes naar xterm.js. De backend interpreteert of logt die output niet. Bij connection-/channel-fouten wordt alleen de sitespecifieke terminalactie, categorie, tijd, duur en veilig geredigeerde technische oorzaak in het foutenlog opgeslagen; nooit de terminalcommandtekst of output.

## Begrensde SFTP-acties

De volgende typed backendacties zijn bewust geen shellcommando en vormen geen algemene filemanager:

| Actie | Read/write | Auth | Destructief | Invoer en backendvalidatie | Operatie/limiet | Failure handling |
|---|---|---:|---:|---|---|---|
| PreviewChecksumFinding | Read | Ja | Nee | UUID site/finding; nieuwste `unexpected` core-, PHP-in-uploads- of modified-files-finding van die site; pad uitsluitend uit SQLite | SFTP read, regulier bestand, 60 s; 256 KiB tekst/SVGZ-bron of 10 MiB ondersteunde afbeelding | Stale/wrong-site, traversal, symlink of gewijzigde metadata wordt geweigerd; onleesbare/binaire inhoud krijgt alleen een passende veilige Raw-weergave |
| DeleteChecksumFinding | Write | Ja | Ja | UUID site/finding; actuele `unexpected` corefinding; strikte delete-padcontrole; confirmatie in UI | Eén SFTP unlink, regulier bestand, 60 s; daarna checksumscan | Delete wordt geaudit; failure verwijdert niets via een alternatief pad; rescanfailure blijft apart zichtbaar |
| BulkDeleteChecksumFindings | Write | Ja | Ja | 1–5.000 unieke actuele `unexpected` corefinding-id's; iedere finding afzonderlijk opnieuw geautoriseerd | Eén unlink per geldige finding; precies één rescan na één of meer successen | Gedeeltelijk resultaat per finding plus bulkaudit; één failure stopt andere geldige items niet |

Voor iedere SFTP-actie wordt de canonieke WordPress-root bepaald, blijft het canonieke doel daar strikt onder en worden symlinks, mappen en traversal geweigerd. Delete weigert aanvullend `wp-content` en configuratiepaden; preview mag alleen het backendpad van de drie expliciet toegestane findingtypen lezen. De metadata wordt nogmaals gecontroleerd vlak vóór openen of verwijderen. Na één of meer geslaagde verwijderingen volgt één nieuwe scan. Bestandinhoud en credentials komen nooit in auditlogs.

## Beveiligde orchestrationflows

Deze application-services combineren meerdere catalogus-/SFTP-acties, maar verbreden de commandallowlist niet:

| Actie | Read/write | Auth | Destructief | Parameters en backendvalidatie | Remote operatie/output | Failure handling |
|---|---|---:|---:|---|---|---|
| VerifyCoreChecksums | Read | Ja | Nee | UUID site; opgeslagen gevalideerde root; bevestigde directe children uit SQLite; alle teruggestuurde findingpaden opnieuw gevalideerd | WP-CLI JSON zonder `--include-root`, gevolgd door begrensde rootbestandscontrole die children vóór traversal overslaat; gecontroleerde plain fallback voor oudere WP-CLI | Modified/missing/unexpected/scan-error typed opgeslagen; truncatie wordt expliciet gemeld; echte uitvoerfouten worden niet dubbel uitgevoerd en bewaren actie, exitstatus en begrensde diagnostiek |
| CheckCoreUpdate | Read | Ja | Nee | UUID site; live huidige versie | WP-CLI core/plugin/theme JSON, per stap 60 s en outputlimiet | Teruggestuurde doelversie wordt voor coremutatie opnieuw live gelezen en gevalideerd |
| UpdateWordPressUser | Write | Ja | Ja | Numerieke user-id, display/emailvalidatie, optionele rol uit live allowlist; laatste admin beschermd | `wp user update`, 60 s; daarna getypeerde userslijst | Remote failure wordt zonder persoonsgegevens in audit vastgelegd; UI houdt oude lijst bij |
| DeleteWordPressUser | Write | Ja | Ja | Numerieke user-id; exact reassign óf content delete; live target/laatste-admincontrole; nooit `--network` | `wp user delete`, 60 s; huidige site | Failure wordt geaudit; users worden alleen na succes opnieuw geladen |
| RepairWordPressCore | Write | Ja | Ja | UUID site; live versie/locale/root/WP-CLI/database en diskprobe; `latest` verboden | Backup, `wp core download --force --skip-content`, daarna scan/versie/database/homepage/updates | Kritieke preflight/backup/mutatiefailure stopt; onbekende vrije ruimte waarschuwt maar blokkeert niet; post-checkproblemen geven warning; volledige run in historie |
| UpdateWordPressCore | Write | Ja | Ja | UUID site; live gevalideerde beschikbare doelversie; dezelfde preflight en diskprobe | Backup, expliciete coreversie, update-db, core languages, post-checks; catalogustime-outs | Gemeten ruimtegebrek of backupfailure stopt vóór mutatie; onbekende vrije ruimte waarschuwt; corefailure stopt DB/talen; run en backup in historie |

Bij useracties wordt de actuele userlijst vóór iedere mutatie opnieuw opgehaald. De laatste Administrator kan niet worden verwijderd of gedegradeerd. Bij verwijderen is exact één keuze vereist: content toewijzen aan een andere bestaande numerieke user-id, of content expliciet mee verwijderen. Op Multisite verwijdert de officiële `wp user delete`-flow alleen van de huidige site; deze app voegt bewust nooit `--network` toe. De UI waarschuwt daarnaast dat weergavenaam en e-mail velden van het gedeelde netwerkaccount zijn.

Core repair en core update zijn aparte orchestrationflows. Beide herhalen de remote preflight, vereisen eerst een geslaagde lokale databasebackup en registreren alle stappen in maintenance history. De diskprobe probeert `df`, daarna PHP `disk_free_space()` en ten slotte WP-CLI; alleen betrouwbaar gemeten ruimtegebrek blokkeert, terwijl het ontbreken van alle methoden als niet-blokkerende waarschuwing in de preflightdetails blijft staan. Repair gebruikt exact de gedetecteerde huidige versie en locale met `--force --skip-content`; het verwijdert geen onbekende bestanden. Update gebruikt exact de vooraf gedetecteerde beschikbare doelversie en voert daarna `UpdateDatabase` en `UpdateCoreLanguages` uit. Beide eindigen met root-checksum, versie-, database-, homepage- en updatecontrole.
