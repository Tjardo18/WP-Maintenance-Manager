# Remote command catalog

Alle remote uitvoering moet via deze catalogus lopen. De uiteindelijke commandostring wordt uitsluitend in Rust opgebouwd. Iedere hieronder genoemde remote actie is alleen bereikbaar vanuit een Tauri-command dat eerst een geldige backend-sessie vereist. De frontend kan catalogusacties of vrije commandotekst niet rechtstreeks aanroepen. Algemene limieten: pad maximaal 4096 bytes, slugs maximaal 200 ASCII-tekens, dagen 1–365 en scanresultaten standaard maximaal 5000 records.

| Actie | Doel | Muterend | Parameters/validatie | Output | Standaardtimeout | Risico |
|---|---|---:|---|---|---:|---|
| TestWordPressPath | Controleren of het ingestelde pad bestaat | Nee | absoluut POSIX-pad | exitstatus | 20 s | laag |
| DetectWordPress | Installatie en database detecteren | Nee | absoluut POSIX-pad | exitstatus | 30 s | laag |
| GetWordPressVersion | Coreversie ophalen | Nee | pad | tekst | 20 s | laag |
| GetPhpVersion | PHP-versie ophalen | Nee | geen | tekst | 20 s | laag |
| GetWpCliVersion | WP-CLI-versie ophalen | Nee | geen | tekst | 20 s | laag |
| GetCoreLocale | Actieve WordPress-locale bepalen | Nee | vaste PHP-expressie | locale | 60 s | geen userinput |
| CheckDiskSpace | Vrije ruimte op filesystem van WordPress-root | Nee | gevalideerd rootpad | vrije KB | 60 s | platformafhankelijk `df` |
| VerifyCoreChecksums | Officiële core checksums inclusief root | Nee | expliciet pad, `core is-installed`, `--include-root` | JSON + exitstatus | 120 s | serverbelasting |
| ListUsers | Accounts en rollen | Nee | pad, vaste velden | JSON | 60 s | privacy; niet loggen |
| ListRoles | Toegestane rollen van de huidige site | Nee | vaste velden `role,name` | JSON | 60 s | custom roles toegestaan na validatie |
| DetectMultisite | Multisite-status bepalen | Nee | vaste PHP-expressie | `0` of `1` | 60 s | alleen status, geen userinput |
| UpdateUser | Weergavenaam/e-mail en optioneel rol wijzigen | Ja | numerieke user-id, gevalideerde waarden, live role-allowlist | exitstatus | 60 s | rechtenwijziging; laatste admin beschermd |
| DeleteUser | Gebruiker van huidige site verwijderen | Ja | numerieke user-id en optionele numerieke reassign-id | exitstatus | 60 s | destructief; nooit `--network` |
| FindPhpFiles | PHP-inventaris in wp-content | Nee | pad, vaste limiet | NUL-records | 120 s | grote output |
| FindPhpInUploads | PHP in uploads | Nee | pad, vaste limiet | NUL-paden | 120 s | grote output |
| FindModifiedFiles | Recent gewijzigd | Nee | dagen 1–365 | NUL-records | 120 s | grote output |
| CheckUnsafePermissions | World-writable objecten | Nee | pad, vaste limiet | NUL-paden | 120 s | grote output |
| CheckSelectedWpConfigConstants | Drie niet-geheime constants | Nee | vaste allowlist | JSON | 30 s | geen secrets opvragen |
| CheckCoreUpdates | Coreupdates | Nee | pad | JSON | 60 s | netwerk op server |
| ListPluginUpdates | Pluginupdates | Nee | pad, vaste velden | JSON | 60 s | netwerk op server |
| ListThemeUpdates | Themaupdates | Nee | pad, vaste velden | JSON | 60 s | netwerk op server |
| CheckDatabase | Database-integriteit | Nee | pad | tekst/exitstatus | 180 s | serverbelasting |
| DatabaseSizes | Grootste tabellen | Nee | pad | JSON | 90 s | serverbelasting |
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

Commands draaien met `LC_ALL=C` voor stabiele parsing. Stderr en exitstatus blijven gescheiden. Niet-nul exitcodes worden typed failures; onleesbare, ongeldige of te grote output faalt gesloten. Time-outs sluiten het kanaal en iedere SSH-sessie wordt altijd opgeruimd.

## Begrensde SFTP-acties

De volgende typed backendacties zijn bewust geen shellcommando en vormen geen algemene filemanager:

| Actie | Read/write | Auth | Destructief | Invoer en backendvalidatie | Operatie/limiet | Failure handling |
|---|---|---:|---:|---|---|---|
| PreviewChecksumFinding | Read | Ja | Nee | UUID site/finding; actuele `unexpected` finding van die site; pad uitsluitend uit SQLite | SFTP read, regulier bestand, 60 s, maximaal 256 KB platte tekst | Stale/wrong-site, traversal, symlink, binary of gewijzigde metadata wordt geweigerd/veilig gemeld |
| DeleteChecksumFinding | Write | Ja | Ja | Zelfde finding- en padcontrole; confirmatie in UI | Eén SFTP unlink, regulier bestand, 60 s; daarna checksumscan | Delete wordt geaudit; failure verwijdert niets via een alternatief pad; rescanfailure blijft apart zichtbaar |
| BulkDeleteChecksumFindings | Write | Ja | Ja | 1–5.000 unieke UUID's; iedere finding afzonderlijk opnieuw geautoriseerd | Eén unlink per geldige finding; precies één rescan na één of meer successen | Gedeeltelijk resultaat per finding plus bulkaudit; één failure stopt andere geldige items niet |

Voor iedere SFTP-actie wordt de canonieke WordPress-root bepaald, blijft het canonieke doel daar strikt onder en worden symlinks, mappen, traversal, `wp-content` en configuratiepaden geweigerd. De metadata wordt nogmaals gecontroleerd vlak vóór openen of verwijderen. Na één of meer geslaagde verwijderingen volgt één nieuwe scan. Bestandinhoud en credentials komen nooit in auditlogs.

## Beveiligde orchestrationflows

Deze application-services combineren meerdere catalogus-/SFTP-acties, maar verbreden de commandallowlist niet:

| Actie | Read/write | Auth | Destructief | Parameters en backendvalidatie | Remote operatie/output | Failure handling |
|---|---|---:|---:|---|---|---|
| VerifyCoreChecksums | Read | Ja | Nee | UUID site; opgeslagen gevalideerde root; findingpaden opnieuw gevalideerd | WP-CLI JSON vanaf root, `--include-root`, 120 s, 512 KB | Modified/missing/unexpected/scan-error typed opgeslagen; ongeldige output faalt de check |
| CheckCoreUpdate | Read | Ja | Nee | UUID site; live huidige versie | WP-CLI core/plugin/theme JSON, per stap 60 s en outputlimiet | Teruggestuurde doelversie wordt voor coremutatie opnieuw live gelezen en gevalideerd |
| UpdateWordPressUser | Write | Ja | Ja | Numerieke user-id, display/emailvalidatie, optionele rol uit live allowlist; laatste admin beschermd | `wp user update`, 60 s; daarna getypeerde userslijst | Remote failure wordt zonder persoonsgegevens in audit vastgelegd; UI houdt oude lijst bij |
| DeleteWordPressUser | Write | Ja | Ja | Numerieke user-id; exact reassign óf content delete; live target/laatste-admincontrole; nooit `--network` | `wp user delete`, 60 s; huidige site | Failure wordt geaudit; users worden alleen na succes opnieuw geladen |
| RepairWordPressCore | Write | Ja | Ja | UUID site; live versie/locale/root/WP-CLI/database/disk; `latest` verboden | Backup, `wp core download --force --skip-content`, daarna scan/versie/database/homepage/updates | Preflight/backup/mutatiefailure stopt en skipt vervolg; post-checkproblemen geven warning; volledige run in historie |
| UpdateWordPressCore | Write | Ja | Ja | UUID site; live gevalideerde beschikbare doelversie; dezelfde preflight | Backup, expliciete coreversie, update-db, core languages, post-checks; catalogustime-outs | Geen update of backupfailure stopt vóór mutatie; corefailure stopt DB/talen; run en backup in historie |

Bij useracties wordt de actuele userlijst vóór iedere mutatie opnieuw opgehaald. De laatste Administrator kan niet worden verwijderd of gedegradeerd. Bij verwijderen is exact één keuze vereist: content toewijzen aan een andere bestaande numerieke user-id, of content expliciet mee verwijderen. Op Multisite verwijdert de officiële `wp user delete`-flow alleen van de huidige site; deze app voegt bewust nooit `--network` toe. De UI waarschuwt daarnaast dat weergavenaam en e-mail velden van het gedeelde netwerkaccount zijn.

Core repair en core update zijn aparte orchestrationflows. Beide herhalen de remote preflight, vereisen eerst een geslaagde lokale databasebackup en registreren alle stappen in maintenance history. Repair gebruikt exact de gedetecteerde huidige versie en locale met `--force --skip-content`; het verwijdert geen onbekende bestanden. Update gebruikt exact de vooraf gedetecteerde beschikbare doelversie en voert daarna `UpdateDatabase` en `UpdateCoreLanguages` uit. Beide eindigen met root-checksum, versie-, database-, homepage- en updatecontrole.
