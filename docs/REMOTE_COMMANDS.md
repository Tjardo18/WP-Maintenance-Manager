# Remote command catalog

Alle remote uitvoering moet via deze catalogus lopen. De uiteindelijke commandostring wordt uitsluitend in Rust opgebouwd. Algemene limieten: pad maximaal 4096 bytes, slugs maximaal 200 ASCII-tekens, dagen 1–365 en scanresultaten standaard maximaal 5000 records.

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
| UpdateCore | WordPress core bijwerken | Ja | pad | JSON/exitstatus | 600 s | sitewijziging |
| UpdateCoreTo | WordPress naar vooraf gedetecteerde doelversie bijwerken | Ja | gevalideerde expliciete versie, nooit `latest` | JSON/exitstatus | 600 s | sitewijziging |
| RepairCore | Officiële huidige coreversie opnieuw downloaden | Ja | gedetecteerde versie + locale, `--force --skip-content` | tekst/exitstatus | 600 s | overschrijft alleen distributiebestanden |
| UpdatePlugin | Eén plugin bijwerken | Ja | gevalideerde slug | JSON | 300 s | sitewijziging |
| UpdateAllPlugins | Alle plugins bijwerken | Ja | pad | JSON | 900 s | sitewijziging |
| UpdateTheme | Eén thema bijwerken | Ja | gevalideerde slug | JSON | 300 s | sitewijziging |
| UpdateAllThemes | Alle thema's bijwerken | Ja | pad | JSON | 600 s | sitewijziging |
| UpdateLanguages | Vertalingen bijwerken | Ja | pad | tekst | 300 s | sitewijziging |
| UpdateCoreLanguages | Alleen corevertalingen bijwerken | Ja | pad | tekst | 300 s | sitewijziging |
| UpdateDatabase | WordPress databaseschema | Ja | pad | tekst | 300 s | databasewijziging |

Commands draaien met `LC_ALL=C` voor stabiele parsing. Stderr en exitstatus blijven gescheiden. Time-outs sluiten het kanaal en iedere SSH-sessie wordt altijd opgeruimd.

## Begrensde SFTP-acties

De volgende typed backendacties zijn bewust geen shellcommando en vormen geen algemene filemanager:

| Actie | Invoer vanuit frontend | Backend-authorisatie | Bestandstype/limiet |
|---|---|---|---|
| PreviewChecksumFinding | `site_id`, `finding_id` | Alleen een `unexpected` finding uit de nieuwste checksumscan van die site | Regulier bestand, alleen-lezen, maximaal 256 KB |
| DeleteChecksumFinding | `site_id`, `finding_id` | Zelfde controle; het pad komt uitsluitend uit de database | Regulier bestand, één unlink via SFTP |
| DeleteChecksumFindings | `site_id`, lijst finding-id's | Iedere finding wordt afzonderlijk gevalideerd en gelogd | Maximaal 5.000 reguliere bestanden, gedeeltelijk resultaat |

Voor iedere SFTP-actie wordt de canonieke WordPress-root bepaald, blijft het canonieke doel daar strikt onder en worden symlinks, mappen, traversal, `wp-content` en configuratiepaden geweigerd. De metadata wordt nogmaals gecontroleerd vlak vóór openen of verwijderen. Na één of meer geslaagde verwijderingen volgt één nieuwe scan. Bestandinhoud en credentials komen nooit in auditlogs.

Bij useracties wordt de actuele userlijst vóór iedere mutatie opnieuw opgehaald. De laatste Administrator kan niet worden verwijderd of gedegradeerd. Bij verwijderen is exact één keuze vereist: content toewijzen aan een andere bestaande numerieke user-id, of content expliciet mee verwijderen. Op Multisite verwijdert de officiële `wp user delete`-flow alleen van de huidige site; deze app voegt bewust nooit `--network` toe. De UI waarschuwt daarnaast dat weergavenaam en e-mail velden van het gedeelde netwerkaccount zijn.

Core repair en core update zijn aparte orchestrationflows. Beide herhalen de remote preflight, vereisen eerst een geslaagde lokale databasebackup en registreren alle stappen in maintenance history. Repair gebruikt exact de gedetecteerde huidige versie en locale met `--force --skip-content`; het verwijdert geen onbekende bestanden. Update gebruikt exact de vooraf gedetecteerde beschikbare doelversie en voert daarna `UpdateDatabase` en `UpdateCoreLanguages` uit. Beide eindigen met root-checksum, versie-, database-, homepage- en updatecontrole.
