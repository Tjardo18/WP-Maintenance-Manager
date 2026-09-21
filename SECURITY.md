# Security

## Threat model

De app beheert gevoelige SSH-toegang tot meerdere websites. Belangrijkste risico's zijn ongeautoriseerd lokaal gebruik, gestolen credentials, command injection, een gewijzigde SSH-serveridentiteit, onbedoelde mutaties, gemanipuleerde remote data en gelekte backups. WordPress-hosts en alle data die zij terugsturen worden als niet-vertrouwd behandeld.

## Applicatielogin en sessies

- Bij de eerste start is een applicatiewachtwoord van minimaal 12 tekens verplicht. Alleen een per installatie gezouten Argon2id-hash staat in SQLite; het leesbare wachtwoord wordt niet opgeslagen.
- De backend houdt maximaal één cryptografisch willekeurige sessie in geheugen bij en vergelijkt alleen een SHA-256-tokenhash constant-time. Een nieuwe login vervangt de vorige sessie; een procesherstart verliest de sessie altijd.
- Alle Tauri-commands voor sitegegevens, instellingen, scans en mutaties roepen eerst dezelfde backend-authorisatie aan. Alleen status, first-run setup en login zijn publiek; status retourneert geen gevoelige data.
- Handmatig vergrendelen, idle timeout en wachtwoordwijziging maken de sessie ongeldig. De standaard idle timeout is 15 minuten en de backend controleert hem onafhankelijk van de UI.
- Herhaalde mislukte logins krijgen een oplopende vertraging. Login-, lock- en wachtwoordwijzigingen worden zonder wachtwoord of sessietoken geaudit.
- Een reeds geautoriseerde managed backendactie mag na vergrendeling veilig afronden. De lock autoriseert geen nieuwe actie en probeert geen half uitgevoerde managed mutatie terug te draaien. Interactieve terminalkanalen worden bij lock wel actief gesloten.

## Bescherming van remote beheer

- **Credentials:** SSH-secrets staan niet in SQLite, logs, fixtures of IPC-responses. Alleen een opaque credentialreferentie wordt als metadata bewaard. Private keys worden niet geïmporteerd; standaard bewaart de app alleen het lokale bestandspad.
- **Hostidentiteit:** de SHA-256-fingerprint wordt uit de SSH-handshake berekend vóór authenticatie. De eerste fingerprint moet zichtbaar worden geaccepteerd en wordt daarna gepind. Tijdens acceptatie haalt de backend de fingerprint opnieuw op en vergelijkt die met de getoonde waarde. Een mismatch is een blokkerende fout, nooit een stille heracceptatie.
- **Geneste installaties:** mapnamen uit de remote WordPress-root worden als onbetrouwbaar behandeld, begrensd tot 200 directe namen en geweigerd bij traversal, separators, controltekens of ongeldige lengte. Een child kan alleen onder een bestaande parent met dezelfde SSH-identiteit en exact het verwachte directe child-pad worden opgeslagen. URL-/padduplicaten en relatiecirkels worden backend-side geblokkeerd. Bij de aanvullende rootchecksum wordt een bevestigde childmap vóór traversal overgeslagen; onverwachte childpaden worden daarnaast nog defensief weggefilterd. De officiële corecontrole en alle andere findingtypen blijven intact, en een childscan gebruikt zijn eigen root zonder parentuitsluitingen.
- **Twee execution modes:** normale beheeracties blijven een vaste Rust-commandcatalogus en opgeslagen managed credentials gebruiken. De afzonderlijke Advanced Terminal is bewust een vrije, interactieve SSH-shell. Daar is arbitrary shell execution het productdoel; de aanvullende securitygrens bestaat uit app-login, verplichte app-reauthenticatie, expliciete SSH-passwordauthenticatie, backend-sessiecontrole, een aparte Terminal-autorisatie, host-key-pinning, de geselecteerde siteconfiguratie en uiteindelijk de rechten van het remote SSH-account.
- **Remote output:** output heeft per actie een byte-limiet en wordt naar getypeerde resultaten geparsed. Door WP-CLI teruggestuurde slugs en checksum-paden worden opnieuw gevalideerd. Remote bron wordt nooit onbewerkt als uitvoerbare HTML geplaatst: gewone UI gebruikt tekstinterpolatie, syntax-highlighting levert escaped markup, Markdown heeft raw HTML uitgeschakeld en SVG doorloopt een actieve-contentfilter.
- **Tauri-grens:** de webview krijgt alleen core-permissies en toegang tot de native bestanddialoog. Er is geen shell- of generieke filesystempermissie. De CSP staat geen remote scripts, fonts of pagina-inhoud toe.
- **Logging en scanmeldingen:** het persistente SQLite-foutenlog bevat alleen een error-ID, tijden, categorie, site, bekende applicatieactie, veilige technische details, cause-chain, duur/exitcode en retry-indicatie. Sessietokens, credentials, terminalcommandostrings, previews en volledige remote output worden niet gelogd. Details worden begrensd, control-charactervrij gemaakt en regels met herkenbare secretmarkers worden vóór opslag weggelaten. Records ouder dan 30 dagen en records boven de nieuwste 10.000 worden verwijderd.
- **Backups:** een backend-gegenereerde remote tijdelijke naam onder `/tmp` blijft buiten de documentroot. Alleen het strikte patroon `/tmp/wpmm-XXXXXXXX.sql` mag via de cleanupactie worden verwijderd. De export wordt via SFTP gestreamd, lokaal gecomprimeerd, begrensd op 20 GiB brondata en gehasht. Download én remote cleanup moeten slagen voordat onderhoud doorgaat. Gzip is geen encryptie; geslaagde lokale backups hebben nog geen automatische retentie en restore is geen beheerde appactie.

## Databaseback-ups

Een geslaagde back-up staat onder `%APPDATA%\nl.wpmaintenancemanager.desktop\backups\<site-id>\` en kan persoonsgegevens, wachtwoordhashes, sessies, tokens en gevoelige plugininstellingen bevatten. De app vertrouwt voor bescherming op het Windows-account, filesystem-ACL's en eventuele schijfversleuteling. Deel of synchroniseer deze map niet onbeveiligd. SQLite bewaart alleen pad, grootte, SHA-256 en tijd; de app verifieert de hash momenteel niet opnieuw via de UI.

Bij een downloadfailure verwijdert de app de gedeeltelijke lokale kopie. Als de remote cleanup mislukt, verwijdert zij eveneens de lokale kopie en stopt de mutatie, maar kan het tijdelijke serverbestand zijn blijven staan. Een harde proces- of computeronderbreking kan dezelfde handmatige controle vereisen. Er is geen periodieke cleanup voor serverresten, partials of oude geslaagde backups.

De app heeft geen restore-endpoint. Handmatig herstel via een hostingtool of de vrije Terminal valt buiten de managed commandcatalogus: er is geen automatische doelcontrole, verse veiligheidsbackup, restorebevestiging, hashverificatie of rollback. De Terminalgate en SSH-accountrechten blijven gelden, maar vervangen deze ontbrekende restorewaarborgen niet. Zie [docs/BACKUPS.md](docs/BACKUPS.md) voor de huidige procedure en beperkingen.

## Bestandspreview en checksumverwijdering

Preview en verwijdering accepteren geen pad uit de frontend, maar alleen een site-id en finding-id uit de nieuwste scan van precies die site. Preview staat uitsluitend een `unexpected` corefinding, PHP-in-uploads-finding of recent-gewijzigd-bestandfinding toe. Verwijderen vereist strikter een `unexpected` corebestand; configuratiepaden en heel `wp-content` blijven voor delete verboden. De backend haalt het opgeslagen pad op, weigert absolute/traversal/control-paden, mappen en symlinks, bepaalt root en doel via SFTP `realpath`, controleert containment en vergelijkt metadata nogmaals vlak vóór openen of unlinken.

Tekst en uitgepakte SVGZ-bron zijn begrensd op 256 KiB; ondersteunde afbeeldingen worden tot 10 MiB gelezen. Gewone binaire of ongeldige UTF-8-data wordt niet als tekst of kunstmatige syntax weergegeven. Binaire afbeeldingsbytes kunnen alleen-lezen worden onderzocht op leesbare reeksen, een vaste set verdachte patronen, extra data na bekende bestandseindes en begrensde hexgebieden. Deze heuristiek voert niets uit, verandert het bestand niet en is geen malwaregarantie.

Markdown-rendering gebruikt geen raw HTML; alleen HTTP(S)-links gaan na een tweede backendvalidatie naar de OS-browser. De SVG-sanitizer weigert `DOCTYPE`, scripts, embedded/foreign content, eventhandlers, externe `href`/`src`, CSS-imports en niet-fragment-URL's. Rasterpreview accepteert alleen expliciete image-MIME-types uit backenddata; TIFF wordt met dimensie- en geheugenlimieten naar PNG geconverteerd. Bulkverwijdering valideert ieder item afzonderlijk, rapporteert gedeeltelijke failures en voert na geslaagde deletes precies één nieuwe checksumscan uit. Dit is bewust geen algemene filemanager. Door beperkingen van de gebruikte SFTP-API blijft de dubbele metadata-/padcontrole een best-effort bescherming tegen zeer kleine racevensters; de app claimt geen filesystem-transactie.

## Exceptions and Trusted Files

Een genegeerde finding is technisch niet verdwenen. De backend bewaart de exacte combinatie van site, checktype, findingtype en genormaliseerd target. Daardoor geldt bijvoorbeeld `readme.html + missing` niet voor `readme.html + modified`, een andere file of een andere site. Permanente en tijdelijke uitzonderingen tellen niet mee voor de hoofdstatus zolang ze actief zijn; na de UTC-verlooptijd wordt dezelfde finding automatisch weer actief. Genegeerde en verlopen records blijven via **Uitzonderingen** vindbaar. Voor ontbrekende, niet-uitvoerbare distributiebestanden `readme.html` en `license.txt` is de centrale standaardseverity `info`, zodat zij zonder uitzondering al geen waarschuwing veroorzaken.

Bestandsvertrouwen is uitsluitend expliciet en hash-based. De backend normaliseert het site-relatieve, case-sensitive pad, weigert traversal en symlinks, controleert dat root en doel canoniek binnen dezelfde WordPress-root vallen en streamt een regulier bestand in blokken door SHA-256. Alleen hash, grootte, bestandstype, beschikbare wijzigingstijd en controletijden komen in SQLite; bestandsinhoud wordt niet voor trust opgeslagen of naar de frontend gestuurd. Metadata wordt vóór en na het lezen vergeleken. Een race blijft op filesysteemniveau best-effort, maar een gedetecteerde vervanging of wijziging breekt de hashactie af.

Bij iedere volgende scan worden actieve trustregistraties opnieuw gecontroleerd. Alleen een gelijke SHA-256 en gelijk bestandstype resulteert in `trusted`. Een andere hash of type wordt `trusted_changed` en telt opnieuw als actieve waarschuwing. Een verdwenen bestand blijft als `missing` beheersbaar zonder de site als securityprobleem te markeren. Een mislukte controle wordt `unchecked`, maakt de oorspronkelijke finding niet stil vertrouwd en schrijft een geredigeerde `trust_hash_failed`-fout. Een vertrouwde hash is bewijs van gelijkheid met de expliciet beoordeelde versie, geen malwaregarantie.

Notities zijn optioneel, begrensd en weigeren herkenbare secretmarkers. Auditregels bevatten alleen site, target, findingtype/actie en tijd; nooit bestandsinhoud, credential of volledige remote output.

## Site Snapshots and Baselines

Site snapshots zijn lokale, getypeerde toestandsmetingen voor veranderingdetectie. Ze bevatten WordPress Core- en PHP-versie, locale/Multisite indien betrouwbaar, plugin- en themametadata, WordPress user-id/login/weergavenaam/e-mail/rollen, geselecteerde veilige configuratie, genormaliseerde cronmetadata en alleen begrensde relevante bestandsmetadata. E-mailadressen en logins zijn persoonsgegevens en staan daarom alleen in de lokale SQLite-database; de frontend ontvangt uitsluitend de metadata en changes die voor de actuele weergave nodig zijn.

Configuratie gebruikt een positieve allowlist. Alleen `site_url`, `home_url`, `active_theme`, `wp_environment_type`, `WP_DEBUG`, `WP_DEBUG_LOG`, `WP_DEBUG_DISPLAY`, `DISALLOW_FILE_EDIT`, `DISALLOW_FILE_MODS`, `php_version`, `permalink_structure` en `multisite` kunnen worden opgeslagen. Een volledige `wp config list`-dump wordt nooit gemaakt. Databasecredentials, SSH-credentials, API keys, WordPress auth keys/salts, SMTP-wachtwoorden, cookies, sessietokens en arbitrary constants zijn uitgesloten.

Snapshots slaan geen WordPress password hashes, application passwords, auth cookies of sessies op. Arbitrary cronargumenten worden niet opgeslagen of naar Vue gestuurd; indien identiteit dit vereist bewaart de builder alleen een SHA-256-fingerprint. File snapshots bevatten geen inhoud en geen volledige filesysteminventaris, maar hoogstens een genormaliseerd site-relatief pad, categorie/type, grootte, wijzigingstijd en reeds beschikbare SHA-256 voor relevante trusted/security/checksumrecords. De WordPress-rootidentiteit is een hash van sitecontext en pad, niet het leesbare serverpad.

De payload heeft een schema-versie, een grens van 16 MiB en wordt vanaf 4 KiB alleen met gzip opgeslagen wanneer dat ruimte bespaart. Compressie is geen encryptie: bescherming van het Windows-account, de app-datamap en schijfversleuteling blijven relevant. Snapshot-, diff-, change- en statewrites zijn transactioneel; retention gebruikt foreign keys/cascades en verwijdert nooit automatisch de expliciete baseline of pre-/post-maintenance snapshots.

Iedere snapshotsectie is afzonderlijk `complete`, `failed` of `not_collected`. De diff-engine vergelijkt alleen twee complete kanten. Een mislukte userverzameling levert dus **Vergelijking niet beschikbaar** op en nooit een lijst alsof alle gebruikers zijn verwijderd. Normalisatie en stabiele entity keys beperken ordering-noise; een normaal doorgeschoven cron-next-run geldt niet als verandering.

Een baseline betekent uitsluitend dat de gebruiker die momentopname als vergelijkingsreferentie kiest. Dit is geen malwaregarantie, veiligheidsverklaring, uitzondering of acknowledgement. Een change is evenmin automatisch een securityincident; alleen centrale severityregels maken bijvoorbeeld een nieuwe Administrator zichtbaar voor extra beoordeling. Wordfence-vulnerabilities blijven buiten snapshots omdat veranderde externe intelligence geen verandering aan de website zelf is.

## Wordfence Intelligence Integration

- De Wordfence API key staat uitsluitend in de beveiligde credentialopslag van het besturingssysteem. SQLite bewaart alleen feed- en scanmetadata; de key komt niet in SQLite, frontendpersistence, auditregels, foutenlogs, fixtures, URL's of Git en wordt na opslag niet aan Vue teruggestuurd.
- Alleen de Rust-backend maakt via `reqwest` en normale TLS-certificaatverificatie verbinding met de officiële V3 Production Feed. Authenticatie gebruikt uitsluitend `Authorization: Bearer …`; de header en sleutel worden nooit gelogd. Er is geen optie om certificaatcontrole uit te schakelen.
- Een verbindingstest streamt de complete feed naar een backend-beheerd tijdelijk cachebestand. De volgende database-update claimt en importeert diezelfde download, zodat de voorgeschreven test- en updateflow niet twee feedrequests veroorzaakt. Een tijdelijke of half gedownloade file wordt nooit als actieve dataset gebruikt.
- De feedrequest bevat geen sitenaam, klant-URL, SSH-hostname of software-inventaris. Core-, plugin- en themamatching gebeurt volledig lokaal. De API key wordt nooit via SSH verzonden en de app installeert Wordfence niet op beheerde websites.
- Een import gebruikt een SQLite-transactie en activeert de nieuwe complete dataset pas nadat streaming JSON-validatie en normalisatie volledig zijn geslaagd. Bij HTTP-, JSON- of databasefouten blijft de vorige dataset actief. Een lokale 30-minutencooldown en 24-uurs automatische policy voorkomen agressieve requests; `429` veroorzaakt geen retry-loop.
- Providerrecords zijn niet-vertrouwde data. Titels, beschrijvingen, remediation, researchers en copyrighttekst worden alleen via tekstinterpolatie weergegeven. Externe links worden in Vue én Rust beperkt tot geldige `http`/`https`-URL's zonder credentials voordat de OS-browseropener wordt gebruikt; `javascript:`, `file:` en custom protocollen worden geweigerd.
- Het volledige `copyrights`-object blijft behouden. Record-specifieke notices en licenties, waaronder aanwezige MITRE/CVE-attributie, zijn toegankelijk via **Bronnen en licenties** in het detailvenster.
- Een feed ouder dan 24 uur blijft bruikbaar maar wordt als verouderd aangeduid. Na een nieuwe feed wordt een opgeslagen software-inventaris uitsluitend lokaal opnieuw gematcht. Inventaris ouder dan zeven dagen levert een expliciete **mogelijke kwetsbaarheid op basis van laatst bekende versie** op met advies om de website opnieuw te scannen.
- Wordfence Intelligence is security intelligence, geen veiligheidsbewijs. Geen finding betekent alleen dat geen bekende vulnerability voor een exact gematchte identiteit en vergelijkbare versie in de actieve lokale feed is gevonden. Onbekende, custom en premiumsoftware kan buiten de dekking vallen.

## WordPress users en core

Usermutaties laden de actuele users, rollen en Multisite-status vlak vóór uitvoering opnieuw. Remote commands gebruiken numerieke user-id's. De backend blokkeert verwijdering of degradatie van de laatste Administrator, eist exact één contentkeuze en voegt nooit `--network` toe.

Core repair en core update zijn aparte, geauthenticeerde flows. Repair gebruikt exact de gedetecteerde huidige versie en locale met `--force --skip-content`; `latest` is verboden en onbekende bestanden worden niet verwijderd. Een update gebruikt een gevalideerde, live gedetecteerde doelversie. Beide herhalen preflight, stoppen bij een mislukte verplichte databasebackup en voeren checksum-, versie-, database-, homepage- en updatecontroles uit. De diskprobe probeert achtereenvolgens `df`, PHP `disk_free_space()` en WP-CLI: een betrouwbaar gemeten tekort blokkeert, maar wanneer geen methode beschikbaar is blijft een expliciete waarschuwing bewaard en wordt onbekend niet ten onrechte als nul bytes behandeld. Een repair beschermt `wp-content`, maar is geen volledige bestandsrollback.

## Interactive Terminal Authentication

De Terminal is bewust krachtiger dan de voorgedefinieerde beheerknoppen en is alleen bedoeld voor beheerders. Een gebruiker met toegang tot een ontgrendelde Terminal heeft effectief dezelfde serverrechten als het gekoppelde SSH-account. `rm`, `chmod`, `mv`, `bash`, `php`, `mysql`, `curl`, `wp` en shelloperators zijn bewust toegestaan; er is geen app-allowlist en geen confirmation per terminalcommando.

- Iedere Terminalopening begint opnieuw met het lokale WP Maintenance Manager-wachtwoord. De backend gebruikt dezelfde Argon2id-verifier en bestaande hash als de normale login; er is geen tweede opgeslagen hash en de frontend vergelijkt het wachtwoord nooit zelf.
- Een fout lokaal app-wachtwoord tijdens Terminalunlock is een securityevent: de volledige app-sessie wordt backend-side ingetrokken, alle challenges en Terminal-autorisaties worden vernietigd en alle terminalkanalen worden gesloten. Daarna weigeren alle protected Tauri-commands de oude sessietoken. De UI wist haar gevoelige state en toont het algemene loginscherm zonder retry in de Terminal.
- Na een correcte app-controle ontstaat een cryptografisch willekeurige challenge die alleen in backendgeheugen staat, 60 seconden geldig is, bij één app-sessie en één site-id hoort en na annuleren of één SSH-poging niet opnieuw bruikbaar is.
- Stap twee vereist het handmatig ingevoerde wachtwoord van precies de opgeslagen SSH-gebruiker. Eerst wordt de gepinde host key gecontroleerd; daarna accepteert de Terminal uitsluitend de door de server geadverteerde `password`-methode. Er is geen fallback naar een opgeslagen SSH-key, key passphrase, agent, credentialstore of managed SSH-verbinding.
- Een server met `PasswordAuthentication no`, of zonder gewone `password`-methode, kan de interactieve Terminal onder dit beleid niet openen. Keyboard-interactive alleen geldt niet als vervanging. Managed appfuncties blijven hun eigen opgeslagen key/passwordflow gebruiken.
- Een fout SSH-wachtwoord sluit de verbindingspoging en challenge af, maar trekt de normale app-sessie niet in. De fout wordt zonder secret als `ssh_authentication` gelogd. Herhaalde SSH-passwordpogingen binnen dezelfde app-sessie en site krijgen een korte oplopende vertraging.
- Alleen na beide succesvolle verificaties wordt een nieuwe PTY plus een willekeurige aparte Terminal-autorisatie gemaakt. Backendgeheugen bewaart alleen hashes van app- en Terminaltokens; input, resize en close vereisen telkens zowel de nog geldige app-sessie als deze Terminal-autorisatie.
- De Terminal-autorisatie geldt uitsluitend voor één terminal-id en de gekozen site. Sluiten, tab/site verlaten, site verwijderen, manual/idle lock, wachtwoordwijziging en procesafsluiting sluiten het kanaal en verwijderen de autorisatie. Een nieuw terminal-id vereist altijd opnieuw beide wachtwoorden; oude IPC-calls worden geweigerd.
- App- en SSH-passwordstrings worden aan Rust-zijde direct in zeroizing wrappers geplaatst. Het SSH-wachtwoord wordt onmiddellijk na de SSH-authenticatiepoging overschreven en nooit opgeslagen in SQLite, de OS-credentialstore, audit-events of het foutenlog. De frontend houdt beide velden alleen lokaal in het unlockcomponent en leegt ze vóór de asynchrone IPC-call terugkeert.
- De ingestelde WordPress-root wordt met een backend-opgebouwde, POSIX-gequote check gevalideerd. Een ontbrekende directory is een duidelijke fout; de terminal valt niet stil terug naar de home-directory.
- Eén worker bezit gedurende de sessie één SSH-connection en één `xterm-256color` PTY/shellkanaal. Bytes worden live in beide richtingen gestreamd; daardoor blijven `cd`, environment en foreground-processen behouden. Ctrl+C gaat als byte `0x03` naar de PTY en vensterwijzigingen sturen een PTY-resize.
- xterm.js verwerkt ANSI- en terminal-controlsequenties als terminaldata en gebruikt geen `v-html`. Serveroutput blijft niet-vertrouwd en kan geen frontend-HTML uitvoeren. De scrollback is lokaal begrensd.
- De waarschuwing “Geavanceerde terminal” toont de concrete site en moet eenmaal lokaal worden bevestigd. Boven de terminal blijven website, SSH-user, host, poort, startpad en verbindingsstatus zichtbaar.
- Terminalcommandtekst, wachtwoorden, lokale history en output worden niet persistent opgeslagen en komen ook bij een terminalfout niet in het SQLite-foutenlog. De server kan volgens zijn eigen shellconfiguratie remote history bijhouden; de app verandert dat beleid niet.
- `wp-cli-commands.json` is uitsluitend niet-uitvoerbare helpdata. Autocomplete wordt lokaal geactiveerd wanneer de eenvoudige actuele nieuwe regel met `wp` begint. Zij verandert de vrije shellrechten niet en parseert in versie 1 geen complexe chained shell-AST.

De oude gecontroleerde WP-CLI argv-executor blijft architectonisch gescheiden en kan voor afgebakende applicatieflows zijn eigen validatie/risicobeleid gebruiken. Hij vormt geen beperking op de interactieve Terminal.

## Dreigingsscenario's

### Iemand gebruikt tijdelijk mijn ontgrendelde computer

Die persoon kan gewone appinformatie mogelijk zien totdat manual/idle lock optreedt, maar kan de interactieve Terminal niet openen zonder zowel het app-wachtwoord opnieuw te kennen als het SSH-wachtwoord van de geselecteerde website. Vergrendel ook Windows wanneer je wegloopt; een al gestarte managed operatie kan afronden.

### Een aanvaller gokt een fout app-wachtwoord bij Terminalunlock

De backend registreert een geredigeerd security-auditevent, trekt de volledige app-sessie onmiddellijk in, verwijdert alle tijdelijke Terminalrechten en sluit alle shells. De aanvaller kan daarna ook geen protected site- of SSH-command meer uitvoeren zonder opnieuw normaal in te loggen.

### Een aanvaller kent slechts één van beide Terminalwachtwoorden

Met alleen het app-wachtwoord blijft de SSH-passwordstap gesloten. Met alleen het SSH-wachtwoord ontstaat geen geldige site- en sessiegebonden challenge. Beide controles en de host-keyverificatie moeten in dezelfde korte flow slagen.

### De frontend roept rechtstreeks een backendcommand aan

De visuele login is niet de beveiligingsgrens. Iedere niet-publieke Tauri-command controleert de geheugensessie in Rust voordat sitegegevens worden gelezen of een remote actie start. Een ontbrekende, verlopen of vervangen token wordt geweigerd.

### Een checksum-bestandsnaam bevat `; rm -rf /`, quotes of traversal

Bestandsverwijdering gebruikt geen shellconcatenatie. De frontend levert alleen een finding-id, waarna SFTP, padvalidatie, canonicalisatie, root-containment en bestandstypecontroles bepalen of één specifiek bestand mag worden verwijderd.

### Een gecompromitteerde WordPress-site retourneert gemanipuleerde data

De backend valideert identifiers, slugs, versies, locales en paden, begrenst output en previewgrootte en parseert naar typed modellen. Remote tekst wordt niet als HTML of command uitgevoerd. Ongeldige output laat de betreffende controle falen in plaats van een beheeractie te verbreden.

### Een bestandspreview bevat kwaadaardige HTML, SVG of JavaScript

Preview is read-only en de oorspronkelijke inhoud wordt nooit als code uitgevoerd. Highlight.js escaped de bron vóór het genereren van markup. Markdown heeft raw HTML uitgeschakeld en staat voor openen alleen HTTP(S)-links toe. SVG wordt gesaneerd en daarna als lokale data-URL in een afbeeldingselement geplaatst; rasterdata gebruikt alleen geallowliste image-MIME-types. Binaire afbeeldingen krijgen in Raw uitsluitend een lokale tekst-/hexanalyse. Geen van deze weergaven bewijst dat een bestand veilig is.

### Volledige fysieke of OS-compromittering

De applicatielogin en dubbele Terminalverificatie helpen tegen ongeautoriseerd gebruik van een achtergelaten of tijdelijk ontgrendelde app. Zeroization verkort de levensduur van plaintext secrets, maar biedt geen absolute bescherming wanneer een aanvaller het Windows-account, administratorrechten, debugger, keylogger, het app-proces/geheugen, de lokale database, keybestanden of de credential store volledig beheerst. JavaScript- en OS-runtimekopieën zijn bovendien niet betrouwbaar volledig te overschrijven. Gebruik daarom Windows-schijfversleuteling, een vergrendeld OS-account, passende keypermissies en zo beperkt mogelijke SSH-/WordPress-rechten.

## Scanbeperkingen

Checks rapporteren uitsluitend wat werkelijk gecontroleerd is. De UI gebruikt daarom “Geen aandachtspunten gevonden in de uitgevoerde controles” en nooit “100% veilig”. Een checksum vergelijkt WordPress-distributiebestanden, maar is geen complete malware- of configuratiescan. Recente of ongebruikelijke bestanden worden als aandachtspunt beschreven en nooit stil automatisch verwijderd.

## Kwetsbaarheid melden

Open geen publiek issue met credentials, hostnamen, databasebackups of volledige logs. Deel een minimale, geredigeerde reproductie rechtstreeks met de repositorybeheerder.
