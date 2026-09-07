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
- **Twee execution modes:** normale beheeracties blijven een vaste Rust-commandcatalogus gebruiken en valideren alle dynamische waarden. De afzonderlijke Advanced Terminal is bewust een vrije, interactieve SSH-shell. Daar is arbitrary shell execution het productdoel; de securitygrens bestaat uit app-login, backend-sessiecontrole, host-key-pinning, de geselecteerde siteconfiguratie en uiteindelijk de rechten van het remote SSH-account.
- **Remote output:** output heeft per actie een byte-limiet en wordt naar getypeerde resultaten geparsed. Door WP-CLI teruggestuurde slugs en checksum-paden worden opnieuw gevalideerd. De Vue-interface gebruikt tekstinterpolatie en voert remote HTML niet uit.
- **Tauri-grens:** de webview krijgt alleen core-permissies en toegang tot de native bestanddialoog. Er is geen shell- of generieke filesystempermissie. De CSP staat geen remote scripts, fonts of pagina-inhoud toe.
- **Logging en scanmeldingen:** het persistente SQLite-foutenlog bevat alleen een error-ID, tijden, categorie, site, bekende applicatieactie, veilige technische details, cause-chain, duur/exitcode en retry-indicatie. Sessietokens, credentials, terminalcommandostrings, previews en volledige remote output worden niet gelogd. Details worden begrensd, control-charactervrij gemaakt en regels met herkenbare secretmarkers worden vóór opslag weggelaten. Records ouder dan 30 dagen en records boven de nieuwste 10.000 worden verwijderd.
- **Backups:** een backend-gegenereerde remote tijdelijke naam onder `/tmp` blijft buiten de documentroot. Alleen het strikte patroon `/tmp/wpmm-XXXXXXXX.sql` mag via de cleanupactie worden verwijderd. De export wordt via SFTP gestreamd, lokaal gecomprimeerd, begrensd op 20 GB en gehasht. Download én remote cleanup moeten slagen voordat onderhoud doorgaat.

## Checksum-bestandsacties

Preview en verwijdering accepteren geen pad uit de frontend, maar alleen een site-id en finding-id. De finding moet `unexpected` zijn en uit de nieuwste checksumscan van precies die site komen. De backend haalt het opgeslagen pad op, weigert absolute/traversal/control-paden, `wp-content`, configuratiepaden, mappen en symlinks, bepaalt root en doel via SFTP `realpath`, controleert containment en vergelijkt metadata nogmaals vlak vóór openen of unlinken.

Een preview is alleen-lezen, maximaal 256 KB en verschijnt als platte tekst; binaire of ongeldige UTF-8-data wordt niet als tekst getoond. Bulkverwijdering valideert ieder item afzonderlijk, rapporteert gedeeltelijke failures en voert na geslaagde deletes precies één nieuwe checksumscan uit. Dit is bewust geen algemene filemanager. Door beperkingen van de gebruikte SFTP-API blijft de dubbele metadata-/padcontrole een best-effort bescherming tegen zeer kleine racevensters; de app claimt geen filesystem-transactie.

## WordPress users en core

Usermutaties laden de actuele users, rollen en Multisite-status vlak vóór uitvoering opnieuw. Remote commands gebruiken numerieke user-id's. De backend blokkeert verwijdering of degradatie van de laatste Administrator, eist exact één contentkeuze en voegt nooit `--network` toe.

Core repair en core update zijn aparte, geauthenticeerde flows. Repair gebruikt exact de gedetecteerde huidige versie en locale met `--force --skip-content`; `latest` is verboden en onbekende bestanden worden niet verwijderd. Een update gebruikt een gevalideerde, live gedetecteerde doelversie. Beide herhalen preflight, stoppen bij een mislukte verplichte databasebackup en voeren checksum-, versie-, database-, homepage- en updatecontroles uit. Een repair beschermt `wp-content`, maar is geen volledige bestandsrollback.

## Advanced SSH Terminal

De Terminal is bewust krachtiger dan de voorgedefinieerde beheerknoppen en is alleen bedoeld voor beheerders. Een gebruiker met toegang tot een ontgrendelde Terminal heeft effectief dezelfde serverrechten als het gekoppelde SSH-account. `rm`, `chmod`, `mv`, `bash`, `php`, `mysql`, `curl`, `wp` en shelloperators zijn bewust toegestaan; er is geen app-allowlist en geen confirmation per terminalcommando.

- Openen, schrijven, resizen en sluiten vereisen ieder een geldige backend-appsessie. Een manual/idle lock en wachtwoordwijziging sluiten alle terminalkanalen en blokkeren verdere invoer.
- De backend haalt host, poort, gebruiker, credential en startpad uit de gekozen site. SSH-authenticatie en de reeds gepinde host key worden opnieuw gecontroleerd voordat een PTY wordt geopend.
- De ingestelde WordPress-root wordt met een backend-opgebouwde, POSIX-gequote check gevalideerd. Een ontbrekende directory is een duidelijke fout; de terminal valt niet stil terug naar de home-directory.
- Eén worker bezit gedurende de sessie één SSH-connection en één `xterm-256color` PTY/shellkanaal. Bytes worden live in beide richtingen gestreamd; daardoor blijven `cd`, environment en foreground-processen behouden. Ctrl+C gaat als byte `0x03` naar de PTY en vensterwijzigingen sturen een PTY-resize.
- xterm.js verwerkt ANSI- en terminal-controlsequenties als terminaldata en gebruikt geen `v-html`. Serveroutput blijft niet-vertrouwd en kan geen frontend-HTML uitvoeren. De scrollback is lokaal begrensd.
- De waarschuwing “Geavanceerde terminal” toont de concrete site en moet eenmaal lokaal worden bevestigd. Boven de terminal blijven website, SSH-user, host, poort, startpad en verbindingsstatus zichtbaar.
- Terminalcommandtekst, lokale history en output worden niet persistent opgeslagen en komen ook bij een terminalfout niet in het SQLite-foutenlog. De server kan volgens zijn eigen shellconfiguratie remote history bijhouden; de app verandert dat beleid niet.
- `wp-cli-commands.json` is uitsluitend niet-uitvoerbare helpdata. Autocomplete wordt lokaal geactiveerd wanneer de eenvoudige actuele nieuwe regel met `wp` begint. Zij verandert de vrije shellrechten niet en parseert in versie 1 geen complexe chained shell-AST.

De oude gecontroleerde WP-CLI argv-executor blijft architectonisch gescheiden en kan voor afgebakende applicatieflows zijn eigen validatie/risicobeleid gebruiken. Hij vormt geen beperking op de interactieve Terminal.

## Dreigingsscenario's

### Iemand gebruikt tijdelijk mijn ontgrendelde computer

Het applicatiewachtwoord, start-locked gedrag, backend-sessiecontrole, handmatige lock en idle auto-lock beperken nieuwe acties. Vergrendel ook Windows wanneer je wegloopt; een al gestarte operatie kan afronden.

### De frontend roept rechtstreeks een backendcommand aan

De visuele login is niet de beveiligingsgrens. Iedere niet-publieke Tauri-command controleert de geheugensessie in Rust voordat sitegegevens worden gelezen of een remote actie start. Een ontbrekende, verlopen of vervangen token wordt geweigerd.

### Een checksum-bestandsnaam bevat `; rm -rf /`, quotes of traversal

Bestandsverwijdering gebruikt geen shellconcatenatie. De frontend levert alleen een finding-id, waarna SFTP, padvalidatie, canonicalisatie, root-containment en bestandstypecontroles bepalen of één specifiek bestand mag worden verwijderd.

### Een gecompromitteerde WordPress-site retourneert gemanipuleerde data

De backend valideert identifiers, slugs, versies, locales en paden, begrenst output en previewgrootte en parseert naar typed modellen. Remote tekst wordt niet als HTML of command uitgevoerd. Ongeldige output laat de betreffende controle falen in plaats van een beheeractie te verbreden.

### Een PHP-preview bevat kwaadaardige HTML of JavaScript

Preview is read-only, wordt nooit uitgevoerd, komt niet in een `v-html`-sink en wordt maximaal als begrensde platte tekst weergegeven. Binaire data krijgt geen tekstpreview.

### Volledige fysieke of OS-compromittering

De applicatielogin helpt tegen ongeautoriseerd gebruik van een achtergelaten of tijdelijk ontgrendelde app. Zij is geen volledige bescherming wanneer een aanvaller het Windows-account, het app-proces/geheugen, de lokale database, keybestanden of de credential store volledig beheerst. Gebruik daarom Windows-schijfversleuteling, een vergrendeld OS-account, passende keypermissies en zo beperkt mogelijke SSH-/WordPress-rechten.

## Scanbeperkingen

Checks rapporteren uitsluitend wat werkelijk gecontroleerd is. De UI gebruikt daarom “Geen aandachtspunten gevonden in de uitgevoerde controles” en nooit “100% veilig”. Een checksum vergelijkt WordPress-distributiebestanden, maar is geen complete malware- of configuratiescan. Recente of ongebruikelijke bestanden worden als aandachtspunt beschreven en nooit stil automatisch verwijderd.

## Kwetsbaarheid melden

Open geen publiek issue met credentials, hostnamen, databasebackups of volledige logs. Deel een minimale, geredigeerde reproductie rechtstreeks met de repositorybeheerder.
