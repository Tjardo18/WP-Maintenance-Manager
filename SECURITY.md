# Security

## Threat model

De app beheert gevoelige SSH-toegang tot meerdere websites. Belangrijkste risico's zijn ongeautoriseerd lokaal gebruik, gestolen credentials, command injection, een gewijzigde SSH-serveridentiteit, onbedoelde mutaties, gemanipuleerde remote data en gelekte backups. WordPress-hosts en alle data die zij terugsturen worden als niet-vertrouwd behandeld.

## Applicatielogin en sessies

- Bij de eerste start is een applicatiewachtwoord van minimaal 12 tekens verplicht. Alleen een per installatie gezouten Argon2id-hash staat in SQLite; het leesbare wachtwoord wordt niet opgeslagen.
- De backend houdt maximaal één cryptografisch willekeurige sessie in geheugen bij en vergelijkt alleen een SHA-256-tokenhash constant-time. Een nieuwe login vervangt de vorige sessie; een procesherstart verliest de sessie altijd.
- Alle Tauri-commands voor sitegegevens, instellingen, scans en mutaties roepen eerst dezelfde backend-authorisatie aan. Alleen status, first-run setup en login zijn publiek; status retourneert geen gevoelige data.
- Handmatig vergrendelen, idle timeout en wachtwoordwijziging maken de sessie ongeldig. De standaard idle timeout is 15 minuten en de backend controleert hem onafhankelijk van de UI.
- Herhaalde mislukte logins krijgen een oplopende vertraging. Login-, lock- en wachtwoordwijzigingen worden zonder wachtwoord of sessietoken geaudit.
- Een reeds geautoriseerde backendactie mag na vergrendeling veilig afronden. De lock autoriseert geen nieuwe actie en probeert geen half uitgevoerde remote mutatie terug te draaien.

## Bescherming van remote beheer

- **Credentials:** SSH-secrets staan niet in SQLite, logs, fixtures of IPC-responses. Alleen een opaque credentialreferentie wordt als metadata bewaard. Private keys worden niet geïmporteerd; standaard bewaart de app alleen het lokale bestandspad.
- **Hostidentiteit:** de SHA-256-fingerprint wordt uit de SSH-handshake berekend vóór authenticatie. De eerste fingerprint moet zichtbaar worden geaccepteerd en wordt daarna gepind. Tijdens acceptatie haalt de backend de fingerprint opnieuw op en vergelijkt die met de getoonde waarde. Een mismatch is een blokkerende fout, nooit een stille heracceptatie.
- **Command injection:** er bestaat geen arbitrary-command-IPC en geen terminalveld. De Rust-commandcatalogus bouwt alle commands op; WordPress-paden, versies, locales, dagenwaarden, user-id's, rollen en slugs worden backendmatig gevalideerd en POSIX-argumenten centraal ge-escaped.
- **Remote output:** output heeft per actie een byte-limiet en wordt naar getypeerde resultaten geparsed. Door WP-CLI teruggestuurde slugs en checksum-paden worden opnieuw gevalideerd. De Vue-interface gebruikt tekstinterpolatie en voert remote HTML niet uit.
- **Tauri-grens:** de webview krijgt alleen core-permissies en toegang tot de native bestanddialoog. Er is geen shell- of generieke filesystempermissie. De CSP staat geen remote scripts, fonts of pagina-inhoud toe.
- **Logging en scanmeldingen:** SSH-logging bevat alleen site-id, catalogusactie, tijden, status en foutcategorie. Sessietokens, credentials, commandostrings, previews en volledige remote output worden niet gelogd. Technische details van mislukte scanchecks worden vóór opslag begrensd, control-charactervrij gemaakt en regels met herkenbare secretmarkers worden weggelaten.
- **Backups:** een backend-gegenereerde remote tijdelijke naam onder `/tmp` blijft buiten de documentroot. Alleen het strikte patroon `/tmp/wpmm-XXXXXXXX.sql` mag via de cleanupactie worden verwijderd. De export wordt via SFTP gestreamd, lokaal gecomprimeerd, begrensd op 20 GB en gehasht. Download én remote cleanup moeten slagen voordat onderhoud doorgaat.

## Checksum-bestandsacties

Preview en verwijdering accepteren geen pad uit de frontend, maar alleen een site-id en finding-id. De finding moet `unexpected` zijn en uit de nieuwste checksumscan van precies die site komen. De backend haalt het opgeslagen pad op, weigert absolute/traversal/control-paden, `wp-content`, configuratiepaden, mappen en symlinks, bepaalt root en doel via SFTP `realpath`, controleert containment en vergelijkt metadata nogmaals vlak vóór openen of unlinken.

Een preview is alleen-lezen, maximaal 256 KB en verschijnt als platte tekst; binaire of ongeldige UTF-8-data wordt niet als tekst getoond. Bulkverwijdering valideert ieder item afzonderlijk, rapporteert gedeeltelijke failures en voert na geslaagde deletes precies één nieuwe checksumscan uit. Dit is bewust geen algemene filemanager. Door beperkingen van de gebruikte SFTP-API blijft de dubbele metadata-/padcontrole een best-effort bescherming tegen zeer kleine racevensters; de app claimt geen filesystem-transactie.

## WordPress users en core

Usermutaties laden de actuele users, rollen en Multisite-status vlak vóór uitvoering opnieuw. Remote commands gebruiken numerieke user-id's. De backend blokkeert verwijdering of degradatie van de laatste Administrator, eist exact één contentkeuze en voegt nooit `--network` toe.

Core repair en core update zijn aparte, geauthenticeerde flows. Repair gebruikt exact de gedetecteerde huidige versie en locale met `--force --skip-content`; `latest` is verboden en onbekende bestanden worden niet verwijderd. Een update gebruikt een gevalideerde, live gedetecteerde doelversie. Beide herhalen preflight, stoppen bij een mislukte verplichte databasebackup en voeren checksum-, versie-, database-, homepage- en updatecontroles uit. Een repair beschermt `wp-content`, maar is geen volledige bestandsrollback.

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
