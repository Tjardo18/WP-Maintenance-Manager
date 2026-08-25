# Security

## Threat model

De app beheert gevoelige SSH-toegang tot meerdere websites. Belangrijkste risico's zijn gestolen credentials, command injection, een gewijzigde SSH-serveridentiteit, onbedoelde mutaties, gelekte backups en misleidende scanclaims.

## Bescherming

- **Credentials:** secrets staan niet in SQLite, logs, fixtures of IPC-responses. Alleen een opaque credentialreferentie wordt als metadata bewaard. Private keys worden niet geïmporteerd; standaard bewaart de app alleen het lokale bestandspad.
- **Hostidentiteit:** de eerste fingerprint moet zichtbaar worden geaccepteerd en wordt daarna gepind. Een mismatch is een blokkerende fout, nooit een stille heracceptatie.
- **Command injection:** er bestaat geen arbitrary-command-IPC. WordPress-paden, dagenwaarden en slugs worden centraal gevalideerd en POSIX-argumenten centraal ge-escaped.
- **Tauri-grens:** de webview krijgt alleen core-permissies en toegang tot de native bestanddialoog. Er is geen shell- of generieke filesystempermissie. De CSP staat geen remote scripts, fonts of pagina-inhoud toe.
- **Logging:** alleen site-id, catalogusactie, tijden, status en foutcategorie worden gelogd. Secrets en volledige remote output worden niet gelogd.
- **Backups:** een zelf gegenereerde remote tijdelijke naam buiten de documentroot wordt na download verwijderd. Lokale backups worden gecomprimeerd en niet door Git gevolgd. Een mislukte backup stopt standaardonderhoud.

## Scanbeperkingen

Checks rapporteren uitsluitend wat werkelijk gecontroleerd is. De UI gebruikt daarom “Geen aandachtspunten gevonden in de uitgevoerde controles” en nooit “100% veilig”. Recente of ongebruikelijke bestanden worden als aandachtspunt beschreven en nooit automatisch verwijderd.

## Kwetsbaarheid melden

Open geen publiek issue met credentials, hostnamen of logs. Deel een minimale, geredigeerde reproductie rechtstreeks met de repositorybeheerder.
