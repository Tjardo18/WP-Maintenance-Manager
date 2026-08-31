# Architectuur

## Grenzen

```text
Vue UI → typed TypeScript service → smalle Tauri commands
                                      ↓
                               backend auth gate
                                      ↓
SQLite repository ← application services → scan / users / core / maintenance
                                              ↓
credential store ← SSH adapter → remote command catalog → WP-CLI
                               ↘ begrensde SFTP ↘ HTTP health check
```

De frontend maakt nooit SQL- of remote commando's. IPC gebruikt expliciete DTO's. De backend accepteert uitsluitend catalogusacties en valideert ieder dynamisch argument opnieuw, ook als het oorspronkelijk uit WP-CLI kwam.

## Frontend

Vue 3, Vue Router, Pinia en TypeScript vormen de interface. `src/services/tauri.ts` is de enige IPC-toegang. Een gewone browser gebruikt duidelijk fictieve `.test`-fixtures; in Tauri worden die nooit gebruikt.

## Backend

De Rust-backend wordt opgesplitst in domeinmodellen, SQLite-repositories, runtime-authenticatie, credentialopslag, SSH-adapter, commandcatalogus, checksum-bestandsservice, userservice, scan-/update-engine en maintenance-/core-orchestratie. De SSH-adapter is een trait zodat tests alleen mocks en fixtures gebruiken. Timestamps worden als UTC/RFC 3339 opgeslagen en lokaal geformatteerd in Vue.

## Beslissingen

- Tauri 2 zonder shell-plugin: alleen Rust mag remote acties uitvoeren.
- De applicatielogin gebruikt een Argon2id-hash in SQLite en één random sessie in backendgeheugen. Ieder niet-publiek Tauri-command autoriseert opnieuw; restart, idle lock, manual lock en wachtwoordwijziging wissen de sessie.
- SQLite met normale migrations en foreign keys.
- OS credential store voor passwords/passphrases; een keybestand blijft op zijn bestaande lokale pad.
- Host-key-pinning is verplicht vóór authenticatie. Een gewijzigde fingerprint blokkeert de verbinding.
- Remote scanoutput wordt begrensd en direct naar typed resultaten geparsed.
- Corechecksums draaien vanuit het expliciete WordPress-pad met `--include-root`. Findings krijgen persistente UUID's en typed statussen, zodat bestandsacties alleen naar de nieuwste finding kunnen verwijzen.
- Checksum-preview/delete is een afzonderlijke SFTP-capability zonder vrij pad-IPC. Root/doel worden gecanonicaliseerd; symlinks, niet-reguliere bestanden, configuratie en `wp-content` worden geweigerd en metadata wordt vlak vóór de actie herbevestigd.
- WordPress-usermutaties gebruiken live users/rollen, numerieke ID's, een laatste-admin guard en huidige-site-semantiek op Multisite.
- Core repair en update delen preflight, backup, post-checks, progress-events en maintenance persistence, maar hebben verschillende typed mutaties. Repair gebruikt dezelfde versie met `--skip-content`; update gebruikt een expliciete live gedetecteerde doelversie en vervolgt met database- en taalupdates.
- Een onderhoudsrun stopt vóór mutaties wanneer preflight of databasebackup faalt.
- Database-export gebruikt uitsluitend een backend-gegenereerde naam onder `/tmp`, downloadt via SFTP naar een gzipbestand in de app-datamap en valideert het pad opnieuw voordat remote cleanup wordt toegestaan.
- De homepagecheck volgt maximaal vijf redirects en rapporteert bereikbaarheid, HTTP-status en globale reactietijd zonder bredere beschikbaarheidsclaim.
- Bulkscans starten centraal maximaal 1–5 workers. Annuleren voorkomt nieuwe read-only scans; reeds actieve scans mogen veilig afronden en een fout van één site blokkeert de overige sites niet.
- Scanruns blijven volledig in SQLite bewaard; de detailweergave kan de 50 recentste scans met checks en findings heropenen.
- Audit-events registreren authenticatie en handmatige destructieve acties met IDs/status/categorie, nooit credentials, sessietokens of previewinhoud.
- SSH-logging bevat alleen site-id, catalogusactie, UTC-start/eindtijd, duur, status, exitcode of foutcategorie. Commandostrings en remote output worden niet gelogd.
