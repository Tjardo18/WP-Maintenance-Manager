# Architectuur

## Grenzen

```text
Vue UI → typed TypeScript service → smalle Tauri commands
                                      ↓
SQLite repository ← application services → maintenance engine
                                              ↓
credential store ← SSH adapter → remote command catalog → WP-CLI
                               ↘ backup/SFTP   ↘ HTTP health check
```

De frontend maakt nooit SQL- of remote commando's. IPC gebruikt expliciete DTO's. De backend accepteert uitsluitend catalogusacties en valideert ieder dynamisch argument opnieuw, ook als het oorspronkelijk uit WP-CLI kwam.

## Frontend

Vue 3, Vue Router, Pinia en TypeScript vormen de interface. `src/services/tauri.ts` is de enige IPC-toegang. Een gewone browser gebruikt duidelijk fictieve `.test`-fixtures; in Tauri worden die nooit gebruikt.

## Backend

De Rust-backend wordt opgesplitst in domeinmodellen, SQLite-repositories, credentialopslag, SSH-adapter, commandcatalogus, scan-engine, update-engine en maintenance-orchestratie. De SSH-adapter is een trait zodat tests alleen fixtures gebruiken. Timestamps worden als UTC/RFC 3339 opgeslagen en lokaal geformatteerd in Vue.

## Beslissingen

- Tauri 2 zonder shell-plugin: alleen Rust mag remote acties uitvoeren.
- SQLite met normale migrations en foreign keys.
- OS credential store voor passwords/passphrases; een keybestand blijft op zijn bestaande lokale pad.
- Host-key-pinning is verplicht vóór authenticatie. Een gewijzigde fingerprint blokkeert de verbinding.
- Remote scanoutput wordt begrensd en direct naar typed resultaten geparsed.
- Een onderhoudsrun stopt vóór mutaties wanneer preflight of databasebackup faalt.
