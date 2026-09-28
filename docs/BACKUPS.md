# Databaseback-ups

Dit document beschrijft de huidige implementatie van databaseback-ups in WP Maintenance Manager `0.13.0-beta.1`. Het gaat uitsluitend om logische WordPress-database-exports; websitebestanden, uploads, plugins, thema's, `wp-config.php` en serverconfiguratie zitten niet in deze back-up.

## Samenvatting

| Onderwerp | Huidig gedrag |
|---|---|
| Wanneer | Automatisch vóór een volledige onderhoudsrun, WordPress-core-update of core-reparatie. Er is nog geen losse knop om alleen een back-up te maken. |
| Definitieve opslag | Lokaal op de Windows-computer waarop de app draait. |
| Tijdelijke opslag | Tijdens het exporteren kort op de webserver onder `/tmp`; na een geslaagde overdracht wordt dit bestand verwijderd. |
| Formaat | Een met gzip gecomprimeerde SQL-export: `.sql.gz`. |
| Retentie | Onbeperkt; de app verwijdert geslaagde lokale back-ups niet automatisch. |
| Terugvinden | Het absolute lokale pad staat in **Onderhoudshistorie**. Er is nog geen openen-, opslaan-als- of downloadknop. |
| Herstellen | Geen ingebouwde herstelfunctie. Herstel gebeurt handmatig met bijvoorbeeld WP-CLI, phpMyAdmin of hostinggereedschap. |
| Herstelbeveiliging | Geen back-upspecifieke controles of bevestigingen in de app, omdat de app geen herstelactie uitvoert. |

## Wanneer wordt een back-up gemaakt?

De app maakt de databaseback-up als verplichte stap vóór:

- een volledige onderhoudsrun;
- het bijwerken van WordPress core via de beveiligde core-updateflow;
- het opnieuw installeren van de huidige officiële WordPress-corebestanden.

De back-up wordt pas gestart nadat de voorafgaande controles zijn geslaagd. Als de back-up niet volledig kan worden gemaakt, gedownload en op de server opgeruimd, stopt de onderhouds- of coreactie vóór de WordPress-mutatie. Een core-update die al actueel blijkt te zijn stopt vóór de back-upstap. Een afzonderlijke plugin-, thema-, taal- of databaseactie buiten de volledige onderhoudsflow maakt niet zelfstandig deze back-up.

## Exacte back-upflow

1. De Rust-backend laat WP-CLI op de geselecteerde WordPress-installatie `wp db export` uitvoeren.
2. WP-CLI schrijft eerst een ongecomprimeerde SQL-export naar een door de backend aangemaakt tijdelijk bestand met het strikte patroon `/tmp/wpmm-XXXXXXXX.sql`. Dit staat buiten de WordPress-documentroot.
3. De app downloadt dit bestand via de bestaande, host-key-gecontroleerde SSH/SFTP-verbinding.
4. Tijdens het downloaden comprimeert de app de SQL-stream lokaal met gzip. De app accepteert maximaal 20 GiB aan ongecomprimeerde brondata.
5. De app probeert het tijdelijke `.sql`-bestand op de server direct te verwijderen. Alleen het exact door de backend toegestane `/tmp/wpmm-XXXXXXXX.sql`-patroon kan door deze cleanupactie worden verwijderd.
6. Na een volledig geslaagde overdracht en servercleanup berekent de app SHA-256 over het lokale `.sql.gz`-bestand en registreert pad, gecomprimeerde bestandsgrootte, hash en aanmaaktijd in SQLite.
7. Pas daarna mag de onderhouds- of coreflow doorgaan.

Als downloaden mislukt, wordt een gedeeltelijke lokale kopie verwijderd. Als de servercleanup niet kan worden bevestigd, verwijdert de app de lokale kopie en stopt de flow. In dat laatste geval, of bij een onverwachte proces-/computeronderbreking, kan uitzonderlijk een tijdelijk `/tmp/wpmm-XXXXXXXX.sql`-bestand op de server of een niet-geregistreerd gedeeltelijk lokaal bestand achterblijven. De app heeft momenteel geen periodieke scavenger voor zulke onderbroken runs.

## Lokale opslaglocatie en bestandsnaam

Op Windows gebruikt Tauri de applicatiedatamap van de ingelogde gebruiker:

```text
%APPDATA%\nl.wpmaintenancemanager.desktop\backups\<site-id>\<UTC-tijd>-<uuid>.sql.gz
```

Dit resolveert normaal naar:

```text
C:\Users\<Windows-gebruiker>\AppData\Roaming\nl.wpmaintenancemanager.desktop\backups
```

Voorbeeld van de naamstructuur:

```text
20260918T123456Z-01234567-89ab-cdef-0123-456789abcdef.sql.gz
```

De map `<site-id>` is de interne UUID van de website. De tijd in de bestandsnaam is UTC. De SQLite-database bewaart alleen de registratie en integriteitsmetadata; de SQL-inhoud zelf staat uitsluitend in het `.sql.gz`-bestand.

## Formaat en vertrouwelijkheid

De inhoud is een logische SQL-export van de database die bij de geconfigureerde WordPress-installatie hoort. Gzip verkleint het bestand, maar versleutelt het niet. Een dump kan persoonsgegevens, gebruikersnamen, wachtwoordhashes, sessies, tokens en plugininstellingen bevatten. Bescherm daarom het Windows-account en de app-datamap, gebruik waar passend schijfversleuteling en deel een back-up nooit als gewone bijlage of publiek bestand.

De opgeslagen SHA-256-hash kan later aantonen of de lokale gecomprimeerde kopie sinds registratie is gewijzigd, maar de app heeft nog geen knop om die hash opnieuw te controleren en toont hem niet in de interface.

## Bewaartermijn en verwijderen

Er is momenteel geen bewaartermijn, maximumaantal of automatische opschoning voor geslaagde lokale databaseback-ups. Ze blijven staan totdat de gebruiker ze buiten de app verwijdert of de applicatiedata zelf wordt verwijderd. Het verwijderen van een website uit de app verwijdert de fysieke back-upmap niet. Handmatig verwijderen van een `.sql.gz`-bestand werkt de bestaande historieregistratie niet bij; de onderhoudshistorie kan dan nog een pad tonen naar een bestand dat niet meer bestaat.

Controleer de map daarom periodiek op ouderdom en schijfruimte. Verwijder alleen bestanden waarvan onafhankelijk is vastgesteld dat ze niet meer nodig zijn.

## Terugvinden en downloaden

Open **Onderhoudshistorie**, klap de betreffende run open en kopieer het pad achter **Lokale databasebackup**. Dat pad verwijst al naar de kopie op de eigen computer; downloaden vanaf de website is na een geslaagde run niet meer nodig. De app biedt momenteel geen bestandsbrowser, **Map openen**, **Opslaan als** of exportknop.

## Herstellen

WP Maintenance Manager heeft momenteel geen beheerde restoreflow. De app uploadt de lokale back-up niet, kiest geen doeldatabase, voert geen import uit en controleert of herstelt geen bestanden. Daardoor zijn er ook geen restore-specifieke bevestiging, doelcontrole, automatische verse back-up of rollback in de app.

Een beheerder kan handmatig herstellen met WP-CLI, phpMyAdmin, het hostingpanel of een databaseclient. Een veilige algemene werkwijze is:

1. Controleer dat de back-up bij de bedoelde website en datum hoort.
2. Maak eerst een nieuwe back-up van de actuele database en bewaar die afzonderlijk.
3. Plan onderhoud en voorkom gelijktijdige writes door bezoekers, cronjobs of beheerders.
4. Decomprimeer `.sql.gz` naar `.sql` wanneer het gekozen importgereedschap geen gzip accepteert.
5. Plaats het SQL-bestand alleen tijdelijk op een privélocatie buiten de documentroot.
6. Importeer naar de gecontroleerde doeldatabase. Met WP-CLI is de algemene vorm bijvoorbeeld:

   ```bash
   wp --path='/absoluut/pad/naar/wordpress' db import '/private/pad/backup.sql'
   ```

7. Verwijder de tijdelijke serverkopie van het SQL-bestand.
8. Controleer database, homepage, beheerlogin en relevante functionaliteit en leeg zo nodig caches.
9. Voer in WP Maintenance Manager opnieuw een scan uit, zodat actuele websitegegevens en momentopnames worden opgebouwd.

Of phpMyAdmin een `.sql.gz` direct accepteert en welke uploadlimieten gelden, hangt af van de hostingomgeving. Herstel naar een andere domeinnaam of installatie kan aanvullende URL-, configuratie- en serialisatieaanpassingen vereisen en valt buiten de huidige appflow.

De geavanceerde Terminal kan na de normale app- en SSH-reauthenticatie een handmatig WP-CLI-importcommando uitvoeren, maar uploadt het lokale back-upbestand niet en biedt geen extra restorebevestiging. Dit blijft een vrije shellactie onder de rechten en verantwoordelijkheid van het gekoppelde SSH-account.
