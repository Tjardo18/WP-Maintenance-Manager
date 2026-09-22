use crate::{
    database::{Database, utc_now},
    error::AppError,
    models::{
        DatabaseCleanupImpact, DatabaseCleanupOption, DatabaseCleanupRequest,
        DatabaseCleanupResult, DatabaseCleanupTarget,
    },
};
use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub struct DatabaseCleanupExecution {
    pub result: DatabaseCleanupResult,
    pub site_ids: Vec<String>,
    pub credential_references: Vec<String>,
}

impl Database {
    pub fn database_cleanup_options(&self) -> Result<Vec<DatabaseCleanupOption>, AppError> {
        let connection = self.connect()?;
        SUPPORTED_TARGETS
            .iter()
            .copied()
            .map(|target| cleanup_option(&connection, target))
            .collect()
    }

    pub fn execute_database_cleanup(
        &self,
        request: &DatabaseCleanupRequest,
    ) -> Result<DatabaseCleanupExecution, AppError> {
        if request.confirmation.trim() != request.target.confirmation_phrase() {
            return Err(AppError::validation(format!(
                "De bevestiging voor tabel '{}' is niet correct.",
                request.target.table_name()
            )));
        }

        let mut connection = self.connect()?;
        let transaction = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
        let option = cleanup_option(&transaction, request.target)
            .map_err(|error| cleanup_step_error("het vooraf tellen van de gegevens", error))?;
        if request.preview_token != option.preview_token {
            return Err(AppError::validation(
                "De database is gewijzigd sinds deze aantallen zijn getoond. Vernieuw het overzicht en controleer de bijgewerkte gevolgen voordat je opnieuw bevestigt.",
            ));
        }
        let (site_ids, credential_references) = if request.target == DatabaseCleanupTarget::Sites {
            let site_ids = database_cleanup_site_ids(&transaction).map_err(|error| {
                cleanup_step_error("het inventariseren van actieve websitekoppelingen", error)
            })?;
            let credential_references =
                distinct_site_credential_references(&transaction).map_err(|error| {
                    cleanup_step_error("het inventariseren van opgeslagen SSH-credentials", error)
                })?;
            (site_ids, credential_references)
        } else {
            (Vec::new(), Vec::new())
        };

        execute_cleanup_statements(&transaction, request.target)
            .map_err(|error| cleanup_step_error("het verwijderen van de records", error))?;
        ensure_cleanup_integrity(&transaction, request.target)
            .map_err(|error| cleanup_step_error("de database-integriteitscontrole", error))?;
        transaction
            .commit()
            .map_err(AppError::from)
            .map_err(|error| {
                cleanup_step_error("het definitief opslaan van de transactie", error)
            })?;

        let mut warnings = Vec::new();
        if let Err(error) = connection.execute_batch("PRAGMA wal_checkpoint(TRUNCATE); VACUUM;") {
            eprintln!("database cleanup compaction failed: {error}");
            warnings.push("De records zijn verwijderd, maar het SQLite-bestand kon niet direct worden verkleind. De vrijgekomen ruimte blijft wel beschikbaar voor hergebruik door de app.".into());
        }

        Ok(DatabaseCleanupExecution {
            result: DatabaseCleanupResult {
                target: request.target,
                table_name: request.target.table_name().into(),
                status: if warnings.is_empty() {
                    "success".into()
                } else {
                    "completed_with_warnings".into()
                },
                impacts: option.impacts,
                warnings,
                completed_at: utc_now(),
            },
            site_ids,
            credential_references,
        })
    }
}

fn cleanup_step_error(step: &str, error: AppError) -> AppError {
    AppError {
        error_id: None,
        category: "database_cleanup".into(),
        user_message: format!(
            "Database opschonen is mislukt tijdens {step}. De transactie is teruggedraaid; er zijn geen gedeeltelijke databasewijzigingen opgeslagen."
        ),
        technical_details: error.technical_details.or(Some(error.user_message)),
        retryable: true,
    }
}

const SUPPORTED_TARGETS: [DatabaseCleanupTarget; 6] = [
    DatabaseCleanupTarget::Sites,
    DatabaseCleanupTarget::ScanRuns,
    DatabaseCleanupTarget::SiteSnapshots,
    DatabaseCleanupTarget::MaintenanceRuns,
    DatabaseCleanupTarget::ErrorLogs,
    DatabaseCleanupTarget::AuditEvents,
];

fn cleanup_option(
    connection: &Connection,
    target: DatabaseCleanupTarget,
) -> Result<DatabaseCleanupOption, AppError> {
    let (title, description, stored_data, dependencies, cleanup_effect) = match target {
        DatabaseCleanupTarget::Sites => (
            "Websites",
            "Alle websites die aan WP Maintenance Manager zijn toegevoegd.",
            vec![
                "Namen, URL's, SSH-servergegevens, WordPress-paden en gepinde serveridentiteiten.",
                "Relaties tussen rootwebsites, subdomeinen en subdirectories.",
                "Actuele versie-, scan-, update- en kwetsbaarheidssamenvattingen.",
            ],
            vec![
                "Alle scans, controles, bevindingen en actuele kwetsbaarheidsstatussen van deze websites.",
                "Alle snapshots, vergelijkingen, uitzonderingen en vertrouwde bestanden.",
                "Alle onderhoudshistorie, onderhoudsstappen en lokale back-upregistraties.",
                "Alle sitegebonden fout- en auditregels en opgeslagen SSH-credentials in Windows.",
                "Actieve SSH-terminals voor deze websites worden na een geslaagde opschoonactie gesloten.",
            ],
            "Alle websites en uitsluitend daaraan gekoppelde gegevens worden atomair uit SQLite verwijderd. De globale app-instellingen, authenticatie, migratiehistorie, Wordfence-feed en niet-sitegebonden logs blijven behouden. Geregistreerde .sql.gz-back-upbestanden op schijf worden niet verwijderd.",
        ),
        DatabaseCleanupTarget::ScanRuns => (
            "Scanhistorie",
            "Alle uitgevoerde websitescans en de resultaten van iedere controle.",
            vec![
                "Start- en eindtijd, eindstatus en afbreekstatus van iedere scan.",
                "Uitgevoerde controles, bevindingen en technische scandetails.",
            ],
            vec![
                "Scancontroles en bevindingen worden via foreign-key-cascades verwijderd.",
                "De actuele kwetsbaarheidsstatus en scansamenvatting van iedere website worden gereset.",
                "Snapshots blijven bestaan, maar hun verwijzing naar de verwijderde scan wordt losgekoppeld.",
            ],
            "De scanhistorie wordt volledig geleegd. Websites, updates, software-inventaris, uitzonderingen, vertrouwde bestanden en snapshots blijven behouden.",
        ),
        DatabaseCleanupTarget::SiteSnapshots => (
            "Snapshots en wijzigingen",
            "Alle opgeslagen momentopnames van websiteconfiguratie en de berekende verschillen daartussen.",
            vec![
                "Versies, plugins, thema's, gebruikers, configuratie, cron en bestandsstatus op een meetmoment.",
                "Vergelijkingen, afzonderlijke wijzigingen, baseline- en gezien-statussen.",
            ],
            vec![
                "Alle snapshotvergelijkingen, sectiestatussen en wijzigingsregels worden verwijderd.",
                "De actuele en baseline-snapshotwijzers van alle websites worden gereset.",
            ],
            "Alle snapshots en daarop gebaseerde wijzigingshistorie worden verwijderd. Scans, websites en onderhoudsrecords blijven behouden.",
        ),
        DatabaseCleanupTarget::MaintenanceRuns => (
            "Onderhoudshistorie",
            "Alle geregistreerde onderhouds- en updateacties voor websites.",
            vec![
                "Tijden, status, duur en versie-informatie van onderhoudsruns.",
                "Afzonderlijke onderhoudsstappen en metadata van gemaakte databaseback-ups.",
            ],
            vec![
                "Onderhoudsstappen en back-upregistraties worden via foreign-key-cascades verwijderd.",
                "Snapshots blijven behouden, maar hun verwijzing naar de onderhoudsrun wordt losgekoppeld.",
                "De .sql.gz-back-upbestanden zelf blijven op de computer staan en worden niet verwijderd.",
            ],
            "De onderhoudshistorie en back-upregistraties worden verwijderd en de datum van het laatste onderhoud wordt bij iedere website gereset. Lokale back-upbestanden blijven behouden.",
        ),
        DatabaseCleanupTarget::ErrorLogs => (
            "Foutenlog",
            "Alle lokaal opgeslagen technische fouten en waarschuwingen.",
            vec![
                "Fout-ID's, tijdstippen, categorieën, samenvattingen en begrensde technische details.",
            ],
            vec![
                "Er zijn geen afhankelijke tabellen. Alleen de foutregels zelf worden verwijderd.",
            ],
            "Het volledige foutenlog wordt geleegd. Websites, scans en instellingen blijven ongewijzigd.",
        ),
        DatabaseCleanupTarget::AuditEvents => (
            "Auditlog",
            "De lokale beveiligings- en actiehistorie van de app.",
            vec![
                "Geslaagde en mislukte beheeracties, doelen en tijdstippen zonder wachtwoorden of andere geheimen.",
            ],
            vec![
                "Er zijn geen afhankelijke tabellen. Alleen de auditregels zelf worden verwijderd.",
            ],
            "Het volledige auditlog wordt geleegd en kan daarna niet worden gereconstrueerd. De opschoonactie zelf wordt daarom niet opnieuw als auditregel toegevoegd.",
        ),
    };
    let impacts = cleanup_impacts(connection, target)?;
    let record_count = impacts
        .iter()
        .find(|impact| impact.key == target.table_name())
        .map_or(0, |impact| impact.count);
    let preview_token = cleanup_preview_token(target, &impacts);
    Ok(DatabaseCleanupOption {
        target,
        table_name: target.table_name().into(),
        title: title.into(),
        description: description.into(),
        stored_data: stored_data.into_iter().map(str::to_owned).collect(),
        dependencies: dependencies.into_iter().map(str::to_owned).collect(),
        cleanup_effect: cleanup_effect.into(),
        record_count,
        impacts,
        preview_token,
        confirmation_mode: if target.typed_confirmation() {
            "typed".into()
        } else {
            "dialog".into()
        },
        confirmation_phrase: target.confirmation_phrase().into(),
        irreversible: true,
    })
}

fn cleanup_preview_token(
    target: DatabaseCleanupTarget,
    impacts: &[DatabaseCleanupImpact],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(target.table_name().as_bytes());
    for impact in impacts {
        hasher.update([0]);
        hasher.update(impact.key.as_bytes());
        hasher.update([0]);
        hasher.update(impact.count.to_le_bytes());
        hasher.update([0]);
        hasher.update(impact.effect.as_bytes());
    }
    hex_digest(&hasher.finalize())
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn cleanup_impacts(
    connection: &Connection,
    target: DatabaseCleanupTarget,
) -> Result<Vec<DatabaseCleanupImpact>, AppError> {
    let counts = match target {
        DatabaseCleanupTarget::Sites => vec![
            impact(
                connection,
                "sites",
                "websites",
                "SELECT COUNT(*) FROM sites",
                "verwijderd",
            )?,
            impact(
                connection,
                "scan_runs",
                "scans",
                "SELECT COUNT(*) FROM scan_runs",
                "verwijderd",
            )?,
            impact(
                connection,
                "scan_checks",
                "scancontroles",
                "SELECT COUNT(*) FROM scan_checks",
                "verwijderd",
            )?,
            impact(
                connection,
                "findings",
                "bevindingen",
                "SELECT COUNT(*) FROM findings",
                "verwijderd",
            )?,
            impact(
                connection,
                "site_snapshots",
                "snapshots",
                "SELECT COUNT(*) FROM site_snapshots",
                "verwijderd",
            )?,
            impact(
                connection,
                "snapshot_diffs",
                "snapshotvergelijkingen",
                "SELECT COUNT(*) FROM snapshot_diffs",
                "verwijderd",
            )?,
            impact(
                connection,
                "snapshot_diff_sections",
                "vergelijkingssecties",
                "SELECT COUNT(*) FROM snapshot_diff_sections",
                "verwijderd",
            )?,
            impact(
                connection,
                "snapshot_changes",
                "geregistreerde wijzigingen",
                "SELECT COUNT(*) FROM snapshot_changes",
                "verwijderd",
            )?,
            impact(
                connection,
                "finding_exceptions",
                "uitzonderingen",
                "SELECT COUNT(*) FROM finding_exceptions",
                "verwijderd",
            )?,
            impact(
                connection,
                "trusted_files",
                "vertrouwde bestanden",
                "SELECT COUNT(*) FROM trusted_files",
                "verwijderd",
            )?,
            impact(
                connection,
                "maintenance_runs",
                "onderhoudsrecords",
                "SELECT COUNT(*) FROM maintenance_runs",
                "verwijderd",
            )?,
            impact(
                connection,
                "maintenance_steps",
                "onderhoudsstappen",
                "SELECT COUNT(*) FROM maintenance_steps",
                "verwijderd",
            )?,
            impact(
                connection,
                "backup_records",
                "back-upregistraties",
                "SELECT COUNT(*) FROM backup_records",
                "verwijderd",
            )?,
            impact(
                connection,
                "available_updates",
                "gecachete updates",
                "SELECT COUNT(*) FROM available_updates",
                "verwijderd",
            )?,
            impact(
                connection,
                "software_inventory",
                "software-inventarisregels",
                "SELECT COUNT(*) FROM software_inventory",
                "verwijderd",
            )?,
            impact(
                connection,
                "site_vulnerability_state",
                "actuele kwetsbaarheidsstatussen",
                "SELECT COUNT(*) FROM site_vulnerability_state",
                "verwijderd",
            )?,
            impact(
                connection,
                "site_snapshot_state",
                "actuele snapshotstatussen",
                "SELECT COUNT(*) FROM site_snapshot_state",
                "verwijderd",
            )?,
            impact(
                connection,
                "site_audit_events",
                "sitegebonden auditregels",
                "SELECT COUNT(*) FROM audit_events WHERE site_id IS NOT NULL",
                "verwijderd",
            )?,
            impact(
                connection,
                "site_error_logs",
                "sitegebonden foutregels",
                "SELECT COUNT(*) FROM error_logs WHERE site_id IS NOT NULL",
                "verwijderd",
            )?,
            impact(
                connection,
                "credential_references",
                "opgeslagen SSH-credentials",
                "SELECT COUNT(DISTINCT credential_ref) FROM sites WHERE credential_ref IS NOT NULL",
                "verwijderd",
            )?,
            impact(
                connection,
                "local_backup_files",
                "geregistreerde lokale .sql.gz-bestanden",
                "SELECT COUNT(*) FROM backup_records",
                "bewaard",
            )?,
        ],
        DatabaseCleanupTarget::ScanRuns => vec![
            impact(
                connection,
                "scan_runs",
                "scans",
                "SELECT COUNT(*) FROM scan_runs",
                "verwijderd",
            )?,
            impact(
                connection,
                "scan_checks",
                "scancontroles",
                "SELECT COUNT(*) FROM scan_checks",
                "verwijderd",
            )?,
            impact(
                connection,
                "findings",
                "bevindingen",
                "SELECT COUNT(*) FROM findings",
                "verwijderd",
            )?,
            impact(
                connection,
                "site_vulnerability_state",
                "actuele kwetsbaarheidsstatussen",
                "SELECT COUNT(*) FROM site_vulnerability_state",
                "verwijderd",
            )?,
            impact(
                connection,
                "site_snapshots_scan_link",
                "snapshotkoppelingen naar scans",
                "SELECT COUNT(*) FROM site_snapshots WHERE scan_run_id IS NOT NULL",
                "losgekoppeld",
            )?,
            impact(
                connection,
                "sites_scan_state",
                "website-scansamenvattingen",
                "SELECT COUNT(*) FROM sites WHERE last_scan_at IS NOT NULL OR status <> 'unscanned' OR security_status IS NOT NULL",
                "gereset",
            )?,
        ],
        DatabaseCleanupTarget::SiteSnapshots => vec![
            impact(
                connection,
                "site_snapshots",
                "snapshots",
                "SELECT COUNT(*) FROM site_snapshots",
                "verwijderd",
            )?,
            impact(
                connection,
                "snapshot_diffs",
                "snapshotvergelijkingen",
                "SELECT COUNT(*) FROM snapshot_diffs",
                "verwijderd",
            )?,
            impact(
                connection,
                "snapshot_diff_sections",
                "vergelijkingssecties",
                "SELECT COUNT(*) FROM snapshot_diff_sections",
                "verwijderd",
            )?,
            impact(
                connection,
                "snapshot_changes",
                "geregistreerde wijzigingen",
                "SELECT COUNT(*) FROM snapshot_changes",
                "verwijderd",
            )?,
            impact(
                connection,
                "site_snapshot_state",
                "actuele snapshotstatussen",
                "SELECT COUNT(*) FROM site_snapshot_state",
                "gereset",
            )?,
        ],
        DatabaseCleanupTarget::MaintenanceRuns => vec![
            impact(
                connection,
                "maintenance_runs",
                "onderhoudsrecords",
                "SELECT COUNT(*) FROM maintenance_runs",
                "verwijderd",
            )?,
            impact(
                connection,
                "maintenance_steps",
                "onderhoudsstappen",
                "SELECT COUNT(*) FROM maintenance_steps",
                "verwijderd",
            )?,
            impact(
                connection,
                "backup_records",
                "back-upregistraties",
                "SELECT COUNT(*) FROM backup_records",
                "verwijderd",
            )?,
            impact(
                connection,
                "site_snapshots_maintenance_link",
                "snapshotkoppelingen naar onderhoud",
                "SELECT COUNT(*) FROM site_snapshots WHERE maintenance_run_id IS NOT NULL",
                "losgekoppeld",
            )?,
            impact(
                connection,
                "snapshot_diffs_maintenance_link",
                "vergelijkingskoppelingen naar onderhoud",
                "SELECT COUNT(*) FROM snapshot_diffs WHERE maintenance_run_id IS NOT NULL",
                "losgekoppeld",
            )?,
            impact(
                connection,
                "sites_maintenance_state",
                "datums van laatste onderhoud",
                "SELECT COUNT(*) FROM sites WHERE last_maintenance_at IS NOT NULL",
                "gereset",
            )?,
            impact(
                connection,
                "local_backup_files",
                "geregistreerde lokale .sql.gz-bestanden",
                "SELECT COUNT(*) FROM backup_records",
                "bewaard",
            )?,
        ],
        DatabaseCleanupTarget::ErrorLogs => vec![impact(
            connection,
            "error_logs",
            "foutregels",
            "SELECT COUNT(*) FROM error_logs",
            "verwijderd",
        )?],
        DatabaseCleanupTarget::AuditEvents => vec![impact(
            connection,
            "audit_events",
            "auditregels",
            "SELECT COUNT(*) FROM audit_events",
            "verwijderd",
        )?],
    };
    Ok(counts)
}

fn impact(
    connection: &Connection,
    key: &str,
    label: &str,
    sql: &str,
    effect: &str,
) -> Result<DatabaseCleanupImpact, AppError> {
    let count = connection.query_row(sql, [], |row| row.get::<_, i64>(0))?;
    Ok(DatabaseCleanupImpact {
        key: key.into(),
        label: label.into(),
        count: u64::try_from(count).unwrap_or(0),
        effect: effect.into(),
    })
}

fn distinct_site_credential_references(
    transaction: &Transaction<'_>,
) -> Result<Vec<String>, AppError> {
    let mut statement = transaction.prepare(
        "SELECT DISTINCT credential_ref FROM sites WHERE credential_ref IS NOT NULL ORDER BY credential_ref",
    )?;
    statement
        .query_map([], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(AppError::from)
}

fn database_cleanup_site_ids(transaction: &Transaction<'_>) -> Result<Vec<String>, AppError> {
    let mut statement = transaction.prepare("SELECT id FROM sites ORDER BY id")?;
    statement
        .query_map([], |row| row.get(0))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(AppError::from)
}

fn execute_cleanup_statements(
    transaction: &Transaction<'_>,
    target: DatabaseCleanupTarget,
) -> Result<(), AppError> {
    match target {
        DatabaseCleanupTarget::Sites => transaction.execute_batch(
            "DELETE FROM audit_events WHERE site_id IS NOT NULL;
             DELETE FROM error_logs WHERE site_id IS NOT NULL;
             DELETE FROM sites;",
        )?,
        DatabaseCleanupTarget::ScanRuns => transaction.execute_batch(
            "DELETE FROM scan_runs;
             UPDATE sites SET
               status='unscanned',
               security_status=NULL,
               last_scan_at=NULL,
               vulnerability_critical_count=0,
               vulnerability_high_count=0,
               vulnerability_medium_count=0,
               vulnerability_low_count=0,
               vulnerability_info_count=0,
               vulnerability_unknown_count=0,
               vulnerability_last_checked_at=NULL,
               vulnerability_feed_updated_at=NULL,
               vulnerability_inventory_observed_at=NULL,
               vulnerability_inventory_stale=0;",
        )?,
        DatabaseCleanupTarget::SiteSnapshots => transaction.execute_batch(
            "DELETE FROM site_snapshots;
             DELETE FROM site_snapshot_state;",
        )?,
        DatabaseCleanupTarget::MaintenanceRuns => transaction.execute_batch(
            "DELETE FROM maintenance_runs;
             UPDATE sites SET last_maintenance_at=NULL;",
        )?,
        DatabaseCleanupTarget::ErrorLogs => transaction.execute_batch("DELETE FROM error_logs;")?,
        DatabaseCleanupTarget::AuditEvents => {
            transaction.execute_batch("DELETE FROM audit_events;")?
        }
    }
    Ok(())
}

fn ensure_cleanup_integrity(
    transaction: &Transaction<'_>,
    target: DatabaseCleanupTarget,
) -> Result<(), AppError> {
    let remaining: i64 = transaction.query_row(
        &format!("SELECT COUNT(*) FROM {}", target.table_name()),
        [],
        |row| row.get(0),
    )?;
    if remaining != 0 {
        return Err(AppError::storage(format!(
            "Tabel {} bevat na opschonen nog {remaining} records",
            target.table_name()
        )));
    }
    let foreign_key_violation: Option<String> = transaction
        .query_row("PRAGMA foreign_key_check", [], |row| row.get(0))
        .optional()?;
    if let Some(table) = foreign_key_violation {
        return Err(AppError::storage(format!(
            "Foreign-key-controle mislukt voor tabel {table}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{AuthMethod, SiteInput};
    use std::fs;
    use uuid::Uuid;

    fn database() -> (Database, std::path::PathBuf) {
        let path = std::env::temp_dir().join(format!("wpmm-cleanup-{}.sqlite3", Uuid::new_v4()));
        (Database::initialize(path.clone()).unwrap(), path)
    }

    fn site_input() -> SiteInput {
        SiteInput {
            id: None,
            name: "Voorbeeld".into(),
            url: "https://example.test".into(),
            ssh_host: "example.test".into(),
            ssh_port: 22,
            ssh_username: "deploy".into(),
            auth_method: AuthMethod::Password,
            key_path: None,
            wordpress_path: "/var/www/html".into(),
            credential_secret: None,
            pinned_host_key: None,
            parent_site_id: None,
            relation_type: None,
            parent_directory: None,
        }
    }

    fn seed_site_history(database: &Database) -> String {
        let site = database
            .save_site(&site_input(), Some("site:cleanup:ssh"))
            .unwrap();
        let connection = database.connect().unwrap();
        connection
            .execute_batch(&format!(
                "INSERT INTO scan_runs(id,site_id,started_at,status,truncated) VALUES('scan','{}','2026-09-21T10:00:00Z','healthy',0);
                 INSERT INTO scan_checks(id,scan_run_id,check_key,label,status,summary) VALUES('check','scan','core','Core','success','Goed');
                 INSERT INTO findings(id,scan_check_id,category,severity,title,detail,site_id,scan_run_id) VALUES('finding','check','core','warning','Test','Test','{}','scan');
                 INSERT INTO maintenance_runs(id,site_id,started_at,status) VALUES('maintenance','{}','2026-09-21T11:00:00Z','success');
                 INSERT INTO maintenance_steps(id,maintenance_run_id,step_key,label,status,position) VALUES('step','maintenance','backup','Backup','success',0);
                 INSERT INTO backup_records(id,maintenance_run_id,local_path,created_at,status) VALUES('backup','maintenance','C:/backup.sql.gz','2026-09-21T11:01:00Z','success');
                 INSERT INTO finding_exceptions(id,site_id,check_type,finding_type,target,reason,created_at) VALUES('exception','{}','core','unexpected','readme.txt','Test','2026-09-21T12:00:00Z');
                 INSERT INTO trusted_files(id,site_id,relative_path,trusted_sha256,size_bytes,trusted_at) VALUES('trusted','{}','index.php','abc',12,'2026-09-21T12:00:00Z');
                 INSERT INTO audit_events(id,site_id,action_type,target,status,created_at) VALUES('audit','{}','scan','site','success','2026-09-21T12:00:00Z');
                 INSERT INTO error_logs(id,created_at,severity,category,site_id,action,summary) VALUES('error','2026-09-21T12:00:00Z','error','ssh_command','{}','Scan','Mislukt');",
                site.id, site.id, site.id, site.id, site.id, site.id, site.id
            ))
            .unwrap();
        site.id
    }

    fn cleanup_request(
        database: &Database,
        target: DatabaseCleanupTarget,
        confirmation: &str,
    ) -> DatabaseCleanupRequest {
        let preview_token = database
            .database_cleanup_options()
            .unwrap()
            .into_iter()
            .find(|option| option.target == target)
            .unwrap()
            .preview_token;
        DatabaseCleanupRequest {
            target,
            confirmation: confirmation.into(),
            preview_token,
        }
    }

    #[test]
    fn exposes_only_the_explicit_safe_allowlist() {
        let (database, path) = database();
        let tables = database
            .database_cleanup_options()
            .unwrap()
            .into_iter()
            .map(|option| option.table_name)
            .collect::<Vec<_>>();
        assert_eq!(
            tables,
            [
                "sites",
                "scan_runs",
                "site_snapshots",
                "maintenance_runs",
                "error_logs",
                "audit_events"
            ]
        );
        assert!(!tables.contains(&"auth_config".to_string()));
        assert!(!tables.contains(&"app_settings".to_string()));
        assert!(!tables.contains(&"schema_migrations".to_string()));
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn sites_require_typed_confirmation_and_cascade_atomically() {
        let (database, path) = database();
        seed_site_history(&database);
        let option = database
            .database_cleanup_options()
            .unwrap()
            .into_iter()
            .find(|option| option.target == DatabaseCleanupTarget::Sites)
            .unwrap();
        assert_eq!(option.record_count, 1);
        assert_eq!(option.confirmation_mode, "typed");
        assert_eq!(option.confirmation_phrase, "VERWIJDEREN");
        assert_eq!(
            option
                .impacts
                .iter()
                .find(|impact| impact.key == "scan_runs")
                .unwrap()
                .count,
            1
        );
        let wrong = database.execute_database_cleanup(&DatabaseCleanupRequest {
            target: DatabaseCleanupTarget::Sites,
            confirmation: "sites".into(),
            preview_token: option.preview_token.clone(),
        });
        assert!(wrong.is_err());
        assert_eq!(database.list_sites().unwrap().len(), 1);

        let execution = database
            .execute_database_cleanup(&cleanup_request(
                &database,
                DatabaseCleanupTarget::Sites,
                "VERWIJDEREN",
            ))
            .unwrap();
        assert_eq!(execution.site_ids.len(), 1);
        assert_eq!(execution.credential_references, ["site:cleanup:ssh"]);
        assert!(database.list_sites().unwrap().is_empty());
        let connection = database.connect().unwrap();
        for table in [
            "scan_runs",
            "scan_checks",
            "findings",
            "maintenance_runs",
            "maintenance_steps",
            "backup_records",
            "finding_exceptions",
            "trusted_files",
        ] {
            assert_eq!(
                connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0,
                "{table} was not emptied"
            );
        }
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
                    row.get::<_, i64>(0)
                })
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM app_settings", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            3
        );
        drop(connection);
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn scoped_history_cleanups_preserve_sites_and_unrelated_history() {
        let (database, path) = database();
        let site_id = seed_site_history(&database);
        let connection = database.connect().unwrap();
        connection.execute_batch(&format!(
            "INSERT INTO site_snapshots(id,site_id,created_at,scan_run_id,maintenance_run_id,source,schema_version,status,scan_timestamp,section_status_json,payload_encoding,payload,is_baseline) VALUES('snapshot','{site_id}','2026-09-21T10:10:00Z','scan','maintenance','pre_maintenance',1,'complete','2026-09-21T10:10:00Z','{{}}','json_utf8',X'7B7D',1);
             INSERT INTO site_snapshot_state(site_id,latest_snapshot_id,baseline_snapshot_id,latest_snapshot_at,updated_at) VALUES('{site_id}','snapshot','snapshot','2026-09-21T10:10:00Z','2026-09-21T10:10:00Z');"
        )).unwrap();
        drop(connection);

        database
            .execute_database_cleanup(&cleanup_request(
                &database,
                DatabaseCleanupTarget::SiteSnapshots,
                "site_snapshots",
            ))
            .unwrap();
        let connection = database.connect().unwrap();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM site_snapshots", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM site_snapshot_state", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM scan_runs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM maintenance_runs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        drop(connection);

        database
            .execute_database_cleanup(&cleanup_request(
                &database,
                DatabaseCleanupTarget::MaintenanceRuns,
                "maintenance_runs",
            ))
            .unwrap();
        database
            .execute_database_cleanup(&cleanup_request(
                &database,
                DatabaseCleanupTarget::ErrorLogs,
                "error_logs",
            ))
            .unwrap();
        database
            .execute_database_cleanup(&cleanup_request(
                &database,
                DatabaseCleanupTarget::AuditEvents,
                "audit_events",
            ))
            .unwrap();
        let connection = database.connect().unwrap();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM sites", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM scan_runs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        for table in [
            "maintenance_runs",
            "maintenance_steps",
            "backup_records",
            "error_logs",
            "audit_events",
        ] {
            assert_eq!(
                connection
                    .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| row
                        .get::<_, i64>(0))
                    .unwrap(),
                0,
                "{table} was not emptied"
            );
        }
        drop(connection);
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn a_failed_cascade_rolls_the_complete_cleanup_back() {
        let (database, path) = database();
        seed_site_history(&database);
        let connection = database.connect().unwrap();
        connection.execute_batch("CREATE TRIGGER block_scan_delete BEFORE DELETE ON scan_runs BEGIN SELECT RAISE(ABORT, 'blocked for test'); END;").unwrap();
        drop(connection);

        let result = database.execute_database_cleanup(&cleanup_request(
            &database,
            DatabaseCleanupTarget::Sites,
            "VERWIJDEREN",
        ));
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .user_message
                .contains("het verwijderen van de records")
        );
        let connection = database.connect().unwrap();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM sites", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM audit_events", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM error_logs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        drop(connection);
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_cleanup_when_the_confirmed_preview_is_stale() {
        let (database, path) = database();
        let request = cleanup_request(&database, DatabaseCleanupTarget::ErrorLogs, "error_logs");
        let connection = database.connect().unwrap();
        connection
            .execute(
                "INSERT INTO error_logs(id,created_at,severity,category,action,summary) VALUES('new-error','2026-09-21T12:00:00Z','error','database','Test','Nieuw na bevestiging')",
                [],
            )
            .unwrap();
        drop(connection);

        let error = database.execute_database_cleanup(&request).unwrap_err();
        assert!(
            error.user_message.contains("De database is gewijzigd"),
            "unexpected error: {error:?}"
        );
        let connection = database.connect().unwrap();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM error_logs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        drop(connection);
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn scan_cleanup_unlinks_snapshots_and_resets_site_scan_state() {
        let (database, path) = database();
        let site_id = seed_site_history(&database);
        let connection = database.connect().unwrap();
        connection.execute_batch(&format!(
            "UPDATE sites SET status='attention',security_status='warning',last_scan_at='2026-09-21T10:10:00Z' WHERE id='{site_id}';
             INSERT INTO site_snapshots(id,site_id,created_at,scan_run_id,source,schema_version,status,scan_timestamp,section_status_json,payload_encoding,payload,is_baseline) VALUES('snapshot','{site_id}','2026-09-21T10:10:00Z','scan','scan',1,'complete','2026-09-21T10:10:00Z','{{}}','json_utf8',X'7B7D',0);"
        )).unwrap();
        drop(connection);

        database
            .execute_database_cleanup(&cleanup_request(
                &database,
                DatabaseCleanupTarget::ScanRuns,
                "scan_runs",
            ))
            .unwrap();
        let connection = database.connect().unwrap();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM scan_runs", [], |row| row
                    .get::<_, i64>(0))
                .unwrap(),
            0
        );
        assert!(
            connection
                .query_row(
                    "SELECT scan_run_id IS NULL FROM site_snapshots WHERE id='snapshot'",
                    [],
                    |row| row.get::<_, bool>(0)
                )
                .unwrap()
        );
        let state: (String, Option<String>, Option<String>) = connection
            .query_row(
                "SELECT status,security_status,last_scan_at FROM sites WHERE id=?1",
                [&site_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(state, ("unscanned".into(), None, None));
        drop(connection);
        drop(database);
        let _ = fs::remove_file(path);
    }
}
