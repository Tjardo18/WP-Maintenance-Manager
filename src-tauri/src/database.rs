use crate::{
    error::AppError,
    models::{
        AuditEvent, AuthConfig, AuthMethod, ChecksumFindingRecord, ChecksumStatus, ErrorCategory,
        ErrorLogFilter, ErrorLogPage, ErrorLogRecord, ErrorSeverity, ExceptionScope, Finding,
        FindingContext, FindingDisposition, FindingException, FindingSeverity, MaintenanceRun,
        MaintenanceStep, ScanCheck, ScanResult, Site, SiteInput, SiteStatus, StepStatus,
        StoredSite, TrustedFile, TrustedFileStatus, UpdateItem, UpdateKind, VulnerabilityFeedState,
        VulnerabilityImportSummary,
    },
    wordfence::{WORDFENCE_PROVIDER, WordfenceVulnerability},
};
use chrono::{SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, Row, Transaction, params};
use serde::de::{DeserializeSeed, Error as _, MapAccess, Visitor};
use std::{
    collections::HashMap,
    fmt, fs,
    io::BufReader,
    path::{Path, PathBuf},
};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct Database {
    path: PathBuf,
}

impl Database {
    pub fn initialize(path: PathBuf) -> Result<Self, AppError> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let database = Self { path };
        let connection = database.connect()?;
        connection.execute_batch("CREATE TABLE IF NOT EXISTS schema_migrations (version INTEGER PRIMARY KEY NOT NULL, applied_at TEXT NOT NULL);")?;
        let applied: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 1)",
            [],
            |row| row.get(0),
        )?;
        if !applied {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute_batch(include_str!("../migrations/0001_initial.sql"))?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES(1, ?1)",
                [utc_now()],
            )?;
            transaction.commit()?;
        }
        let settings_applied: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 2)",
            [],
            |row| row.get(0),
        )?;
        if !settings_applied {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute_batch(include_str!("../migrations/0002_settings.sql"))?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES(2, ?1)",
                [utc_now()],
            )?;
            transaction.commit()?;
        }
        let auth_applied: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 3)",
            [],
            |row| row.get(0),
        )?;
        if !auth_applied {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute_batch(include_str!("../migrations/0003_auth_and_audit.sql"))?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES(3, ?1)",
                [utc_now()],
            )?;
            transaction.commit()?;
        }
        let checksum_applied: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 4)",
            [],
            |row| row.get(0),
        )?;
        if !checksum_applied {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute_batch(include_str!("../migrations/0004_checksum_findings.sql"))?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES(4, ?1)",
                [utc_now()],
            )?;
            transaction.commit()?;
        }
        let diagnostics_applied: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 5)",
            [],
            |row| row.get(0),
        )?;
        if !diagnostics_applied {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute_batch(include_str!("../migrations/0005_scan_diagnostics.sql"))?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES(5, ?1)",
                [utc_now()],
            )?;
            transaction.commit()?;
        }
        let error_log_applied: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 6)",
            [],
            |row| row.get(0),
        )?;
        if !error_log_applied {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute_batch(include_str!("../migrations/0006_error_log.sql"))?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES(6, ?1)",
                [utc_now()],
            )?;
            transaction.commit()?;
        }
        let performance_indexes_applied: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 7)",
            [],
            |row| row.get(0),
        )?;
        if !performance_indexes_applied {
            let transaction = connection.unchecked_transaction()?;
            transaction
                .execute_batch(include_str!("../migrations/0007_performance_indexes.sql"))?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES(7, ?1)",
                [utc_now()],
            )?;
            transaction.commit()?;
        }
        let security_exceptions_applied: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 8)",
            [],
            |row| row.get(0),
        )?;
        if !security_exceptions_applied {
            let transaction = connection.unchecked_transaction()?;
            transaction
                .execute_batch(include_str!("../migrations/0008_security_exceptions.sql"))?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES(8, ?1)",
                [utc_now()],
            )?;
            transaction.commit()?;
        }
        let vulnerability_intelligence_applied: bool = connection.query_row(
            "SELECT EXISTS(SELECT 1 FROM schema_migrations WHERE version = 9)",
            [],
            |row| row.get(0),
        )?;
        if !vulnerability_intelligence_applied {
            let transaction = connection.unchecked_transaction()?;
            transaction.execute_batch(include_str!(
                "../migrations/0009_vulnerability_intelligence.sql"
            ))?;
            transaction.execute(
                "INSERT INTO schema_migrations(version, applied_at) VALUES(9, ?1)",
                [utc_now()],
            )?;
            transaction.commit()?;
        }
        Ok(database)
    }

    fn connect(&self) -> Result<Connection, AppError> {
        let connection = Connection::open(&self.path)?;
        connection.execute_batch(
            "PRAGMA foreign_keys = ON; PRAGMA busy_timeout = 5000; PRAGMA journal_mode = WAL;",
        )?;
        Ok(connection)
    }

    pub fn list_sites(&self) -> Result<Vec<Site>, AppError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare("SELECT id,name,url,ssh_host,ssh_port,ssh_username,auth_method,key_path,wordpress_path,credential_ref,pinned_host_key,status,wordpress_version,php_version,update_count,security_status,last_scan_at,last_maintenance_at,created_at,updated_at FROM sites ORDER BY name COLLATE NOCASE")?;
        let rows = statement.query_map([], row_to_stored_site)?;
        rows.map(|row| row.map(|stored| stored.site).map_err(AppError::from))
            .collect()
    }

    pub fn get_site(&self, id: &str) -> Result<StoredSite, AppError> {
        let connection = self.connect()?;
        connection.query_row("SELECT id,name,url,ssh_host,ssh_port,ssh_username,auth_method,key_path,wordpress_path,credential_ref,pinned_host_key,status,wordpress_version,php_version,update_count,security_status,last_scan_at,last_maintenance_at,created_at,updated_at FROM sites WHERE id = ?1", [id], row_to_stored_site).optional()?.ok_or_else(|| AppError::not_found("Website"))
    }

    pub fn save_site(
        &self,
        input: &SiteInput,
        credential_ref: Option<&str>,
    ) -> Result<Site, AppError> {
        let existing = input.id.as_deref().and_then(|id| self.get_site(id).ok());
        let id = match &input.id {
            Some(id) => Uuid::parse_str(id)
                .map_err(|_| AppError::validation("De website-id is ongeldig."))?
                .to_string(),
            None => Uuid::new_v4().to_string(),
        };
        let now = utc_now();
        let created_at = existing
            .as_ref()
            .map_or_else(|| now.clone(), |stored| stored.site.created_at.clone());
        let pinned = existing
            .as_ref()
            .and_then(|stored| stored.site.pinned_host_key.clone());
        let status = existing
            .as_ref()
            .map_or(SiteStatus::Unscanned, |stored| stored.site.status);
        let effective_ref = credential_ref.map(str::to_owned).or_else(|| {
            existing
                .as_ref()
                .and_then(|stored| stored.credential_ref.clone())
        });
        let connection = self.connect()?;
        connection.execute(
            "INSERT INTO sites(id,name,url,ssh_host,ssh_port,ssh_username,auth_method,key_path,wordpress_path,credential_ref,pinned_host_key,status,wordpress_version,php_version,update_count,security_status,last_scan_at,last_maintenance_at,created_at,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,NULL,NULL,0,NULL,NULL,NULL,?13,?14) ON CONFLICT(id) DO UPDATE SET name=excluded.name,url=excluded.url,ssh_host=excluded.ssh_host,ssh_port=excluded.ssh_port,ssh_username=excluded.ssh_username,auth_method=excluded.auth_method,key_path=excluded.key_path,wordpress_path=excluded.wordpress_path,credential_ref=excluded.credential_ref,pinned_host_key=CASE WHEN sites.ssh_host <> excluded.ssh_host OR sites.ssh_port <> excluded.ssh_port THEN NULL ELSE sites.pinned_host_key END,updated_at=excluded.updated_at",
            params![id, input.name.trim(), input.url.trim(), input.ssh_host.trim(), input.ssh_port, input.ssh_username.trim(), input.auth_method.as_db(), input.key_path.as_deref().filter(|path| !path.is_empty()), input.wordpress_path.trim(), effective_ref, pinned, status.as_db(), created_at, now]
        )?;
        Ok(self.get_site(&id)?.site)
    }

    pub fn delete_site(&self, id: &str) -> Result<Option<String>, AppError> {
        let existing = self.get_site(id)?;
        let connection = self.connect()?;
        connection.execute("DELETE FROM sites WHERE id = ?1", [id])?;
        Ok(existing.credential_ref)
    }

    pub fn set_host_key(&self, id: &str, fingerprint: &str) -> Result<(), AppError> {
        let connection = self.connect()?;
        if connection.execute(
            "UPDATE sites SET pinned_host_key = ?1, updated_at = ?2 WHERE id = ?3",
            params![fingerprint, utc_now(), id],
        )? == 0
        {
            return Err(AppError::not_found("Website"));
        }
        Ok(())
    }

    pub fn save_scan(&self, scan: &ScanResult, security_status: &str) -> Result<(), AppError> {
        let connection = self.connect()?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO scan_runs(id,site_id,started_at,finished_at,status,truncated) VALUES(?1,?2,?3,?4,?5,?6)",
            params![scan.id, scan.site_id, scan.started_at, scan.finished_at, scan.status.as_db(), scan.truncated],
        )?;
        {
            let mut insert_check = transaction.prepare_cached(
                "INSERT INTO scan_checks(id,scan_run_id,check_key,label,status,summary,technical_details) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            )?;
            let mut insert_finding = transaction.prepare_cached(
                "INSERT INTO findings(id,scan_check_id,category,severity,title,detail,path,checksum_status,observed_at,site_id,scan_run_id,disposition,exception_id,trusted_file_id,policy_reason) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)",
            )?;
            for check in &scan.checks {
                let check_id = Uuid::new_v4().to_string();
                insert_check.execute(params![
                    check_id,
                    scan.id,
                    check.key,
                    check.label,
                    check.status.as_db(),
                    check.summary,
                    check.technical_details
                ])?;
                for finding in &check.findings {
                    let finding_id = finding
                        .id
                        .clone()
                        .unwrap_or_else(|| Uuid::new_v4().to_string());
                    insert_finding.execute(params![
                        finding_id,
                        check_id,
                        finding.category,
                        finding.severity.as_db(),
                        finding.title,
                        finding.detail,
                        finding.path,
                        finding.checksum_status.map(ChecksumStatus::as_db),
                        finding.observed_at,
                        scan.site_id,
                        scan.id,
                        finding.disposition.as_db(),
                        finding.exception_id,
                        finding.trusted_file_id,
                        finding.policy_reason
                    ])?;
                }
            }
        }
        transaction.execute(
            "UPDATE sites SET status=?1,security_status=?2,last_scan_at=?3,updated_at=?3 WHERE id=?4",
            params![scan.status.as_db(), security_status, scan.finished_at, scan.site_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn list_scans(&self, site_id: &str) -> Result<Vec<ScanResult>, AppError> {
        self.list_scans_with_limit(site_id, 20)
    }

    pub fn current_unexpected_checksum_finding(
        &self,
        site_id: &str,
        finding_id: &str,
    ) -> Result<ChecksumFindingRecord, AppError> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT f.id,f.site_id,f.scan_run_id,f.category,f.severity,f.title,f.detail,f.path,f.checksum_status,f.observed_at,f.disposition,f.exception_id,f.trusted_file_id,f.policy_reason
                 FROM findings f
                 JOIN scan_checks sc ON sc.id=f.scan_check_id
                 WHERE f.id=?1 AND f.site_id=?2 AND f.checksum_status='unexpected' AND sc.check_key='core_checksum'
                   AND f.scan_run_id=(
                     SELECT sr.id FROM scan_runs sr
                     JOIN scan_checks latest_check ON latest_check.scan_run_id=sr.id AND latest_check.check_key='core_checksum'
                     WHERE sr.site_id=?2
                     ORDER BY sr.started_at DESC,sr.rowid DESC LIMIT 1
                   )",
                params![finding_id, site_id],
                |row| {
                    Ok(ChecksumFindingRecord {
                        site_id: row.get(1)?,
                        scan_run_id: row.get(2)?,
                        finding: Finding {
                            id: row.get(0)?,
                            category: row.get(3)?,
                            severity: FindingSeverity::from_db(&row.get::<_, String>(4)?),
                            title: row.get(5)?,
                            detail: row.get(6)?,
                            path: row.get(7)?,
                            checksum_status: row
                                .get::<_, Option<String>>(8)?
                                .as_deref()
                                .and_then(ChecksumStatus::from_db),
                            observed_at: row.get(9)?,
                            disposition: FindingDisposition::from_db(
                                &row.get::<_, String>(10)?,
                            ),
                            exception_id: row.get(11)?,
                            trusted_file_id: row.get(12)?,
                            policy_reason: row.get(13)?,
                        },
                    })
                },
            )
            .optional()?
            .ok_or_else(|| AppError::not_found("Actuele onverwachte checksumfinding"))
    }

    fn list_scans_with_limit(
        &self,
        site_id: &str,
        limit: usize,
    ) -> Result<Vec<ScanResult>, AppError> {
        let connection = self.connect()?;
        let row_limit = i64::try_from(limit).map_err(AppError::storage)?;
        let mut scans: Vec<ScanResult> = {
            let mut statement = connection.prepare(
                "SELECT id,site_id,started_at,COALESCE(finished_at,started_at),status,truncated FROM scan_runs WHERE site_id=?1 ORDER BY started_at DESC LIMIT ?2",
            )?;
            statement
                .query_map(params![site_id, row_limit], |row| {
                    Ok(ScanResult {
                        id: row.get(0)?,
                        site_id: row.get(1)?,
                        started_at: row.get(2)?,
                        finished_at: row.get(3)?,
                        status: SiteStatus::from_db(&row.get::<_, String>(4)?),
                        checks: Vec::new(),
                        truncated: row.get(5)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?
        };
        if scans.is_empty() {
            return Ok(scans);
        }

        let scan_indexes: HashMap<String, usize> = scans
            .iter()
            .enumerate()
            .map(|(index, scan)| (scan.id.clone(), index))
            .collect();
        let mut check_indexes: HashMap<String, (usize, usize)> = HashMap::new();
        {
            let mut statement = connection.prepare(
                "SELECT sc.id,sc.scan_run_id,sc.check_key,sc.label,sc.status,sc.summary,sc.technical_details
                 FROM scan_checks sc
                 WHERE sc.scan_run_id IN (SELECT id FROM scan_runs WHERE site_id=?1 ORDER BY started_at DESC LIMIT ?2)
                 ORDER BY sc.rowid",
            )?;
            let rows = statement.query_map(params![site_id, row_limit], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    ScanCheck {
                        key: row.get(2)?,
                        label: row.get(3)?,
                        status: StepStatus::from_db(&row.get::<_, String>(4)?),
                        summary: row.get(5)?,
                        technical_details: row.get(6)?,
                        findings: Vec::new(),
                    },
                ))
            })?;
            for row in rows {
                let (check_id, scan_id, check) = row?;
                if let Some(&scan_index) = scan_indexes.get(&scan_id) {
                    let check_index = scans[scan_index].checks.len();
                    scans[scan_index].checks.push(check);
                    check_indexes.insert(check_id, (scan_index, check_index));
                }
            }
        }
        {
            let mut statement = connection.prepare(
                "SELECT f.scan_check_id,f.id,f.category,f.severity,f.title,f.detail,f.path,f.checksum_status,f.observed_at,f.disposition,f.exception_id,f.trusted_file_id,f.policy_reason
                 FROM findings f
                 JOIN scan_checks sc ON sc.id=f.scan_check_id
                 WHERE sc.scan_run_id IN (SELECT id FROM scan_runs WHERE site_id=?1 ORDER BY started_at DESC LIMIT ?2)
                 ORDER BY f.rowid",
            )?;
            let rows = statement.query_map(params![site_id, row_limit], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    Finding {
                        id: row.get(1)?,
                        category: row.get(2)?,
                        severity: FindingSeverity::from_db(&row.get::<_, String>(3)?),
                        title: row.get(4)?,
                        detail: row.get(5)?,
                        path: row.get(6)?,
                        checksum_status: row
                            .get::<_, Option<String>>(7)?
                            .as_deref()
                            .and_then(ChecksumStatus::from_db),
                        observed_at: row.get(8)?,
                        disposition: FindingDisposition::from_db(&row.get::<_, String>(9)?),
                        exception_id: row.get(10)?,
                        trusted_file_id: row.get(11)?,
                        policy_reason: row.get(12)?,
                    },
                ))
            })?;
            for row in rows {
                let (check_id, finding) = row?;
                if let Some(&(scan_index, check_index)) = check_indexes.get(&check_id) {
                    scans[scan_index].checks[check_index].findings.push(finding);
                }
            }
        }
        Ok(scans)
    }

    pub fn latest_scan(&self, site_id: &str) -> Result<Option<ScanResult>, AppError> {
        Ok(self.list_scans_with_limit(site_id, 1)?.into_iter().next())
    }

    pub fn get_finding_context(
        &self,
        site_id: &str,
        finding_id: &str,
    ) -> Result<FindingContext, AppError> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT f.site_id,f.scan_run_id,sc.check_key,f.id,f.category,f.severity,f.title,f.detail,f.path,f.checksum_status,f.observed_at,f.disposition,f.exception_id,f.trusted_file_id,f.policy_reason
                 FROM findings f
                 JOIN scan_checks sc ON sc.id=f.scan_check_id
                 WHERE f.site_id=?1 AND f.id=?2
                   AND f.scan_run_id=(SELECT id FROM scan_runs WHERE site_id=?1 ORDER BY started_at DESC,rowid DESC LIMIT 1)",
                params![site_id, finding_id],
                |row| {
                    Ok(FindingContext {
                        site_id: row.get(0)?,
                        scan_run_id: row.get(1)?,
                        check_type: row.get(2)?,
                        finding: Finding {
                            id: row.get(3)?,
                            category: row.get(4)?,
                            severity: FindingSeverity::from_db(&row.get::<_, String>(5)?),
                            title: row.get(6)?,
                            detail: row.get(7)?,
                            path: row.get(8)?,
                            checksum_status: row
                                .get::<_, Option<String>>(9)?
                                .as_deref()
                                .and_then(ChecksumStatus::from_db),
                            observed_at: row.get(10)?,
                            disposition: FindingDisposition::from_db(
                                &row.get::<_, String>(11)?,
                            ),
                            exception_id: row.get(12)?,
                            trusted_file_id: row.get(13)?,
                            policy_reason: row.get(14)?,
                        },
                    })
                },
            )
            .optional()?
            .ok_or_else(|| AppError::not_found("Actuele beveiligingsmelding"))
    }

    pub fn list_finding_exceptions(
        &self,
        site_id: Option<&str>,
    ) -> Result<Vec<FindingException>, AppError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT e.id,e.site_id,s.name,e.check_type,e.finding_type,e.target,e.scope,e.reason,e.note,e.created_at,e.expires_at,e.active
             FROM finding_exceptions e JOIN sites s ON s.id=e.site_id
             WHERE (?1 IS NULL OR e.site_id=?1)
             ORDER BY e.active DESC,e.created_at DESC",
        )?;
        statement
            .query_map([site_id], row_to_finding_exception)?
            .collect::<rusqlite::Result<_>>()
            .map_err(AppError::from)
    }

    pub fn save_finding_exception(&self, exception: &FindingException) -> Result<(), AppError> {
        let connection = self.connect()?;
        connection.execute(
            "INSERT INTO finding_exceptions(id,site_id,check_type,finding_type,target,scope,reason,note,created_at,expires_at,active)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)
             ON CONFLICT(id) DO UPDATE SET reason=excluded.reason,note=excluded.note,created_at=excluded.created_at,expires_at=excluded.expires_at,active=excluded.active",
            params![
                exception.id,
                exception.site_id,
                exception.check_type,
                exception.finding_type,
                exception.target,
                exception.scope.as_db(),
                exception.reason,
                exception.note,
                exception.created_at,
                exception.expires_at,
                exception.active,
            ],
        )?;
        Ok(())
    }

    pub fn deactivate_finding_exception(&self, id: &str) -> Result<String, AppError> {
        let connection = self.connect()?;
        let site_id = connection
            .query_row(
                "SELECT site_id FROM finding_exceptions WHERE id=?1 AND active=1",
                [id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| AppError::not_found("Actieve uitzondering"))?;
        connection.execute("UPDATE finding_exceptions SET active=0 WHERE id=?1", [id])?;
        Ok(site_id)
    }

    pub fn list_trusted_files(&self, site_id: Option<&str>) -> Result<Vec<TrustedFile>, AppError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT t.id,t.site_id,s.name,t.relative_path,t.trusted_sha256,t.current_sha256,t.size_bytes,t.current_size_bytes,t.modified_at_snapshot,t.current_modified_at,t.file_type,t.status,t.trusted_at,t.last_checked_at,t.note,t.active
             FROM trusted_files t JOIN sites s ON s.id=t.site_id
             WHERE (?1 IS NULL OR t.site_id=?1)
             ORDER BY t.active DESC,t.trusted_at DESC",
        )?;
        statement
            .query_map([site_id], row_to_trusted_file)?
            .collect::<rusqlite::Result<_>>()
            .map_err(AppError::from)
    }

    pub fn get_trusted_file(&self, id: &str) -> Result<TrustedFile, AppError> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT t.id,t.site_id,s.name,t.relative_path,t.trusted_sha256,t.current_sha256,t.size_bytes,t.current_size_bytes,t.modified_at_snapshot,t.current_modified_at,t.file_type,t.status,t.trusted_at,t.last_checked_at,t.note,t.active
                 FROM trusted_files t JOIN sites s ON s.id=t.site_id WHERE t.id=?1",
                [id],
                row_to_trusted_file,
            )
            .optional()?
            .ok_or_else(|| AppError::not_found("Vertrouwd bestand"))
    }

    pub fn active_trusted_file(
        &self,
        site_id: &str,
        relative_path: &str,
    ) -> Result<Option<TrustedFile>, AppError> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT t.id,t.site_id,s.name,t.relative_path,t.trusted_sha256,t.current_sha256,t.size_bytes,t.current_size_bytes,t.modified_at_snapshot,t.current_modified_at,t.file_type,t.status,t.trusted_at,t.last_checked_at,t.note,t.active
                 FROM trusted_files t JOIN sites s ON s.id=t.site_id
                 WHERE t.site_id=?1 AND t.relative_path=?2 AND t.active=1",
                params![site_id, relative_path],
                row_to_trusted_file,
            )
            .optional()
            .map_err(AppError::from)
    }

    pub fn save_trusted_file(&self, trusted: &TrustedFile) -> Result<(), AppError> {
        let size_bytes = i64::try_from(trusted.size_bytes).map_err(AppError::storage)?;
        let current_size = trusted
            .current_size_bytes
            .map(i64::try_from)
            .transpose()
            .map_err(AppError::storage)?;
        let connection = self.connect()?;
        connection.execute(
            "INSERT INTO trusted_files(id,site_id,relative_path,trusted_sha256,current_sha256,size_bytes,current_size_bytes,modified_at_snapshot,current_modified_at,file_type,status,trusted_at,last_checked_at,note,active)
             VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15)
             ON CONFLICT(id) DO UPDATE SET trusted_sha256=excluded.trusted_sha256,current_sha256=excluded.current_sha256,size_bytes=excluded.size_bytes,current_size_bytes=excluded.current_size_bytes,modified_at_snapshot=excluded.modified_at_snapshot,current_modified_at=excluded.current_modified_at,file_type=excluded.file_type,status=excluded.status,trusted_at=excluded.trusted_at,last_checked_at=excluded.last_checked_at,note=excluded.note,active=excluded.active",
            params![
                trusted.id,
                trusted.site_id,
                trusted.relative_path,
                trusted.trusted_sha256,
                trusted.current_sha256,
                size_bytes,
                current_size,
                trusted.modified_at_snapshot,
                trusted.current_modified_at,
                trusted.file_type,
                trusted.status.as_db(),
                trusted.trusted_at,
                trusted.last_checked_at,
                trusted.note,
                trusted.active,
            ],
        )?;
        Ok(())
    }

    pub fn update_trusted_observation(
        &self,
        id: &str,
        current_sha256: Option<&str>,
        current_size_bytes: Option<u64>,
        current_modified_at: Option<&str>,
        status: TrustedFileStatus,
        checked_at: &str,
    ) -> Result<(), AppError> {
        let current_size = current_size_bytes
            .map(i64::try_from)
            .transpose()
            .map_err(AppError::storage)?;
        let connection = self.connect()?;
        connection.execute(
            "UPDATE trusted_files SET current_sha256=?1,current_size_bytes=?2,current_modified_at=?3,status=?4,last_checked_at=?5 WHERE id=?6 AND active=1",
            params![current_sha256,current_size,current_modified_at,status.as_db(),checked_at,id],
        )?;
        Ok(())
    }

    pub fn deactivate_trusted_file(&self, id: &str) -> Result<String, AppError> {
        let connection = self.connect()?;
        let site_id = connection
            .query_row(
                "SELECT site_id FROM trusted_files WHERE id=?1 AND active=1",
                [id],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .ok_or_else(|| AppError::not_found("Actief vertrouwd bestand"))?;
        connection.execute("UPDATE trusted_files SET active=0 WHERE id=?1", [id])?;
        Ok(site_id)
    }

    pub fn update_scan_policy(
        &self,
        scan: &ScanResult,
        security_status: &str,
    ) -> Result<(), AppError> {
        let connection = self.connect()?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "UPDATE scan_runs SET status=?1 WHERE id=?2 AND site_id=?3",
            params![scan.status.as_db(), scan.id, scan.site_id],
        )?;
        for check in &scan.checks {
            transaction.execute(
                "UPDATE scan_checks SET status=?1,summary=?2 WHERE scan_run_id=?3 AND check_key=?4",
                params![check.status.as_db(), check.summary, scan.id, check.key],
            )?;
            for finding in &check.findings {
                if let Some(finding_id) = finding.id.as_deref() {
                    transaction.execute(
                        "UPDATE findings SET severity=?1,disposition=?2,exception_id=?3,trusted_file_id=?4,policy_reason=?5 WHERE id=?6 AND scan_run_id=?7",
                        params![
                            finding.severity.as_db(),
                            finding.disposition.as_db(),
                            finding.exception_id,
                            finding.trusted_file_id,
                            finding.policy_reason,
                            finding_id,
                            scan.id,
                        ],
                    )?;
                }
            }
        }
        transaction.execute(
            "UPDATE sites SET status=?1,security_status=?2,updated_at=?3 WHERE id=?4",
            params![
                scan.status.as_db(),
                security_status,
                utc_now(),
                scan.site_id
            ],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn save_updates(&self, site_id: &str, updates: &[UpdateItem]) -> Result<(), AppError> {
        let connection = self.connect()?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute("DELETE FROM available_updates WHERE site_id=?1", [site_id])?;
        let checked_at = utc_now();
        for update in updates {
            transaction.execute(
                "INSERT INTO available_updates(id,site_id,kind,slug,name,current_version,new_version,checked_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
                params![Uuid::new_v4().to_string(), site_id, update.kind.as_db(), update.slug, update.name, update.current_version, update.new_version, checked_at],
            )?;
        }
        transaction.execute(
            "UPDATE sites SET update_count=?1,status=CASE WHEN ?1 > 0 AND status NOT IN ('problem','unreachable') THEN 'updates' WHEN ?1 = 0 AND status = 'updates' THEN 'healthy' ELSE status END,updated_at=?2 WHERE id=?3",
            params![updates.len() as u32, checked_at, site_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn list_cached_updates(&self, site_id: &str) -> Result<Vec<UpdateItem>, AppError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT kind,slug,name,current_version,new_version FROM available_updates WHERE site_id=?1 ORDER BY kind,name COLLATE NOCASE",
        )?;
        statement
            .query_map([site_id], |row| {
                Ok(UpdateItem {
                    kind: UpdateKind::from_db(&row.get::<_, String>(0)?),
                    slug: row.get(1)?,
                    name: row.get(2)?,
                    current_version: row.get(3)?,
                    new_version: row.get(4)?,
                    status: "available".into(),
                })
            })?
            .collect::<rusqlite::Result<_>>()
            .map_err(AppError::from)
    }

    pub fn update_versions(
        &self,
        site_id: &str,
        wordpress: &str,
        php: &str,
    ) -> Result<(), AppError> {
        let connection = self.connect()?;
        connection.execute(
            "UPDATE sites SET wordpress_version=?1,php_version=?2,updated_at=?3 WHERE id=?4",
            params![wordpress, php, utc_now(), site_id],
        )?;
        Ok(())
    }

    pub fn mark_unreachable(&self, site_id: &str) -> Result<(), AppError> {
        let connection = self.connect()?;
        connection.execute(
            "UPDATE sites SET status='unreachable',security_status='Scan mislukt',last_scan_at=?1,updated_at=?1 WHERE id=?2",
            params![utc_now(), site_id],
        )?;
        Ok(())
    }

    pub fn start_maintenance(&self, run: &MaintenanceRun) -> Result<(), AppError> {
        let connection = self.connect()?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "INSERT INTO maintenance_runs(id,site_id,started_at,status,before_versions) VALUES(?1,?2,?3,?4,?5)",
            params![run.id, run.site_id, run.started_at, run.status.as_db(), run.before_versions],
        )?;
        for (position, step) in run.steps.iter().enumerate() {
            transaction.execute(
                "INSERT INTO maintenance_steps(id,maintenance_run_id,step_key,label,status,detail,position) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![Uuid::new_v4().to_string(), run.id, step.key, step.label, step.status.as_db(), step.detail, position as u32],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn update_maintenance_step(
        &self,
        run_id: &str,
        step: &MaintenanceStep,
    ) -> Result<(), AppError> {
        let connection = self.connect()?;
        connection.execute(
            "UPDATE maintenance_steps SET status=?1,detail=?2 WHERE maintenance_run_id=?3 AND step_key=?4",
            params![step.status.as_db(), step.detail, run_id, step.key],
        )?;
        Ok(())
    }

    pub fn finish_maintenance(
        &self,
        run: &MaintenanceRun,
        backup: Option<(&str, u64, &str)>,
    ) -> Result<(), AppError> {
        let connection = self.connect()?;
        let transaction = connection.unchecked_transaction()?;
        transaction.execute(
            "UPDATE maintenance_runs SET finished_at=?1,status=?2,duration_ms=?3,before_versions=?4,after_versions=?5 WHERE id=?6",
            params![run.finished_at, run.status.as_db(), run.duration_ms.and_then(|value| i64::try_from(value).ok()), run.before_versions, run.after_versions, run.id],
        )?;
        if let Some((path, size, sha256)) = backup {
            transaction.execute(
                "INSERT INTO backup_records(id,maintenance_run_id,local_path,size_bytes,sha256,created_at,status) VALUES(?1,?2,?3,?4,?5,?6,'success')",
                params![Uuid::new_v4().to_string(), run.id, path, i64::try_from(size).unwrap_or(i64::MAX), sha256, utc_now()],
            )?;
        }
        transaction.execute(
            "UPDATE sites SET last_maintenance_at=?1,updated_at=?1 WHERE id=?2",
            params![run.finished_at, run.site_id],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn list_maintenance_runs(
        &self,
        site_id: Option<&str>,
    ) -> Result<Vec<MaintenanceRun>, AppError> {
        let connection = self.connect()?;
        let sql = "SELECT r.id,r.site_id,s.name,r.started_at,r.finished_at,r.status,r.duration_ms,r.before_versions,r.after_versions,(SELECT local_path FROM backup_records b WHERE b.maintenance_run_id=r.id ORDER BY b.created_at DESC LIMIT 1) FROM maintenance_runs r JOIN sites s ON s.id=r.site_id WHERE (?1 IS NULL OR r.site_id=?1) ORDER BY r.started_at DESC LIMIT 500";
        let mut statement = connection.prepare(sql)?;
        let rows = statement.query_map([site_id], |row| {
            Ok(MaintenanceRun {
                id: row.get(0)?,
                site_id: row.get(1)?,
                site_name: row.get(2)?,
                started_at: row.get(3)?,
                finished_at: row.get(4)?,
                status: StepStatus::from_db(&row.get::<_, String>(5)?),
                duration_ms: row
                    .get::<_, Option<i64>>(6)?
                    .and_then(|value| u64::try_from(value).ok()),
                before_versions: row.get(7)?,
                after_versions: row.get(8)?,
                backup_path: row.get(9)?,
                steps: Vec::new(),
            })
        })?;
        let mut runs: Vec<MaintenanceRun> = rows.collect::<rusqlite::Result<_>>()?;
        for run in &mut runs {
            let mut steps = connection.prepare("SELECT step_key,label,status,detail FROM maintenance_steps WHERE maintenance_run_id=?1 ORDER BY position")?;
            run.steps = steps
                .query_map([&run.id], |row| {
                    Ok(MaintenanceStep {
                        key: row.get(0)?,
                        label: row.get(1)?,
                        status: StepStatus::from_db(&row.get::<_, String>(2)?),
                        detail: row.get(3)?,
                    })
                })?
                .collect::<rusqlite::Result<_>>()?;
        }
        Ok(runs)
    }

    pub fn scan_concurrency(&self) -> Result<usize, AppError> {
        let connection = self.connect()?;
        let value: String = connection.query_row(
            "SELECT value FROM app_settings WHERE key='scan_concurrency'",
            [],
            |row| row.get(0),
        )?;
        value
            .parse::<usize>()
            .map(|value| value.clamp(1, 5))
            .map_err(AppError::storage)
    }

    pub fn set_scan_concurrency(&self, value: usize) -> Result<(), AppError> {
        let connection = self.connect()?;
        connection.execute(
            "INSERT INTO app_settings(key,value,updated_at) VALUES('scan_concurrency',?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at",
            params![value.to_string(), utc_now()],
        )?;
        Ok(())
    }

    pub fn vulnerability_feed_state(
        &self,
        provider: &str,
    ) -> Result<VulnerabilityFeedState, AppError> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT s.active_dataset_id,s.last_attempt_at,s.last_successful_update_at,s.last_error,COALESCE(d.vulnerability_count,0),COALESCE(d.software_record_count,0) FROM vulnerability_feed_state s LEFT JOIN vulnerability_datasets d ON d.id=s.active_dataset_id WHERE s.provider=?1",
                [provider],
                |row| {
                    Ok(VulnerabilityFeedState {
                        active_dataset_id: row.get(0)?,
                        last_attempt_at: row.get(1)?,
                        last_successful_update_at: row.get(2)?,
                        last_error: row.get(3)?,
                        vulnerability_count: u64::try_from(row.get::<_, i64>(4)?).unwrap_or(0),
                        software_record_count: u64::try_from(row.get::<_, i64>(5)?).unwrap_or(0),
                    })
                },
            )
            .optional()
            .map(|state| state.unwrap_or_default())
            .map_err(AppError::from)
    }

    pub fn vulnerability_feed_cooldown_remaining(
        &self,
        provider: &str,
        cooldown_seconds: i64,
    ) -> Result<u64, AppError> {
        let state = self.vulnerability_feed_state(provider)?;
        let Some(last_attempt) = state
            .last_attempt_at
            .as_deref()
            .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok())
        else {
            return Ok(0);
        };
        let remaining = cooldown_seconds - (Utc::now().timestamp() - last_attempt.timestamp());
        Ok(u64::try_from(remaining.max(0)).unwrap_or(0))
    }

    pub fn record_vulnerability_feed_attempt(&self, provider: &str) -> Result<String, AppError> {
        let connection = self.connect()?;
        let now = utc_now();
        connection.execute(
            "INSERT INTO vulnerability_feed_state(provider,last_attempt_at,updated_at) VALUES(?1,?2,?2) ON CONFLICT(provider) DO UPDATE SET last_attempt_at=excluded.last_attempt_at,updated_at=excluded.updated_at",
            params![provider, now],
        )?;
        Ok(now)
    }

    pub fn record_vulnerability_feed_failure(
        &self,
        provider: &str,
        summary: &str,
    ) -> Result<(), AppError> {
        let connection = self.connect()?;
        connection.execute(
            "INSERT INTO vulnerability_feed_state(provider,last_error,updated_at) VALUES(?1,?2,?3) ON CONFLICT(provider) DO UPDATE SET last_error=excluded.last_error,updated_at=excluded.updated_at",
            params![provider, bound_text(summary, 500), utc_now()],
        )?;
        Ok(())
    }

    pub fn import_wordfence_feed(
        &self,
        source: &Path,
        downloaded_at: &str,
    ) -> Result<VulnerabilityImportSummary, AppError> {
        let file = fs::File::open(source).map_err(AppError::storage)?;
        let mut connection = self.connect()?;
        let transaction = connection.transaction()?;
        let dataset_id = Uuid::new_v4().to_string();
        let parsed_at = utc_now();
        transaction.execute(
            "INSERT INTO vulnerability_datasets(id,provider,feed_type,downloaded_at,parsed_at,vulnerability_count,software_record_count,status,created_at) VALUES(?1,?2,'production',?3,?4,0,0,'superseded',?4)",
            params![dataset_id, WORDFENCE_PROVIDER, downloaded_at, parsed_at],
        )?;

        let mut deserializer = serde_json::Deserializer::from_reader(BufReader::new(file));
        let (vulnerability_count, software_record_count) = WordfenceFeedSeed {
            transaction: &transaction,
            dataset_id: &dataset_id,
        }
        .deserialize(&mut deserializer)
        .map_err(|error| AppError {
            error_id: None,
            category: "vulnerability_parse".into(),
            user_message: "De Wordfence vulnerability database kon niet worden verwerkt.".into(),
            technical_details: Some(format!(
                "Ongeldige V3 Production Feed bij regel {}, kolom {}: {error}",
                error.line(),
                error.column()
            )),
            retryable: false,
        })?;
        deserializer.end().map_err(|error| AppError {
            error_id: None,
            category: "vulnerability_parse".into(),
            user_message: "De Wordfence vulnerability database bevat extra ongeldige data.".into(),
            technical_details: Some(error.to_string()),
            retryable: false,
        })?;
        if vulnerability_count == 0 || software_record_count == 0 {
            return Err(AppError {
                error_id: None,
                category: "vulnerability_parse".into(),
                user_message: "De Wordfence vulnerability database bevat geen bruikbare records."
                    .into(),
                technical_details: Some("Een lege feed wordt niet geactiveerd.".into()),
                retryable: false,
            });
        }

        transaction.execute(
            "UPDATE vulnerability_datasets SET status='superseded' WHERE provider=?1 AND status='active'",
            [WORDFENCE_PROVIDER],
        )?;
        let vulnerability_count_db = i64::try_from(vulnerability_count)
            .map_err(|_| AppError::storage("Vulnerability count overflow"))?;
        let software_record_count_db = i64::try_from(software_record_count)
            .map_err(|_| AppError::storage("Software record count overflow"))?;
        transaction.execute(
            "UPDATE vulnerability_datasets SET vulnerability_count=?2,software_record_count=?3,status='active' WHERE id=?1",
            params![dataset_id, vulnerability_count_db, software_record_count_db],
        )?;
        transaction.execute(
            "INSERT INTO vulnerability_feed_state(provider,active_dataset_id,last_attempt_at,last_successful_update_at,last_error,updated_at) VALUES(?1,?2,?3,?3,NULL,?4) ON CONFLICT(provider) DO UPDATE SET active_dataset_id=excluded.active_dataset_id,last_attempt_at=excluded.last_attempt_at,last_successful_update_at=excluded.last_successful_update_at,last_error=NULL,updated_at=excluded.updated_at",
            params![WORDFENCE_PROVIDER, dataset_id, downloaded_at, parsed_at],
        )?;
        transaction.execute(
            "DELETE FROM vulnerability_datasets WHERE provider=?1 AND id<>?2",
            params![WORDFENCE_PROVIDER, dataset_id],
        )?;
        transaction.commit()?;
        Ok(VulnerabilityImportSummary {
            dataset_id,
            vulnerability_count,
            software_record_count,
            parsed_at,
        })
    }

    pub fn auth_config(&self) -> Result<Option<AuthConfig>, AppError> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT password_hash,idle_timeout_minutes FROM auth_config WHERE id=1",
                [],
                |row| {
                    Ok(AuthConfig {
                        password_hash: row.get(0)?,
                        idle_timeout_minutes: row.get(1)?,
                    })
                },
            )
            .optional()
            .map_err(AppError::from)
    }

    pub fn create_auth_config(&self, password_hash: &str) -> Result<AuthConfig, AppError> {
        let connection = self.connect()?;
        let now = utc_now();
        let changed = connection.execute(
            "INSERT OR IGNORE INTO auth_config(id,password_hash,idle_timeout_minutes,created_at,updated_at) VALUES(1,?1,15,?2,?2)",
            params![password_hash, now],
        )?;
        if changed != 1 {
            return Err(AppError::validation(
                "De applicatiebeveiliging is al ingesteld.",
            ));
        }
        self.auth_config()?
            .ok_or_else(|| AppError::storage("Auth config missing after insert"))
    }

    pub fn update_password_hash(&self, password_hash: &str) -> Result<(), AppError> {
        let connection = self.connect()?;
        if connection.execute(
            "UPDATE auth_config SET password_hash=?1,updated_at=?2 WHERE id=1",
            params![password_hash, utc_now()],
        )? != 1
        {
            return Err(AppError::validation(
                "Stel eerst een applicatiewachtwoord in.",
            ));
        }
        Ok(())
    }

    pub fn set_idle_timeout(&self, minutes: u16) -> Result<(), AppError> {
        let connection = self.connect()?;
        if connection.execute(
            "UPDATE auth_config SET idle_timeout_minutes=?1,updated_at=?2 WHERE id=1",
            params![minutes, utc_now()],
        )? != 1
        {
            return Err(AppError::validation(
                "Stel eerst een applicatiewachtwoord in.",
            ));
        }
        Ok(())
    }

    pub fn save_audit_event(
        &self,
        site_id: Option<&str>,
        action_type: &str,
        target: &str,
        status: &str,
        details: Option<&str>,
    ) -> Result<(), AppError> {
        let connection = self.connect()?;
        connection.execute(
            "INSERT INTO audit_events(id,site_id,action_type,target,status,details,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7)",
            params![Uuid::new_v4().to_string(), site_id, action_type, target, status, details, utc_now()],
        )?;
        Ok(())
    }

    pub fn list_audit_events(&self, site_id: Option<&str>) -> Result<Vec<AuditEvent>, AppError> {
        let connection = self.connect()?;
        let mut statement = connection.prepare(
            "SELECT id,site_id,action_type,target,status,details,created_at FROM audit_events WHERE (?1 IS NULL OR site_id=?1) ORDER BY created_at DESC LIMIT 500",
        )?;
        statement
            .query_map([site_id], |row| {
                Ok(AuditEvent {
                    id: row.get(0)?,
                    site_id: row.get(1)?,
                    action_type: row.get(2)?,
                    target: row.get(3)?,
                    status: row.get(4)?,
                    details: row.get(5)?,
                    created_at: row.get(6)?,
                })
            })?
            .collect::<rusqlite::Result<_>>()
            .map_err(AppError::from)
    }

    pub fn save_error_log(&self, record: &ErrorLogRecord) -> Result<(), AppError> {
        let connection = self.connect()?;
        let transaction = connection.unchecked_transaction()?;
        let cause_chain = if record.cause_chain.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&record.cause_chain).map_err(AppError::storage)?)
        };
        transaction.execute(
            "INSERT INTO error_logs(id,created_at,severity,category,site_id,site_name,action,summary,technical_details,exit_code,cause_chain,duration_ms,retryable) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",
            params![record.id, record.created_at, record.severity.as_db(), record.category.as_db(), record.site_id, record.site_name, record.action, record.summary, record.technical_details, record.exit_code, cause_chain, record.duration_ms.and_then(|value| i64::try_from(value).ok()), record.retryable],
        )?;
        transaction.execute(
            "DELETE FROM error_logs WHERE datetime(created_at) < datetime('now', '-30 days')",
            [],
        )?;
        transaction.execute(
            "DELETE FROM error_logs WHERE id IN (SELECT id FROM error_logs ORDER BY created_at DESC, rowid DESC LIMIT -1 OFFSET 10000)",
            [],
        )?;
        transaction.commit()?;
        Ok(())
    }

    pub fn list_error_logs(&self, filter: &ErrorLogFilter) -> Result<ErrorLogPage, AppError> {
        let connection = self.connect()?;
        let category = filter.category.map(ErrorCategory::as_db);
        let severity = filter.severity.map(ErrorSeverity::as_db);
        let query = filter
            .query
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(|value| {
                let bounded: String = value.chars().take(200).collect();
                format!("%{}%", bounded.to_lowercase())
            });
        let limit = filter.limit.unwrap_or(50).clamp(1, 100);
        let offset = filter.offset.unwrap_or(0).min(100_000);
        let where_sql = "(?1 IS NULL OR e.site_id=?1) AND (?2 IS NULL OR e.category=?2) AND (?3 IS NULL OR e.severity=?3) AND (?4 IS NULL OR e.created_at>=?4) AND (?5 IS NULL OR e.created_at<=?5) AND (?6 IS NULL OR lower(e.summary || ' ' || COALESCE(e.technical_details,'') || ' ' || e.action || ' ' || COALESCE(e.site_name,'')) LIKE ?6)";
        let total: i64 = connection.query_row(
            &format!("SELECT COUNT(*) FROM error_logs e WHERE {where_sql}"),
            params![
                filter.site_id,
                category,
                severity,
                filter.from,
                filter.to,
                query
            ],
            |row| row.get(0),
        )?;
        let mut statement = connection.prepare(&format!(
            "SELECT e.id,e.created_at,e.severity,e.category,e.site_id,e.site_name,e.action,e.summary,e.technical_details,e.exit_code,e.cause_chain,e.duration_ms,e.retryable FROM error_logs e WHERE {where_sql} ORDER BY e.created_at DESC,e.rowid DESC LIMIT ?7 OFFSET ?8"
        ))?;
        let records = statement
            .query_map(
                params![
                    filter.site_id,
                    category,
                    severity,
                    filter.from,
                    filter.to,
                    query,
                    limit,
                    offset
                ],
                row_to_error_log,
            )?
            .collect::<rusqlite::Result<_>>()?;
        Ok(ErrorLogPage {
            records,
            total: u64::try_from(total).unwrap_or(0),
            limit,
            offset,
        })
    }
}

struct WordfenceFeedSeed<'transaction, 'connection> {
    transaction: &'transaction Transaction<'connection>,
    dataset_id: &'transaction str,
}

impl<'de> DeserializeSeed<'de> for WordfenceFeedSeed<'_, '_> {
    type Value = (u64, u64);

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(WordfenceFeedVisitor {
            transaction: self.transaction,
            dataset_id: self.dataset_id,
        })
    }
}

struct WordfenceFeedVisitor<'transaction, 'connection> {
    transaction: &'transaction Transaction<'connection>,
    dataset_id: &'transaction str,
}

impl<'de> Visitor<'de> for WordfenceFeedVisitor<'_, '_> {
    type Value = (u64, u64);

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("een object met Wordfence V3-vulnerabilityrecords")
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut vulnerability_count = 0_u64;
        let mut software_record_count = 0_u64;
        while let Some((key, record)) = map.next_entry::<String, WordfenceVulnerability>()? {
            validate_wordfence_record(&key, &record).map_err(A::Error::custom)?;
            let inserted = insert_wordfence_record(self.transaction, self.dataset_id, &record)
                .map_err(A::Error::custom)?;
            vulnerability_count = vulnerability_count
                .checked_add(1)
                .ok_or_else(|| A::Error::custom("te veel vulnerabilityrecords"))?;
            software_record_count = software_record_count
                .checked_add(inserted)
                .ok_or_else(|| A::Error::custom("te veel softwarerecords"))?;
        }
        Ok((vulnerability_count, software_record_count))
    }
}

fn validate_wordfence_record(key: &str, record: &WordfenceVulnerability) -> Result<(), String> {
    if Uuid::parse_str(key).is_err() || key != record.id {
        return Err("de UUID-sleutel en vulnerability-id komen niet exact overeen".into());
    }
    if record.title.trim().is_empty() || record.title.len() > 20_000 {
        return Err(format!(
            "vulnerability {} heeft een ongeldige titel",
            record.id
        ));
    }
    if record.software.len() > 10_000
        || record.references.len() > 10_000
        || record.researchers.len() > 10_000
    {
        return Err(format!(
            "vulnerability {} overschrijdt recordlimieten",
            record.id
        ));
    }
    for software in &record.software {
        if !matches!(software.software_type.as_str(), "core" | "plugin" | "theme") {
            return Err(format!(
                "vulnerability {} heeft onbekend softwaretype",
                record.id
            ));
        }
        if software.slug.trim().is_empty()
            || software.slug.len() > 500
            || software.name.len() > 20_000
            || software.affected_versions.len() > 10_000
            || software.patched_versions.len() > 10_000
        {
            return Err(format!(
                "vulnerability {} heeft ongeldige softwaremetadata",
                record.id
            ));
        }
        for range in software.affected_versions.values() {
            if range.from_version.is_empty()
                || range.to_version.is_empty()
                || range.from_version.len() > 500
                || range.to_version.len() > 500
            {
                return Err(format!(
                    "vulnerability {} heeft een ongeldig versiebereik",
                    record.id
                ));
            }
        }
    }
    Ok(())
}

fn insert_wordfence_record(
    transaction: &Transaction<'_>,
    dataset_id: &str,
    record: &WordfenceVulnerability,
) -> Result<u64, String> {
    let researchers_json = serde_json::to_string(&record.researchers).map_err(|e| e.to_string())?;
    let references_json = serde_json::to_string(&record.references).map_err(|e| e.to_string())?;
    let copyrights_json = record
        .copyrights
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| e.to_string())?;
    let cwe = record.cwe.as_ref();
    let cvss = record.cvss.as_ref();
    transaction
        .execute(
            "INSERT INTO vulnerabilities(dataset_id,provider,vulnerability_id,title,description,informational,cve,cve_link,published,updated,cvss_vector,cvss_score,cvss_rating,cwe_id,cwe_name,cwe_description,researchers_json,references_json,copyrights_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19)",
            params![
                dataset_id,
                WORDFENCE_PROVIDER,
                record.id,
                record.title,
                record.description,
                record.informational,
                record.cve,
                record.cve_link,
                record.published,
                record.updated,
                cvss.map(|value| value.vector.as_str()),
                cvss.map(|value| value.score),
                cvss.map(|value| value.rating.as_str()),
                cwe.map(|value| value.id),
                cwe.map(|value| value.name.as_str()),
                cwe.map(|value| value.description.as_str()),
                researchers_json,
                references_json,
                copyrights_json,
            ],
        )
        .map_err(|error| error.to_string())?;
    for software in &record.software {
        let affected_ranges_json =
            serde_json::to_string(&software.affected_versions).map_err(|e| e.to_string())?;
        let patched_versions_json =
            serde_json::to_string(&software.patched_versions).map_err(|e| e.to_string())?;
        transaction
            .execute(
                "INSERT INTO vulnerable_software(id,dataset_id,provider,vulnerability_id,software_type,software_slug,software_name,affected_ranges_json,patched,patched_versions_json,remediation) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                params![
                    Uuid::new_v4().to_string(),
                    dataset_id,
                    WORDFENCE_PROVIDER,
                    record.id,
                    software.software_type,
                    software.slug,
                    software.name,
                    affected_ranges_json,
                    software.patched,
                    patched_versions_json,
                    software.remediation,
                ],
            )
            .map_err(|error| error.to_string())?;
    }
    u64::try_from(record.software.len()).map_err(|error| error.to_string())
}

fn bound_text(value: &str, max_chars: usize) -> String {
    value.chars().take(max_chars).collect()
}

fn row_to_finding_exception(row: &Row<'_>) -> rusqlite::Result<FindingException> {
    Ok(FindingException {
        id: row.get(0)?,
        site_id: row.get(1)?,
        site_name: row.get(2)?,
        check_type: row.get(3)?,
        finding_type: row.get(4)?,
        target: row.get(5)?,
        scope: ExceptionScope::from_db(&row.get::<_, String>(6)?),
        reason: row.get(7)?,
        note: row.get(8)?,
        created_at: row.get(9)?,
        expires_at: row.get(10)?,
        active: row.get(11)?,
    })
}

fn row_to_trusted_file(row: &Row<'_>) -> rusqlite::Result<TrustedFile> {
    Ok(TrustedFile {
        id: row.get(0)?,
        site_id: row.get(1)?,
        site_name: row.get(2)?,
        relative_path: row.get(3)?,
        trusted_sha256: row.get(4)?,
        current_sha256: row.get(5)?,
        size_bytes: u64::try_from(row.get::<_, i64>(6)?).unwrap_or(0),
        current_size_bytes: row
            .get::<_, Option<i64>>(7)?
            .and_then(|value| u64::try_from(value).ok()),
        modified_at_snapshot: row.get(8)?,
        current_modified_at: row.get(9)?,
        file_type: row.get(10)?,
        status: TrustedFileStatus::from_db(&row.get::<_, String>(11)?),
        trusted_at: row.get(12)?,
        last_checked_at: row.get(13)?,
        note: row.get(14)?,
        active: row.get(15)?,
    })
}

fn row_to_error_log(row: &Row<'_>) -> rusqlite::Result<ErrorLogRecord> {
    let cause_chain_json: Option<String> = row.get(10)?;
    Ok(ErrorLogRecord {
        id: row.get(0)?,
        created_at: row.get(1)?,
        severity: ErrorSeverity::from_db(&row.get::<_, String>(2)?),
        category: ErrorCategory::from_db(&row.get::<_, String>(3)?),
        site_id: row.get(4)?,
        site_name: row.get(5)?,
        action: row.get(6)?,
        summary: row.get(7)?,
        technical_details: row.get(8)?,
        exit_code: row.get(9)?,
        cause_chain: cause_chain_json
            .as_deref()
            .and_then(|value| serde_json::from_str(value).ok())
            .unwrap_or_default(),
        duration_ms: row
            .get::<_, Option<i64>>(11)?
            .and_then(|value| u64::try_from(value).ok()),
        retryable: row.get(12)?,
    })
}

fn row_to_stored_site(row: &Row<'_>) -> rusqlite::Result<StoredSite> {
    Ok(StoredSite {
        site: Site {
            id: row.get(0)?,
            name: row.get(1)?,
            url: row.get(2)?,
            ssh_host: row.get(3)?,
            ssh_port: row.get(4)?,
            ssh_username: row.get(5)?,
            auth_method: AuthMethod::from_db(&row.get::<_, String>(6)?),
            key_path: row.get(7)?,
            wordpress_path: row.get(8)?,
            pinned_host_key: row.get(10)?,
            status: SiteStatus::from_db(&row.get::<_, String>(11)?),
            wordpress_version: row.get(12)?,
            php_version: row.get(13)?,
            update_count: row.get(14)?,
            security_status: row.get(15)?,
            last_scan_at: row.get(16)?,
            last_maintenance_at: row.get(17)?,
            created_at: row.get(18)?,
            updated_at: row.get(19)?,
        },
        credential_ref: row.get(9)?,
    })
}

pub fn utc_now() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::AuthMethod;
    fn input() -> SiteInput {
        SiteInput {
            id: None,
            name: "Voorbeeld".into(),
            url: "https://example.test".into(),
            ssh_host: "example.test".into(),
            ssh_port: 22,
            ssh_username: "deploy".into(),
            auth_method: AuthMethod::KeyFile,
            key_path: Some("C:\\keys\\id_ed25519".into()),
            wordpress_path: "/var/www/public".into(),
            credential_secret: None,
        }
    }

    fn error_record(id: &str, created_at: &str) -> ErrorLogRecord {
        ErrorLogRecord {
            id: id.into(),
            created_at: created_at.into(),
            severity: ErrorSeverity::Error,
            category: ErrorCategory::SshChannel,
            site_id: None,
            site_name: Some("Voorbeeld".into()),
            action: "SSH verbinden".into(),
            summary: "Verbinding mislukt".into(),
            technical_details: Some("connection reset".into()),
            exit_code: None,
            cause_chain: Vec::new(),
            duration_ms: Some(20),
            retryable: true,
        }
    }

    fn wordfence_fixture(vulnerability_id: &str, software_json: &str) -> String {
        format!(
            r#"{{"{vulnerability_id}":{{"id":"{vulnerability_id}","title":"Fixture vulnerability","software":[{software_json}],"informational":false,"description":"Stored XSS fixture","references":["https://www.wordfence.com/threat-intel/vulnerabilities/example"],"cwe":{{"id":79,"name":"XSS","description":"Fixture"}},"cvss":{{"vector":"CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N","score":6.1,"rating":"Medium"}},"cve":"CVE-2026-1234","cve_link":"https://www.cve.org/CVERecord?id=CVE-2026-1234","researchers":["Researcher"],"published":"2026-09-01 10:00:00","updated":"2026-09-02 11:00:00","copyrights":{{"message":"Copyright applies","mitre":{{"notice":"MITRE notice","license":"License text","license_url":"https://www.cve.org/Legal/TermsOfUse"}}}}}}}}"#
        )
    }

    #[test]
    fn error_log_persists_filters_and_removes_expired_records() {
        let path = std::env::temp_dir().join(format!("wpmm-errors-{}.sqlite3", Uuid::new_v4()));
        let database = Database::initialize(path.clone()).unwrap();
        database
            .save_error_log(&error_record("ERR-OLD", "2020-01-01T00:00:00.000Z"))
            .unwrap();
        database
            .save_error_log(&error_record("ERR-NEW", &utc_now()))
            .unwrap();

        let page = database
            .list_error_logs(&ErrorLogFilter {
                category: Some(ErrorCategory::SshChannel),
                query: Some("reset".into()),
                ..ErrorLogFilter::default()
            })
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.records[0].id, "ERR-NEW");
        assert!(!page.records.iter().any(|record| record.id == "ERR-OLD"));
        drop(database);
        let _ = fs::remove_file(path);
    }
    #[test]
    fn migrates_and_roundtrips_sites() {
        let path = std::env::temp_dir().join(format!("wpmm-test-{}.sqlite3", Uuid::new_v4()));
        let database = Database::initialize(path.clone()).unwrap();
        let saved = database.save_site(&input(), Some("test-ref")).unwrap();
        assert_eq!(saved.name, "Voorbeeld");
        assert_eq!(database.list_sites().unwrap().len(), 1);
        assert_eq!(
            database.delete_site(&saved.id).unwrap().as_deref(),
            Some("test-ref")
        );
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn vulnerability_feed_import_is_atomic_normalized_and_replaces_complete_datasets() {
        let path = std::env::temp_dir().join(format!("wpmm-feed-{}.sqlite3", Uuid::new_v4()));
        let feed_path = std::env::temp_dir().join(format!("wpmm-feed-{}.json", Uuid::new_v4()));
        let database = Database::initialize(path.clone()).unwrap();
        let first_id = Uuid::new_v4().to_string();
        let plugin = r#"{"type":"plugin","name":"Example Plugin","slug":"example-plugin","affected_versions":{"1.0.0 - 1.2.3":{"from_version":"1.0.0","from_inclusive":true,"to_version":"1.2.3","to_inclusive":true}},"patched":true,"patched_versions":["1.2.4"],"remediation":"Update to 1.2.4"}"#;
        fs::write(&feed_path, wordfence_fixture(&first_id, plugin)).unwrap();
        let first = database
            .import_wordfence_feed(&feed_path, &utc_now())
            .unwrap();
        assert_eq!(first.vulnerability_count, 1);
        assert_eq!(first.software_record_count, 1);
        let state = database
            .vulnerability_feed_state(WORDFENCE_PROVIDER)
            .unwrap();
        assert_eq!(
            state.active_dataset_id.as_deref(),
            Some(first.dataset_id.as_str())
        );
        assert_eq!(state.vulnerability_count, 1);

        fs::write(&feed_path, "{malformed").unwrap();
        assert!(
            database
                .import_wordfence_feed(&feed_path, &utc_now())
                .is_err()
        );
        assert_eq!(
            database
                .vulnerability_feed_state(WORDFENCE_PROVIDER)
                .unwrap()
                .active_dataset_id,
            Some(first.dataset_id)
        );

        let second_id = Uuid::new_v4().to_string();
        let core = r#"{"type":"core","name":"WordPress","slug":"wordpress","affected_versions":{"* - 6.6.1":{"from_version":"*","from_inclusive":true,"to_version":"6.6.1","to_inclusive":true}},"patched":true,"patched_versions":["6.6.2"],"remediation":"Update WordPress"}"#;
        fs::write(&feed_path, wordfence_fixture(&second_id, core)).unwrap();
        let second = database
            .import_wordfence_feed(&feed_path, &utc_now())
            .unwrap();
        assert_ne!(second.dataset_id, first_id);
        let connection = database.connect().unwrap();
        let datasets: i64 = connection
            .query_row("SELECT COUNT(*) FROM vulnerability_datasets", [], |row| {
                row.get(0)
            })
            .unwrap();
        let old_records: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM vulnerabilities WHERE vulnerability_id=?1",
                [first_id],
                |row| row.get(0),
            )
            .unwrap();
        let copyrights: String = connection
            .query_row(
                "SELECT copyrights_json FROM vulnerabilities WHERE vulnerability_id=?1",
                [second_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(datasets, 1);
        assert_eq!(old_records, 0);
        assert!(copyrights.contains("MITRE notice"));
        drop(connection);
        drop(database);
        let _ = fs::remove_file(path);
        let _ = fs::remove_file(feed_path);
    }

    #[test]
    fn vulnerability_feed_attempt_enforces_a_local_cooldown() {
        let path = std::env::temp_dir().join(format!("wpmm-cooldown-{}.sqlite3", Uuid::new_v4()));
        let database = Database::initialize(path.clone()).unwrap();
        database
            .record_vulnerability_feed_attempt(WORDFENCE_PROVIDER)
            .unwrap();
        assert!(
            database
                .vulnerability_feed_cooldown_remaining(WORDFENCE_PROVIDER, 1_800)
                .unwrap()
                > 1_700
        );
        let old_attempt = (Utc::now() - chrono::Duration::minutes(31))
            .to_rfc3339_opts(SecondsFormat::Millis, true);
        database
            .connect()
            .unwrap()
            .execute(
                "UPDATE vulnerability_feed_state SET last_attempt_at=?1 WHERE provider=?2",
                params![old_attempt, WORDFENCE_PROVIDER],
            )
            .unwrap();
        assert_eq!(
            database
                .vulnerability_feed_cooldown_remaining(WORDFENCE_PROVIDER, 1_800)
                .unwrap(),
            0
        );
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn migration_roundtrips_site_exceptions_and_hash_trust_without_touching_sites() {
        let path = std::env::temp_dir().join(format!("wpmm-policy-{}.sqlite3", Uuid::new_v4()));
        let database = Database::initialize(path.clone()).unwrap();
        let site = database.save_site(&input(), None).unwrap();
        let exception = FindingException {
            id: Uuid::new_v4().to_string(),
            site_id: site.id.clone(),
            site_name: site.name.clone(),
            check_type: "core_checksum".into(),
            finding_type: "missing".into(),
            target: "readme.html".into(),
            scope: ExceptionScope::Site,
            reason: "Handmatig genegeerd".into(),
            note: Some("Niet operationeel relevant".into()),
            created_at: utc_now(),
            expires_at: None,
            active: true,
        };
        database.save_finding_exception(&exception).unwrap();
        database.save_finding_exception(&exception).unwrap();
        assert_eq!(
            database.list_finding_exceptions(Some(&site.id)).unwrap(),
            vec![exception.clone()]
        );

        let trusted = TrustedFile {
            id: Uuid::new_v4().to_string(),
            site_id: site.id.clone(),
            site_name: site.name.clone(),
            relative_path: "wp-content/custom-loader.php".into(),
            trusted_sha256: "a".repeat(64),
            current_sha256: Some("a".repeat(64)),
            size_bytes: 123,
            current_size_bytes: Some(123),
            modified_at_snapshot: Some(utc_now()),
            current_modified_at: Some(utc_now()),
            file_type: "regular".into(),
            status: TrustedFileStatus::Trusted,
            trusted_at: utc_now(),
            last_checked_at: Some(utc_now()),
            note: None,
            active: true,
        };
        database.save_trusted_file(&trusted).unwrap();
        database
            .update_trusted_observation(
                &trusted.id,
                Some(&"b".repeat(64)),
                Some(124),
                None,
                TrustedFileStatus::Changed,
                &utc_now(),
            )
            .unwrap();
        let changed = database.get_trusted_file(&trusted.id).unwrap();
        assert_eq!(changed.status, TrustedFileStatus::Changed);
        assert_eq!(changed.current_size_bytes, Some(124));
        assert_eq!(database.list_sites().unwrap().len(), 1);

        assert_eq!(
            database
                .deactivate_finding_exception(&exception.id)
                .unwrap(),
            site.id
        );
        assert_eq!(
            database.deactivate_trusted_file(&trusted.id).unwrap(),
            site.id
        );
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn restores_latest_scan_with_findings() {
        let path = std::env::temp_dir().join(format!("wpmm-test-{}.sqlite3", Uuid::new_v4()));
        let database = Database::initialize(path.clone()).unwrap();
        let site = database.save_site(&input(), None).unwrap();
        let scan = ScanResult {
            id: Uuid::new_v4().to_string(),
            site_id: site.id.clone(),
            started_at: "2026-08-25T10:00:00.000Z".into(),
            finished_at: "2026-08-25T10:00:01.000Z".into(),
            status: SiteStatus::Attention,
            checks: vec![ScanCheck {
                key: "core_checksum".into(),
                label: "WordPress core".into(),
                status: StepStatus::Warning,
                summary: "Eén aandachtspunt".into(),
                technical_details: Some("Actie: test; exitstatus: 1".into()),
                findings: vec![Finding {
                    id: Some("finding-test".into()),
                    category: "wordpress-core-unexpected".into(),
                    severity: FindingSeverity::Attention,
                    title: "Hoort niet aanwezig te zijn".into(),
                    detail: "Handmatige beoordeling nodig.".into(),
                    path: Some("unexpected.php".into()),
                    checksum_status: Some(ChecksumStatus::Unexpected),
                    disposition: crate::models::FindingDisposition::Active,
                    exception_id: None,
                    trusted_file_id: None,
                    policy_reason: None,
                    observed_at: Some("2026-08-25T10:00:00.000Z".into()),
                }],
            }],
            truncated: false,
        };
        database.save_scan(&scan, "Aandacht nodig").unwrap();

        let restored = database.list_scans(&site.id).unwrap().remove(0);
        assert_eq!(restored.id, scan.id);
        assert_eq!(restored.checks[0].findings, scan.checks[0].findings);
        assert_eq!(
            restored.checks[0].technical_details.as_deref(),
            Some("Actie: test; exitstatus: 1")
        );
        assert_eq!(database.list_scans(&site.id).unwrap().len(), 1);
        let current = database
            .current_unexpected_checksum_finding(&site.id, "finding-test")
            .unwrap();
        assert_eq!(current.site_id, site.id);
        assert!(
            database
                .current_unexpected_checksum_finding("another-site", "finding-test")
                .is_err()
        );

        let mut newer_scan = scan.clone();
        newer_scan.id = Uuid::new_v4().to_string();
        newer_scan.started_at = "2026-08-25T11:00:00.000Z".into();
        newer_scan.finished_at = "2026-08-25T11:00:01.000Z".into();
        newer_scan.checks[0].findings[0].id = Some("modified-finding".into());
        newer_scan.checks[0].findings[0].checksum_status = Some(ChecksumStatus::Modified);
        database
            .save_scan(&newer_scan, "Probleem gevonden")
            .unwrap();
        assert!(
            database
                .current_unexpected_checksum_finding(&site.id, "finding-test")
                .is_err()
        );
        assert!(
            database
                .current_unexpected_checksum_finding(&site.id, "modified-finding")
                .is_err()
        );

        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn persists_five_thousand_findings_in_one_transaction() {
        let path = std::env::temp_dir().join(format!("wpmm-stress-{}.sqlite3", Uuid::new_v4()));
        let database = Database::initialize(path.clone()).unwrap();
        let site = database.save_site(&input(), None).unwrap();
        let findings = (0..5_000)
            .map(|index| Finding {
                id: Some(format!("stress-{index}")),
                category: "stress".into(),
                severity: FindingSeverity::Attention,
                title: format!("Finding {index}"),
                detail: "Gebonden testfinding".into(),
                path: Some(format!("wp-content/uploads/file-{index}.php")),
                checksum_status: None,
                disposition: crate::models::FindingDisposition::Active,
                exception_id: None,
                trusted_file_id: None,
                policy_reason: None,
                observed_at: None,
            })
            .collect();
        let scan = ScanResult {
            id: Uuid::new_v4().to_string(),
            site_id: site.id.clone(),
            started_at: utc_now(),
            finished_at: utc_now(),
            status: SiteStatus::Attention,
            checks: vec![ScanCheck {
                key: "stress".into(),
                label: "Stress".into(),
                status: StepStatus::Warning,
                summary: "5000 findings".into(),
                technical_details: None,
                findings,
            }],
            truncated: false,
        };

        let write_started = std::time::Instant::now();
        database.save_scan(&scan, "Aandacht nodig").unwrap();
        let write_ms = write_started.elapsed().as_millis();
        let read_started = std::time::Instant::now();
        let restored = database.list_scans(&site.id).unwrap();
        eprintln!(
            "sqlite_5000_findings_write_ms={} read_ms={}",
            write_ms,
            read_started.elapsed().as_millis()
        );
        assert_eq!(restored[0].checks[0].findings.len(), 5_000);

        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn performance_migration_enables_wal_and_indexed_lookup_plans() {
        let path = std::env::temp_dir().join(format!("wpmm-query-plan-{}.sqlite3", Uuid::new_v4()));
        let database = Database::initialize(path.clone()).unwrap();
        let connection = database.connect().unwrap();
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(journal_mode.to_ascii_lowercase(), "wal");

        let scan_check_plan: String = connection
            .query_row(
                "EXPLAIN QUERY PLAN SELECT id FROM scan_checks WHERE scan_run_id=?1 AND check_key=?2",
                params!["scan", "core_checksum"],
                |row| row.get(3),
            )
            .unwrap();
        assert!(scan_check_plan.contains("idx_scan_checks_run_key"));

        let finding_plan: String = connection
            .query_row(
                "EXPLAIN QUERY PLAN SELECT id FROM findings WHERE scan_check_id=?1",
                ["check"],
                |row| row.get(3),
            )
            .unwrap();
        assert!(finding_plan.contains("idx_findings_check"));

        drop(connection);
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn auth_config_is_created_once_and_never_replaced() {
        let path = std::env::temp_dir().join(format!("wpmm-test-{}.sqlite3", Uuid::new_v4()));
        let database = Database::initialize(path.clone()).unwrap();
        let encoded = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdA$aGFzaA";
        let config = database.create_auth_config(encoded).unwrap();
        assert_eq!(config.password_hash, encoded);
        assert_eq!(config.idle_timeout_minutes, 15);
        assert!(database.create_auth_config("plaintext").is_err());
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn persists_core_operation_in_maintenance_history() {
        let path = std::env::temp_dir().join(format!("wpmm-test-{}.sqlite3", Uuid::new_v4()));
        let database = Database::initialize(path.clone()).unwrap();
        let site = database.save_site(&input(), None).unwrap();
        let stored = database.get_site(&site.id).unwrap();
        let mut run =
            crate::core_operations::new_run(&stored, crate::models::CoreOperationKind::Repair);

        database.start_maintenance(&run).unwrap();
        for step in &mut run.steps {
            step.status = StepStatus::Success;
            step.detail = Some("Teststap voltooid.".into());
            database.update_maintenance_step(&run.id, step).unwrap();
        }
        run.status = StepStatus::Success;
        run.finished_at = Some("2026-08-31T12:00:00.000Z".into());
        run.duration_ms = Some(1_250);
        run.before_versions = Some("WordPress 6.8.2".into());
        run.after_versions = Some("WordPress 6.8.2".into());
        database.finish_maintenance(&run, None).unwrap();

        let restored = database
            .list_maintenance_runs(Some(&site.id))
            .unwrap()
            .remove(0);
        assert_eq!(restored.id, run.id);
        assert_eq!(restored.status, StepStatus::Success);
        assert_eq!(restored.steps.len(), run.steps.len());
        assert_eq!(restored.steps[0].key, "preflight");
        assert_eq!(restored.steps[2].key, "repair");
        assert!(restored.steps.iter().all(|step| {
            step.status == StepStatus::Success
                && step.detail.as_deref() == Some("Teststap voltooid.")
        }));

        drop(database);
        let _ = fs::remove_file(path);
    }
}
