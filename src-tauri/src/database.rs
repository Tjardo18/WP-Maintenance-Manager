use crate::{
    error::AppError,
    models::{
        AuditEvent, AuthConfig, AuthMethod, ChecksumFindingRecord, ChecksumStatus, Finding,
        FindingSeverity, MaintenanceRun, MaintenanceStep, ScanCheck, ScanResult, Site, SiteInput,
        SiteStatus, StepStatus, StoredSite, UpdateItem,
    },
};
use chrono::{SecondsFormat, Utc};
use rusqlite::{Connection, OptionalExtension, Row, params};
use std::{fs, path::PathBuf};
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
        for check in &scan.checks {
            let check_id = Uuid::new_v4().to_string();
            transaction.execute(
                "INSERT INTO scan_checks(id,scan_run_id,check_key,label,status,summary) VALUES(?1,?2,?3,?4,?5,?6)",
                params![check_id, scan.id, check.key, check.label, check.status.as_db(), check.summary],
            )?;
            for finding in &check.findings {
                let finding_id = finding
                    .id
                    .clone()
                    .unwrap_or_else(|| Uuid::new_v4().to_string());
                transaction.execute(
                    "INSERT INTO findings(id,scan_check_id,category,severity,title,detail,path,checksum_status,observed_at,site_id,scan_run_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                    params![finding_id, check_id, finding.category, finding.severity.as_db(), finding.title, finding.detail, finding.path, finding.checksum_status.map(ChecksumStatus::as_db), finding.observed_at, scan.site_id, scan.id],
                )?;
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
        self.list_scans_with_limit(site_id, 50)
    }

    pub fn current_unexpected_checksum_finding(
        &self,
        site_id: &str,
        finding_id: &str,
    ) -> Result<ChecksumFindingRecord, AppError> {
        let connection = self.connect()?;
        connection
            .query_row(
                "SELECT f.id,f.site_id,f.scan_run_id,f.category,f.severity,f.title,f.detail,f.path,f.checksum_status,f.observed_at
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
        let mut scan_statement = connection.prepare(
            "SELECT id,site_id,started_at,COALESCE(finished_at,started_at),status,truncated FROM scan_runs WHERE site_id=?1 ORDER BY started_at DESC LIMIT ?2",
        )?;
        let scan_rows = scan_statement.query_map(params![site_id, row_limit], |row| {
            Ok(ScanResult {
                id: row.get(0)?,
                site_id: row.get(1)?,
                started_at: row.get(2)?,
                finished_at: row.get(3)?,
                status: SiteStatus::from_db(&row.get::<_, String>(4)?),
                checks: Vec::new(),
                truncated: row.get(5)?,
            })
        })?;
        let mut scans: Vec<ScanResult> = scan_rows.collect::<rusqlite::Result<_>>()?;
        for scan in &mut scans {
            let mut check_statement = connection.prepare(
                "SELECT id,check_key,label,status,summary FROM scan_checks WHERE scan_run_id=?1 ORDER BY rowid",
            )?;
            let check_rows = check_statement.query_map([&scan.id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    ScanCheck {
                        key: row.get(1)?,
                        label: row.get(2)?,
                        status: StepStatus::from_db(&row.get::<_, String>(3)?),
                        summary: row.get(4)?,
                        findings: Vec::new(),
                    },
                ))
            })?;
            let mut checks: Vec<(String, ScanCheck)> =
                check_rows.collect::<rusqlite::Result<_>>()?;
            for (check_id, check) in &mut checks {
                let mut finding_statement = connection.prepare(
                    "SELECT id,category,severity,title,detail,path,checksum_status,observed_at FROM findings WHERE scan_check_id=?1 ORDER BY rowid",
                )?;
                check.findings = finding_statement
                    .query_map([check_id.as_str()], |row| {
                        Ok(Finding {
                            id: row.get(0)?,
                            category: row.get(1)?,
                            severity: FindingSeverity::from_db(&row.get::<_, String>(2)?),
                            title: row.get(3)?,
                            detail: row.get(4)?,
                            path: row.get(5)?,
                            checksum_status: row
                                .get::<_, Option<String>>(6)?
                                .as_deref()
                                .and_then(ChecksumStatus::from_db),
                            observed_at: row.get(7)?,
                        })
                    })?
                    .collect::<rusqlite::Result<_>>()?;
            }
            scan.checks = checks.into_iter().map(|(_, check)| check).collect();
        }
        Ok(scans)
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
                findings: vec![Finding {
                    id: Some("finding-test".into()),
                    category: "wordpress-core-unexpected".into(),
                    severity: FindingSeverity::Attention,
                    title: "Hoort niet aanwezig te zijn".into(),
                    detail: "Handmatige beoordeling nodig.".into(),
                    path: Some("unexpected.php".into()),
                    checksum_status: Some(ChecksumStatus::Unexpected),
                    observed_at: Some("2026-08-25T10:00:00.000Z".into()),
                }],
            }],
            truncated: false,
        };
        database.save_scan(&scan, "Aandacht nodig").unwrap();

        let restored = database.list_scans(&site.id).unwrap().remove(0);
        assert_eq!(restored.id, scan.id);
        assert_eq!(restored.checks[0].findings, scan.checks[0].findings);
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
}
