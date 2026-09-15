use crate::{
    database::{Database, utc_now},
    error::AppError,
    snapshots::{MAX_SNAPSHOTS_PER_SITE, SNAPSHOT_SCHEMA_VERSION, SiteSnapshot, SnapshotDiff},
};
use rusqlite::{OptionalExtension, Transaction, params};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotPersistResult {
    pub snapshot_id: String,
    pub first_snapshot: bool,
    pub is_baseline: bool,
    pub removed_by_retention: usize,
}

pub struct SnapshotRepository<'a> {
    database: &'a Database,
}

struct StoredSnapshotPayload {
    schema_version: u32,
    encoding: String,
    payload: Vec<u8>,
    is_baseline: bool,
    previous_snapshot_id: Option<String>,
}

impl Database {
    pub fn snapshot_repository(&self) -> SnapshotRepository<'_> {
        SnapshotRepository { database: self }
    }
}

impl SnapshotRepository<'_> {
    pub fn save_snapshot(
        &self,
        snapshot: &SiteSnapshot,
    ) -> Result<SnapshotPersistResult, AppError> {
        self.save_snapshot_with_diff(snapshot, None)
    }

    pub fn save_snapshot_with_diff(
        &self,
        snapshot: &SiteSnapshot,
        diff: Option<&SnapshotDiff>,
    ) -> Result<SnapshotPersistResult, AppError> {
        let mut connection = self.database.connect()?;
        let transaction = connection.transaction()?;
        let result = persist_snapshot_in_transaction(&transaction, snapshot, diff)?;
        transaction.commit()?;
        Ok(result)
    }

    pub fn get_snapshot(&self, snapshot_id: &str) -> Result<SiteSnapshot, AppError> {
        let connection = self.database.connect()?;
        load_snapshot(&connection, snapshot_id)?.ok_or_else(|| AppError::not_found("Momentopname"))
    }

    pub fn latest_snapshot(&self, site_id: &str) -> Result<Option<SiteSnapshot>, AppError> {
        let connection = self.database.connect()?;
        let id: Option<String> = connection
            .query_row(
                "SELECT id FROM site_snapshots WHERE site_id=?1 ORDER BY created_at DESC,rowid DESC LIMIT 1",
                [site_id],
                |row| row.get(0),
            )
            .optional()?;
        id.as_deref()
            .map(|id| load_snapshot(&connection, id))
            .transpose()
            .map(Option::flatten)
    }

    pub fn baseline_snapshot(&self, site_id: &str) -> Result<Option<SiteSnapshot>, AppError> {
        let connection = self.database.connect()?;
        let id: Option<String> = connection
            .query_row(
                "SELECT baseline_snapshot_id FROM site_snapshot_state WHERE site_id=?1",
                [site_id],
                |row| row.get(0),
            )
            .optional()?
            .flatten();
        id.as_deref()
            .map(|id| load_snapshot(&connection, id))
            .transpose()
            .map(Option::flatten)
    }

    pub fn list_snapshots(
        &self,
        site_id: &str,
        limit: usize,
    ) -> Result<Vec<SiteSnapshot>, AppError> {
        let connection = self.database.connect()?;
        let limit = i64::try_from(limit.clamp(1, MAX_SNAPSHOTS_PER_SITE))
            .unwrap_or(MAX_SNAPSHOTS_PER_SITE as i64);
        let mut statement = connection.prepare(
            "SELECT id FROM site_snapshots WHERE site_id=?1 ORDER BY created_at DESC,rowid DESC LIMIT ?2",
        )?;
        let ids = statement
            .query_map(params![site_id, limit], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ids.iter()
            .map(|id| {
                load_snapshot(&connection, id)?.ok_or_else(|| AppError::not_found("Momentopname"))
            })
            .collect()
    }

    pub fn mark_as_baseline(&self, site_id: &str, snapshot_id: &str) -> Result<(), AppError> {
        let mut connection = self.database.connect()?;
        let transaction = connection.transaction()?;
        let belongs_to_site: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM site_snapshots WHERE id=?1 AND site_id=?2)",
            params![snapshot_id, site_id],
            |row| row.get(0),
        )?;
        if !belongs_to_site {
            return Err(AppError::not_found("Momentopname"));
        }
        transaction.execute(
            "UPDATE site_snapshots SET is_baseline=0 WHERE site_id=?1",
            [site_id],
        )?;
        transaction.execute(
            "UPDATE site_snapshots SET is_baseline=1 WHERE id=?1 AND site_id=?2",
            params![snapshot_id, site_id],
        )?;
        refresh_state(&transaction, site_id)?;
        transaction.commit()?;
        Ok(())
    }
}

pub(crate) fn persist_snapshot_in_transaction(
    transaction: &Transaction<'_>,
    snapshot: &SiteSnapshot,
    diff: Option<&SnapshotDiff>,
) -> Result<SnapshotPersistResult, AppError> {
    validate_snapshot(snapshot)?;
    validate_relations(transaction, snapshot)?;
    let first_snapshot = transaction.query_row(
        "SELECT NOT EXISTS(SELECT 1 FROM site_snapshots WHERE site_id=?1)",
        [&snapshot.metadata.site_id],
        |row| row.get(0),
    )?;
    if snapshot.metadata.is_baseline {
        transaction.execute(
            "UPDATE site_snapshots SET is_baseline=0 WHERE site_id=?1",
            [&snapshot.metadata.site_id],
        )?;
    }
    let section_status_json =
        serde_json::to_string(&snapshot.completeness).map_err(snapshot_persist_error)?;
    let payload = serde_json::to_vec(snapshot).map_err(snapshot_persist_error)?;
    transaction.execute(
        "INSERT INTO site_snapshots(id,site_id,created_at,scan_run_id,maintenance_run_id,source,schema_version,status,wordpress_root_identity,scan_timestamp,app_version,section_status_json,payload_encoding,payload,is_baseline,previous_snapshot_id) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,'json_utf8',?13,?14,?15)",
        params![
            snapshot.metadata.snapshot_id,
            snapshot.metadata.site_id,
            snapshot.metadata.created_at,
            snapshot.metadata.scan_run_id,
            snapshot.metadata.maintenance_run_id,
            snapshot.metadata.source.as_db(),
            snapshot.metadata.schema_version,
            snapshot.metadata.status.as_db(),
            snapshot.metadata.wordpress_root_identity,
            snapshot.metadata.scan_timestamp,
            snapshot.metadata.app_version,
            section_status_json,
            payload,
            snapshot.metadata.is_baseline,
            snapshot.metadata.previous_snapshot_id,
        ],
    )?;
    if let Some(diff) = diff {
        persist_diff(transaction, snapshot, diff)?;
    }
    let removed_by_retention = enforce_retention(transaction, &snapshot.metadata.site_id)?;
    refresh_state(transaction, &snapshot.metadata.site_id)?;
    Ok(SnapshotPersistResult {
        snapshot_id: snapshot.metadata.snapshot_id.clone(),
        first_snapshot,
        is_baseline: snapshot.metadata.is_baseline,
        removed_by_retention,
    })
}

fn persist_diff(
    transaction: &Transaction<'_>,
    snapshot: &SiteSnapshot,
    diff: &SnapshotDiff,
) -> Result<(), AppError> {
    validate_diff(snapshot, diff)?;
    transaction.execute(
        "INSERT INTO snapshot_diffs(id,site_id,from_snapshot_id,to_snapshot_id,created_at,schema_version,origin,maintenance_run_id,change_count) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
        params![
            diff.id,
            diff.site_id,
            diff.from_snapshot_id,
            diff.to_snapshot_id,
            diff.created_at,
            diff.schema_version,
            enum_db(&diff.origin)?,
            diff.maintenance_run_id,
            i64::try_from(diff.changes.len()).map_err(snapshot_persist_error)?,
        ],
    )?;
    {
        let mut insert = transaction.prepare_cached(
            "INSERT INTO snapshot_diff_sections(diff_id,category,status,reason) VALUES(?1,?2,?3,?4)",
        )?;
        for section in &diff.sections {
            insert.execute(params![
                diff.id,
                section.category.as_db(),
                enum_db(&section.status)?,
                section.reason,
            ])?;
        }
    }
    {
        let mut insert = transaction.prepare_cached(
            "INSERT INTO snapshot_changes(id,diff_id,site_id,from_snapshot_id,to_snapshot_id,category,entity_type,entity_key,change_type,field,old_value_json,new_value_json,severity,summary,metadata_json,origin,seen,created_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18)",
        )?;
        for change in &diff.changes {
            insert.execute(params![
                change.id,
                diff.id,
                change.site_id,
                change.from_snapshot_id,
                change.to_snapshot_id,
                change.category.as_db(),
                change.entity_type,
                change.entity_key,
                enum_db(&change.change_type)?,
                change.field,
                change
                    .old_value
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()
                    .map_err(snapshot_persist_error)?,
                change
                    .new_value
                    .as_ref()
                    .map(serde_json::to_string)
                    .transpose()
                    .map_err(snapshot_persist_error)?,
                enum_db(&change.severity)?,
                change.summary,
                serde_json::to_string(&change.metadata).map_err(snapshot_persist_error)?,
                enum_db(&change.origin)?,
                change.seen,
                change.created_at,
            ])?;
        }
    }
    Ok(())
}

fn validate_diff(snapshot: &SiteSnapshot, diff: &SnapshotDiff) -> Result<(), AppError> {
    if diff.schema_version != SNAPSHOT_SCHEMA_VERSION
        || diff.site_id != snapshot.metadata.site_id
        || diff.to_snapshot_id != snapshot.metadata.snapshot_id
        || snapshot.metadata.previous_snapshot_id.as_deref() != Some(diff.from_snapshot_id.as_str())
        || diff.changes.iter().any(|change| {
            change.site_id != diff.site_id
                || change.from_snapshot_id != diff.from_snapshot_id
                || change.to_snapshot_id != diff.to_snapshot_id
        })
    {
        return Err(snapshot_persist_error(
            "De snapshotdiff komt niet overeen met de gekoppelde momentopnames.",
        ));
    }
    Ok(())
}

fn enum_db(value: &impl serde::Serialize) -> Result<String, AppError> {
    serde_json::to_value(value)
        .map_err(snapshot_persist_error)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| snapshot_persist_error("Een snapshotwaarde kon niet worden opgeslagen."))
}

fn validate_snapshot(snapshot: &SiteSnapshot) -> Result<(), AppError> {
    if snapshot.metadata.schema_version != SNAPSHOT_SCHEMA_VERSION {
        return Err(snapshot_schema_error(format!(
            "Snapshot schema {} wordt niet ondersteund; verwacht {}.",
            snapshot.metadata.schema_version, SNAPSHOT_SCHEMA_VERSION
        )));
    }
    if snapshot.metadata.status != snapshot.completeness.overall_status() {
        return Err(snapshot_persist_error(
            "De snapshotstatus komt niet overeen met de sectiestatussen.",
        ));
    }
    if snapshot.metadata.snapshot_id.trim().is_empty()
        || snapshot.metadata.site_id.trim().is_empty()
        || snapshot.metadata.created_at.trim().is_empty()
    {
        return Err(snapshot_persist_error("De snapshotmetadata is onvolledig."));
    }
    Ok(())
}

fn validate_relations(
    transaction: &Transaction<'_>,
    snapshot: &SiteSnapshot,
) -> Result<(), AppError> {
    let site_exists: bool = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM sites WHERE id=?1)",
        [&snapshot.metadata.site_id],
        |row| row.get(0),
    )?;
    if !site_exists {
        return Err(snapshot_persist_error(
            "De website voor de momentopname bestaat niet.",
        ));
    }
    for (table, relation_id, label) in [
        (
            "scan_runs",
            snapshot.metadata.scan_run_id.as_deref(),
            "scan",
        ),
        (
            "maintenance_runs",
            snapshot.metadata.maintenance_run_id.as_deref(),
            "maintenance-run",
        ),
        (
            "site_snapshots",
            snapshot.metadata.previous_snapshot_id.as_deref(),
            "vorige momentopname",
        ),
    ] {
        let Some(relation_id) = relation_id else {
            continue;
        };
        let sql = format!("SELECT EXISTS(SELECT 1 FROM {table} WHERE id=?1 AND site_id=?2)");
        let valid: bool = transaction.query_row(
            &sql,
            params![relation_id, snapshot.metadata.site_id],
            |row| row.get(0),
        )?;
        if !valid {
            return Err(snapshot_persist_error(format!(
                "De gekoppelde {label} hoort niet bij deze website."
            )));
        }
    }
    Ok(())
}

fn enforce_retention(transaction: &Transaction<'_>, site_id: &str) -> Result<usize, AppError> {
    let total: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM site_snapshots WHERE site_id=?1",
        [site_id],
        |row| row.get(0),
    )?;
    let excess = (total - MAX_SNAPSHOTS_PER_SITE as i64).max(0);
    if excess == 0 {
        return Ok(0);
    }
    let ids = {
        let mut statement = transaction.prepare(
            "SELECT id FROM site_snapshots WHERE site_id=?1 AND is_baseline=0 AND source NOT IN ('pre_maintenance','post_maintenance') ORDER BY created_at ASC,rowid ASC LIMIT ?2",
        )?;
        statement
            .query_map(params![site_id, excess], |row| row.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
    };
    for id in &ids {
        transaction.execute("DELETE FROM site_snapshots WHERE id=?1", [id])?;
    }
    Ok(ids.len())
}

fn refresh_state(transaction: &Transaction<'_>, site_id: &str) -> Result<(), AppError> {
    let latest: Option<(String, String)> = transaction
        .query_row(
            "SELECT id,created_at FROM site_snapshots WHERE site_id=?1 ORDER BY created_at DESC,rowid DESC LIMIT 1",
            [site_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let baseline: Option<String> = transaction
        .query_row(
            "SELECT id FROM site_snapshots WHERE site_id=?1 AND is_baseline=1 LIMIT 1",
            [site_id],
            |row| row.get(0),
        )
        .optional()?;
    let (latest_id, latest_at) = latest.unzip();
    let latest_change_count: i64 = latest_id.as_deref().map_or(Ok(0), |snapshot_id| {
        transaction.query_row(
            "SELECT COALESCE(MAX(change_count),0) FROM snapshot_diffs WHERE to_snapshot_id=?1",
            [snapshot_id],
            |row| row.get(0),
        )
    })?;
    let unseen_change_count: i64 = transaction.query_row(
        "SELECT COUNT(*) FROM snapshot_changes WHERE site_id=?1 AND seen=0",
        [site_id],
        |row| row.get(0),
    )?;
    let important_change_summary: Option<String> = latest_id
        .as_deref()
        .map(|snapshot_id| {
            transaction
                .query_row(
                    "SELECT summary FROM snapshot_changes WHERE to_snapshot_id=?1 AND severity IN ('critical','warning') ORDER BY CASE severity WHEN 'critical' THEN 0 ELSE 1 END,created_at DESC LIMIT 1",
                    [snapshot_id],
                    |row| row.get(0),
                )
                .optional()
        })
        .transpose()?
        .flatten();
    transaction.execute(
        "INSERT INTO site_snapshot_state(site_id,latest_snapshot_id,baseline_snapshot_id,latest_snapshot_at,latest_change_count,unseen_change_count,important_change_summary,updated_at) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(site_id) DO UPDATE SET latest_snapshot_id=excluded.latest_snapshot_id,baseline_snapshot_id=excluded.baseline_snapshot_id,latest_snapshot_at=excluded.latest_snapshot_at,latest_change_count=excluded.latest_change_count,unseen_change_count=excluded.unseen_change_count,important_change_summary=excluded.important_change_summary,updated_at=excluded.updated_at",
        params![site_id, latest_id, baseline, latest_at, latest_change_count, unseen_change_count, important_change_summary, utc_now()],
    )?;
    Ok(())
}

fn load_snapshot(
    connection: &rusqlite::Connection,
    snapshot_id: &str,
) -> Result<Option<SiteSnapshot>, AppError> {
    let stored: Option<StoredSnapshotPayload> = connection
        .query_row(
            "SELECT schema_version,payload_encoding,payload,is_baseline,previous_snapshot_id FROM site_snapshots WHERE id=?1",
            [snapshot_id],
            |row| Ok(StoredSnapshotPayload {
                schema_version: row.get(0)?,
                encoding: row.get(1)?,
                payload: row.get(2)?,
                is_baseline: row.get(3)?,
                previous_snapshot_id: row.get(4)?,
            }),
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    if stored.schema_version != SNAPSHOT_SCHEMA_VERSION {
        return Err(snapshot_schema_error(format!(
            "Snapshot schema {} wordt nog niet ondersteund.",
            stored.schema_version
        )));
    }
    if stored.encoding != "json_utf8" {
        return Err(snapshot_schema_error(format!(
            "Snapshot encoding {} wordt nog niet ondersteund.",
            stored.encoding
        )));
    }
    let mut snapshot: SiteSnapshot =
        serde_json::from_slice(&stored.payload).map_err(snapshot_schema_error)?;
    if snapshot.metadata.schema_version != stored.schema_version
        || snapshot.metadata.snapshot_id != snapshot_id
    {
        return Err(snapshot_schema_error(
            "De snapshotpayload komt niet overeen met de relationele metadata.",
        ));
    }
    snapshot.metadata.is_baseline = stored.is_baseline;
    snapshot.metadata.previous_snapshot_id = stored.previous_snapshot_id;
    Ok(Some(snapshot))
}

fn snapshot_persist_error(error: impl std::fmt::Display) -> AppError {
    AppError {
        error_id: None,
        category: "snapshot_persist".into(),
        user_message: "De momentopname kon niet veilig worden opgeslagen.".into(),
        technical_details: Some(error.to_string()),
        retryable: true,
    }
}

fn snapshot_schema_error(error: impl std::fmt::Display) -> AppError {
    AppError {
        error_id: None,
        category: "snapshot_schema".into(),
        user_message: "De versie van deze momentopname wordt niet ondersteund.".into(),
        technical_details: Some(error.to_string()),
        retryable: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        models::{AuthMethod, ScanResult, SiteInput, SiteStatus},
        snapshot_builder::{SnapshotBuildInput, SnapshotBuildSection, SnapshotBuilder},
        snapshot_diff::SnapshotDiffEngine,
        snapshots::{
            SnapshotChangeOrigin, SnapshotCompleteness, SnapshotCore, SnapshotFileState,
            SnapshotSectionStatus, SnapshotSource, SnapshotStatus,
        },
    };
    use std::{collections::BTreeMap, fs, path::PathBuf};
    use uuid::Uuid;

    fn database() -> (Database, PathBuf, String) {
        let path = std::env::temp_dir().join(format!("wpmm-snapshots-{}.sqlite3", Uuid::new_v4()));
        let database = Database::initialize(path.clone()).unwrap();
        let site = database
            .save_site(
                &SiteInput {
                    id: None,
                    name: "Snapshot test".into(),
                    url: "https://example.test".into(),
                    ssh_host: "example.test".into(),
                    ssh_port: 22,
                    ssh_username: "deploy".into(),
                    auth_method: AuthMethod::KeyFile,
                    key_path: Some("C:/keys/example".into()),
                    wordpress_path: "/var/www/public_html".into(),
                    credential_secret: None,
                },
                None,
            )
            .unwrap();
        (database, path, site.id)
    }

    fn snapshot(site_id: &str, timestamp: &str, source: SnapshotSource) -> SiteSnapshot {
        SnapshotBuilder::build(SnapshotBuildInput {
            site_id: site_id.into(),
            scan_run_id: None,
            maintenance_run_id: None,
            source,
            previous_snapshot_id: None,
            wordpress_path: "/var/www/public_html".into(),
            scan_timestamp: timestamp.into(),
            core: SnapshotBuildSection::Complete(SnapshotCore {
                version: "6.8.2".into(),
                locale: Some("nl_NL".into()),
                multisite: Some(false),
                php_version: Some("8.3.1".into()),
            }),
            plugins: SnapshotBuildSection::Complete(Vec::new()),
            themes: SnapshotBuildSection::Complete(Vec::new()),
            users: SnapshotBuildSection::Complete(Vec::new()),
            configuration: SnapshotBuildSection::Complete(BTreeMap::new()),
            cron: SnapshotBuildSection::Complete(Vec::new()),
            files: SnapshotBuildSection::Complete(Vec::<SnapshotFileState>::new()),
        })
        .unwrap()
    }

    #[test]
    fn snapshot_roundtrips_and_updates_latest_and_baseline_pointers() {
        let (database, path, site_id) = database();
        let baseline = snapshot(&site_id, "2026-09-15T08:00:00Z", SnapshotSource::Baseline);
        let result = database
            .snapshot_repository()
            .save_snapshot(&baseline)
            .unwrap();
        assert!(result.first_snapshot);
        assert!(result.is_baseline);
        assert_eq!(
            database
                .snapshot_repository()
                .get_snapshot(&baseline.metadata.snapshot_id)
                .unwrap(),
            baseline
        );
        assert_eq!(
            database
                .snapshot_repository()
                .latest_snapshot(&site_id)
                .unwrap()
                .unwrap()
                .metadata
                .snapshot_id,
            baseline.metadata.snapshot_id
        );
        assert_eq!(
            database
                .snapshot_repository()
                .baseline_snapshot(&site_id)
                .unwrap()
                .unwrap()
                .metadata
                .snapshot_id,
            baseline.metadata.snapshot_id
        );
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn marking_new_baseline_preserves_snapshot_history() {
        let (database, path, site_id) = database();
        let baseline = snapshot(&site_id, "2026-09-15T08:00:00Z", SnapshotSource::Baseline);
        let current = snapshot(&site_id, "2026-09-15T09:00:00Z", SnapshotSource::Scan);
        let repository = database.snapshot_repository();
        repository.save_snapshot(&baseline).unwrap();
        repository.save_snapshot(&current).unwrap();
        repository
            .mark_as_baseline(&site_id, &current.metadata.snapshot_id)
            .unwrap();
        assert_eq!(repository.list_snapshots(&site_id, 100).unwrap().len(), 2);
        assert_eq!(
            repository
                .baseline_snapshot(&site_id)
                .unwrap()
                .unwrap()
                .metadata
                .snapshot_id,
            current.metadata.snapshot_id
        );
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn persists_diff_changes_and_refreshes_cached_site_state() {
        let (database, path, site_id) = database();
        let baseline = snapshot(&site_id, "2026-09-15T08:00:00Z", SnapshotSource::Baseline);
        database
            .snapshot_repository()
            .save_snapshot(&baseline)
            .unwrap();
        let mut current = snapshot(&site_id, "2026-09-15T09:00:00Z", SnapshotSource::Scan);
        current.metadata.previous_snapshot_id = Some(baseline.metadata.snapshot_id.clone());
        current.core.as_mut().unwrap().version = "6.8.3".into();
        let diff =
            SnapshotDiffEngine::compare(&baseline, &current, SnapshotChangeOrigin::Scan, None)
                .unwrap();
        assert_eq!(diff.changes.len(), 1);
        database
            .snapshot_repository()
            .save_snapshot_with_diff(&current, Some(&diff))
            .unwrap();

        let connection = database.connect().unwrap();
        let persisted: (i64, i64, i64) = connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM snapshot_diffs),(SELECT COUNT(*) FROM snapshot_changes),latest_change_count FROM site_snapshot_state WHERE site_id=?1",
                [&site_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(persisted, (1, 1, 1));
        drop(connection);
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn scan_snapshot_and_diff_roll_back_as_one_unit() {
        let (database, path, site_id) = database();
        let baseline = snapshot(&site_id, "2026-09-15T08:00:00Z", SnapshotSource::Baseline);
        database
            .snapshot_repository()
            .save_snapshot(&baseline)
            .unwrap();
        let scan_id = Uuid::new_v4().to_string();
        let mut current = snapshot(&site_id, "2026-09-15T09:00:00Z", SnapshotSource::Scan);
        current.metadata.scan_run_id = Some(scan_id.clone());
        current.metadata.previous_snapshot_id = Some(baseline.metadata.snapshot_id.clone());
        current.core.as_mut().unwrap().version = "6.8.3".into();
        let mut diff =
            SnapshotDiffEngine::compare(&baseline, &current, SnapshotChangeOrigin::Scan, None)
                .unwrap();
        diff.to_snapshot_id = "verkeerde-snapshot".into();
        let scan = ScanResult {
            id: scan_id.clone(),
            site_id: site_id.clone(),
            started_at: "2026-09-15T08:59:00Z".into(),
            finished_at: "2026-09-15T09:00:00Z".into(),
            status: SiteStatus::Healthy,
            checks: Vec::new(),
            truncated: false,
        };
        assert!(
            database
                .save_scan_with_snapshot(&scan, "Veilig", Some(&current), Some(&diff))
                .is_err()
        );
        let connection = database.connect().unwrap();
        let counts: (i64, i64) = connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM scan_runs WHERE id=?1),(SELECT COUNT(*) FROM site_snapshots WHERE id=?2)",
                params![scan_id, current.metadata.snapshot_id],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .unwrap();
        assert_eq!(counts, (0, 0));
        drop(connection);
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn maintenance_snapshots_and_changes_keep_the_run_correlation() {
        let (database, path, site_id) = database();
        let baseline = snapshot(&site_id, "2026-09-15T08:00:00Z", SnapshotSource::Baseline);
        database
            .snapshot_repository()
            .save_snapshot(&baseline)
            .unwrap();
        let stored = database.get_site(&site_id).unwrap();
        let run = crate::maintenance::new_run(&stored);
        database.start_maintenance(&run).unwrap();

        let scan = |id: String, finished_at: &str| ScanResult {
            id,
            site_id: site_id.clone(),
            started_at: finished_at.into(),
            finished_at: finished_at.into(),
            status: SiteStatus::Healthy,
            checks: Vec::new(),
            truncated: false,
        };
        let pre_scan = scan(Uuid::new_v4().to_string(), "2026-09-15T09:00:00Z");
        let mut pre = snapshot(
            &site_id,
            "2026-09-15T09:00:00Z",
            SnapshotSource::PreMaintenance,
        );
        pre.metadata.scan_run_id = Some(pre_scan.id.clone());
        pre.metadata.maintenance_run_id = Some(run.id.clone());
        pre.metadata.previous_snapshot_id = Some(baseline.metadata.snapshot_id.clone());
        database
            .save_scan_with_snapshot(&pre_scan, "Veilig", Some(&pre), None)
            .unwrap();

        let post_scan = scan(Uuid::new_v4().to_string(), "2026-09-15T09:05:00Z");
        let mut post = snapshot(
            &site_id,
            "2026-09-15T09:05:00Z",
            SnapshotSource::PostMaintenance,
        );
        post.metadata.scan_run_id = Some(post_scan.id.clone());
        post.metadata.maintenance_run_id = Some(run.id.clone());
        post.metadata.previous_snapshot_id = Some(pre.metadata.snapshot_id.clone());
        post.core.as_mut().unwrap().version = "6.8.3".into();
        let diff = SnapshotDiffEngine::compare(
            &pre,
            &post,
            SnapshotChangeOrigin::Maintenance,
            Some(run.id.clone()),
        )
        .unwrap();
        database
            .save_scan_with_snapshot(&post_scan, "Veilig", Some(&post), Some(&diff))
            .unwrap();

        let connection = database.connect().unwrap();
        let counts: (i64, i64, i64) = connection
            .query_row(
                "SELECT (SELECT COUNT(*) FROM site_snapshots WHERE maintenance_run_id=?1),(SELECT COUNT(*) FROM snapshot_diffs WHERE maintenance_run_id=?1 AND origin='maintenance'),(SELECT COUNT(*) FROM snapshot_changes WHERE origin='maintenance' AND to_snapshot_id=?2)",
                params![run.id, post.metadata.snapshot_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(counts, (2, 1, 1));
        drop(connection);
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn retention_keeps_baseline_and_protected_maintenance_snapshots() {
        let (database, path, site_id) = database();
        let repository = database.snapshot_repository();
        let baseline = snapshot(&site_id, "2026-01-01T00:00:00Z", SnapshotSource::Baseline);
        let baseline_id = baseline.metadata.snapshot_id.clone();
        repository.save_snapshot(&baseline).unwrap();
        let maintenance = snapshot(
            &site_id,
            "2026-01-01T00:00:01Z",
            SnapshotSource::PostMaintenance,
        );
        let maintenance_id = maintenance.metadata.snapshot_id.clone();
        repository.save_snapshot(&maintenance).unwrap();
        for index in 0..MAX_SNAPSHOTS_PER_SITE {
            let item = snapshot(
                &site_id,
                &format!("2026-02-{:02}T00:00:00Z", 1 + index / 28),
                SnapshotSource::Scan,
            );
            repository.save_snapshot(&item).unwrap();
        }
        let snapshots = repository
            .list_snapshots(&site_id, MAX_SNAPSHOTS_PER_SITE)
            .unwrap();
        assert_eq!(snapshots.len(), MAX_SNAPSHOTS_PER_SITE);
        assert!(
            repository.get_snapshot(&baseline_id).is_ok(),
            "baseline must survive retention"
        );
        assert!(
            repository.get_snapshot(&maintenance_id).is_ok(),
            "maintenance snapshot must survive retention"
        );
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn failed_persistence_leaves_no_snapshot_or_state_pointer() {
        let (database, path, _) = database();
        let invalid = snapshot(
            "missing-site",
            "2026-09-15T08:00:00Z",
            SnapshotSource::Baseline,
        );
        assert!(
            database
                .snapshot_repository()
                .save_snapshot(&invalid)
                .is_err()
        );
        let connection = database.connect().unwrap();
        let snapshots: i64 = connection
            .query_row("SELECT COUNT(*) FROM site_snapshots", [], |row| row.get(0))
            .unwrap();
        let states: i64 = connection
            .query_row("SELECT COUNT(*) FROM site_snapshot_state", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!((snapshots, states), (0, 0));
        drop(connection);
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn unknown_future_schema_returns_typed_error() {
        let (database, path, site_id) = database();
        let snapshot = snapshot(&site_id, "2026-09-15T08:00:00Z", SnapshotSource::Baseline);
        database
            .snapshot_repository()
            .save_snapshot(&snapshot)
            .unwrap();
        database
            .connect()
            .unwrap()
            .execute(
                "UPDATE site_snapshots SET schema_version=999 WHERE id=?1",
                [&snapshot.metadata.snapshot_id],
            )
            .unwrap();
        let error = database
            .snapshot_repository()
            .get_snapshot(&snapshot.metadata.snapshot_id)
            .unwrap_err();
        assert_eq!(error.category, "snapshot_schema");
        drop(database);
        let _ = fs::remove_file(path);
    }

    #[test]
    fn rejects_payload_status_that_disagrees_with_completeness() {
        let (database, path, site_id) = database();
        let mut snapshot = snapshot(&site_id, "2026-09-15T08:00:00Z", SnapshotSource::Baseline);
        snapshot.completeness = SnapshotCompleteness {
            core: SnapshotSectionStatus::Failed,
            plugins: SnapshotSectionStatus::Complete,
            themes: SnapshotSectionStatus::Complete,
            users: SnapshotSectionStatus::Complete,
            configuration: SnapshotSectionStatus::Complete,
            cron: SnapshotSectionStatus::Complete,
            files: SnapshotSectionStatus::Complete,
        };
        snapshot.metadata.status = SnapshotStatus::Complete;
        let error = database
            .snapshot_repository()
            .save_snapshot(&snapshot)
            .unwrap_err();
        assert_eq!(error.category, "snapshot_persist");
        drop(database);
        let _ = fs::remove_file(path);
    }
}
