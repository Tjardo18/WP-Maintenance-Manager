use crate::{
    error::AppError,
    models::{AuthMethod, Site, SiteInput, SiteStatus, StoredSite},
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
}
