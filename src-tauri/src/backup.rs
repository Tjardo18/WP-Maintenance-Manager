use crate::{
    command_catalog::{RemoteAction, build, validate_remote_backup_path},
    engine::checked_output,
    error::AppError,
    models::StoredSite,
    ssh::SshExecutor,
};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::{fs, io::Read, path::Path};
use uuid::Uuid;

#[derive(Debug, Clone)]
pub struct BackupResult {
    pub local_path: String,
    pub size_bytes: u64,
    pub sha256: String,
}

pub fn create_database_backup(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    backup_root: &Path,
) -> Result<BackupResult, AppError> {
    let site_directory = backup_root.join(&stored.site.id);
    fs::create_dir_all(&site_directory)?;
    let filename = format!(
        "{}-{}.sql.gz",
        Utc::now().format("%Y%m%dT%H%M%SZ"),
        Uuid::new_v4()
    );
    let local_path = site_directory.join(filename);
    ensure_inside(&local_path, backup_root)?;

    let export_command = build(
        &stored.site.wordpress_path,
        RemoteAction::CreateDatabaseBackup,
    )?;
    let export = checked_output(executor, &stored.site, credential, export_command)?;
    let remote_path = export.stdout_text()?.trim().to_owned();
    validate_remote_backup_path(&remote_path)?;

    let download_result = executor.download(&stored.site, credential, &remote_path, &local_path);
    let cleanup_command = build(
        &stored.site.wordpress_path,
        RemoteAction::DeleteTemporaryBackup {
            path: remote_path.clone(),
        },
    )?;
    let cleanup_result = checked_output(executor, &stored.site, credential, cleanup_command);

    if let Err(error) = cleanup_result {
        let local_cleanup = cleanup_local(&local_path)
            .err()
            .map_or_else(String::new, |local| format!("; lokale cleanup: {local}"));
        return Err(AppError::ssh(
            "backup_cleanup_failed",
            "Het tijdelijke backupbestand kon niet veilig van de server worden verwijderd. Onderhoud is gestopt.",
            format!("{error}{local_cleanup}"),
            false,
        ));
    }
    if let Err(error) = download_result {
        cleanup_local(&local_path)?;
        return Err(error);
    }

    let metadata = fs::metadata(&local_path)?;
    let sha256 = hash_file(&local_path)?;
    Ok(BackupResult {
        local_path: local_path.to_string_lossy().into_owned(),
        size_bytes: metadata.len(),
        sha256,
    })
}

fn cleanup_local(path: &Path) -> Result<(), AppError> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(AppError::storage(error)),
    }
}

fn ensure_inside(path: &Path, root: &Path) -> Result<(), AppError> {
    let absolute_root = root.canonicalize().map_err(AppError::storage)?;
    let parent = path
        .parent()
        .ok_or_else(|| AppError::validation("De lokale backuplocatie is ongeldig."))?
        .canonicalize()
        .map_err(AppError::storage)?;
    if !parent.starts_with(absolute_root) {
        return Err(AppError::validation(
            "De lokale backuplocatie valt buiten de applicatiemap.",
        ));
    }
    Ok(())
}

fn hash_file(path: &Path) -> Result<String, AppError> {
    let mut file = fs::File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn local_backup_path_must_stay_below_root() {
        let root = std::env::temp_dir().join(format!("wpmm-backup-test-{}", Uuid::new_v4()));
        let child = root.join("site");
        fs::create_dir_all(&child).unwrap();
        assert!(ensure_inside(&child.join("backup.sql.gz"), &root).is_ok());
        assert!(ensure_inside(&root.join("..").join("outside.sql.gz"), &root).is_err());
        let _ = fs::remove_dir_all(root);
    }
}
