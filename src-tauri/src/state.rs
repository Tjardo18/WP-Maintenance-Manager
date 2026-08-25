use crate::{credentials::CredentialVault, database::Database, ssh::SshExecutor};
use std::path::PathBuf;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize},
};

pub struct AppState {
    pub database: Database,
    pub credentials: CredentialVault,
    pub ssh: Arc<dyn SshExecutor>,
    pub backup_directory: PathBuf,
    pub scan_concurrency: AtomicUsize,
    pub bulk_scan_cancelled: Arc<AtomicBool>,
}
