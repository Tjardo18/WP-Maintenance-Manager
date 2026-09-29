use crate::{
    auth::AuthManager, credentials::CredentialVault, database::Database, scan_jobs::ScanJobManager,
    ssh::SshExecutor, terminal::TerminalManager, terminal_auth::TerminalAccessManager,
    vulnerability_jobs::VulnerabilityRefreshManager,
};
use std::path::PathBuf;
use std::sync::{Arc, atomic::AtomicUsize};

pub struct AppState {
    pub database: Database,
    pub credentials: CredentialVault,
    pub ssh: Arc<dyn SshExecutor>,
    pub backup_directory: PathBuf,
    pub vulnerability_cache_directory: PathBuf,
    pub scan_concurrency: AtomicUsize,
    pub auth: AuthManager,
    pub terminals: TerminalManager,
    pub terminal_access: TerminalAccessManager,
    pub filemanager_access: crate::filemanager::FilemanagerAccessManager,
    pub scan_jobs: ScanJobManager,
    pub vulnerability_jobs: VulnerabilityRefreshManager,
}
