use crate::{
    auth::AuthManager, credentials::CredentialVault, database::Database, scan_jobs::ScanJobManager,
    ssh::SshExecutor, terminal::TerminalManager, terminal_auth::TerminalAccessManager,
};
use std::path::PathBuf;
use std::sync::{Arc, atomic::AtomicUsize};

pub struct AppState {
    pub database: Database,
    pub credentials: CredentialVault,
    pub ssh: Arc<dyn SshExecutor>,
    pub backup_directory: PathBuf,
    pub scan_concurrency: AtomicUsize,
    pub auth: AuthManager,
    pub terminals: TerminalManager,
    pub terminal_access: TerminalAccessManager,
    pub scan_jobs: ScanJobManager,
}
