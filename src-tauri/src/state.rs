use crate::{credentials::CredentialVault, database::Database};

#[derive(Debug)]
pub struct AppState {
    pub database: Database,
    pub credentials: CredentialVault,
}
