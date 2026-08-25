use crate::error::AppError;

#[derive(Debug, Clone, Default)]
pub struct CredentialVault;

impl CredentialVault {
    const SERVICE: &'static str = "nl.wpmaintenancemanager.app";

    pub fn set(&self, reference: &str, secret: &str) -> Result<(), AppError> {
        keyring::Entry::new(Self::SERVICE, reference)
            .map_err(AppError::credential)?
            .set_password(secret)
            .map_err(AppError::credential)
    }

    pub fn delete(&self, reference: &str) -> Result<(), AppError> {
        let entry = keyring::Entry::new(Self::SERVICE, reference).map_err(AppError::credential)?;
        match entry.delete_credential() {
            Ok(()) | Err(keyring::Error::NoEntry) => Ok(()),
            Err(error) => Err(AppError::credential(error)),
        }
    }
}
