use crate::{credentials::CredentialVault, error::AppError, models::WordfenceIntegrationStatus};

pub const WORDFENCE_CREDENTIAL_REFERENCE: &str = "integration:wordfence-intelligence:api-key";

pub fn integration_status(vault: &CredentialVault) -> Result<WordfenceIntegrationStatus, AppError> {
    Ok(WordfenceIntegrationStatus {
        configured: vault
            .get_optional(WORDFENCE_CREDENTIAL_REFERENCE)?
            .is_some(),
        connection_status: "not_tested".into(),
        feed_status: "missing".into(),
        last_successful_update_at: None,
        next_automatic_update_at: None,
        vulnerability_count: 0,
        software_record_count: 0,
        refresh_running: false,
        refresh_phase: None,
        cooldown_remaining_seconds: 0,
        last_error: None,
    })
}

pub fn save_api_key(vault: &CredentialVault, api_key: &str) -> Result<(), AppError> {
    let api_key = validate_api_key(api_key)?;
    vault.set(WORDFENCE_CREDENTIAL_REFERENCE, api_key)
}

pub fn remove_api_key(vault: &CredentialVault) -> Result<(), AppError> {
    vault.delete(WORDFENCE_CREDENTIAL_REFERENCE)
}

fn validate_api_key(api_key: &str) -> Result<&str, AppError> {
    let trimmed = api_key.trim();
    if trimmed.is_empty() {
        return Err(AppError::validation("Voer een Wordfence API-sleutel in."));
    }
    if trimmed.len() > 512 || trimmed.chars().any(char::is_control) {
        return Err(AppError::validation(
            "De Wordfence API-sleutel heeft geen geldig formaat.",
        ));
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_key_validation_accepts_an_opaque_secret_without_exposing_it() {
        assert_eq!(
            validate_api_key("  opaque-test-key  ").unwrap(),
            "opaque-test-key"
        );
    }

    #[test]
    fn api_key_validation_rejects_empty_control_and_oversized_values() {
        assert!(validate_api_key("   ").is_err());
        assert!(validate_api_key("key\nvalue").is_err());
        assert!(validate_api_key(&"x".repeat(513)).is_err());
    }
}
