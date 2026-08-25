use serde::Serialize;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppError {
    pub category: String,
    pub user_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technical_details: Option<String>,
    pub retryable: bool,
}

impl AppError {
    pub fn validation(message: impl Into<String>) -> Self {
        Self {
            category: "validation".into(),
            user_message: message.into(),
            technical_details: None,
            retryable: false,
        }
    }

    pub fn storage(error: impl Display) -> Self {
        Self {
            category: "storage".into(),
            user_message: "Lokale gegevens konden niet worden verwerkt.".into(),
            technical_details: Some(error.to_string()),
            retryable: true,
        }
    }

    pub fn credential(error: impl Display) -> Self {
        Self {
            category: "credential_store".into(),
            user_message: "De beveiligde credentialopslag is niet beschikbaar.".into(),
            technical_details: Some(error.to_string()),
            retryable: true,
        }
    }

    pub fn not_found(entity: &str) -> Self {
        Self {
            category: "not_found".into(),
            user_message: format!("{entity} is niet gevonden."),
            technical_details: None,
            retryable: false,
        }
    }

    pub fn ssh(
        category: &str,
        message: impl Into<String>,
        detail: impl Display,
        retryable: bool,
    ) -> Self {
        Self {
            category: category.into(),
            user_message: message.into(),
            technical_details: Some(detail.to_string()),
            retryable,
        }
    }

    pub fn command_failed(action: &str, exit_code: i32, stderr: &str) -> Self {
        let redacted = if stderr.chars().count() > 2000 {
            format!("{}…", stderr.chars().take(2000).collect::<String>())
        } else {
            stderr.to_owned()
        };
        Self {
            category: "command_failed".into(),
            user_message: "De servercontrole kon niet worden voltooid.".into(),
            technical_details: Some(format!(
                "Actie: {action}; exitstatus: {exit_code}; stderr: {redacted}"
            )),
            retryable: true,
        }
    }
}

impl Display for AppError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}", self.user_message)
    }
}
impl std::error::Error for AppError {}
impl From<rusqlite::Error> for AppError {
    fn from(value: rusqlite::Error) -> Self {
        Self::storage(value)
    }
}
impl From<std::io::Error> for AppError {
    fn from(value: std::io::Error) -> Self {
        Self::storage(value)
    }
}
