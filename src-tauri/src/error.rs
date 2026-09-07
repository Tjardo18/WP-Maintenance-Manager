use serde::Serialize;
use std::fmt::{Display, Formatter};

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AppError {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_id: Option<String>,
    pub category: String,
    pub user_message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technical_details: Option<String>,
    pub retryable: bool,
}

impl AppError {
    pub fn safe_diagnostic(&self) -> Option<String> {
        let details = self.technical_details.as_deref()?;
        let sensitive_markers = [
            "password",
            "passwd",
            "secret",
            "token",
            "authorization",
            "cookie",
            "db_password",
            "database_url",
        ];
        let mut safe = String::new();
        for line in details.lines() {
            let lower = line.to_ascii_lowercase();
            let clean = if sensitive_markers
                .iter()
                .any(|marker| lower.contains(marker))
            {
                "[gevoelige regel weggelaten]"
            } else {
                line
            };
            if !safe.is_empty() {
                safe.push('\n');
            }
            safe.extend(
                clean
                    .chars()
                    .filter(|character| !character.is_control() || *character == '\t'),
            );
            if safe.chars().count() >= 2_000 {
                safe = safe.chars().take(2_000).collect();
                safe.push('…');
                break;
            }
        }
        (!safe.trim().is_empty()).then_some(safe)
    }

    pub fn unauthorized(category: &str, message: &str) -> Self {
        Self {
            error_id: None,
            category: category.into(),
            user_message: message.into(),
            technical_details: None,
            retryable: category == "session_expired",
        }
    }

    pub fn rate_limited(retry_after_seconds: u64) -> Self {
        Self {
            error_id: None,
            category: "rate_limited".into(),
            user_message: format!(
                "Te veel mislukte pogingen. Probeer het over {retry_after_seconds} seconden opnieuw."
            ),
            technical_details: None,
            retryable: true,
        }
    }

    pub fn validation(message: impl Into<String>) -> Self {
        Self {
            error_id: None,
            category: "validation".into(),
            user_message: message.into(),
            technical_details: None,
            retryable: false,
        }
    }

    pub fn storage(error: impl Display) -> Self {
        Self {
            error_id: None,
            category: "storage".into(),
            user_message: "Lokale gegevens konden niet worden verwerkt.".into(),
            technical_details: Some(error.to_string()),
            retryable: true,
        }
    }

    pub fn credential(error: impl Display) -> Self {
        Self {
            error_id: None,
            category: "credential_store".into(),
            user_message: "De beveiligde credentialopslag is niet beschikbaar.".into(),
            technical_details: Some(error.to_string()),
            retryable: true,
        }
    }

    pub fn not_found(entity: &str) -> Self {
        Self {
            error_id: None,
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
            error_id: None,
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
            error_id: None,
            category: "command_failed".into(),
            user_message: "De servercontrole kon niet worden voltooid.".into(),
            technical_details: Some(format!(
                "Actie: {action}; exitstatus: {exit_code}; stderr: {redacted}"
            )),
            retryable: true,
        }
    }

    pub fn with_error_id(mut self, error_id: String) -> Self {
        self.error_id = Some(error_id);
        self
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_diagnostics_are_bounded_and_redact_sensitive_lines() {
        let error = AppError::command_failed(
            "FindPhpFiles",
            1,
            "head: invalid option -- z\nDB_PASSWORD=do-not-store",
        );
        let diagnostic = error.safe_diagnostic().unwrap();
        assert!(diagnostic.contains("head: invalid option -- z"));
        assert!(diagnostic.contains("[gevoelige regel weggelaten]"));
        assert!(!diagnostic.contains("do-not-store"));

        let long = AppError::ssh("test", "test", "x".repeat(3_000), false);
        assert!(long.safe_diagnostic().unwrap().chars().count() <= 2_001);
    }
}
