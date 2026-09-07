use crate::{
    database::{Database, utc_now},
    error::AppError,
    models::{ErrorCategory, ErrorLogRecord, ErrorSeverity},
};
use uuid::Uuid;

pub fn classify_error(error: &AppError, action: &str) -> ErrorCategory {
    let category = error.category.to_ascii_lowercase();
    let action = action.to_ascii_lowercase();
    let classified = match category.as_str() {
        "dns" | "dns_host_error" => ErrorCategory::Dns,
        "timeout" | "connection_timeout" => ErrorCategory::ConnectionTimeout,
        "authentication_failed" | "ssh_authentication" => ErrorCategory::SshAuthentication,
        "host_key_unknown" | "host_key_mismatch" | "ssh_host_key" => ErrorCategory::SshHostKey,
        "ssh_channel" | "ssh_protocol" | "sftp" | "sftp_path" | "sftp_file" | "sftp_delete" => {
            ErrorCategory::SshChannel
        }
        "command_failed" | "ssh_command" | "output_limit" => ErrorCategory::SshCommand,
        "wp_cli" | "wp_cli_missing" => ErrorCategory::WpCli,
        "http" | "http_status" | "tls" => ErrorCategory::Http,
        "storage" | "database" => ErrorCategory::Database,
        "filesystem" | "io" => ErrorCategory::Filesystem,
        "parse" | "json" | "invalid_json" => ErrorCategory::Parse,
        "locked" | "session_expired" | "invalid_session" | "setup_required"
        | "invalid_password" | "rate_limited" => ErrorCategory::Authentication,
        "application" | "validation" | "not_found" | "credential_store" => {
            ErrorCategory::Application
        }
        value if value.starts_with("ssh_") => ErrorCategory::Network,
        _ => ErrorCategory::Unknown,
    };
    if classified != ErrorCategory::Unknown && classified != ErrorCategory::SshCommand {
        return classified;
    }
    if action.contains("backup") {
        ErrorCategory::Backup
    } else if action.contains("update") || action.contains("bijwerk") {
        ErrorCategory::Update
    } else if action.contains("wp-cli") {
        ErrorCategory::WpCli
    } else {
        classified
    }
}

pub fn friendly_summary(error: &AppError) -> String {
    let technical = error
        .technical_details
        .as_deref()
        .unwrap_or_default()
        .to_ascii_lowercase();
    match error.category.as_str() {
        "timeout" | "connection_timeout" => {
            "Server niet bereikbaar binnen de toegestane tijd".into()
        }
        "authentication_failed" | "ssh_authentication" => "SSH-authenticatie mislukt".into(),
        "host_key_mismatch" => "SSH host key komt niet overeen".into(),
        "host_key_unknown" => "SSH-serveridentiteit is nog niet geaccepteerd".into(),
        _ if technical.contains("connection refused") || technical.contains("10061") => {
            "Server weigert SSH-verbinding".into()
        }
        _ => error.user_message.clone(),
    }
}

pub fn persist_error(
    database: &Database,
    site_id: Option<&str>,
    site_name: Option<&str>,
    action: &str,
    duration_ms: Option<u64>,
    exit_code: Option<i32>,
    error: AppError,
) -> AppError {
    let id = format!(
        "ERR-{}",
        Uuid::new_v4().simple().to_string()[..12].to_ascii_uppercase()
    );
    let safe_details = error.safe_diagnostic();
    let cause_chain = safe_details
        .as_deref()
        .map(|details| {
            details
                .lines()
                .filter(|line| line.to_ascii_lowercase().starts_with("caused by:"))
                .take(10)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let record = ErrorLogRecord {
        id: id.clone(),
        created_at: utc_now(),
        severity: if error.category == "host_key_mismatch" {
            ErrorSeverity::Critical
        } else {
            ErrorSeverity::Error
        },
        category: classify_error(&error, action),
        site_id: site_id.map(str::to_owned),
        site_name: site_name.map(str::to_owned),
        action: action.chars().take(160).collect(),
        summary: friendly_summary(&error).chars().take(500).collect(),
        technical_details: safe_details,
        exit_code,
        cause_chain,
        duration_ms,
        retryable: error.retryable,
    };
    if let Err(write_error) = database.save_error_log(&record) {
        eprintln!("error log write failed category={}", write_error.category);
        return error;
    }
    error.with_error_id(id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::ErrorLogFilter;
    use std::fs;

    #[test]
    fn classifies_connection_auth_host_key_command_parse_and_unknown_errors() {
        let cases = [
            ("timeout", ErrorCategory::ConnectionTimeout),
            ("dns_host_error", ErrorCategory::Dns),
            ("authentication_failed", ErrorCategory::SshAuthentication),
            ("host_key_mismatch", ErrorCategory::SshHostKey),
            ("ssh_channel", ErrorCategory::SshChannel),
            ("command_failed", ErrorCategory::SshCommand),
            ("json", ErrorCategory::Parse),
            ("something_new", ErrorCategory::Unknown),
        ];
        for (category, expected) in cases {
            let error = AppError::ssh(category, "test", "test", true);
            assert_eq!(classify_error(&error, "Verbinding testen"), expected);
        }
    }

    #[test]
    fn persists_error_id_and_never_stores_secret_lines() {
        let path = std::env::temp_dir().join(format!("wpmm-error-log-{}.sqlite3", Uuid::new_v4()));
        let database = Database::initialize(path.clone()).unwrap();
        let error = AppError::ssh(
            "authentication_failed",
            "SSH-authenticatie is mislukt.",
            "connection failed\nAuthorization: Bearer never-store-this\nCaused by: key rejected",
            false,
        );
        let returned = persist_error(
            &database,
            None,
            None,
            "SSH verbinding testen",
            Some(25),
            None,
            error,
        );
        assert!(returned.error_id.as_deref().unwrap().starts_with("ERR-"));

        let page = database
            .list_error_logs(&ErrorLogFilter::default())
            .unwrap();
        assert_eq!(page.total, 1);
        assert_eq!(page.records[0].category, ErrorCategory::SshAuthentication);
        assert_eq!(page.records[0].duration_ms, Some(25));
        let details = page.records[0].technical_details.as_deref().unwrap();
        assert!(details.contains("[gevoelige regel weggelaten]"));
        assert!(!details.contains("never-store-this"));
        assert_eq!(page.records[0].cause_chain, vec!["Caused by: key rejected"]);
        drop(database);
        let _ = fs::remove_file(path);
    }
}
