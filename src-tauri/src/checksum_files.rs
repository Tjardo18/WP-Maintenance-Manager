use crate::{
    error::AppError,
    models::{
        ChecksumFindingRecord, ChecksumStatus, FilePreview, Finding, FindingContext, StoredSite,
    },
    ssh::{RemoteFileRead, SshExecutor},
    validation::{validate_checksum_file_action_path, validate_checksum_relative_path},
};
use chrono::{DateTime, SecondsFormat, Utc};

pub const PREVIEW_LIMIT_BYTES: usize = 256 * 1024;

pub fn preview(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    context: &FindingContext,
) -> Result<FilePreview, AppError> {
    let relative_path = validate_preview_context(&stored.site.id, context)?;
    let remote =
        executor.read_site_file(&stored.site, credential, relative_path, PREVIEW_LIMIT_BYTES)?;
    Ok(build_preview(&context.finding, relative_path, remote))
}

pub fn delete(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    record: &ChecksumFindingRecord,
) -> Result<String, AppError> {
    let relative_path = validate_delete_record(stored, record)?;
    executor.delete_checksum_file(&stored.site, credential, relative_path)?;
    Ok(relative_path.to_owned())
}

fn validate_preview_context<'a>(
    site_id: &str,
    context: &'a FindingContext,
) -> Result<&'a str, AppError> {
    let permitted_check = matches!(
        context.check_type.as_str(),
        "php_uploads" | "modified_files"
    ) || (context.check_type == "core_checksum"
        && context.finding.checksum_status == Some(ChecksumStatus::Unexpected));
    if context.site_id != site_id
        || context.scan_run_id.is_empty()
        || context.finding.id.as_deref().is_none_or(str::is_empty)
        || !permitted_check
    {
        return Err(AppError::validation(
            "Deze finding is niet geldig voor een bestandspreview.",
        ));
    }
    let path = context
        .finding
        .path
        .as_deref()
        .ok_or_else(|| AppError::validation("De finding bevat geen bestandspad."))?;
    validate_checksum_relative_path(path)?;
    Ok(path)
}

fn validate_delete_record<'a>(
    stored: &StoredSite,
    record: &'a ChecksumFindingRecord,
) -> Result<&'a str, AppError> {
    if record.site_id != stored.site.id
        || record.scan_run_id.is_empty()
        || record.finding.id.as_deref().is_none_or(str::is_empty)
        || record.finding.checksum_status != Some(ChecksumStatus::Unexpected)
    {
        return Err(AppError::validation(
            "Deze finding is niet geldig voor een checksum-bestandsactie.",
        ));
    }
    let path = record
        .finding
        .path
        .as_deref()
        .ok_or_else(|| AppError::validation("De checksumfinding bevat geen bestandspad."))?;
    validate_checksum_file_action_path(path)?;
    Ok(path)
}

fn build_preview(finding: &Finding, relative_path: &str, remote: RemoteFileRead) -> FilePreview {
    let contains_nul = remote.bytes.contains(&0);
    let text_content = if contains_nul {
        None
    } else {
        String::from_utf8(remote.bytes).ok()
    };
    let binary = text_content.is_none();
    let file_name = relative_path
        .rsplit('/')
        .next()
        .unwrap_or(relative_path)
        .to_owned();
    let extension = file_name
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map(|(_, extension)| extension.to_ascii_lowercase());
    let file_type = extension
        .as_deref()
        .map_or_else(|| "Bestand".into(), |value| format!("{value}-bestand"));
    let modified_at = remote
        .modified_unix
        .and_then(|timestamp| i64::try_from(timestamp).ok())
        .and_then(|timestamp| DateTime::<Utc>::from_timestamp(timestamp, 0))
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true));
    FilePreview {
        finding: finding.clone(),
        file_name,
        relative_path: relative_path.into(),
        size_bytes: remote.size_bytes,
        modified_at,
        file_type,
        extension,
        text_content,
        binary,
        truncated: remote.truncated,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ChecksumStatus, Finding, FindingSeverity};

    fn record() -> ChecksumFindingRecord {
        ChecksumFindingRecord {
            site_id: "site-1".into(),
            scan_run_id: "scan-1".into(),
            finding: Finding {
                id: Some("finding-1".into()),
                category: "wordpress-core-unexpected".into(),
                severity: FindingSeverity::Attention,
                title: "Hoort niet aanwezig te zijn".into(),
                detail: "File should not exist".into(),
                path: Some("wp-admin/extra.php".into()),
                checksum_status: Some(ChecksumStatus::Unexpected),
                disposition: crate::models::FindingDisposition::Active,
                exception_id: None,
                trusted_file_id: None,
                policy_reason: None,
                policy_target: None,
                vulnerability: None,
                observed_at: Some("2026-08-31T10:00:00Z".into()),
            },
        }
    }

    fn context(check_type: &str, path: &str) -> FindingContext {
        let mut context = FindingContext {
            site_id: "site-1".into(),
            scan_run_id: "scan-1".into(),
            check_type: check_type.into(),
            finding: record().finding,
        };
        context.finding.path = Some(path.into());
        if check_type != "core_checksum" {
            context.finding.checksum_status = None;
        }
        context
    }

    #[test]
    fn preview_keeps_markup_as_plain_text() {
        let preview = build_preview(
            &record().finding,
            "wp-admin/extra.php",
            RemoteFileRead {
                bytes: b"<script>alert(1)</script><?php echo 'x';".to_vec(),
                size_bytes: 42,
                modified_unix: Some(1_700_000_000),
                truncated: false,
            },
        );
        assert_eq!(
            preview.text_content.as_deref(),
            Some("<script>alert(1)</script><?php echo 'x';")
        );
        assert!(!preview.binary);
        assert_eq!(preview.extension.as_deref(), Some("php"));
    }

    #[test]
    fn binary_preview_never_returns_corrupt_text() {
        let preview = build_preview(
            &record().finding,
            "wp-admin/extra.php",
            RemoteFileRead {
                bytes: vec![0, 159, 146, 150],
                size_bytes: 4,
                modified_unix: None,
                truncated: false,
            },
        );
        assert!(preview.binary);
        assert!(preview.text_content.is_none());
    }

    #[test]
    fn truncation_metadata_is_preserved() {
        let preview = build_preview(
            &record().finding,
            "wp-admin/extra.php",
            RemoteFileRead {
                bytes: vec![b'a'; PREVIEW_LIMIT_BYTES],
                size_bytes: PREVIEW_LIMIT_BYTES as u64 + 10,
                modified_unix: None,
                truncated: true,
            },
        );
        assert!(preview.truncated);
        assert_eq!(preview.text_content.unwrap().len(), PREVIEW_LIMIT_BYTES);
    }

    #[test]
    fn preview_accepts_current_upload_and_modified_file_findings() {
        assert_eq!(
            validate_preview_context(
                "site-1",
                &context("php_uploads", "wp-content/uploads/2026/suspicious.php")
            )
            .unwrap(),
            "wp-content/uploads/2026/suspicious.php"
        );
        assert_eq!(
            validate_preview_context("site-1", &context("modified_files", "wp-config.php"))
                .unwrap(),
            "wp-config.php"
        );
    }

    #[test]
    fn preview_rejects_unrelated_checks_and_unsafe_paths() {
        assert!(
            validate_preview_context("site-1", &context("permissions", "wp-admin/test.php"))
                .is_err()
        );
        assert!(
            validate_preview_context("site-1", &context("modified_files", "../wp-config.php"))
                .is_err()
        );
        let mut modified_core = context("core_checksum", "wp-admin/load.php");
        modified_core.finding.checksum_status = Some(ChecksumStatus::Modified);
        assert!(validate_preview_context("site-1", &modified_core).is_err());
        assert!(
            validate_preview_context(
                "another-site",
                &context("php_uploads", "wp-content/uploads/test.php")
            )
            .is_err()
        );
    }
}
