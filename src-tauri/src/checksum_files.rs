use crate::{
    error::AppError,
    models::{
        ChecksumFindingRecord, ChecksumStatus, FileContentPreview, FilePreview, Finding,
        FindingContext, StoredSite,
    },
    ssh::{RemoteFileRead, SshExecutor},
    validation::{validate_checksum_file_action_path, validate_checksum_relative_path},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use chrono::{DateTime, SecondsFormat, Utc};
use flate2::read::GzDecoder;
use image::{ImageFormat, ImageReader, Limits};
use std::io::{Cursor, Read};

pub const PREVIEW_LIMIT_BYTES: usize = 256 * 1024;
pub const IMAGE_PREVIEW_LIMIT_BYTES: usize = 10 * 1024 * 1024;

pub fn preview(
    executor: &dyn SshExecutor,
    stored: &StoredSite,
    credential: Option<&str>,
    context: &FindingContext,
) -> Result<FilePreview, AppError> {
    let relative_path = validate_preview_context(&stored.site.id, context)?;
    let max_bytes = preview_extension(relative_path)
        .filter(|extension| is_binary_image_extension(extension) || extension == "svgz")
        .map_or(PREVIEW_LIMIT_BYTES, |_| IMAGE_PREVIEW_LIMIT_BYTES);
    let remote = executor.read_site_file(&stored.site, credential, relative_path, max_bytes)?;
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
        && matches!(
            context.finding.checksum_status,
            Some(ChecksumStatus::Modified | ChecksumStatus::Unexpected)
        ));
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
    FilePreview {
        finding: finding.clone(),
        content: build_file_content_preview(relative_path, remote),
    }
}

pub(crate) fn build_file_content_preview(
    relative_path: &str,
    remote: RemoteFileRead,
) -> FileContentPreview {
    let file_name = relative_path
        .rsplit('/')
        .next()
        .unwrap_or(relative_path)
        .to_owned();
    let extension = preview_extension(&file_name);
    let mut truncated = remote.truncated;
    let mut text_content = None;
    let mut image_mime_type = None;
    let mut image_data_base64 = None;
    let mut raw_data_base64 = None;
    let binary;

    match extension.as_deref() {
        Some("svgz") => {
            image_mime_type = Some("image/svg+xml".into());
            let (source, decompressed_truncated) = if remote.truncated {
                (None, false)
            } else {
                decode_svgz_source(&remote.bytes)
            };
            truncated |= decompressed_truncated;
            text_content = source;
            binary = text_content.is_none();
        }
        Some(extension) if is_binary_image_extension(extension) => {
            binary = true;
            image_mime_type = image_mime_type_for_extension(extension).map(str::to_owned);
            if remote.truncated {
                raw_data_base64 = Some(STANDARD.encode(&remote.bytes));
            } else if matches!(extension, "tif" | "tiff") {
                raw_data_base64 = Some(STANDARD.encode(&remote.bytes));
                if let Some(png) = convert_tiff_to_png(&remote.bytes) {
                    image_mime_type = Some("image/png".into());
                    image_data_base64 = Some(STANDARD.encode(png));
                }
            } else {
                image_data_base64 = Some(STANDARD.encode(&remote.bytes));
            }
        }
        _ => {
            let contains_nul = remote.bytes.contains(&0);
            text_content = if contains_nul {
                None
            } else {
                String::from_utf8(remote.bytes).ok()
            };
            binary = text_content.is_none();
        }
    }

    let file_type = extension
        .as_deref()
        .map_or_else(|| "Bestand".into(), |value| format!("{value}-bestand"));
    let modified_at = remote
        .modified_unix
        .and_then(|timestamp| i64::try_from(timestamp).ok())
        .and_then(|timestamp| DateTime::<Utc>::from_timestamp(timestamp, 0))
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true));
    FileContentPreview {
        edit_version: None,
        file_name,
        relative_path: relative_path.into(),
        size_bytes: remote.size_bytes,
        modified_at,
        file_type,
        extension,
        text_content,
        image_mime_type,
        image_data_base64,
        raw_data_base64,
        binary,
        truncated,
    }
}

fn preview_extension(path: &str) -> Option<String> {
    let file_name = path.rsplit('/').next().unwrap_or(path);
    file_name
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map(|(_, extension)| extension.to_ascii_lowercase())
}

fn is_binary_image_extension(extension: &str) -> bool {
    matches!(
        extension.to_ascii_lowercase().as_str(),
        "jpg" | "jpeg" | "png" | "gif" | "webp" | "avif" | "ico" | "bmp" | "tiff" | "tif"
    )
}

fn image_mime_type_for_extension(extension: &str) -> Option<&'static str> {
    match extension.to_ascii_lowercase().as_str() {
        "jpg" | "jpeg" => Some("image/jpeg"),
        "png" => Some("image/png"),
        "gif" => Some("image/gif"),
        "webp" => Some("image/webp"),
        "avif" => Some("image/avif"),
        "ico" => Some("image/x-icon"),
        "bmp" => Some("image/bmp"),
        "tiff" | "tif" => Some("image/tiff"),
        _ => None,
    }
}

fn decode_svgz_source(bytes: &[u8]) -> (Option<String>, bool) {
    let mut decoded = Vec::with_capacity(PREVIEW_LIMIT_BYTES);
    let result = GzDecoder::new(bytes)
        .take(PREVIEW_LIMIT_BYTES as u64 + 1)
        .read_to_end(&mut decoded);
    if result.is_err() || decoded.len() > PREVIEW_LIMIT_BYTES {
        return (None, decoded.len() > PREVIEW_LIMIT_BYTES);
    }
    (String::from_utf8(decoded).ok(), false)
}

fn convert_tiff_to_png(bytes: &[u8]) -> Option<Vec<u8>> {
    let mut reader = ImageReader::with_format(Cursor::new(bytes), ImageFormat::Tiff);
    let mut limits = Limits::default();
    limits.max_alloc = Some(128 * 1024 * 1024);
    limits.max_image_width = Some(16_384);
    limits.max_image_height = Some(16_384);
    reader.limits(limits);
    let image = reader.decode().ok()?;
    let mut output = Cursor::new(Vec::new());
    image.write_to(&mut output, ImageFormat::Png).ok()?;
    Some(output.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{ChecksumStatus, Finding, FindingSeverity};
    use flate2::{Compression, write::GzEncoder};
    use image::{ExtendedColorType, ImageEncoder, codecs::tiff::TiffEncoder};
    use std::io::Write;

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
        assert!(preview.image_data_base64.is_none());
        assert!(preview.raw_data_base64.is_none());
    }

    #[test]
    fn binary_image_previews_keep_the_original_bytes_and_mime_type() {
        for (extension, mime_type) in [
            ("jpg", "image/jpeg"),
            ("jpeg", "image/jpeg"),
            ("png", "image/png"),
            ("gif", "image/gif"),
            ("webp", "image/webp"),
            ("avif", "image/avif"),
            ("ico", "image/x-icon"),
            ("bmp", "image/bmp"),
        ] {
            let bytes = vec![0, 1, 2, 3, 4];
            let preview = build_preview(
                &record().finding,
                &format!("wp-content/uploads/image.{extension}"),
                RemoteFileRead {
                    bytes: bytes.clone(),
                    size_bytes: bytes.len() as u64,
                    modified_unix: None,
                    truncated: false,
                },
            );

            assert!(preview.binary, "{extension}");
            assert!(preview.text_content.is_none(), "{extension}");
            assert_eq!(preview.image_mime_type.as_deref(), Some(mime_type));
            assert_eq!(
                STANDARD
                    .decode(preview.image_data_base64.as_ref().unwrap())
                    .unwrap(),
                bytes
            );
        }
    }

    #[test]
    fn svgz_preview_decompresses_to_highlightable_svg_source() {
        let source = r#"<svg xmlns="http://www.w3.org/2000/svg"><path d="M0 0h10v10z" /></svg>"#;
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(source.as_bytes()).unwrap();
        let compressed = encoder.finish().unwrap();
        let preview = build_preview(
            &record().finding,
            "wp-content/uploads/logo.svgz",
            RemoteFileRead {
                size_bytes: compressed.len() as u64,
                bytes: compressed,
                modified_unix: None,
                truncated: false,
            },
        );

        assert!(!preview.binary);
        assert_eq!(preview.extension.as_deref(), Some("svgz"));
        assert_eq!(preview.text_content.as_deref(), Some(source));
        assert_eq!(preview.image_mime_type.as_deref(), Some("image/svg+xml"));
        assert!(preview.image_data_base64.is_none());
    }

    #[test]
    fn truncated_image_keeps_partial_original_bytes_for_raw_analysis_only() {
        let bytes = b"PNG bytes with <?php hidden(); ?>".to_vec();
        let preview = build_preview(
            &record().finding,
            "wp-content/uploads/large.png",
            RemoteFileRead {
                size_bytes: IMAGE_PREVIEW_LIMIT_BYTES as u64 + 1,
                bytes: bytes.clone(),
                modified_unix: None,
                truncated: true,
            },
        );

        assert!(preview.truncated);
        assert!(preview.image_data_base64.is_none());
        assert_eq!(
            STANDARD
                .decode(preview.raw_data_base64.as_ref().unwrap())
                .unwrap(),
            bytes
        );
    }

    #[test]
    fn tiff_preview_is_converted_to_a_browser_safe_png() {
        let mut tiff = Cursor::new(Vec::new());
        TiffEncoder::new(&mut tiff)
            .write_image(&[255, 0, 0, 255], 1, 1, ExtendedColorType::Rgba8)
            .unwrap();
        let tiff = tiff.into_inner();
        let preview = build_preview(
            &record().finding,
            "wp-content/uploads/pixel.tiff",
            RemoteFileRead {
                size_bytes: tiff.len() as u64,
                bytes: tiff.clone(),
                modified_unix: None,
                truncated: false,
            },
        );

        let original = STANDARD
            .decode(preview.raw_data_base64.as_ref().unwrap())
            .unwrap();
        let png = STANDARD
            .decode(preview.image_data_base64.as_ref().unwrap())
            .unwrap();
        assert!(preview.binary);
        assert_eq!(preview.image_mime_type.as_deref(), Some("image/png"));
        assert_eq!(original, tiff);
        assert_eq!(&png[..8], b"\x89PNG\r\n\x1a\n");
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
        assert_eq!(
            preview.text_content.as_ref().unwrap().len(),
            PREVIEW_LIMIT_BYTES
        );
    }

    #[test]
    fn preview_accepts_findings_that_refer_to_existing_files() {
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
        let mut modified_core = context("core_checksum", "wp-includes/PHPMailer/PHPMailer.php");
        modified_core.finding.checksum_status = Some(ChecksumStatus::Modified);
        assert_eq!(
            validate_preview_context("site-1", &modified_core).unwrap(),
            "wp-includes/PHPMailer/PHPMailer.php"
        );
        assert_eq!(
            validate_preview_context(
                "site-1",
                &context("core_checksum", "wp-admin/unexpected.php")
            )
            .unwrap(),
            "wp-admin/unexpected.php"
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
        let mut missing_core = context("core_checksum", "wp-admin/load.php");
        missing_core.finding.checksum_status = Some(ChecksumStatus::Missing);
        assert!(validate_preview_context("site-1", &missing_core).is_err());
        let mut failed_core = context("core_checksum", "wp-admin/load.php");
        failed_core.finding.checksum_status = Some(ChecksumStatus::ScanError);
        assert!(validate_preview_context("site-1", &failed_core).is_err());
        assert!(
            validate_preview_context(
                "another-site",
                &context("php_uploads", "wp-content/uploads/test.php")
            )
            .is_err()
        );
    }
}
