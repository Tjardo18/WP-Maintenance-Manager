use crate::{checksum_files, models::FileContentPreview, ssh::RemoteFileRead};

pub const TEXT_PREVIEW_LIMIT_BYTES: usize = checksum_files::PREVIEW_LIMIT_BYTES;
pub const IMAGE_PREVIEW_LIMIT_BYTES: usize = checksum_files::IMAGE_PREVIEW_LIMIT_BYTES;

pub fn preview_limit(path: &str) -> usize {
    match extension(path).as_deref() {
        Some(
            "svgz" | "jpg" | "jpeg" | "png" | "gif" | "webp" | "avif" | "ico" | "bmp" | "tiff"
            | "tif",
        ) => IMAGE_PREVIEW_LIMIT_BYTES,
        _ => TEXT_PREVIEW_LIMIT_BYTES,
    }
}

pub fn build_preview(path: &str, remote: RemoteFileRead) -> FileContentPreview {
    checksum_files::build_file_content_preview(path, remote)
}

fn extension(path: &str) -> Option<String> {
    let name = path.rsplit('/').next().unwrap_or(path);
    name.rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map(|(_, extension)| extension.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preview_limits_are_central_and_extension_aware() {
        assert_eq!(preview_limit("/wp-config.php"), TEXT_PREVIEW_LIMIT_BYTES);
        assert_eq!(preview_limit("/.htaccess"), TEXT_PREVIEW_LIMIT_BYTES);
        assert_eq!(preview_limit("/LICENSE"), TEXT_PREVIEW_LIMIT_BYTES);
        assert_eq!(
            preview_limit("/uploads/PHOTO.PNG"),
            IMAGE_PREVIEW_LIMIT_BYTES
        );
        assert_eq!(
            preview_limit("/uploads/logo.svgz"),
            IMAGE_PREVIEW_LIMIT_BYTES
        );
    }

    #[test]
    fn utf8_and_binary_content_use_the_existing_preview_contract() {
        let text = build_preview(
            "/bestand-ë.php",
            RemoteFileRead {
                bytes: "<?php echo '€ 中文 🙂';".as_bytes().to_vec(),
                size_bytes: 34,
                modified_unix: Some(1_700_000_000),
                truncated: false,
            },
        );
        assert!(!text.binary);
        assert!(text.text_content.as_deref().unwrap().contains("中文"));

        let binary = build_preview(
            "/archive.zip",
            RemoteFileRead {
                bytes: vec![0, 159, 146, 150],
                size_bytes: 4,
                modified_unix: None,
                truncated: false,
            },
        );
        assert!(binary.binary);
        assert!(binary.text_content.is_none());
    }
}
