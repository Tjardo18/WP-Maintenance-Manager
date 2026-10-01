//! Existing-file updates only. No shell, no direct truncation and no force overwrite.
use crate::{
    error::AppError,
    filemanager_file::{TEXT_PREVIEW_LIMIT_BYTES, build_preview},
    filemanager_paths::{RemotePaths, ResolvedFile, resolve_file, same_file_snapshot},
    models::FileContentPreview,
    ssh::RemoteFileRead,
};
use sha2::{Digest, Sha256};

#[derive(serde::Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SaveInput {
    pub path: String,
    pub content: String,
    pub expected_version: String,
}

pub fn editable(path: &str, bytes: &[u8]) -> bool {
    let extension = path.rsplit('.').next().unwrap_or("").to_ascii_lowercase();
    bytes.len() <= TEXT_PREVIEW_LIMIT_BYTES
        && !matches!(
            extension.as_str(),
            "svgz"
                | "jpg"
                | "jpeg"
                | "png"
                | "gif"
                | "webp"
                | "avif"
                | "ico"
                | "bmp"
                | "tiff"
                | "tif"
                | "pdf"
                | "zip"
                | "gz"
                | "tar"
                | "7z"
                | "rar"
                | "exe"
                | "dll"
                | "woff"
                | "woff2"
                | "ttf"
                | "otf"
        )
        && std::str::from_utf8(bytes).is_ok_and(|text| {
            !text
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        })
}

pub fn version(path: &str, bytes: &[u8], stat: &ssh2::FileStat) -> String {
    let mut hash = Sha256::new();
    hash.update(path.as_bytes());
    hash.update([0]);
    hash.update(format!(
        "{:?}",
        (stat.size, stat.mtime, stat.perm, stat.uid, stat.gid)
    ));
    hash.update([0]);
    hash.update(bytes);
    hash.finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn validate_input(content: &str, expected: &str) -> Result<(), AppError> {
    if content.len() > TEXT_PREVIEW_LIMIT_BYTES {
        return Err(error(
            "too_large",
            "Dit bestand is te groot om via de filemanager te bewerken (maximaal 256 KiB).",
        ));
    }
    if expected.len() != 64 || !expected.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(error(
            "version_required",
            "Herlaad het bestand voordat je wijzigingen opslaat.",
        ));
    }
    if !editable("text", content.as_bytes()) {
        return Err(error(
            "unsupported_file",
            "Deze inhoud is niet geschikt voor tekstbewerking.",
        ));
    }
    Ok(())
}

pub fn error(kind: &str, message: &str) -> AppError {
    AppError::unauthorized(&format!("filemanager_{kind}"), message)
}

pub fn conflict() -> AppError {
    error(
        "edit_conflict",
        "Dit bestand is gewijzigd sinds je het hebt geopend. Herlaad het bestand voordat je jouw wijzigingen opslaat.",
    )
}

pub trait EditTransport: RemotePaths {
    type Temp;
    fn read(&mut self, file: &ResolvedFile) -> Result<Vec<u8>, AppError>;
    // Must open WRITE without CREATE or TRUNCATE, to check actual file write access.
    fn check_writable(&mut self, file: &ResolvedFile) -> Result<(), AppError>;
    fn create_temp(&mut self, path: &str) -> Result<Self::Temp, AppError>;
    fn stage(
        &mut self,
        temp: &mut Self::Temp,
        content: &[u8],
        original: &ssh2::FileStat,
    ) -> Result<(), AppError>;
    fn replace(&mut self, temp_path: &str, file: &ResolvedFile) -> Result<(), AppError>;
    fn cleanup(&mut self, temp_path: &str) -> Result<(), AppError>;
}

pub fn save(
    remote: &mut impl EditTransport,
    root: &str,
    path: &str,
    content: &str,
    expected: &str,
    authorize: impl Fn() -> Result<(), AppError>,
) -> Result<FileContentPreview, AppError> {
    validate_input(content, expected)?;
    authorize()?;
    let target = resolve_file(remote, root, path)?;
    if target
        .stat()
        .size
        .is_none_or(|n| n > TEXT_PREVIEW_LIMIT_BYTES as u64)
    {
        return Err(error(
            "too_large",
            "Dit bestand is te groot of de grootte kon niet betrouwbaar worden vastgesteld.",
        ));
    }
    let original = remote.read(&target)?;
    target.revalidate(remote)?;
    if !editable(path, &original) {
        return Err(error(
            "unsupported_file",
            "Dit bestand kan niet als tekst worden bewerkt.",
        ));
    }
    if version(target.absolute(), &original, target.stat()) != expected {
        return Err(conflict());
    }
    if !editable(path, content.as_bytes()) {
        return Err(error(
            "unsupported_file",
            "Dit bestand kan niet als tekst worden bewerkt.",
        ));
    }
    remote.check_writable(&target)?;
    if content.as_bytes() == original {
        return response(&target, original);
    }
    let parent = target.absolute().rsplit_once('/').unwrap().0;
    let temp_path = format!("{parent}/.wpmm-save-{}.tmp", uuid::Uuid::new_v4());
    // Only clean up a temp that was actually created by this operation (EXCL).
    let mut temp = remote.create_temp(&temp_path)?;
    let result = (|| {
        target.revalidate(remote)?;
        remote.stage(&mut temp, content.as_bytes(), target.stat())?;
        target.revalidate(remote)?;
        let current = remote.read(&target)?;
        target.revalidate(remote)?;
        if current != original {
            return Err(conflict());
        }
        authorize()?;
        remote.replace(&temp_path, &target)?;
        let saved = resolve_file(remote, root, path)?;
        let actual = remote.read(&saved)?;
        let final_stat = saved.revalidate(remote)?;
        if actual != content.as_bytes()
            || final_stat.perm != target.stat().perm
            || final_stat.uid != target.stat().uid
            || final_stat.gid != target.stat().gid
        {
            return Err(error(
                "save_unconfirmed",
                "Opslaan kon niet worden bevestigd. Herlaad het bestand om de serverinhoud te controleren.",
            ));
        }
        authorize()?;
        response(&saved, actual)
    })();
    drop(temp);
    result.map_err(|mut failure| {
        if remote.cleanup(&temp_path).is_err() {
            failure.user_message.push_str(" Een tijdelijk .wpmm-save-*.tmp-bestand kon mogelijk niet worden opgeruimd. Controleer de map na opnieuw verbinden.");
        }
        failure
    })
}

fn response(target: &ResolvedFile, bytes: Vec<u8>) -> Result<FileContentPreview, AppError> {
    let revision = version(target.absolute(), &bytes, target.stat());
    let mut preview = build_preview(
        target.relative().as_str(),
        RemoteFileRead {
            size_bytes: bytes.len() as u64,
            bytes,
            modified_unix: target.stat().mtime,
            truncated: false,
        },
    );
    preview.edit_version = Some(revision);
    Ok(preview)
}

pub fn verify_handle(target: &ResolvedFile, opened: &ssh2::FileStat) -> Result<(), AppError> {
    if same_file_snapshot(target.stat(), opened) {
        Ok(())
    } else {
        Err(conflict())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    #[derive(Clone)]
    struct Entry {
        bytes: Vec<u8>,
        stat: ssh2::FileStat,
    }
    struct Remote {
        files: HashMap<String, Entry>,
        fail: &'static str,
        change_during_stage: bool,
        replaced: usize,
    }
    fn stat(mode: u32, size: usize) -> ssh2::FileStat {
        ssh2::FileStat {
            size: Some(size as u64),
            uid: Some(1000),
            gid: Some(1000),
            perm: Some(mode),
            atime: None,
            mtime: Some(100),
        }
    }
    impl Remote {
        fn new(name: &str, bytes: &[u8], mode: u32) -> Self {
            Self {
                files: HashMap::from([(
                    format!("/srv/site/{name}"),
                    Entry {
                        bytes: bytes.into(),
                        stat: stat(mode, bytes.len()),
                    },
                )]),
                fail: "",
                change_during_stage: false,
                replaced: 0,
            }
        }
        fn revision(&self, name: &str) -> String {
            let p = format!("/srv/site/{name}");
            let file = &self.files[&p];
            version(&p, &file.bytes, &file.stat)
        }
        fn temps(&self) -> usize {
            self.files
                .keys()
                .filter(|p| p.contains(".wpmm-save-"))
                .count()
        }
    }
    impl RemotePaths for Remote {
        fn realpath(&mut self, path: &str) -> Result<String, AppError> {
            Ok(path.into())
        }
        fn lstat(&mut self, path: &str) -> Result<ssh2::FileStat, AppError> {
            if matches!(path, "/srv" | "/srv/site") {
                return Ok(stat(0o040755, 0));
            }
            self.files
                .get(path)
                .map(|f| f.stat.clone())
                .ok_or_else(|| error("directory_missing", "Missing"))
        }
    }
    impl EditTransport for Remote {
        type Temp = String;
        fn read(&mut self, file: &ResolvedFile) -> Result<Vec<u8>, AppError> {
            Ok(self.files[file.absolute()].bytes.clone())
        }
        fn check_writable(&mut self, _: &ResolvedFile) -> Result<(), AppError> {
            if self.fail == "permission" {
                Err(error("permission_denied", "Geen schrijfrechten"))
            } else {
                Ok(())
            }
        }
        fn create_temp(&mut self, path: &str) -> Result<String, AppError> {
            assert!(!self.files.contains_key(path));
            assert!(path.starts_with("/srv/site/.wpmm-save-"));
            if self.fail == "collision" {
                return Err(error("collision", "Collision"));
            }
            self.files.insert(
                path.into(),
                Entry {
                    bytes: vec![],
                    stat: stat(0o100600, 0),
                },
            );
            Ok(path.into())
        }
        fn stage(
            &mut self,
            temp: &mut String,
            content: &[u8],
            original: &ssh2::FileStat,
        ) -> Result<(), AppError> {
            if matches!(self.fail, "write" | "quota" | "disconnect") {
                return Err(error(self.fail, "Stage failed"));
            }
            let entry = self.files.get_mut(temp).unwrap();
            entry.bytes = content.into();
            entry.stat = original.clone();
            entry.stat.size = Some(content.len() as u64);
            entry.stat.mtime = Some(101);
            if self.change_during_stage {
                let original = self.files.get_mut("/srv/site/test.php").unwrap();
                original.bytes = b"EXT".to_vec();
            }
            Ok(())
        }
        fn replace(&mut self, temp: &str, file: &ResolvedFile) -> Result<(), AppError> {
            if self.fail == "replace" {
                return Err(error("replace_failed", "Replace failed"));
            }
            let entry = self.files.remove(temp).unwrap();
            self.files.insert(file.absolute().into(), entry);
            self.replaced += 1;
            Ok(())
        }
        fn cleanup(&mut self, temp: &str) -> Result<(), AppError> {
            if self.fail == "disconnect" {
                return Err(error("disconnected", "Offline"));
            }
            self.files.remove(temp);
            Ok(())
        }
    }

    #[test]
    fn preserves_bytes_permissions_ownership_and_rotates_version() {
        for mode in [0o100644, 0o100755, 0o100640] {
            let name = "my ' plugin $;& 中文.php";
            let mut remote = Remote::new(name, b"old", mode);
            let revision = remote.revision(name);
            let content = "\u{feff}<?php echo '$HOME';\r\né ë € 中文 🚀\r\n";
            let preview = save(
                &mut remote,
                "/srv/site",
                &format!("/{name}"),
                content,
                &revision,
                || Ok(()),
            )
            .unwrap();
            assert_eq!(preview.text_content.as_deref(), Some(content));
            assert_ne!(preview.edit_version.as_deref(), Some(revision.as_str()));
            let entry = &remote.files[&format!("/srv/site/{name}")];
            assert_eq!(entry.stat.perm, Some(mode));
            assert_eq!(entry.stat.uid, Some(1000));
            assert_eq!(entry.stat.gid, Some(1000));
            assert_eq!(remote.temps(), 0);
            assert_eq!(remote.replaced, 1);
        }
    }
    #[test]
    fn rejects_stale_second_editor_and_same_size_same_mtime_external_change() {
        let mut remote = Remote::new("test.php", b"old", 0o100644);
        let revision = remote.revision("test.php");
        save(
            &mut remote,
            "/srv/site",
            "/test.php",
            "new",
            &revision,
            || Ok(()),
        )
        .unwrap();
        assert_eq!(
            save(
                &mut remote,
                "/srv/site",
                "/test.php",
                "two",
                &revision,
                || Ok(())
            )
            .unwrap_err()
            .category,
            "filemanager_edit_conflict"
        );
        let current = remote.revision("test.php");
        remote.change_during_stage = true;
        assert_eq!(
            save(
                &mut remote,
                "/srv/site",
                "/test.php",
                "two",
                &current,
                || Ok(())
            )
            .unwrap_err()
            .category,
            "filemanager_edit_conflict"
        );
        assert_eq!(remote.files["/srv/site/test.php"].bytes, b"EXT");
        assert_eq!(remote.temps(), 0);
    }
    #[test]
    fn failures_keep_original_and_cleanup_only_owned_temps() {
        for failure in [
            "permission",
            "collision",
            "write",
            "quota",
            "replace",
            "disconnect",
        ] {
            let mut remote = Remote::new("test.php", b"old", 0o100644);
            let revision = remote.revision("test.php");
            remote.fail = failure;
            let err = save(
                &mut remote,
                "/srv/site",
                "/test.php",
                "new",
                &revision,
                || Ok(()),
            )
            .unwrap_err();
            assert_eq!(remote.files["/srv/site/test.php"].bytes, b"old");
            assert_eq!(remote.replaced, 0);
            if failure == "disconnect" {
                assert!(err.user_message.contains("tijdelijk"));
            } else {
                assert_eq!(remote.temps(), 0);
            }
        }
    }
    #[test]
    fn refuses_missing_directories_symlinks_traversal_binary_and_large_files() {
        for mode in [0o040755, 0o120777, 0o010644] {
            let mut remote = Remote::new("test.php", b"old", mode);
            let revision = remote.revision("test.php");
            assert!(
                save(
                    &mut remote,
                    "/srv/site",
                    "/test.php",
                    "new",
                    &revision,
                    || Ok(())
                )
                .is_err()
            );
            assert_eq!(remote.replaced, 0);
        }
        let mut remote = Remote::new("test.php", b"old", 0o100644);
        let revision = remote.revision("test.php");
        assert!(
            save(
                &mut remote,
                "/srv/site",
                "../../../etc/passwd",
                "new",
                &revision,
                || Ok(())
            )
            .is_err()
        );
        remote.files.clear();
        assert_eq!(
            save(
                &mut remote,
                "/srv/site",
                "/test.php",
                "new",
                &revision,
                || Ok(())
            )
            .unwrap_err()
            .category,
            "filemanager_file_missing"
        );
        assert!(remote.files.is_empty());
        for (name, bytes) in [
            ("x.png", b"ASCII".to_vec()),
            ("x.php", vec![0, 1]),
            ("x.php", vec![b'a'; TEXT_PREVIEW_LIMIT_BYTES + 1]),
        ] {
            let mut remote = Remote::new(name, &bytes, 0o100644);
            let revision = remote.revision(name);
            assert!(
                save(
                    &mut remote,
                    "/srv/site",
                    &format!("/{name}"),
                    "new",
                    &revision,
                    || Ok(())
                )
                .is_err()
            );
            assert_eq!(remote.replaced, 0);
        }
        assert!(validate_input(&"a".repeat(TEXT_PREVIEW_LIMIT_BYTES + 1), &revision).is_err());
    }
    #[test]
    fn revocation_before_replace_discards_staged_write_and_noop_never_writes() {
        let mut remote = Remote::new("test.php", b"old", 0o100644);
        let revision = remote.revision("test.php");
        save(
            &mut remote,
            "/srv/site",
            "/test.php",
            "old",
            &revision,
            || Ok(()),
        )
        .unwrap();
        assert_eq!(remote.replaced, 0);
        let calls = std::cell::Cell::new(0);
        assert!(
            save(
                &mut remote,
                "/srv/site",
                "/test.php",
                "new",
                &revision,
                || {
                    calls.set(calls.get() + 1);
                    if calls.get() > 1 {
                        Err(error("auth_required", "Revoked"))
                    } else {
                        Ok(())
                    }
                }
            )
            .is_err()
        );
        assert_eq!(remote.files["/srv/site/test.php"].bytes, b"old");
        assert_eq!(remote.temps(), 0);
    }
}
