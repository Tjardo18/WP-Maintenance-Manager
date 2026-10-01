//! Phase 9: bounded, root-relative SFTP downloads into a caller-owned local file.
use crate::{
    error::AppError,
    filemanager_directory::{DirectoryTransport, EntryKind, list_directory},
    filemanager_mutation::{BulkInput, ItemKind, validate_bulk},
    filemanager_paths::{
        ResolvedFile, VirtualPath, resolve_directory, resolve_file, validate_name,
    },
};
use serde::Serialize;
use std::{
    io::{Seek, Write},
    time::{Duration, Instant},
};
use zip::{CompressionMethod, ZipWriter, write::SimpleFileOptions};

pub const MAX_DOWNLOAD_BYTES: u64 = 4 * 1024 * 1024 * 1024;
pub const MAX_ARCHIVE_ENTRIES: usize = 10_000;
pub const MAX_ARCHIVE_DEPTH: usize = 64;
pub const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(600);

pub trait DownloadTransport: DirectoryTransport {
    fn copy_file(
        &mut self,
        file: &ResolvedFile,
        sink: &mut dyn Write,
        budget: &mut Budget,
    ) -> Result<u64, AppError>;
}

pub struct Budget {
    bytes: u64,
    files: usize,
    started: Instant,
}

impl Default for Budget {
    fn default() -> Self {
        Self {
            bytes: 0,
            files: 0,
            started: Instant::now(),
        }
    }
}

impl Budget {
    pub fn check(&self) -> Result<(), AppError> {
        if self.started.elapsed() > DOWNLOAD_TIMEOUT {
            return Err(failure(
                "filemanager_download_timeout",
                "De download duurde te lang en is afgebroken.",
            ));
        }
        Ok(())
    }
    pub fn add_file(&mut self) -> Result<(), AppError> {
        self.check()?;
        self.files += 1;
        if self.files > MAX_ARCHIVE_ENTRIES {
            return Err(failure(
                "filemanager_archive_limit",
                "Het archief bevat te veel bestanden of mappen.",
            ));
        }
        Ok(())
    }
    pub fn add_bytes(&mut self, n: usize) -> Result<(), AppError> {
        self.check()?;
        self.bytes = self.bytes.checked_add(n as u64).ok_or_else(limit_error)?;
        if self.bytes > MAX_DOWNLOAD_BYTES {
            return Err(limit_error());
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DownloadResult {
    pub file_name: String,
    pub bytes: u64,
    pub archived: bool,
    pub saved_to: Option<String>,
}

pub fn suggested_name(input: &BulkInput) -> String {
    let archive = input.items.len() != 1 || input.items[0].expected_kind != ItemKind::File;
    let raw = if input.items.len() == 1 {
        input.items[0].path.rsplit('/').next().unwrap_or("download")
    } else {
        "filemanager-download"
    };
    let mut clean: String = raw
        .chars()
        .filter(|c| !c.is_control() && !"\\/:*?\"<>|".contains(*c))
        .take(160)
        .collect();
    clean = clean.trim().trim_end_matches('.').to_string();
    if clean.is_empty() {
        clean = "download".into();
    }
    if archive {
        format!("{clean}.zip")
    } else {
        clean
    }
}

fn failure(category: &str, message: &str) -> AppError {
    AppError::unauthorized(category, message)
}
fn limit_error() -> AppError {
    failure(
        "filemanager_download_limit",
        "De download overschrijdt de limiet van 4 GB.",
    )
}
fn write_error(_: std::io::Error) -> AppError {
    failure(
        "filemanager_download_write_failed",
        "Het lokale downloadbestand kon niet volledig worden geschreven. Controleer schijfruimte en toegangsrechten.",
    )
}
fn zip_error(_: zip::result::ZipError) -> AppError {
    failure(
        "filemanager_archive_failed",
        "Het ZIP-archief kon niet volledig worden opgebouwd.",
    )
}

fn safe_entry(path: &str) -> Result<String, AppError> {
    if path.is_empty() || path.starts_with('/') || path.contains('\\') {
        return Err(failure(
            "filemanager_archive_path",
            "Het archiefpad is ongeldig.",
        ));
    }
    for component in path.trim_end_matches('/').split('/') {
        validate_name(component)?;
        if component.contains(':') {
            return Err(failure(
                "filemanager_archive_path",
                "Dit bestand heeft een naam die niet veilig in een ZIP-archief kan worden opgenomen.",
            ));
        }
    }
    Ok(path.into())
}

pub fn write_download<W: Write + Seek>(
    remote: &mut impl DownloadTransport,
    root: &str,
    input: &BulkInput,
    output: &mut W,
) -> Result<DownloadResult, AppError> {
    validate_bulk(input)?;
    let parent = resolve_directory(remote, root, &input.directory)?;
    let archive_mode = input.items.len() != 1 || input.items[0].expected_kind != ItemKind::File;
    let mut selections = Vec::with_capacity(input.items.len());
    for item in &input.items {
        if item.expected_kind == ItemKind::Symlink {
            return Err(failure(
                "filemanager_symlink_blocked",
                "Symlinks kunnen niet worden gedownload.",
            ));
        }
        let path = VirtualPath::parse(&item.path)?;
        let name = path.as_str().rsplit('/').next().unwrap_or_default();
        let absolute = format!("{}/{}", parent.absolute().trim_end_matches('/'), name);
        let stat = remote.lstat(&absolute)?;
        let actual = match stat.perm.map(|mode| mode & 0o170000) {
            Some(0o100000) => ItemKind::File,
            Some(0o040000) => ItemKind::Directory,
            Some(0o120000) => {
                return Err(failure(
                    "filemanager_symlink_blocked",
                    "Symlinks kunnen niet worden gedownload.",
                ));
            }
            _ => {
                return Err(failure(
                    "filemanager_unsupported_item",
                    "Dit serverobject kan niet worden gedownload.",
                ));
            }
        };
        if actual != item.expected_kind {
            return Err(failure(
                "filemanager_item_changed",
                "Een geselecteerd item is gewijzigd. Vernieuw de map.",
            ));
        }
        let entry = if archive_mode {
            safe_entry(name)?
        } else {
            name.to_string()
        };
        selections.push((path, entry, actual));
    }
    parent.revalidate(remote)?;
    let file_name = suggested_name(input);
    let mut budget = Budget::default();
    if selections.len() == 1 && selections[0].2 == ItemKind::File {
        let file = resolve_file(remote, root, selections[0].0.as_str())?;
        if file
            .stat()
            .size
            .is_some_and(|size| size > MAX_DOWNLOAD_BYTES)
        {
            return Err(limit_error());
        }
        budget.add_file()?;
        let bytes = remote.copy_file(&file, output, &mut budget)?;
        output.flush().map_err(write_error)?;
        return Ok(DownloadResult {
            file_name,
            bytes,
            archived: false,
            saved_to: None,
        });
    }
    let mut archive = ZipWriter::new(output);
    let file_options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .large_file(true)
        .unix_permissions(0o644);
    let dir_options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Stored)
        .unix_permissions(0o755);
    let mut stack: Vec<(VirtualPath, String, ItemKind, usize)> = selections
        .into_iter()
        .rev()
        .map(|(path, entry, kind)| (path, entry, kind, 0))
        .collect();
    while let Some((path, entry, kind, depth)) = stack.pop() {
        budget.check()?;
        match kind {
            ItemKind::File => {
                budget.add_file()?;
                let file = resolve_file(remote, root, path.as_str())?;
                if file
                    .stat()
                    .size
                    .is_some_and(|size| size > MAX_DOWNLOAD_BYTES - budget.bytes)
                {
                    return Err(limit_error());
                }
                archive
                    .start_file(safe_entry(&entry)?, file_options)
                    .map_err(zip_error)?;
                remote.copy_file(&file, &mut archive, &mut budget)?;
            }
            ItemKind::Directory => {
                budget.add_file()?;
                if depth >= MAX_ARCHIVE_DEPTH {
                    return Err(failure(
                        "filemanager_archive_depth",
                        "De mapstructuur is te diep voor een downloadarchief.",
                    ));
                }
                let directory = resolve_directory(remote, root, path.as_str())?;
                let zip_path = safe_entry(&format!("{entry}/"))?;
                archive
                    .add_directory(zip_path, dir_options)
                    .map_err(zip_error)?;
                let listing = list_directory(remote, root, path.as_str())?;
                if listing.truncated {
                    return Err(failure(
                        "filemanager_archive_limit",
                        "Een map bevat meer bestanden dan veilig kunnen worden opgenomen.",
                    ));
                }
                for item in listing.items.into_iter().rev() {
                    let child_kind = match item.kind {
                        EntryKind::File => ItemKind::File,
                        EntryKind::Directory => ItemKind::Directory,
                        EntryKind::Symlink => {
                            return Err(failure(
                                "filemanager_symlink_blocked",
                                "Het archief bevat een symlink; de download is afgebroken.",
                            ));
                        }
                        EntryKind::Other => {
                            return Err(failure(
                                "filemanager_unsupported_item",
                                "Het archief bevat een niet-ondersteund serverobject.",
                            ));
                        }
                    };
                    stack.push((
                        VirtualPath::parse(&item.path)?,
                        safe_entry(&format!("{entry}/{}", item.name))?,
                        child_kind,
                        depth + 1,
                    ));
                }
                directory.revalidate(remote)?;
            }
            ItemKind::Symlink => {
                return Err(failure(
                    "filemanager_symlink_blocked",
                    "Symlinks kunnen niet worden gedownload.",
                ));
            }
        }
    }
    archive.finish().map_err(zip_error)?;
    Ok(DownloadResult {
        file_name,
        bytes: budget.bytes,
        archived: true,
        saved_to: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        filemanager_mutation::DeleteInput,
        filemanager_paths::{RemotePaths, ResolvedDirectory},
    };
    use std::{
        collections::{HashMap, HashSet, VecDeque},
        io::{Cursor, Read},
    };

    #[derive(Default)]
    struct Remote {
        files: HashMap<String, Vec<u8>>,
        dirs: HashSet<String>,
        links: HashSet<String>,
        fail_read: bool,
    }

    impl Remote {
        fn fixture() -> Self {
            let mut r = Self::default();
            r.dirs.extend(
                [
                    "/srv",
                    "/srv/site",
                    "/srv/site/root",
                    "/srv/site/root/wp-content",
                ]
                .map(str::to_string),
            );
            r.files
                .insert("/srv/site/root/index.php".into(), b"<?php echo 1;".to_vec());
            r.files
                .insert("/srv/site/root/wp-content/a.txt".into(), b"hello".to_vec());
            r
        }
        fn stat(&self, path: &str) -> Result<ssh2::FileStat, AppError> {
            let (mode, size) = if self.dirs.contains(path) {
                (0o040755, 0)
            } else if let Some(content) = self.files.get(path) {
                (0o100644, content.len() as u64)
            } else if self.links.contains(path) {
                (0o120777, 0)
            } else {
                return Err(failure("filemanager_directory_missing", "Ontbreekt."));
            };
            Ok(ssh2::FileStat {
                size: Some(size),
                uid: Some(1),
                gid: Some(1),
                perm: Some(mode),
                atime: None,
                mtime: Some(1),
            })
        }
    }
    impl RemotePaths for Remote {
        fn realpath(&mut self, path: &str) -> Result<String, AppError> {
            Ok(path.into())
        }
        fn lstat(&mut self, path: &str) -> Result<ssh2::FileStat, AppError> {
            self.stat(path)
        }
    }
    impl DirectoryTransport for Remote {
        type Handle = VecDeque<(String, ssh2::FileStat)>;
        fn open_directory(&mut self, path: &ResolvedDirectory) -> Result<Self::Handle, AppError> {
            let prefix = format!("{}/", path.absolute().trim_end_matches('/'));
            let mut entries = VecDeque::new();
            for candidate in self
                .dirs
                .iter()
                .chain(self.files.keys())
                .chain(self.links.iter())
            {
                if let Some(name) = candidate.strip_prefix(&prefix)
                    && !name.is_empty()
                    && !name.contains('/')
                {
                    entries.push_back((name.into(), self.stat(candidate)?));
                }
            }
            Ok(entries)
        }
        fn next_entry(
            &mut self,
            handle: &mut Self::Handle,
        ) -> Result<Option<(String, ssh2::FileStat)>, AppError> {
            Ok(handle.pop_front())
        }
    }
    impl DownloadTransport for Remote {
        fn copy_file(
            &mut self,
            file: &ResolvedFile,
            sink: &mut dyn Write,
            budget: &mut Budget,
        ) -> Result<u64, AppError> {
            if self.fail_read {
                return Err(failure("filemanager_file_read_failed", "Lezen mislukt."));
            }
            let bytes = self
                .files
                .get(file.absolute())
                .ok_or_else(|| failure("filemanager_file_missing", "Ontbreekt."))?;
            for part in bytes.chunks(2) {
                budget.add_bytes(part.len())?;
                sink.write_all(part).map_err(write_error)?;
            }
            Ok(bytes.len() as u64)
        }
    }
    fn selected(items: &[(&str, ItemKind)]) -> BulkInput {
        BulkInput {
            directory: "/".into(),
            items: items
                .iter()
                .map(|(path, kind)| DeleteInput {
                    path: (*path).into(),
                    expected_kind: *kind,
                })
                .collect(),
        }
    }
    #[test]
    fn direct_file_streams_original_bytes_and_sanitizes_suggested_name() {
        let mut remote = Remote::fixture();
        let input = selected(&[("/index.php", ItemKind::File)]);
        let mut output = Cursor::new(Vec::new());
        let result = write_download(&mut remote, "/srv/site/root", &input, &mut output).unwrap();
        assert!(!result.archived);
        assert_eq!(result.file_name, "index.php");
        assert_eq!(output.into_inner(), b"<?php echo 1;");
        let quoted = selected(&[("/a\"b.php", ItemKind::File)]);
        assert_eq!(suggested_name(&quoted), "ab.php");
    }
    #[test]
    fn archive_contains_only_selected_relative_paths_and_nested_files() {
        let mut remote = Remote::fixture();
        let input = selected(&[
            ("/index.php", ItemKind::File),
            ("/wp-content", ItemKind::Directory),
        ]);
        let mut output = Cursor::new(Vec::new());
        let result = write_download(&mut remote, "/srv/site/root", &input, &mut output).unwrap();
        assert!(result.archived);
        assert_eq!(result.file_name, "filemanager-download.zip");
        let mut archive = zip::ZipArchive::new(Cursor::new(output.into_inner())).unwrap();
        assert_eq!(archive.len(), 3);
        let mut content = String::new();
        archive
            .by_name("wp-content/a.txt")
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert_eq!(content, "hello");
        assert!(archive.by_name("index.php").is_ok());
        assert!(archive.by_name("/srv/site/root/index.php").is_err());
    }
    #[test]
    fn traversal_symlinks_and_partial_reads_do_not_succeed() {
        let mut remote = Remote::fixture();
        let bad = selected(&[
            ("/index.php", ItemKind::File),
            ("../../../etc/passwd", ItemKind::File),
        ]);
        let mut output = Cursor::new(Vec::new());
        assert!(write_download(&mut remote, "/srv/site/root", &bad, &mut output).is_err());
        assert!(output.get_ref().is_empty());
        remote.links.insert("/srv/site/root/wp-content/link".into());
        let mut archive = Cursor::new(Vec::new());
        assert!(
            write_download(
                &mut remote,
                "/srv/site/root",
                &selected(&[("/wp-content", ItemKind::Directory)]),
                &mut archive
            )
            .is_err()
        );
        remote.links.clear();
        remote.fail_read = true;
        let mut direct = Cursor::new(Vec::new());
        assert!(
            write_download(
                &mut remote,
                "/srv/site/root",
                &selected(&[("/index.php", ItemKind::File)]),
                &mut direct
            )
            .is_err()
        );
    }
    #[test]
    fn archive_entries_reject_zip_slip_and_windows_paths() {
        for path in [
            "../escape",
            "/etc/passwd",
            "C:/outside",
            "a\\b",
            "a/../b",
            "a\nb",
        ] {
            assert!(safe_entry(path).is_err(), "{path:?}");
        }
        for path in [
            "hello;whoami.txt",
            "$(id).txt",
            "`id`.txt",
            "a&b.txt",
            "name with spaces.txt",
            "quoted\".txt",
            "bestand-ë.txt",
        ] {
            assert!(safe_entry(path).is_ok(), "{path:?}");
        }
    }
    #[test]
    fn direct_download_preserves_space_unicode_and_shell_punctuation() {
        for name in [
            "my file.php",
            "bestand-ë.txt",
            "foo;bar.txt",
            "$(whoami).txt",
        ] {
            let mut remote = Remote::fixture();
            remote
                .files
                .insert(format!("/srv/site/root/{name}"), b"server version".to_vec());
            let input = selected(&[(&format!("/{name}"), ItemKind::File)]);
            let mut output = Cursor::new(Vec::new());
            let result =
                write_download(&mut remote, "/srv/site/root", &input, &mut output).unwrap();
            assert_eq!(result.file_name, name);
            assert_eq!(output.into_inner(), b"server version");
        }
        assert_eq!(
            suggested_name(&selected(&[("/quoted\".txt", ItemKind::File)])),
            "quoted.txt"
        );
        assert_eq!(
            suggested_name(&selected(&[("/line\nfeed.txt", ItemKind::File)])),
            "linefeed.txt"
        );
        assert_eq!(
            suggested_name(&selected(&[("/carriage\rreturn.txt", ItemKind::File)])),
            "carriagereturn.txt"
        );
    }
    #[test]
    fn missing_items_and_stream_limits_fail_without_success() {
        let mut remote = Remote::fixture();
        let mut output = Cursor::new(Vec::new());
        assert!(
            write_download(
                &mut remote,
                "/srv/site/root",
                &selected(&[("/gone.php", ItemKind::File)]),
                &mut output
            )
            .is_err()
        );
        assert!(output.get_ref().is_empty());
        let mut budget = Budget::default();
        assert_eq!(
            budget
                .add_bytes(MAX_DOWNLOAD_BYTES as usize + 1)
                .unwrap_err()
                .category,
            "filemanager_download_limit"
        );
        for _ in 0..MAX_ARCHIVE_ENTRIES {
            budget.add_file().unwrap();
        }
        assert_eq!(
            budget.add_file().unwrap_err().category,
            "filemanager_archive_limit"
        );
    }
}
