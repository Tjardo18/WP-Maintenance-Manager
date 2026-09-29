use crate::{
    error::AppError,
    filemanager_paths::{RemotePaths, ResolvedDirectory, resolve_directory, validate_name},
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use std::collections::HashSet;

pub const MAX_DIRECTORY_ITEMS: usize = 5_000;

pub trait DirectoryTransport: RemotePaths {
    type Handle;
    fn open_directory(&mut self, path: &ResolvedDirectory) -> Result<Self::Handle, AppError>;
    fn next_entry(
        &mut self,
        handle: &mut Self::Handle,
    ) -> Result<Option<(String, ssh2::FileStat)>, AppError>;
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EntryKind {
    Directory,
    File,
    Symlink,
    Other,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryItem {
    pub name: String,
    pub path: String,
    pub kind: EntryKind,
    pub extension: Option<String>,
    pub size: Option<u64>,
    pub permissions: Option<String>,
    pub modified_at: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DirectoryListing {
    pub current_path: String,
    pub is_root: bool,
    pub parent_path: Option<String>,
    pub items: Vec<DirectoryItem>,
    pub truncated: bool,
}

pub fn list_directory(
    remote: &mut impl DirectoryTransport,
    configured_root: &str,
    requested: &str,
) -> Result<DirectoryListing, AppError> {
    let directory = resolve_directory(remote, configured_root, requested)?;
    let mut handle = remote.open_directory(&directory)?;
    // SFTP has no openat/O_NOFOLLOW: validate on both sides of opening/reading.
    directory.revalidate(remote)?;
    let mut items = Vec::new();
    let mut names = HashSet::new();
    let mut complete = false;
    // Bounded even if a broken server repeats dot entries indefinitely.
    for _ in 0..MAX_DIRECTORY_ITEMS + 3 {
        let Some((name, stat)) = remote.next_entry(&mut handle)? else {
            complete = true;
            break;
        };
        if matches!(name.as_str(), "." | "..") {
            continue;
        }
        validate_name(&name).map_err(|_| malformed_listing())?;
        if !names.insert(name.clone()) {
            return Err(malformed_listing());
        }
        if items.len() == MAX_DIRECTORY_ITEMS {
            break;
        }
        let kind = match stat.perm.map(|mode| mode & 0o170000) {
            Some(0o040000) => EntryKind::Directory,
            Some(0o100000) => EntryKind::File,
            Some(0o120000) => EntryKind::Symlink,
            _ => EntryKind::Other,
        };
        let extension = if kind == EntryKind::File {
            name.rsplit_once('.')
                .filter(|(base, extension)| !base.is_empty() && !extension.is_empty())
                .map(|(_, extension)| extension.to_lowercase())
        } else {
            None
        };
        let size = if kind == EntryKind::File {
            stat.size
        } else {
            None
        };
        let modified_at = stat
            .mtime
            .and_then(|seconds| i64::try_from(seconds).ok())
            .and_then(|seconds| DateTime::<Utc>::from_timestamp(seconds, 0))
            .map(|date| date.to_rfc3339_opts(SecondsFormat::Secs, true));
        items.push(DirectoryItem {
            path: directory.relative().child(&name)?.as_str().into(),
            name,
            kind,
            extension,
            size,
            permissions: stat.perm.map(|mode| format!("{:03o}", mode & 0o7777)),
            modified_at,
        });
    }
    directory.revalidate(remote)?;
    items.sort_by_cached_key(|item| {
        (
            match item.kind {
                EntryKind::Directory => 0,
                EntryKind::File => 1,
                EntryKind::Symlink => 2,
                EntryKind::Other => 3,
            },
            item.name.to_lowercase(),
            item.name.clone(),
        )
    });
    Ok(DirectoryListing {
        current_path: directory.relative().as_str().into(),
        is_root: directory.relative().as_str() == "/",
        parent_path: directory.relative().parent(),
        items,
        truncated: !complete,
    })
}

pub fn malformed_listing() -> AppError {
    AppError::unauthorized(
        "filemanager_invalid_directory_response",
        "De server gaf ongeldige of niet-ondersteunde mapgegevens terug. De lijst wordt niet getoond.",
    )
}
