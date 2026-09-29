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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filemanager_paths::RemotePaths;
    use std::collections::VecDeque;

    fn stat(mode: Option<u32>) -> ssh2::FileStat {
        ssh2::FileStat {
            perm: mode,
            size: Some(1234),
            mtime: Some(1_700_000_000),
            uid: None,
            gid: None,
            atime: None,
        }
    }

    #[derive(Default)]
    struct Remote {
        entries: VecDeque<(String, ssh2::FileStat)>,
        opened: Vec<String>,
        reads: usize,
        failure: Option<AppError>,
        fail_stage: &'static str,
        symlink: bool,
        change_on_open: bool,
        change_on_read: bool,
        target_mode: Option<u32>,
        missing_type: bool,
    }
    impl RemotePaths for Remote {
        fn realpath(&mut self, path: &str) -> Result<String, AppError> {
            Ok(path.into())
        }
        fn lstat(&mut self, path: &str) -> Result<ssh2::FileStat, AppError> {
            if self.fail_stage == "lstat" {
                return Err(self.failure.clone().unwrap());
            }
            if path == "/srv/site/content" {
                return Ok(stat(if self.missing_type {
                    None
                } else if self.symlink {
                    Some(0o120777)
                } else {
                    Some(self.target_mode.unwrap_or(0o040755))
                }));
            }
            Ok(stat(Some(0o040755)))
        }
    }
    impl DirectoryTransport for Remote {
        type Handle = ();
        fn open_directory(&mut self, path: &ResolvedDirectory) -> Result<(), AppError> {
            self.opened.push(path.absolute().into());
            if self.fail_stage == "open" {
                return Err(self.failure.clone().unwrap());
            }
            if self.change_on_open {
                self.symlink = true;
            }
            Ok(())
        }
        fn next_entry(&mut self, _: &mut ()) -> Result<Option<(String, ssh2::FileStat)>, AppError> {
            self.reads += 1;
            if self.fail_stage == "read" {
                return Err(self.failure.clone().unwrap());
            }
            if self.change_on_read {
                self.symlink = true;
            }
            Ok(self.entries.pop_front())
        }
    }

    #[test]
    fn listings_include_dotfiles_unicode_spaces_metadata_and_stable_sorting() {
        let mut remote = Remote::default();
        for (name, mode) in [
            ("z.php", 0o100644),
            ("my plugin.php", 0o100640),
            ("Alpha", 0o040755),
            ("alpha", 0o040750),
            (".htaccess", 0o100644),
            ("één 文件", 0o100600),
            ("shared", 0o120777),
            ("pipe", 0o010600),
            (".", 0o040755),
            ("..", 0o040755),
        ] {
            remote.entries.push_back((name.into(), stat(Some(mode))));
        }
        let response = list_directory(&mut remote, "/srv/site/", "/content/./").unwrap();
        assert_eq!(response.current_path, "/content");
        assert_eq!(response.parent_path.as_deref(), Some("/"));
        assert!(!response.is_root);
        assert!(!response.truncated);
        assert_eq!(
            response
                .items
                .iter()
                .map(|entry| entry.name.as_str())
                .collect::<Vec<_>>(),
            [
                "Alpha",
                "alpha",
                ".htaccess",
                "my plugin.php",
                "z.php",
                "één 文件",
                "shared",
                "pipe"
            ]
        );
        assert_eq!(response.items[0].size, None);
        assert_eq!(response.items[3].size, Some(1234));
        assert_eq!(response.items[3].extension.as_deref(), Some("php"));
        assert_eq!(response.items[3].permissions.as_deref(), Some("640"));
        assert_eq!(
            response.items[3].modified_at.as_deref(),
            Some("2023-11-14T22:13:20Z")
        );
        assert_eq!(response.items[6].kind, EntryKind::Symlink);
        assert_eq!(response.items[6].size, None);
        assert!(
            response
                .items
                .iter()
                .all(|item| item.path.starts_with("/content/"))
        );
        assert!(
            !serde_json::to_string(&response)
                .unwrap()
                .contains("/srv/site")
        );
        assert_eq!(remote.opened, ["/srv/site/content"]);
    }

    #[test]
    fn root_has_no_parent_and_missing_metadata_is_not_fabricated() {
        let mut remote = Remote::default();
        remote.entries.push_back((
            "unknown".into(),
            ssh2::FileStat {
                size: None,
                perm: None,
                uid: None,
                gid: None,
                atime: None,
                mtime: None,
            },
        ));
        remote
            .entries
            .push_back(("setgid".into(), stat(Some(0o102750))));
        let response = list_directory(&mut remote, "/srv/site", "/").unwrap();
        assert!(response.is_root);
        assert!(response.parent_path.is_none());
        assert_eq!(response.items[0].permissions.as_deref(), Some("2750"));
        let unknown = &response.items[1];
        assert_eq!(unknown.kind, EntryKind::Other);
        assert!(
            unknown.size.is_none()
                && unknown.permissions.is_none()
                && unknown.modified_at.is_none()
        );
    }

    #[test]
    fn non_directory_missing_type_and_symlink_never_get_opened() {
        for (mode, missing_type, category) in [
            (0o100644, false, "filemanager_not_directory"),
            (0o120777, false, "filemanager_symlink_blocked"),
            (0, true, "filemanager_metadata_invalid"),
        ] {
            let mut remote = Remote {
                target_mode: Some(mode),
                missing_type,
                ..Default::default()
            };
            assert_eq!(
                list_directory(&mut remote, "/srv/site", "/content")
                    .unwrap_err()
                    .category,
                category
            );
            assert!(remote.opened.is_empty());
        }
    }

    #[test]
    fn malformed_or_duplicate_entries_never_form_unsafe_identifiers() {
        for name in [
            "",
            "../escape",
            "/etc",
            "a/b",
            "a\\b",
            "a\nb",
            "a\0b",
            "\u{fffd}",
        ] {
            let mut remote = Remote::default();
            remote
                .entries
                .push_back((name.into(), stat(Some(0o100644))));
            assert_eq!(
                list_directory(&mut remote, "/srv/site", "/")
                    .unwrap_err()
                    .category,
                "filemanager_invalid_directory_response"
            );
        }
        let mut remote = Remote::default();
        remote
            .entries
            .extend(vec![("same".into(), stat(Some(0o100644))); 2]);
        assert!(list_directory(&mut remote, "/srv/site", "/").is_err());
    }

    #[test]
    fn shell_characters_remain_literal_entries_and_no_shell_interface_exists() {
        let mut remote = Remote::default();
        for name in [
            "a;b",
            "&&",
            "|",
            "$(id)",
            "`whoami`",
            "a'b\"c",
            "with space",
            "文件",
        ] {
            remote
                .entries
                .push_back((name.into(), stat(Some(0o100644))));
        }
        let response = list_directory(&mut remote, "/srv/site", "/").unwrap();
        for entry in response.items {
            assert_eq!(entry.path, format!("/{}", entry.name));
        }
        assert_eq!(remote.opened, ["/srv/site"]);
    }

    #[test]
    fn changed_paths_around_open_and_read_discard_results() {
        for on_open in [true, false] {
            let mut remote = Remote {
                change_on_open: on_open,
                change_on_read: !on_open,
                ..Default::default()
            };
            remote
                .entries
                .push_back(("private".into(), stat(Some(0o100644))));
            assert!(list_directory(&mut remote, "/srv/site", "/content").is_err());
            if on_open {
                assert_eq!(remote.reads, 0);
            }
        }
    }

    #[test]
    fn missing_permission_timeout_and_disconnect_failures_propagate_without_partial_success() {
        for (stage, category) in [
            ("lstat", "filemanager_directory_missing"),
            ("open", "filemanager_permission_denied"),
            ("read", "filemanager_timeout"),
            ("read", "filemanager_disconnected"),
        ] {
            let mut remote = Remote {
                fail_stage: stage,
                failure: Some(AppError::unauthorized(category, "Test")),
                ..Default::default()
            };
            assert_eq!(
                list_directory(&mut remote, "/srv/site", "/")
                    .unwrap_err()
                    .category,
                category
            );
        }
    }

    #[test]
    fn large_listings_are_bounded_and_explicitly_marked_truncated() {
        let mut remote = Remote::default();
        for index in 0..MAX_DIRECTORY_ITEMS + 10 {
            remote
                .entries
                .push_back((format!("{index}.php"), stat(Some(0o100644))));
        }
        let response = list_directory(&mut remote, "/srv/site", "/").unwrap();
        assert!(response.truncated);
        assert_eq!(response.items.len(), MAX_DIRECTORY_ITEMS);
        assert_eq!(remote.reads, MAX_DIRECTORY_ITEMS + 1);
        let mut dots = Remote::default();
        dots.entries.extend(vec![
            (".".into(), stat(Some(0o040755)));
            MAX_DIRECTORY_ITEMS + 10
        ]);
        assert!(
            list_directory(&mut dots, "/srv/site", "/")
                .unwrap()
                .truncated
        );
        assert_eq!(dots.reads, MAX_DIRECTORY_ITEMS + 3);
    }
}
