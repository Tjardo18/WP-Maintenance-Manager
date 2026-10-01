//! Phase 7 mutations: named children only, rooted SFTP operations and no recursion.
use crate::{
    error::AppError,
    filemanager_paths::{
        MAX_PATH_BYTES, RemotePaths, ResolvedDirectory, VirtualPath, invalid_path,
        resolve_directory, validate_name,
    },
};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

pub const MAX_BULK_ITEMS: usize = 100;

#[derive(Debug, Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ItemKind {
    File,
    Directory,
    Symlink,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CreateInput {
    pub directory: String,
    pub name: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeleteInput {
    pub path: String,
    pub expected_kind: ItemKind,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MutationResult {
    pub path: String,
    pub name: String,
    pub kind: ItemKind,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PermissionInput {
    pub path: String,
    pub expected_kind: ItemKind,
    pub mode: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BulkInput {
    pub directory: String,
    pub items: Vec<DeleteInput>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct BulkPermissionInput {
    pub directory: String,
    pub items: Vec<DeleteInput>,
    pub mode: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkFailure {
    pub path: String,
    pub reason: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkResult {
    pub requested: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub failures: Vec<BulkFailure>,
}

pub trait MutationTransport: RemotePaths {
    fn create_file_exclusive(&mut self, path: &str) -> Result<(), AppError>;
    fn create_directory(&mut self, path: &str) -> Result<(), AppError>;
    fn is_directory_empty(&mut self, path: &str) -> Result<bool, AppError>;
    fn unlink(&mut self, path: &str) -> Result<(), AppError>;
    fn remove_directory(&mut self, path: &str) -> Result<(), AppError>;
    fn set_permissions(&mut self, path: &str, mode: u32) -> Result<(), AppError>;
}

pub fn parse_mode(value: &str) -> Result<u32, AppError> {
    if value.len() != 3 || !value.bytes().all(|byte| (b'0'..=b'7').contains(&byte)) {
        return Err(failure(
            "filemanager_invalid_permissions",
            "Gebruik precies drie octale cijfers (000–777).",
        ));
    }
    u32::from_str_radix(value, 8).map_err(|_| {
        failure(
            "filemanager_invalid_permissions",
            "De permissions zijn ongeldig.",
        )
    })
}

fn validate_target(path: &str, directory: &str) -> Result<(), AppError> {
    let target = VirtualPath::parse(path)?;
    let parent = target.parent().ok_or_else(root_delete)?;
    if parent != directory || target.as_str() != path {
        return Err(failure(
            "filemanager_bulk_scope",
            "Alle items moeten direct in de huidige map staan.",
        ));
    }
    Ok(())
}

pub fn validate_bulk(input: &BulkInput) -> Result<(), AppError> {
    if input.items.is_empty() || input.items.len() > MAX_BULK_ITEMS {
        return Err(failure(
            "filemanager_bulk_limit",
            "Selecteer 1 tot 100 items per actie.",
        ));
    }
    let directory = VirtualPath::parse(&input.directory)?;
    if directory.as_str() != input.directory {
        return Err(failure(
            "filemanager_invalid_path",
            "Het mappad is ongeldig.",
        ));
    }
    let mut seen = HashSet::new();
    for item in &input.items {
        validate_target(&item.path, directory.as_str())?;
        if !seen.insert(&item.path) {
            return Err(failure(
                "filemanager_bulk_duplicate",
                "De selectie bevat dubbele items.",
            ));
        }
    }
    Ok(())
}

fn actual_kind(mode: Option<u32>) -> Result<ItemKind, AppError> {
    match mode.map(|value| value & 0o170000) {
        Some(0o100000) => Ok(ItemKind::File),
        Some(0o040000) => Ok(ItemKind::Directory),
        Some(0o120000) => Ok(ItemKind::Symlink),
        _ => Err(failure(
            "filemanager_unsupported_item",
            "Dit serverobject wordt niet ondersteund.",
        )),
    }
}

pub fn change_permissions(
    remote: &mut impl MutationTransport,
    root: &str,
    input: &PermissionInput,
) -> Result<(), AppError> {
    let mode = parse_mode(&input.mode)?;
    let path = VirtualPath::parse(&input.path)?;
    let directory = path.parent().ok_or_else(root_delete)?;
    validate_target(&input.path, &directory)?;
    if input.expected_kind == ItemKind::Symlink {
        return Err(failure(
            "filemanager_symlink_blocked",
            "Permissions van symlinks kunnen niet veilig worden gewijzigd.",
        ));
    }
    let name = path.as_str().rsplit('/').next().unwrap_or_default();
    let (parent, absolute, _) = child(remote, root, &directory, name)?;
    parent.revalidate(remote)?;
    let stat = remote.lstat(&absolute).map_err(map_missing)?;
    if actual_kind(stat.perm)? != input.expected_kind {
        return Err(changed());
    }
    parent.revalidate(remote)?;
    if actual_kind(remote.lstat(&absolute).map_err(map_missing)?.perm)? != input.expected_kind {
        return Err(changed());
    }
    remote.set_permissions(&absolute, mode)
}

fn bulk_apply(
    remote: &mut impl MutationTransport,
    root: &str,
    input: &BulkInput,
    mode: Option<&str>,
) -> Result<BulkResult, AppError> {
    validate_bulk(input)?;
    if let Some(mode) = mode {
        parse_mode(mode)?;
    }
    // Every target is a validated direct child of this one resolved directory.
    let parent = resolve_directory(remote, root, &input.directory)?;
    parent.revalidate(remote)?;
    for item in &input.items {
        let path = VirtualPath::parse(&item.path)?;
        let name = path.as_str().rsplit('/').next().unwrap_or_default();
        validate_name(name)?;
        let absolute = format!("{}/{}", parent.absolute().trim_end_matches('/'), name);
        if absolute.len() > MAX_PATH_BYTES {
            return Err(invalid_path());
        }
        if mode.is_some() && item.expected_kind == ItemKind::Symlink {
            return Err(failure(
                "filemanager_symlink_blocked",
                "Symlinks kunnen niet in een permissionactie worden opgenomen.",
            ));
        }
        if mode.is_some() {
            match remote.lstat(&absolute) {
                Ok(stat) if matches!(actual_kind(stat.perm), Ok(ItemKind::Symlink)) => {
                    return Err(failure(
                        "filemanager_symlink_blocked",
                        "Permissions van symlinks kunnen niet veilig worden gewijzigd.",
                    ));
                }
                Err(error)
                    if error.category != "filemanager_directory_missing"
                        && error.category != "filemanager_item_missing" =>
                {
                    return Err(error);
                }
                _ => {}
            }
        }
    }
    let mut result = BulkResult {
        requested: input.items.len(),
        succeeded: 0,
        failed: 0,
        failures: Vec::new(),
    };
    for item in &input.items {
        let outcome = if let Some(mode) = mode {
            change_permissions(
                remote,
                root,
                &PermissionInput {
                    path: item.path.clone(),
                    expected_kind: item.expected_kind,
                    mode: mode.into(),
                },
            )
        } else {
            delete_item(remote, root, item).map(|_| ())
        };
        match outcome {
            Ok(()) => result.succeeded += 1,
            Err(error) => {
                result.failed += 1;
                result.failures.push(BulkFailure {
                    path: item.path.clone(),
                    reason: error.user_message,
                });
            }
        }
    }
    Ok(result)
}

pub fn change_permissions_bulk(
    remote: &mut impl MutationTransport,
    root: &str,
    input: &BulkPermissionInput,
) -> Result<BulkResult, AppError> {
    bulk_apply(
        remote,
        root,
        &BulkInput {
            directory: input.directory.clone(),
            items: input.items.clone(),
        },
        Some(&input.mode),
    )
}

pub fn delete_bulk(
    remote: &mut impl MutationTransport,
    root: &str,
    input: &BulkInput,
) -> Result<BulkResult, AppError> {
    bulk_apply(remote, root, input, None)
}

fn failure(category: &str, message: &str) -> AppError {
    AppError::unauthorized(category, message)
}
fn exists() -> AppError {
    failure(
        "filemanager_item_exists",
        "Er bestaat al een bestand of map met deze naam.",
    )
}
fn root_delete() -> AppError {
    failure(
        "filemanager_root_delete_blocked",
        "De hoofdmap van de filemanager kan niet worden verwijderd.",
    )
}
fn changed() -> AppError {
    failure(
        "filemanager_item_changed",
        "Het item is gewijzigd sinds de lijst werd geladen. Vernieuw de map en probeer opnieuw.",
    )
}
pub fn error_not_empty() -> AppError {
    failure(
        "filemanager_directory_not_empty",
        "Deze map is niet leeg en kan daarom niet worden verwijderd.",
    )
}

fn child(
    remote: &mut impl RemotePaths,
    root: &str,
    directory: &str,
    name: &str,
) -> Result<(ResolvedDirectory, String, VirtualPath), AppError> {
    validate_name(name)?;
    let parent = resolve_directory(remote, root, directory)?;
    let relative = parent.relative().child(name)?;
    let absolute = format!("{}/{}", parent.absolute().trim_end_matches('/'), name);
    if absolute.len() > MAX_PATH_BYTES {
        return Err(invalid_path());
    }
    Ok((parent, absolute, relative))
}

pub fn create_file(
    remote: &mut impl MutationTransport,
    root: &str,
    input: &CreateInput,
) -> Result<MutationResult, AppError> {
    let (parent, absolute, relative) = child(remote, root, &input.directory, &input.name)?;
    parent.revalidate(remote)?;
    remote.create_file_exclusive(&absolute)?;
    parent.revalidate(remote)?;
    Ok(MutationResult {
        path: relative.as_str().into(),
        name: input.name.clone(),
        kind: ItemKind::File,
    })
}

pub fn create_directory(
    remote: &mut impl MutationTransport,
    root: &str,
    input: &CreateInput,
) -> Result<MutationResult, AppError> {
    let (parent, absolute, relative) = child(remote, root, &input.directory, &input.name)?;
    parent.revalidate(remote)?;
    remote.create_directory(&absolute)?;
    parent.revalidate(remote)?;
    Ok(MutationResult {
        path: relative.as_str().into(),
        name: input.name.clone(),
        kind: ItemKind::Directory,
    })
}

pub fn delete_item(
    remote: &mut impl MutationTransport,
    root: &str,
    input: &DeleteInput,
) -> Result<MutationResult, AppError> {
    let path = VirtualPath::parse(&input.path)?;
    if path.as_str() == "/" {
        return Err(root_delete());
    }
    let (directory, name) = path
        .as_str()
        .rsplit_once('/')
        .ok_or_else(|| failure("filemanager_invalid_path", "Het bestandspad is ongeldig."))?;
    let directory = if directory.is_empty() { "/" } else { directory };
    let (parent, absolute, relative) = child(remote, root, directory, name)?;
    parent.revalidate(remote)?;
    let stat = remote.lstat(&absolute).map_err(map_missing)?;
    let actual = match stat.perm.map(|mode| mode & 0o170000) {
        Some(0o100000) => ItemKind::File,
        Some(0o040000) => ItemKind::Directory,
        Some(0o120000) => ItemKind::Symlink,
        _ => {
            return Err(failure(
                "filemanager_unsupported_item",
                "Dit serverobject kan niet via de filemanager worden verwijderd.",
            ));
        }
    };
    if actual != input.expected_kind {
        return Err(changed());
    }
    parent.revalidate(remote)?;
    match actual {
        ItemKind::File | ItemKind::Symlink => remote.unlink(&absolute)?,
        ItemKind::Directory => {
            if !remote.is_directory_empty(&absolute)? {
                return Err(failure(
                    "filemanager_directory_not_empty",
                    "Deze map is niet leeg en kan daarom niet worden verwijderd.",
                ));
            }
            parent.revalidate(remote)?;
            remote.remove_directory(&absolute)?;
        }
    }
    Ok(MutationResult {
        path: relative.as_str().into(),
        name: name.into(),
        kind: actual,
    })
}

pub fn map_create_error(error: ssh2::Error) -> AppError {
    match error.code() {
        ssh2::ErrorCode::SFTP(11) => exists(),
        ssh2::ErrorCode::SFTP(3) => failure(
            "filemanager_permission_denied",
            "De SSH-gebruiker heeft onvoldoende rechten om dit item aan te maken.",
        ),
        ssh2::ErrorCode::SFTP(14 | 15) => failure(
            "filemanager_write_failed",
            "Aanmaken is mislukt door onvoldoende vrije schijfruimte of quota.",
        ),
        _ => {
            let mut result = failure(
                "filemanager_mutation_failed",
                "De bestandssysteemactie is mislukt.",
            );
            result.technical_details = Some(format!("SFTP status: {:?}", error.code()));
            result
        }
    }
}
pub fn map_missing(error: AppError) -> AppError {
    if error.category == "filemanager_directory_missing" {
        failure(
            "filemanager_item_missing",
            "Het bestand of de map bestaat niet meer.",
        )
    } else {
        error
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::{HashMap, HashSet};
    #[derive(Default)]
    struct Remote {
        nodes: HashMap<String, u32>,
        children: HashSet<String>,
    }
    fn stat(mode: u32) -> ssh2::FileStat {
        ssh2::FileStat {
            size: Some(0),
            perm: Some(mode),
            uid: Some(1),
            gid: Some(1),
            atime: None,
            mtime: Some(1),
        }
    }
    impl RemotePaths for Remote {
        fn realpath(&mut self, p: &str) -> Result<String, AppError> {
            Ok(p.into())
        }
        fn lstat(&mut self, p: &str) -> Result<ssh2::FileStat, AppError> {
            self.nodes
                .get(p)
                .copied()
                .map(stat)
                .ok_or_else(|| failure("filemanager_directory_missing", "missing"))
        }
    }
    impl MutationTransport for Remote {
        fn set_permissions(&mut self, p: &str, mode: u32) -> Result<(), AppError> {
            let entry = self
                .nodes
                .get_mut(p)
                .ok_or_else(|| failure("filemanager_item_missing", "missing"))?;
            *entry = (*entry & 0o170000) | mode;
            Ok(())
        }
        fn create_file_exclusive(&mut self, p: &str) -> Result<(), AppError> {
            if self.nodes.contains_key(p) {
                Err(exists())
            } else {
                self.nodes.insert(p.into(), 0o100644);
                Ok(())
            }
        }
        fn create_directory(&mut self, p: &str) -> Result<(), AppError> {
            if self.nodes.contains_key(p) {
                Err(exists())
            } else {
                self.nodes.insert(p.into(), 0o040755);
                Ok(())
            }
        }
        fn is_directory_empty(&mut self, p: &str) -> Result<bool, AppError> {
            Ok(!self.children.contains(p))
        }
        fn unlink(&mut self, p: &str) -> Result<(), AppError> {
            self.nodes
                .remove(p)
                .map(|_| ())
                .ok_or_else(|| failure("filemanager_item_missing", "missing"))
        }
        fn remove_directory(&mut self, p: &str) -> Result<(), AppError> {
            if self.children.contains(p) {
                Err(failure("filemanager_directory_not_empty", "full"))
            } else {
                self.unlink(p)
            }
        }
    }
    fn remote() -> Remote {
        let mut r = Remote::default();
        for p in [
            "/srv",
            "/srv/site",
            "/srv/site/root",
            "/srv/site/root/current",
        ] {
            r.nodes.insert(p.into(), 0o040755);
        }
        r
    }
    #[test]
    fn creates_named_children_exclusively_and_blocks_traversal() {
        let mut r = remote();
        let file = CreateInput {
            directory: "/current".into(),
            name: "test $; 中文.php".into(),
        };
        assert_eq!(
            create_file(&mut r, "/srv/site/root", &file).unwrap().path,
            "/current/test $; 中文.php"
        );
        assert!(create_file(&mut r, "/srv/site/root", &file).is_err());
        assert_eq!(
            create_directory(
                &mut r,
                "/srv/site/root",
                &CreateInput {
                    directory: "/current".into(),
                    name: ".hidden".into()
                }
            )
            .unwrap()
            .kind,
            ItemKind::Directory
        );
        for name in ["", ".", "..", "../x", "a/b", "/x", "a\\b", "a\n"] {
            assert!(
                create_file(
                    &mut r,
                    "/srv/site/root",
                    &CreateInput {
                        directory: "/current".into(),
                        name: name.into()
                    }
                )
                .is_err()
            );
        }
    }
    #[test]
    fn deletes_only_expected_leaf_and_never_recursive_root_or_target() {
        let mut r = remote();
        r.nodes
            .insert("/srv/site/root/current/a.php".into(), 0o100644);
        r.nodes
            .insert("/srv/site/root/current/link".into(), 0o120777);
        r.nodes
            .insert("/srv/site/root/current/empty".into(), 0o040755);
        r.nodes
            .insert("/srv/site/root/current/full".into(), 0o040755);
        r.children.insert("/srv/site/root/current/full".into());
        for (path, kind) in [
            ("/current/a.php", ItemKind::File),
            ("/current/link", ItemKind::Symlink),
            ("/current/empty", ItemKind::Directory),
        ] {
            delete_item(
                &mut r,
                "/srv/site/root",
                &DeleteInput {
                    path: path.into(),
                    expected_kind: kind,
                },
            )
            .unwrap();
        }
        assert_eq!(
            delete_item(
                &mut r,
                "/srv/site/root",
                &DeleteInput {
                    path: "/current/full".into(),
                    expected_kind: ItemKind::Directory
                }
            )
            .unwrap_err()
            .category,
            "filemanager_directory_not_empty"
        );
        assert!(
            delete_item(
                &mut r,
                "/srv/site/root",
                &DeleteInput {
                    path: "/".into(),
                    expected_kind: ItemKind::Directory
                }
            )
            .is_err()
        );
        assert!(
            delete_item(
                &mut r,
                "/srv/site/root",
                &DeleteInput {
                    path: "/../../x".into(),
                    expected_kind: ItemKind::File
                }
            )
            .is_err()
        );
    }

    #[test]
    fn permissions_are_strict_octal_and_symlinks_are_rejected() {
        for invalid in ["888", "99", "abc", "7x5", "-644", "6444"] {
            assert!(parse_mode(invalid).is_err());
        }
        assert_eq!(parse_mode("644").unwrap(), 0o644);
        assert_eq!(parse_mode("000").unwrap(), 0);
        let mut r = remote();
        r.nodes
            .insert("/srv/site/root/current/index.php".into(), 0o100644);
        r.nodes
            .insert("/srv/site/root/current/uploads".into(), 0o040755);
        r.nodes
            .insert("/srv/site/root/current/link".into(), 0o120777);
        for (path, kind, mode, expected) in [
            ("/current/index.php", ItemKind::File, "600", 0o100600),
            ("/current/uploads", ItemKind::Directory, "750", 0o040750),
        ] {
            change_permissions(
                &mut r,
                "/srv/site/root",
                &PermissionInput {
                    path: path.into(),
                    expected_kind: kind,
                    mode: mode.into(),
                },
            )
            .unwrap();
            assert_eq!(r.nodes[&format!("/srv/site/root{path}")], expected);
        }
        for path in ["/", "../../../etc/passwd", "/current/link"] {
            assert!(
                change_permissions(
                    &mut r,
                    "/srv/site/root",
                    &PermissionInput {
                        path: path.into(),
                        expected_kind: ItemKind::Symlink,
                        mode: "644".into()
                    }
                )
                .is_err()
            );
        }
        assert_eq!(r.nodes["/srv/site/root/current/link"], 0o120777);
    }

    #[test]
    fn bulk_rejects_unsafe_payload_before_mutating_and_reports_partial_failures() {
        let mut r = remote();
        r.nodes
            .insert("/srv/site/root/current/a.php".into(), 0o100644);
        r.nodes
            .insert("/srv/site/root/current/b.php".into(), 0o100644);
        let invalid = BulkInput {
            directory: "/current".into(),
            items: vec![
                DeleteInput {
                    path: "/current/a.php".into(),
                    expected_kind: ItemKind::File,
                },
                DeleteInput {
                    path: "../../../etc/passwd".into(),
                    expected_kind: ItemKind::File,
                },
            ],
        };
        assert!(delete_bulk(&mut r, "/srv/site/root", &invalid).is_err());
        assert!(r.nodes.contains_key("/srv/site/root/current/a.php"));
        assert!(
            validate_bulk(&BulkInput {
                directory: "/current".into(),
                items: vec![invalid.items[0].clone(); MAX_BULK_ITEMS + 1]
            })
            .is_err()
        );
        let input = BulkInput {
            directory: "/current".into(),
            items: vec![
                DeleteInput {
                    path: "/current/a.php".into(),
                    expected_kind: ItemKind::File,
                },
                DeleteInput {
                    path: "/current/missing.php".into(),
                    expected_kind: ItemKind::File,
                },
            ],
        };
        let result = delete_bulk(&mut r, "/srv/site/root", &input).unwrap();
        assert_eq!(
            (result.requested, result.succeeded, result.failed),
            (2, 1, 1)
        );
        assert!(!r.nodes.contains_key("/srv/site/root/current/a.php"));
        let chmod = BulkPermissionInput {
            directory: "/current".into(),
            items: vec![
                DeleteInput {
                    path: "/current/b.php".into(),
                    expected_kind: ItemKind::File,
                },
                DeleteInput {
                    path: "/current/missing.php".into(),
                    expected_kind: ItemKind::File,
                },
            ],
            mode: "755".into(),
        };
        let result = change_permissions_bulk(&mut r, "/srv/site/root", &chmod).unwrap();
        assert_eq!((result.succeeded, result.failed), (1, 1));
        assert_eq!(r.nodes["/srv/site/root/current/b.php"], 0o100755);

        r.nodes
            .insert("/srv/site/root/current/link".into(), 0o120777);
        let forged = BulkPermissionInput {
            directory: "/current".into(),
            items: vec![
                DeleteInput {
                    path: "/current/b.php".into(),
                    expected_kind: ItemKind::File,
                },
                DeleteInput {
                    path: "/current/link".into(),
                    expected_kind: ItemKind::File,
                },
            ],
            mode: "600".into(),
        };
        assert!(change_permissions_bulk(&mut r, "/srv/site/root", &forged).is_err());
        assert_eq!(r.nodes["/srv/site/root/current/b.php"], 0o100755);
    }

    #[test]
    fn bulk_delete_keeps_non_empty_directory_and_symlink_target_intact() {
        let mut r = remote();
        r.nodes
            .insert("/srv/site/root/current/old.php".into(), 0o100644);
        r.nodes
            .insert("/srv/site/root/current/full".into(), 0o040755);
        r.nodes
            .insert("/srv/site/root/current/link".into(), 0o120777);
        r.children.insert("/srv/site/root/current/full".into());
        let result = delete_bulk(
            &mut r,
            "/srv/site/root",
            &BulkInput {
                directory: "/current".into(),
                items: vec![
                    DeleteInput {
                        path: "/current/old.php".into(),
                        expected_kind: ItemKind::File,
                    },
                    DeleteInput {
                        path: "/current/full".into(),
                        expected_kind: ItemKind::Directory,
                    },
                    DeleteInput {
                        path: "/current/link".into(),
                        expected_kind: ItemKind::Symlink,
                    },
                ],
            },
        )
        .unwrap();
        assert_eq!((result.succeeded, result.failed), (2, 1));
        assert!(r.nodes.contains_key("/srv/site/root/current/full"));
        assert!(!r.nodes.contains_key("/srv/site/root/current/link"));
    }
}
