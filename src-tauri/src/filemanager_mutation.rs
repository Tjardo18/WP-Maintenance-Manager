//! Phase 7 mutations: named children only, rooted SFTP operations and no recursion.
use crate::{
    error::AppError,
    filemanager_paths::{
        RemotePaths, ResolvedDirectory, VirtualPath, resolve_directory, validate_name,
    },
};
use serde::{Deserialize, Serialize};

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

pub trait MutationTransport: RemotePaths {
    fn create_file_exclusive(&mut self, path: &str) -> Result<(), AppError>;
    fn create_directory(&mut self, path: &str) -> Result<(), AppError>;
    fn is_directory_empty(&mut self, path: &str) -> Result<bool, AppError>;
    fn unlink(&mut self, path: &str) -> Result<(), AppError>;
    fn remove_directory(&mut self, path: &str) -> Result<(), AppError>;
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
}
