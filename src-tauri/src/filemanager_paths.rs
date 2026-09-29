//! POSIX-only, root-relative paths. Never interpret remote paths with Windows path semantics.
use crate::error::AppError;

pub const MAX_PATH_BYTES: usize = 4096;
const MAX_DEPTH: usize = 128;

pub trait RemotePaths {
    fn realpath(&mut self, path: &str) -> Result<String, AppError>;
    fn lstat(&mut self, path: &str) -> Result<ssh2::FileStat, AppError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtualPath(String);

impl VirtualPath {
    pub fn parse(input: &str) -> Result<Self, AppError> {
        validate_text(input)?;
        let mut parts = Vec::new();
        for part in input.split('/') {
            match part {
                "" | "." => {}
                ".." => {
                    parts.pop().ok_or_else(outside_root)?;
                }
                value => parts.push(value),
            }
            if parts.len() > MAX_DEPTH {
                return Err(invalid_path());
            }
        }
        Ok(Self(format!("/{}", parts.join("/"))))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn parent(&self) -> Option<String> {
        if self.0 == "/" {
            None
        } else {
            Some(
                self.0
                    .rsplit_once('/')
                    .map_or(
                        "/",
                        |(parent, _)| if parent.is_empty() { "/" } else { parent },
                    )
                    .into(),
            )
        }
    }

    pub fn child(&self, name: &str) -> Result<Self, AppError> {
        validate_name(name)?;
        Self::parse(&format!("{}/{name}", self.0.trim_end_matches('/')))
    }
}

// Fields private: only this resolver may construct a trusted directory target.
pub struct ResolvedDirectory {
    root: String,
    absolute: String,
    relative: VirtualPath,
}

impl ResolvedDirectory {
    pub fn absolute(&self) -> &str {
        &self.absolute
    }
    pub fn relative(&self) -> &VirtualPath {
        &self.relative
    }

    pub fn revalidate(&self, remote: &mut impl RemotePaths) -> Result<(), AppError> {
        let again = resolve_directory(remote, &self.root, self.relative.as_str())?;
        if again.absolute != self.absolute {
            return Err(outside_root());
        }
        Ok(())
    }
}

pub fn resolve_directory(
    remote: &mut impl RemotePaths,
    configured_root: &str,
    requested: &str,
) -> Result<ResolvedDirectory, AppError> {
    let relative = VirtualPath::parse(requested)?;
    if !configured_root.starts_with('/') {
        return Err(invalid_root());
    }
    let root = VirtualPath::parse(configured_root)
        .map_err(|_| invalid_root())?
        .0;
    if root == "/" {
        return Err(invalid_root());
    }
    // Reject symlinks in every component, including ancestors of the configured root.
    verify_directory_chain(remote, &root)?;
    let canonical_root = canonical(remote.realpath(&root)?)?;
    if canonical_root != root {
        return Err(symlink_denied());
    }
    let target = format!(
        "{}{}",
        root,
        if relative.0 == "/" { "" } else { &relative.0 }
    );
    if target.len() > MAX_PATH_BYTES {
        return Err(invalid_path());
    }
    verify_directory_chain(remote, &target)?;
    let absolute = canonical(remote.realpath(&target)?)?;
    ensure_contained(&canonical_root, &absolute)?;
    if absolute != target {
        return Err(symlink_denied());
    }
    Ok(ResolvedDirectory {
        root,
        absolute,
        relative,
    })
}

fn verify_directory_chain(remote: &mut impl RemotePaths, path: &str) -> Result<(), AppError> {
    let mut current = String::new();
    for component in path.split('/').filter(|part| !part.is_empty()) {
        current.push('/');
        current.push_str(component);
        let stat = remote.lstat(&current)?;
        match stat.perm.map(|mode| mode & 0o170000) {
            Some(0o040000) => {}
            Some(0o120000) => return Err(symlink_denied()),
            Some(_) => {
                return Err(AppError::unauthorized(
                    "filemanager_not_directory",
                    "Het aangevraagde pad is geen map.",
                ));
            }
            None => {
                return Err(AppError::unauthorized(
                    "filemanager_metadata_invalid",
                    "Het maptype kon niet betrouwbaar worden vastgesteld.",
                ));
            }
        }
    }
    Ok(())
}

pub fn ensure_contained(root: &str, target: &str) -> Result<(), AppError> {
    if target == root
        || target
            .strip_prefix(root)
            .is_some_and(|tail| tail.starts_with('/'))
    {
        Ok(())
    } else {
        Err(outside_root())
    }
}

fn canonical(path: String) -> Result<String, AppError> {
    if !path.starts_with('/') || VirtualPath::parse(&path)?.as_str() != path {
        return Err(invalid_path());
    }
    Ok(path)
}

fn validate_text(value: &str) -> Result<(), AppError> {
    if value.len() > MAX_PATH_BYTES
        || value
            .chars()
            .any(|c| c.is_control() || c == '\\' || c == '\u{fffd}')
    {
        return Err(invalid_path());
    }
    Ok(())
}

pub fn validate_name(name: &str) -> Result<(), AppError> {
    validate_text(name)?;
    if name.is_empty() || matches!(name, "." | "..") || name.contains('/') {
        return Err(invalid_path());
    }
    Ok(())
}

pub fn invalid_path() -> AppError {
    AppError::unauthorized(
        "filemanager_invalid_path",
        "Het bestandspad is ongeldig of wordt niet ondersteund.",
    )
}
fn invalid_root() -> AppError {
    AppError::unauthorized(
        "filemanager_invalid_root",
        "Stel een geldige absolute WordPress-root in; de serverroot is niet toegestaan.",
    )
}
fn outside_root() -> AppError {
    AppError::unauthorized(
        "filemanager_outside_root",
        "Het pad valt buiten de toegestane website-root.",
    )
}
fn symlink_denied() -> AppError {
    AppError::unauthorized(
        "filemanager_symlink_blocked",
        "Symlinks in het mappad worden uit veiligheid niet gevolgd, ook niet in het pad naar de website-root.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    #[derive(Default)]
    struct Remote {
        modes: HashMap<String, u32>,
        aliases: HashMap<String, String>,
        seen: Vec<String>,
    }
    impl RemotePaths for Remote {
        fn realpath(&mut self, path: &str) -> Result<String, AppError> {
            Ok(self.aliases.get(path).cloned().unwrap_or(path.into()))
        }
        fn lstat(&mut self, path: &str) -> Result<ssh2::FileStat, AppError> {
            self.seen.push(path.into());
            Ok(ssh2::FileStat {
                perm: Some(*self.modes.get(path).unwrap_or(&0o040755)),
                size: None,
                uid: None,
                gid: None,
                atime: None,
                mtime: None,
            })
        }
    }

    #[test]
    fn normalizes_virtual_paths_and_never_returns_parent_above_root() {
        for (input, expected) in [
            ("", "/"),
            ("/", "/"),
            ("/wp-content", "/wp-content"),
            (
                "wp-content/plugins/my-plugin",
                "/wp-content/plugins/my-plugin",
            ),
            ("/wp-content/./plugins", "/wp-content/plugins"),
            ("/wp-content/plugins/../themes", "/wp-content/themes"),
            ("//wp-content///plugins", "/wp-content/plugins"),
        ] {
            let path = VirtualPath::parse(input).unwrap();
            assert_eq!(path.as_str(), expected);
            let result =
                resolve_directory(&mut Remote::default(), "/server/public_html/", input).unwrap();
            assert_eq!(result.relative().as_str(), expected);
            assert!(result.absolute().starts_with("/server/public_html"));
        }
        assert_eq!(VirtualPath::parse("/").unwrap().parent(), None);
        assert_eq!(
            VirtualPath::parse("/wp-content")
                .unwrap()
                .parent()
                .as_deref(),
            Some("/")
        );
        assert_eq!(
            VirtualPath::parse("/wp-content/plugins")
                .unwrap()
                .parent()
                .as_deref(),
            Some("/wp-content")
        );
    }

    #[test]
    fn traversal_and_malformed_paths_are_rejected_before_remote_calls() {
        for path in [
            "..",
            "../",
            "../../",
            "../../../etc/passwd",
            "/wp-content/../../../etc",
            "wp-content/plugins/../../../../",
            "x\0y",
            "x\ny",
            "..\\etc",
            "C:\\Windows",
            "x\ry",
        ] {
            let mut remote = Remote::default();
            assert!(
                resolve_directory(&mut remote, "/server/root", path).is_err(),
                "{path:?}"
            );
            assert!(remote.seen.is_empty());
        }
        assert!(VirtualPath::parse(&"a".repeat(4097)).is_err());
        assert!(VirtualPath::parse(&"a/".repeat(129)).is_err());
    }

    #[test]
    fn virtual_absolute_paths_and_encoded_text_cannot_override_server_root() {
        let mut remote = Remote::default();
        for path in [
            "/etc/passwd",
            "/server/public_html_backup",
            "/%2e%2e/%2fetc",
            "/%252e%252e",
        ] {
            let result = resolve_directory(&mut remote, "/server/public_html", path).unwrap();
            assert_eq!(result.absolute(), format!("/server/public_html{path}"));
        }
        assert!(ensure_contained("/server/public_html", "/server/public_html_backup").is_err());
        assert!(ensure_contained("/server/public_html", "/server/public_html/a").is_ok());
    }

    #[test]
    fn symlinks_including_ancestors_are_blocked_and_canonical_escape_is_rejected() {
        for link in [
            "/server",
            "/server/root",
            "/server/root/uploads",
            "/server/root/uploads/shared",
        ] {
            let mut remote = Remote::default();
            remote.modes.insert(link.into(), 0o120777);
            assert!(resolve_directory(&mut remote, "/server/root", "/uploads/shared").is_err());
        }
        for target in [
            "/etc",
            "/server/root_backup",
            "/server/root/other",
            "relative",
            "/server/root/../etc",
        ] {
            let mut remote = Remote::default();
            remote
                .aliases
                .insert("/server/root/link".into(), target.into());
            assert!(resolve_directory(&mut remote, "/server/root", "/link").is_err());
        }
    }

    #[test]
    fn shell_metacharacters_are_literal_posix_names_and_changes_fail_revalidation() {
        let mut remote = Remote::default();
        for name in [
            "my plugin",
            ".htaccess",
            "één_文件",
            "a;b",
            "a&&b",
            "a|b",
            "$(id)",
            "`id`",
            "a'b\"c",
            "(test)",
        ] {
            let path = VirtualPath::parse("/").unwrap().child(name).unwrap();
            let result = resolve_directory(&mut remote, "/server/root", path.as_str()).unwrap();
            assert_eq!(result.absolute(), format!("/server/root/{name}"));
        }
        let result = resolve_directory(&mut remote, "/server/root", "/folder").unwrap();
        remote.modes.insert("/server/root/folder".into(), 0o120777);
        assert!(result.revalidate(&mut remote).is_err());
        assert!(resolve_directory(&mut remote, "/", "/").is_err());
        assert!(resolve_directory(&mut remote, "relative", "/").is_err());
    }
}
