//! Opportunistic recovery of this application's interrupted save files only.
use crate::{
    error::AppError,
    filemanager_directory::{DirectoryListing, DirectoryTransport, EntryKind},
    filemanager_paths::{ResolvedFile, resolve_file},
};
use std::time::{Duration, Instant};

pub const STALE_SAVE_TEMP_AGE: Duration = Duration::from_secs(60 * 60);
pub const CLEANUP_BUDGET: Duration = Duration::from_secs(2);
pub const MAX_CLEANUP_CANDIDATES: usize = 8;

pub fn new_name() -> String {
    format!(".wpmm-save-{}.tmp", uuid::Uuid::new_v4())
}

pub fn is_save_temp(name: &str) -> bool {
    let Some(value) = name
        .strip_prefix(".wpmm-save-")
        .and_then(|v| v.strip_suffix(".tmp"))
    else {
        return false;
    };
    uuid::Uuid::parse_str(value).is_ok_and(|id| {
        id.get_version_num() == 4
            && id.get_variant() == uuid::Variant::RFC4122
            && id.to_string() == value
    })
}

fn stale(now: u64, modified: Option<u64>) -> bool {
    modified
        .and_then(|mtime| now.checked_sub(mtime))
        .is_some_and(|age| age > STALE_SAVE_TEMP_AGE.as_secs())
}

pub trait CleanupTransport: DirectoryTransport {
    /// Bound actual blocking I/O as well as the orchestration loop.
    fn begin_cleanup(&mut self, budget: Duration);
    /// SFTP unlink only; caller supplies a resolved/revalidated regular file.
    fn unlink_save_temp(&mut self, file: &ResolvedFile) -> Result<(), AppError>;
}

/// Used only by the authenticated interactive listing, never archive traversal.
pub fn list_directory(
    remote: &mut impl CleanupTransport,
    root: &str,
    requested: &str,
    now: u64,
    cleanup_allowed: bool,
) -> Result<DirectoryListing, AppError> {
    let mut listing = crate::filemanager_directory::list_directory(remote, root, requested)?;
    if !cleanup_allowed {
        return Ok(listing);
    }
    let mut removed = std::collections::HashSet::new();
    let mut attempted = 0;
    let mut failed = 0;
    let started = Instant::now();
    for item in &listing.items {
        // All cheap filtering uses metadata already fetched by the normal listing.
        if item.kind != EntryKind::File || !is_save_temp(&item.name) {
            continue;
        }
        let modified = item
            .modified_at
            .as_deref()
            .and_then(|s| chrono::DateTime::parse_from_rfc3339(s).ok())
            .and_then(|d| u64::try_from(d.timestamp()).ok());
        if !stale(now, modified) {
            continue;
        }
        if attempted == MAX_CLEANUP_CANDIDATES || started.elapsed() >= CLEANUP_BUDGET {
            break;
        }
        if attempted == 0 {
            remote.begin_cleanup(CLEANUP_BUDGET.saturating_sub(started.elapsed()));
        }
        attempted += 1;
        let result: Result<bool, AppError> = (|| {
            let target = resolve_file(remote, root, &item.path)?;
            // A file updated/replaced since listing is left alone, even if still old.
            if target.stat().mtime != modified
                || target.stat().size != item.size
                || !stale(now, target.stat().mtime)
            {
                return Ok(false);
            }
            let latest = target.revalidate(remote)?;
            if !stale(now, latest.mtime) {
                return Ok(false);
            }
            remote.unlink_save_temp(&target)?;
            Ok(true)
        })();
        match result {
            Ok(true) => {
                removed.insert(item.path.clone());
            }
            Ok(false) => {}
            Err(error) => {
                // Fail closed for authorization/path security; operational cleanup is best-effort.
                if matches!(
                    error.category.as_str(),
                    "locked"
                        | "session_expired"
                        | "invalid_session"
                        | "setup_required"
                        | "filemanager_auth_required"
                        | "filemanager_outside_root"
                        | "filemanager_invalid_path"
                        | "filemanager_invalid_root"
                        | "filemanager_symlink_blocked"
                ) {
                    return Err(error);
                }
                failed += 1;
                if matches!(
                    error.category.as_str(),
                    "filemanager_timeout" | "filemanager_disconnected" | "filemanager_sftp_failed"
                ) {
                    break;
                }
            }
        }
    }
    if attempted > 0 {
        eprintln!(
            "filemanager stale-save cleanup removed={} failed={failed}",
            removed.len()
        );
    }
    // Never hide a file whose unlink failed or was uncertain.
    listing.items.retain(|item| !removed.contains(&item.path));
    Ok(listing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::filemanager_paths::{RemotePaths, ResolvedDirectory};
    use std::collections::{HashMap, VecDeque};

    const NOW: u64 = 10_000;
    const ROOT: &str = "/srv/site-a";
    fn stat(mode: u32, mtime: Option<u64>) -> ssh2::FileStat {
        ssh2::FileStat {
            size: Some(0),
            uid: Some(1000),
            gid: Some(1000),
            perm: Some(mode),
            atime: None,
            mtime,
        }
    }
    #[derive(Default)]
    struct Remote {
        entries: HashMap<String, ssh2::FileStat>,
        unlinked: Vec<String>,
        lookups: Vec<String>,
        fail: Option<&'static str>,
        changed: Option<(String, ssh2::FileStat)>,
        change_on_lookup: usize,
        candidate_lookups: usize,
        cleanup_started: bool,
    }
    impl Remote {
        fn fixture() -> Self {
            let mut r = Self::default();
            for path in ["/srv", ROOT, "/srv/site-b", "/srv/site-a/nested"] {
                r.entries.insert(path.into(), stat(0o040755, Some(0)));
            }
            r
        }
        fn add(&mut self, name: &str, mode: u32, age: u64) -> String {
            let path = format!("{ROOT}/{name}");
            self.entries
                .insert(path.clone(), stat(mode, Some(NOW - age)));
            path
        }
    }
    impl RemotePaths for Remote {
        fn realpath(&mut self, path: &str) -> Result<String, AppError> {
            Ok(path.into())
        }
        fn lstat(&mut self, path: &str) -> Result<ssh2::FileStat, AppError> {
            self.lookups.push(path.into());
            if let Some((changed_path, changed_stat)) = &self.changed
                && path == changed_path
            {
                self.candidate_lookups += 1;
                if self.candidate_lookups == self.change_on_lookup {
                    self.entries.insert(path.into(), changed_stat.clone());
                }
            }
            self.entries
                .get(path)
                .cloned()
                .ok_or_else(|| crate::filemanager_edit::error("directory_missing", "Missing"))
        }
    }
    impl DirectoryTransport for Remote {
        type Handle = VecDeque<(String, ssh2::FileStat)>;
        fn open_directory(&mut self, path: &ResolvedDirectory) -> Result<Self::Handle, AppError> {
            let prefix = format!("{}/", path.absolute());
            Ok(self
                .entries
                .iter()
                .filter_map(|(p, s)| {
                    let name = p.strip_prefix(&prefix)?;
                    if name.is_empty() || name.contains('/') {
                        None
                    } else {
                        Some((name.into(), s.clone()))
                    }
                })
                .collect())
        }
        fn next_entry(
            &mut self,
            handle: &mut Self::Handle,
        ) -> Result<Option<(String, ssh2::FileStat)>, AppError> {
            Ok(handle.pop_front())
        }
    }
    impl CleanupTransport for Remote {
        fn begin_cleanup(&mut self, budget: Duration) {
            assert!(budget <= CLEANUP_BUDGET);
            self.cleanup_started = true;
        }
        fn unlink_save_temp(&mut self, file: &ResolvedFile) -> Result<(), AppError> {
            if let Some(category) = self.fail {
                return Err(AppError::unauthorized(category, "Cleanup failed"));
            }
            assert_eq!(
                self.entries[file.absolute()].perm.unwrap() & 0o170000,
                0o100000
            );
            self.entries.remove(file.absolute());
            self.unlinked.push(file.absolute().into());
            Ok(())
        }
    }

    #[test]
    fn names_match_only_the_exact_generated_uuid_v4_convention() {
        for _ in 0..20 {
            assert!(is_save_temp(&new_name()));
        }
        for name in [
            "plugin.tmp",
            "wordpress.tmp",
            ".cache.tmp",
            ".wpmm-save-test.tmp",
            ".wpmm-save-backup.tmp",
            ".wpmm-save-123.tmp",
            ".wpmm-save-00000000-0000-0000-0000-000000000000.tmp",
            ".wpmm-save-943421f3-a21a-146d-a6c5-016841403a1c.tmp",
            ".wpmm-save-943421f3-a21a-446d-06c5-016841403a1c.tmp",
            ".wpmm-save-943421F3-a21a-446d-a6c5-016841403a1c.tmp",
            ".wpmm-save-943421f3a21a446da6c5016841403a1c.tmp",
            "/.wpmm-save-943421f3-a21a-446d-a6c5-016841403a1c.tmp",
            ".wpmm-save-943421f3-a21a-446d-a6c5-016841403a1c.tmp.extra",
        ] {
            assert!(!is_save_temp(name), "{name}");
        }
    }

    #[test]
    fn listing_removes_only_old_regular_temps_and_keeps_boundaries_and_other_types() {
        let mut remote = Remote::fixture();
        for _ in 0..3 {
            remote.add(&new_name(), 0o100600, 3601);
        }
        let mut kept = vec![];
        for age in [5, 3599, 3600] {
            kept.push(remote.add(&new_name(), 0o100600, age));
        }
        for mode in [0o040755, 0o120777, 0o140600, 0o060600, 0o020600] {
            kept.push(remote.add(&new_name(), mode, 7200));
        }
        for name in [
            "plugin.tmp",
            "wordpress.tmp",
            ".cache.tmp",
            ".wpmm-save-test.tmp",
            ".wpmm-save-123.tmp",
            "atomic-test.txt",
        ] {
            kept.push(remote.add(name, 0o100644, 7200));
        }
        let unknown = remote.add(&new_name(), 0o100600, 0);
        remote.entries.get_mut(&unknown).unwrap().mtime = None;
        kept.push(unknown);
        let future = remote.add(&new_name(), 0o100600, 0);
        remote.entries.get_mut(&future).unwrap().mtime = Some(NOW + 100);
        kept.push(future);
        let outside = format!("/srv/site-b/{}", new_name());
        let nested = format!("{ROOT}/nested/{}", new_name());
        for p in [&outside, &nested] {
            remote.entries.insert(p.clone(), stat(0o100600, Some(0)));
        }
        let result = list_directory(&mut remote, ROOT, "/", NOW, true).unwrap();
        assert_eq!(remote.unlinked.len(), 3);
        for p in kept.iter().chain([&outside, &nested]) {
            assert!(remote.entries.contains_key(p), "{p}");
        }
        for path in &remote.unlinked {
            assert!(
                !result
                    .items
                    .iter()
                    .any(|i| format!("{ROOT}{}", i.path) == *path)
            );
        }
        // Symlinks/special files are filtered using listing metadata: no lstat/follow of their target.
        assert!(!remote.lookups.iter().any(|p| {
            remote
                .entries
                .get(p)
                .is_some_and(|s| s.perm == Some(0o120777))
        }));
    }

    #[test]
    fn ordinary_listing_and_active_save_do_not_trigger_extra_cleanup_io() {
        let mut normal = Remote::fixture();
        normal.add("plugin.tmp", 0o100600, 7200);
        normal.add(&new_name(), 0o100600, 5);
        let mut control = Remote::fixture();
        control.entries = normal.entries.clone();
        crate::filemanager_directory::list_directory(&mut control, ROOT, "/").unwrap();
        list_directory(&mut normal, ROOT, "/", NOW, true).unwrap();
        assert_eq!(normal.lookups, control.lookups);
        assert!(!normal.cleanup_started);
        let old = normal.add(&new_name(), 0o100600, 7200);
        list_directory(&mut normal, ROOT, "/", NOW, false).unwrap();
        assert!(!normal.cleanup_started);
        assert!(normal.entries.contains_key(&old));
    }

    #[test]
    fn traversal_and_symlink_directory_never_reach_cleanup() {
        let mut remote = Remote::fixture();
        let path = remote.add(&new_name(), 0o100600, 7200);
        for requested in [
            "../site-b",
            "../../etc",
            "/../../",
            "../.wpmm-save-943421f3-a21a-446d-a6c5-016841403a1c.tmp",
        ] {
            assert!(list_directory(&mut remote, ROOT, requested, NOW, true).is_err());
        }
        remote.entries.get_mut("/srv/site-a/nested").unwrap().perm = Some(0o120777);
        assert!(list_directory(&mut remote, ROOT, "/nested", NOW, true).is_err());
        // Absolute-looking client input stays virtual; it cannot select site B.
        assert!(list_directory(&mut remote, ROOT, "/srv/site-b", NOW, true).is_err());
        assert!(remote.entries.contains_key(&path));
        assert!(remote.unlinked.is_empty());
    }

    #[test]
    fn changed_metadata_or_recent_replacement_is_not_unlinked() {
        for lookup in [1, 2] {
            for mode in [0o100600, 0o040755, 0o120777] {
                let mut remote = Remote::fixture();
                let path = remote.add(&new_name(), 0o100600, 7200);
                remote.changed = Some((path.clone(), stat(mode, Some(NOW - 5))));
                remote.change_on_lookup = lookup;
                let _ = list_directory(&mut remote, ROOT, "/", NOW, true);
                assert!(remote.unlinked.is_empty());
                assert!(remote.entries.contains_key(&path));
            }
        }
    }

    #[test]
    fn operational_failures_keep_listing_but_security_failures_are_not_swallowed() {
        for category in [
            "filemanager_permission_denied",
            "filemanager_disconnected",
            "filemanager_timeout",
            "filemanager_write_failed",
        ] {
            let mut remote = Remote::fixture();
            let path = remote.add(&new_name(), 0o100600, 7200);
            remote.fail = Some(category);
            let result = list_directory(&mut remote, ROOT, "/", NOW, true).unwrap();
            assert!(
                result
                    .items
                    .iter()
                    .any(|i| format!("{ROOT}{}", i.path) == path)
            );
            assert!(remote.unlinked.is_empty());
        }
        for category in [
            "filemanager_auth_required",
            "filemanager_outside_root",
            "filemanager_symlink_blocked",
        ] {
            let mut remote = Remote::fixture();
            remote.add(&new_name(), 0o100600, 7200);
            remote.fail = Some(category);
            assert_eq!(
                list_directory(&mut remote, ROOT, "/", NOW, true)
                    .unwrap_err()
                    .category,
                category
            );
        }
    }

    #[test]
    fn number_of_candidate_requests_is_bounded() {
        let mut remote = Remote::fixture();
        for _ in 0..MAX_CLEANUP_CANDIDATES + 3 {
            remote.add(&new_name(), 0o100600, 7200);
        }
        list_directory(&mut remote, ROOT, "/", NOW, true).unwrap();
        assert_eq!(remote.unlinked.len(), MAX_CLEANUP_CANDIDATES);
    }
}
