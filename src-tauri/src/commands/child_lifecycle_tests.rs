//! Isolated lifecycle tests: a local directory tree stands in for the remote
//! WordPress roots, while all site records use the real SQLite database.

use super::*;
use crate::{
    auth::AuthManager,
    credentials::CredentialVault,
    database::Database,
    models::{AuthMethod, SiteRelationType},
    ssh::{ExecOutput, SshExecutor},
};
use std::path::{Path, PathBuf};
use uuid::Uuid;

const FINGERPRINT: &str = "SHA256:abcdefghijklmnopqrstuv";

struct LocalServer {
    root: PathBuf,
}

impl LocalServer {
    fn path(&self, virtual_path: &str) -> PathBuf {
        let relative = virtual_path
            .strip_prefix("/srv/site")
            .expect("test sites stay below their isolated WordPress root")
            .trim_start_matches('/');
        self.root.join(relative)
    }
}

impl SshExecutor for LocalServer {
    fn fingerprint(&self, _: &Site) -> Result<String, AppError> {
        Ok(FINGERPRINT.into())
    }

    fn authenticate(&self, _: &Site, _: Option<&str>) -> Result<(), AppError> {
        Ok(())
    }

    fn execute(
        &self,
        site: &Site,
        _: Option<&str>,
        command: &RemoteCommand,
    ) -> Result<ExecOutput, AppError> {
        assert!(
            !command.mutating,
            "the lifecycle must not change remote files"
        );
        let path = self.path(&site.wordpress_path);
        let stdout = match command.action_name {
            "TestWordPressPath" => {
                assert!(path.is_dir());
                Vec::new()
            }
            "DetectWordPress" | "CheckDatabase" => {
                assert!(path.join("wp-config.php").is_file());
                Vec::new()
            }
            "GetWpCliVersion" => b"WP-CLI 2.12.0\n".to_vec(),
            "GetWordPressVersion" => b"6.8.2\n".to_vec(),
            "GetPhpVersion" => b"8.3.12\n".to_vec(),
            "GetSiteUrl" => site.url.as_bytes().to_vec(),
            "ListUnexpectedRootDirectories" => {
                let mut directories = fs::read_dir(path)
                    .unwrap()
                    .map(|entry| entry.unwrap())
                    .filter(|entry| entry.file_type().unwrap().is_dir())
                    .map(|entry| entry.file_name().to_string_lossy().into_owned())
                    .filter(|name| {
                        !matches!(name.as_str(), "wp-admin" | "wp-content" | "wp-includes")
                    })
                    .collect::<Vec<_>>();
                directories.sort();
                serde_json::json!({ "directories": directories, "truncated": false })
                    .to_string()
                    .into_bytes()
            }
            action => panic!("unexpected remote action in child lifecycle: {action}"),
        };
        Ok(ExecOutput {
            stdout,
            stderr: Vec::new(),
            exit_code: 0,
            truncated: false,
        })
    }

    fn download(&self, _: &Site, _: Option<&str>, _: &str, _: &Path) -> Result<u64, AppError> {
        panic!("the lifecycle must not download or modify remote files")
    }
}

struct Fixture {
    temp: PathBuf,
    state: AppState,
}

impl Fixture {
    fn new() -> Self {
        let temp = std::env::temp_dir().join(format!("wpmm-child-lifecycle-{}", Uuid::new_v4()));
        let root = temp.join("remote-wordpress-root");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("wp-config.php"), b"<?php // parent").unwrap();
        let database = Database::initialize(temp.join("app.sqlite3")).unwrap();
        let state = AppState {
            database,
            credentials: CredentialVault,
            ssh: Arc::new(LocalServer { root }),
            backup_directory: temp.join("backups"),
            vulnerability_cache_directory: temp.join("vulnerability-cache"),
            scan_concurrency: std::sync::atomic::AtomicUsize::new(1),
            auth: AuthManager::default(),
            terminals: crate::terminal::TerminalManager::default(),
            terminal_access: crate::terminal_auth::TerminalAccessManager::default(),
            scan_jobs: crate::scan_jobs::ScanJobManager::new(2),
            vulnerability_jobs: crate::vulnerability_jobs::VulnerabilityRefreshManager::default(),
        };
        Self { temp, state }
    }

    fn add_remote_installation(&self, relative: &str) -> PathBuf {
        let directory = self.temp.join("remote-wordpress-root").join(relative);
        fs::create_dir_all(&directory).unwrap();
        let file = directory.join("wp-config.php");
        fs::write(&file, format!("<?php // {relative}")).unwrap();
        file
    }

    fn parent(&self) -> Site {
        let input = SiteInput {
            id: None,
            name: "Yellowbrand".into(),
            url: "https://yellowbrand.nl/".into(),
            ssh_host: "host.example.test".into(),
            ssh_port: 22,
            ssh_username: "deploy".into(),
            auth_method: AuthMethod::KeyFile,
            key_path: Some("C:\\keys\\id_ed25519".into()),
            wordpress_path: "/srv/site".into(),
            credential_secret: None,
            pinned_host_key: Some(FINGERPRINT.into()),
            parent_site_id: None,
            relation_type: None,
            parent_directory: None,
        };
        assert!(
            test_connection_internal(&self.state, input.clone())
                .unwrap()
                .success
        );
        save_site_internal(&self.state, input).unwrap()
    }

    fn child_input(
        &self,
        parent: &Site,
        directory: &str,
        relation: SiteRelationType,
        url: &str,
    ) -> SiteInput {
        SiteInput {
            id: None,
            name: format!("{directory} site"),
            url: url.into(),
            ssh_host: parent.ssh_host.clone(),
            ssh_port: parent.ssh_port,
            ssh_username: parent.ssh_username.clone(),
            auth_method: parent.auth_method,
            key_path: parent.key_path.clone(),
            wordpress_path: child_wordpress_path(&parent.wordpress_path, directory),
            credential_secret: None,
            pinned_host_key: parent.pinned_host_key.clone(),
            parent_site_id: Some(parent.id.clone()),
            relation_type: Some(relation),
            parent_directory: Some(directory.into()),
        }
    }

    fn detect(&self, parent: &Site) -> Vec<String> {
        let mut input = self.child_input(
            parent,
            "unused",
            SiteRelationType::Subdirectory,
            &parent.url,
        );
        input.id = Some(parent.id.clone());
        input.name = parent.name.clone();
        input.wordpress_path = parent.wordpress_path.clone();
        input.parent_site_id = parent.parent_site_id.clone();
        input.relation_type = parent.relation_type;
        input.parent_directory = parent.parent_directory.clone();
        let result = test_connection_internal(&self.state, input).unwrap();
        assert!(
            result.success,
            "connection check failed: {:?}",
            result.error
        );
        result.unexpected_directories
    }

    fn assert_integrity(&self) {
        let sites = self.state.database.list_sites().unwrap();
        let mut identities = HashSet::new();
        for site in &sites {
            assert!(identities.insert((
                site.ssh_host.to_ascii_lowercase(),
                site.ssh_port,
                site.wordpress_path.trim_end_matches('/').to_owned(),
            )));
        }
        let connection = self.state.database.connect().unwrap();
        let foreign_key_errors: i64 = connection
            .query_row("SELECT count(*) FROM pragma_foreign_key_check", [], |row| {
                row.get(0)
            })
            .unwrap();
        assert_eq!(
            foreign_key_errors, 0,
            "the database contains dangling references"
        );
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.temp);
    }
}

#[test]
fn subdomain_and_subdirectory_can_be_deleted_detected_and_linked_again() {
    for (directory, relation, url) in [
        (
            "dev",
            SiteRelationType::Subdomain,
            "https://dev.yellowbrand.nl/",
        ),
        (
            "academy",
            SiteRelationType::Subdirectory,
            "https://yellowbrand.nl/academy/",
        ),
    ] {
        let fixture = Fixture::new();
        let remote_file = fixture.add_remote_installation(directory);
        let original_bytes = fs::read(&remote_file).unwrap();
        let parent = fixture.parent();
        assert!(fixture.detect(&parent).contains(&directory.to_owned()));

        let input = fixture.child_input(&parent, directory, relation, url);
        assert!(
            test_connection_internal(&fixture.state, input.clone())
                .unwrap()
                .success
        );
        let child = save_site_internal(&fixture.state, input.clone()).unwrap();
        assert_eq!(child.parent_site_id.as_deref(), Some(parent.id.as_str()));
        assert_eq!(
            fixture
                .state
                .database
                .child_installation_directories(&parent.id)
                .unwrap(),
            vec![directory]
        );
        let connection = fixture.state.database.connect().unwrap();
        connection
            .execute(
                "INSERT INTO scan_runs(id,site_id,started_at,status,truncated) VALUES(?1,?2,?3,?4,0)",
                rusqlite::params![Uuid::new_v4().to_string(), child.id, "2026-10-01T14:00:00Z", "success"],
            )
            .unwrap();
        drop(connection);

        delete_site_internal(&fixture.state, child.id.clone()).unwrap();
        assert!(fixture.state.database.get_site(&child.id).is_err());
        assert!(
            fixture
                .state
                .database
                .child_installation_directories(&parent.id)
                .unwrap()
                .is_empty()
        );
        let connection = fixture.state.database.connect().unwrap();
        let stale_scans: i64 = connection
            .query_row(
                "SELECT count(*) FROM scan_runs WHERE site_id=?1",
                [&child.id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(
            stale_scans, 0,
            "deleted child scan history must be cascaded"
        );
        assert_eq!(fs::read(&remote_file).unwrap(), original_bytes);
        assert!(fixture.detect(&parent).contains(&directory.to_owned()));
        fixture.assert_integrity();

        let replacement = save_site_internal(&fixture.state, input).unwrap();
        assert_ne!(replacement.id, child.id);
        assert_eq!(
            replacement.parent_site_id.as_deref(),
            Some(parent.id.as_str())
        );
        assert_eq!(replacement.relation_type, Some(relation));
        assert_eq!(replacement.parent_directory.as_deref(), Some(directory));
        assert_eq!(
            fixture
                .state
                .database
                .child_installation_directories(&parent.id)
                .unwrap(),
            vec![directory]
        );
        assert_eq!(fixture.state.database.list_sites().unwrap().len(), 2);
        assert_eq!(fs::read(&remote_file).unwrap(), original_bytes);
        fixture.assert_integrity();
    }
}

#[test]
fn removing_a_child_with_its_own_child_detaches_then_allows_safe_relinking() {
    let fixture = Fixture::new();
    let child_file = fixture.add_remote_installation("dev");
    let grandchild_file = fixture.add_remote_installation("dev/portal");
    let child_bytes = fs::read(&child_file).unwrap();
    let grandchild_bytes = fs::read(&grandchild_file).unwrap();
    let parent = fixture.parent();
    let child_input = fixture.child_input(
        &parent,
        "dev",
        SiteRelationType::Subdomain,
        "https://dev.yellowbrand.nl/",
    );
    let child = save_site_internal(&fixture.state, child_input.clone()).unwrap();
    let grandchild_input = fixture.child_input(
        &child,
        "portal",
        SiteRelationType::Subdirectory,
        "https://dev.yellowbrand.nl/portal/",
    );
    let grandchild = save_site_internal(&fixture.state, grandchild_input.clone()).unwrap();
    assert_eq!(
        fixture
            .state
            .database
            .child_installation_directories(&child.id)
            .unwrap(),
        vec!["portal"]
    );

    delete_site_internal(&fixture.state, child.id.clone()).unwrap();
    let detached = fixture
        .state
        .database
        .get_site(&grandchild.id)
        .unwrap()
        .site;
    assert_eq!(detached.parent_site_id, None);
    assert_eq!(detached.relation_type, None);
    assert_eq!(detached.parent_directory, None);
    assert!(
        fixture
            .state
            .database
            .child_installation_directories(&parent.id)
            .unwrap()
            .is_empty()
    );
    assert!(fixture.detect(&parent).contains(&"dev".into()));
    assert_eq!(fs::read(&child_file).unwrap(), child_bytes);
    assert_eq!(fs::read(&grandchild_file).unwrap(), grandchild_bytes);
    fixture.assert_integrity();

    let replacement = save_site_internal(&fixture.state, child_input).unwrap();
    assert_ne!(replacement.id, child.id);
    assert!(
        fixture
            .state
            .database
            .child_installation_directories(&replacement.id)
            .unwrap()
            .is_empty(),
        "a detached grandchild must not silently become a checksum exclusion"
    );
    assert!(fixture.detect(&replacement).contains(&"portal".into()));
    let mut reconnect_grandchild = grandchild_input;
    reconnect_grandchild.id = Some(grandchild.id.clone());
    reconnect_grandchild.parent_site_id = Some(replacement.id.clone());
    let relinked = save_site_internal(&fixture.state, reconnect_grandchild).unwrap();
    assert_eq!(
        relinked.id, grandchild.id,
        "relinking must not duplicate the existing site"
    );
    assert_eq!(
        relinked.parent_site_id.as_deref(),
        Some(replacement.id.as_str())
    );
    assert_eq!(relinked.relation_type, Some(SiteRelationType::Subdirectory));
    assert_eq!(
        fixture
            .state
            .database
            .child_installation_directories(&replacement.id)
            .unwrap(),
        vec!["portal"]
    );
    assert_eq!(fixture.state.database.list_sites().unwrap().len(), 3);
    assert_eq!(fs::read(&child_file).unwrap(), child_bytes);
    assert_eq!(fs::read(&grandchild_file).unwrap(), grandchild_bytes);
    fixture.assert_integrity();
}
