use crate::{database::Database, error::AppError};
use crate::{
    models::Site,
    terminal_auth::{TerminalAccessManager, TerminalChallengeInfo, hash_secret},
};
use serde::Serialize;
use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

const ACCESS_TTL: Duration = Duration::from_secs(15 * 60);

struct Access {
    token: [u8; 32],
    session: [u8; 32],
    site_id: String,
    configuration: [u8; 32],
    expires: Instant,
    connection: Option<Arc<Mutex<ssh2::Session>>>,
}

#[derive(Default)]
pub struct FilemanagerAccessManager {
    // Serialize saves across access tokens, including two editors of the same site.
    saves: Mutex<()>,
    downloads: Mutex<()>,
    // Separate instance: terminal challenges can never authorize this feature.
    challenges: TerminalAccessManager,
    access: Mutex<Vec<Access>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilemanagerAuthorization {
    pub site_id: String,
    pub expires_in_seconds: u64,
}

fn denied() -> AppError {
    AppError::unauthorized(
        "filemanager_auth_required",
        "De filemanagerverificatie is ongeldig of verlopen. Bevestig beide wachtwoorden opnieuw.",
    )
}

fn configuration(site: &Site) -> [u8; 32] {
    hash_secret(&format!(
        "{:?}",
        (
            &site.ssh_host,
            site.ssh_port,
            &site.ssh_username,
            &site.wordpress_path,
            &site.pinned_host_key
        )
    ))
}

impl FilemanagerAccessManager {
    pub fn reserve_download(&self) -> Result<std::sync::MutexGuard<'_, ()>, AppError> {
        self.downloads.try_lock().map_err(|_| {
            AppError::unauthorized(
                "filemanager_busy",
                "Er is al een download of opslagdialoog actief. Rond deze eerst af.",
            )
        })
    }

    pub fn begin(&self, session: &str, site: &Site) -> Result<TerminalChallengeInfo, AppError> {
        let challenge = self.challenges.create_challenge(session, &site.id)?;
        let mut entries = self.access.lock().map_err(|_| denied())?;
        entries.retain(|entry| entry.expires > Instant::now() && entry.site_id != site.id);
        if entries.len() >= 128 {
            entries.remove(0);
        }
        entries.push(Access {
            token: hash_secret(&challenge.challenge_token),
            session: hash_secret(session),
            site_id: site.id.clone(),
            configuration: configuration(site),
            expires: Instant::now() + Duration::from_secs(challenge.expires_in_seconds),
            connection: None,
        });
        Ok(challenge)
    }

    pub fn connect(
        &self,
        session: &str,
        site: &Site,
        token: &str,
        password: &str,
    ) -> Result<FilemanagerAuthorization, AppError> {
        self.connect_with(session, site, token, || {
            crate::ssh::verified_terminal_password_session(site, password, Duration::from_secs(30))
        })
    }

    fn connect_with(
        &self,
        session: &str,
        site: &Site,
        token: &str,
        connect: impl FnOnce() -> Result<ssh2::Session, AppError>,
    ) -> Result<FilemanagerAuthorization, AppError> {
        self.challenges
            .consume_challenge(session, &site.id, token)
            .map_err(|error| {
                if error.category == "terminal_ssh_rate_limited" {
                    AppError::unauthorized(
                        "filemanager_ssh_rate_limited",
                        "Te veel SSH-pogingen. Wacht even en bevestig beide wachtwoorden opnieuw.",
                    )
                } else {
                    denied()
                }
            })?;
        // Check before opening a socket; check again afterwards to defeat close/navigation races.
        self.with_entry(session, site, token, false, |_| Ok(()))?;
        let connection = match connect() {
            Ok(connection) => connection,
            Err(error) => {
                if error.category == "ssh_authentication" {
                    self.challenges.register_ssh_failure(session, &site.id)?;
                }
                self.close(session, &site.id, token);
                // Never expose transport details or server-controlled strings in this login UI.
                eprintln!(
                    "filemanager SSH verification failed category={}",
                    error.category
                );
                let message = match error.category.as_str() {
                    "ssh_authentication" => {
                        "SSH-authenticatie mislukt. Controleer het wachtwoord en probeer opnieuw."
                    }
                    "ssh_password_auth_unsupported" => {
                        "Deze server ondersteunt de vereiste SSH-wachtwoordcontrole niet."
                    }
                    "host_key_unknown" | "host_key_mismatch" => {
                        "Controleer eerst de vertrouwde SSH-hostsleutel in de website-instellingen."
                    }
                    "connection_timeout" => {
                        "De SSH-verbinding duurde te lang. Controleer de bereikbaarheid en probeer opnieuw."
                    }
                    _ => {
                        "SSH-verbinding niet gelukt. Controleer de websiteconfiguratie en bereikbaarheid van de server en probeer opnieuw."
                    }
                };
                return Err(AppError::unauthorized("filemanager_ssh_failed", message));
            }
        };
        self.with_entry(session, site, token, false, |entry| {
            entry.connection = Some(Arc::new(Mutex::new(connection)));
            entry.expires = Instant::now() + ACCESS_TTL;
            Ok(())
        })?;
        self.challenges.clear_ssh_failures(session, &site.id);
        self.authorize(session, site, token)
    }

    // All future file operations must also require a live app session before using this guard.
    pub fn authorize(
        &self,
        session: &str,
        site: &Site,
        token: &str,
    ) -> Result<FilemanagerAuthorization, AppError> {
        self.with_entry(session, site, token, true, |entry| {
            Ok(FilemanagerAuthorization {
                site_id: site.id.clone(),
                expires_in_seconds: entry
                    .expires
                    .saturating_duration_since(Instant::now())
                    .as_secs(),
            })
        })
    }

    pub fn list_directory(
        &self,
        session: &str,
        site: &Site,
        token: &str,
        requested: &str,
        authorize: impl Fn() -> Result<(), AppError>,
    ) -> Result<crate::filemanager_directory::DirectoryListing, AppError> {
        self.with_connection(session, site, token, &authorize, |connection, check| {
            crate::ssh::list_filemanager_directory(
                connection,
                &site.wordpress_path,
                requested,
                check,
            )
        })
    }

    pub fn read_file(
        &self,
        session: &str,
        site: &Site,
        token: &str,
        requested: &str,
        authorize: impl Fn() -> Result<(), AppError>,
    ) -> Result<crate::models::FileContentPreview, AppError> {
        self.with_connection(session, site, token, &authorize, |connection, check| {
            crate::ssh::read_filemanager_file(connection, &site.wordpress_path, requested, check)
        })
    }

    fn with_connection<T>(
        &self,
        session: &str,
        site: &Site,
        token: &str,
        authorize: &dyn Fn() -> Result<(), AppError>,
        operation: impl FnOnce(&ssh2::Session, &dyn Fn() -> Result<(), AppError>) -> Result<T, AppError>,
    ) -> Result<T, AppError> {
        let connection = self.with_entry(session, site, token, true, |entry| {
            entry.connection.clone().ok_or_else(denied)
        })?;
        // Never hold the global authorization mutex during network I/O. Closing/locking remains responsive.
        let guard = connection.try_lock().map_err(|_| {
            AppError::unauthorized(
                "filemanager_busy",
                "Er is al een filemanageractie bezig voor deze toegang. Probeer het zo opnieuw.",
            )
        })?;
        let check = || {
            authorize()?;
            self.authorize(session, site, token).map(|_| ())
        };
        check()?;
        let result = operation(&guard, &check);
        drop(guard);
        if result.as_ref().is_err_and(|error| {
            matches!(
                error.category.as_str(),
                "filemanager_timeout"
                    | "filemanager_disconnected"
                    | "filemanager_sftp_failed"
                    | "filemanager_file_read_failed"
                    | "filemanager_invalid_directory_response"
            )
        }) {
            self.close(session, &site.id, token);
        } else {
            // A result from an expired/revoked/replaced attempt must not reach the client.
            self.authorize(session, site, token)?;
        }
        result
    }

    pub fn save_file(
        &self,
        session: &str,
        site: &Site,
        token: &str,
        input: &crate::filemanager_edit::SaveInput,
        authorize: impl Fn() -> Result<(), AppError>,
    ) -> Result<crate::models::FileContentPreview, AppError> {
        let _save = self.saves.try_lock().map_err(|_| {
            AppError::unauthorized(
                "filemanager_busy",
                "Er wordt al een bestand opgeslagen. Probeer het zo opnieuw.",
            )
        })?;
        self.with_connection(session, site, token, &authorize, |connection, check| {
            crate::ssh::save_filemanager_file(
                connection,
                &site.wordpress_path,
                &input.path,
                &input.content,
                &input.expected_version,
                check,
            )
        })
    }

    pub fn create_file(
        &self,
        session: &str,
        site: &Site,
        token: &str,
        input: &crate::filemanager_mutation::CreateInput,
        authorize: impl Fn() -> Result<(), AppError>,
    ) -> Result<crate::filemanager_mutation::MutationResult, AppError> {
        self.with_connection(session, site, token, &authorize, |connection, check| {
            crate::ssh::create_filemanager_file(connection, &site.wordpress_path, input, check)
        })
    }
    pub fn create_directory(
        &self,
        session: &str,
        site: &Site,
        token: &str,
        input: &crate::filemanager_mutation::CreateInput,
        authorize: impl Fn() -> Result<(), AppError>,
    ) -> Result<crate::filemanager_mutation::MutationResult, AppError> {
        self.with_connection(session, site, token, &authorize, |connection, check| {
            crate::ssh::create_filemanager_directory(connection, &site.wordpress_path, input, check)
        })
    }
    pub fn delete_item(
        &self,
        session: &str,
        site: &Site,
        token: &str,
        input: &crate::filemanager_mutation::DeleteInput,
        authorize: impl Fn() -> Result<(), AppError>,
    ) -> Result<crate::filemanager_mutation::MutationResult, AppError> {
        self.with_connection(session, site, token, &authorize, |connection, check| {
            crate::ssh::delete_filemanager_item(connection, &site.wordpress_path, input, check)
        })
    }

    pub fn change_permissions(
        &self,
        session: &str,
        site: &Site,
        token: &str,
        input: &crate::filemanager_mutation::PermissionInput,
        authorize: impl Fn() -> Result<(), AppError>,
    ) -> Result<(), AppError> {
        self.with_connection(session, site, token, &authorize, |connection, check| {
            crate::ssh::change_filemanager_permissions(
                connection,
                &site.wordpress_path,
                input,
                check,
            )
        })
    }

    pub fn change_permissions_bulk(
        &self,
        session: &str,
        site: &Site,
        token: &str,
        input: &crate::filemanager_mutation::BulkPermissionInput,
        authorize: impl Fn() -> Result<(), AppError>,
    ) -> Result<crate::filemanager_mutation::BulkResult, AppError> {
        self.with_connection(session, site, token, &authorize, |connection, check| {
            crate::ssh::change_filemanager_permissions_bulk(
                connection,
                &site.wordpress_path,
                input,
                check,
            )
        })
    }

    pub fn delete_bulk(
        &self,
        session: &str,
        site: &Site,
        token: &str,
        input: &crate::filemanager_mutation::BulkInput,
        authorize: impl Fn() -> Result<(), AppError>,
    ) -> Result<crate::filemanager_mutation::BulkResult, AppError> {
        self.with_connection(session, site, token, &authorize, |connection, check| {
            crate::ssh::delete_filemanager_bulk(connection, &site.wordpress_path, input, check)
        })
    }

    pub fn download<W: std::io::Write + std::io::Seek>(
        &self,
        session: &str,
        site: &Site,
        token: &str,
        input: &crate::filemanager_mutation::BulkInput,
        output: &mut W,
        authorize: impl Fn() -> Result<(), AppError>,
    ) -> Result<crate::filemanager_download::DownloadResult, AppError> {
        self.with_connection(session, site, token, &authorize, |connection, check| {
            crate::ssh::write_filemanager_download(
                connection,
                &site.wordpress_path,
                input,
                output,
                check,
            )
        })
    }

    fn with_entry<T>(
        &self,
        session: &str,
        site: &Site,
        token: &str,
        require_connection: bool,
        operation: impl FnOnce(&mut Access) -> Result<T, AppError>,
    ) -> Result<T, AppError> {
        if token.is_empty() || token.len() > 512 || session.is_empty() || session.len() > 512 {
            return Err(denied());
        }
        let mut entries = self.access.lock().map_err(|_| denied())?;
        entries.retain(|entry| entry.expires > Instant::now());
        let entry = entries
            .iter_mut()
            .find(|entry| {
                entry.token.ct_eq(&hash_secret(token)).unwrap_u8() == 1
                    && entry.session.ct_eq(&hash_secret(session)).unwrap_u8() == 1
                    && entry.site_id == site.id
                    && entry.configuration == configuration(site)
            })
            .ok_or_else(denied)?;
        if require_connection && entry.connection.is_none() {
            return Err(denied());
        }
        operation(entry)
    }

    pub fn close(&self, session: &str, site_id: &str, token: &str) {
        let _ = self.challenges.cancel_challenge(session, site_id, token);
        if let Ok(mut entries) = self.access.lock() {
            entries.retain(|entry| {
                !(entry.site_id == site_id
                    && entry.session.ct_eq(&hash_secret(session)).unwrap_u8() == 1
                    && entry.token.ct_eq(&hash_secret(token)).unwrap_u8() == 1)
            });
        }
    }

    pub fn revoke_site(&self, site_id: &str) {
        self.challenges.revoke_site(site_id);
        if let Ok(mut entries) = self.access.lock() {
            entries.retain(|entry| entry.site_id != site_id);
        }
    }

    pub fn revoke_all(&self) {
        self.challenges.revoke_all();
        if let Ok(mut entries) = self.access.lock() {
            entries.clear();
        }
    }

    pub fn reap_expired(&self) {
        if let Ok(mut entries) = self.access.lock() {
            entries.retain(|entry| entry.expires > Instant::now());
        }
    }

    #[cfg(test)]
    pub(crate) fn install_test_access(&self, session: &str, site: &Site) -> String {
        let token = self.begin(session, site).unwrap().challenge_token;
        self.connect_with(session, site, &token, || Ok(ssh2::Session::new().unwrap()))
            .unwrap();
        token
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FilemanagerContext {
    pub site_id: String,
    pub site_name: String,
    pub site_url: String,
}

// Metadata only: this context is not authorization to access remote files.
pub fn context(database: &Database, site_id: &str) -> Result<FilemanagerContext, AppError> {
    let stored = database.get_site(site_id)?;
    Ok(FilemanagerContext {
        site_id: stored.site.id,
        site_name: stored.site.name,
        site_url: stored.site.url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_dialog_reservation_is_exclusive_and_released() {
        let manager = FilemanagerAccessManager::default();
        let reservation = manager.reserve_download().unwrap();
        assert!(manager.reserve_download().is_err());
        drop(reservation);
        assert!(manager.reserve_download().is_ok());
    }
    use uuid::Uuid;

    fn site() -> Site {
        serde_json::from_value(serde_json::json!({
            "id": Uuid::new_v4().to_string(), "name": "Test", "url": "https://example.test",
            "sshHost": "example.test", "sshPort": 22, "sshUsername": "deploy", "authMethod": "password",
            "wordpressPath": "/srv/wordpress", "pinnedHostKey": "test-fingerprint", "status": "unscanned",
            "updateCount": 0, "createdAt": "2026-09-29", "updatedAt": "2026-09-29"
        })).unwrap()
    }

    // Transport is injected at the verified-password boundary, never via a production bypass.
    fn verified_transport() -> Result<ssh2::Session, AppError> {
        Ok(ssh2::Session::new().unwrap())
    }

    #[test]
    fn app_challenge_alone_cannot_open_workspace_and_success_is_site_and_session_bound() {
        let manager = FilemanagerAccessManager::default();
        let a = site();
        let mut b = a.clone();
        b.id = Uuid::new_v4().to_string(); // identical host/user/path is not the same website
        let session = Uuid::new_v4().to_string();
        let token = manager.begin(&session, &a).unwrap().challenge_token;
        assert!(manager.authorize(&session, &a, &token).is_err());
        assert_eq!(
            manager
                .connect_with(&session, &a, &token, verified_transport)
                .unwrap()
                .site_id,
            a.id
        );
        assert!(manager.authorize(&session, &a, &token).is_ok());
        assert!(manager.authorize(&session, &b, &token).is_err());
        assert!(
            manager
                .authorize(&Uuid::new_v4().to_string(), &a, &token)
                .is_err()
        );
        assert!(
            manager
                .connect_with(&session, &a, &token, || panic!("challenge reused"))
                .is_err()
        );
        let mut changed = a.clone();
        changed.ssh_host = "changed.test".into();
        assert!(manager.authorize(&session, &changed, &token).is_err());
    }

    #[test]
    fn terminal_challenges_never_authorize_filemanager() {
        let manager = FilemanagerAccessManager::default();
        let terminal = TerminalAccessManager::default();
        let site = site();
        let session = Uuid::new_v4().to_string();
        let token = terminal
            .create_challenge(&session, &site.id)
            .unwrap()
            .challenge_token;
        assert!(
            manager
                .connect_with(&session, &site, &token, || panic!("wrong purpose"))
                .is_err()
        );
        let token = manager.begin(&session, &site).unwrap().challenge_token;
        assert!(
            terminal
                .consume_challenge(&session, &site.id, &token)
                .is_err()
        );
    }

    #[test]
    fn transport_failures_never_authorize_or_echo_sensitive_details() {
        for category in [
            "ssh_authentication",
            "network",
            "connection_timeout",
            "storage",
            "host_key_mismatch",
        ] {
            let manager = FilemanagerAccessManager::default();
            let site = site();
            let session = Uuid::new_v4().to_string();
            let secret = Uuid::new_v4().to_string();
            let token = manager.begin(&session, &site).unwrap().challenge_token;
            let error = manager
                .connect_with(&session, &site, &token, || {
                    Err(AppError::ssh(category, &secret, &secret, false))
                })
                .unwrap_err();
            assert!(!format!("{error:?}").contains(&secret));
            assert!(manager.authorize(&session, &site, &token).is_err());
        }
    }

    #[test]
    fn canceled_or_revoked_inflight_login_cannot_reactivate_access() {
        let manager = FilemanagerAccessManager::default();
        let site = site();
        let session = Uuid::new_v4().to_string();
        for global in [false, true] {
            let token = manager.begin(&session, &site).unwrap().challenge_token;
            assert!(
                manager
                    .connect_with(&session, &site, &token, || {
                        if global {
                            manager.revoke_all();
                        } else {
                            manager.close(&session, &site.id, &token);
                        }
                        verified_transport()
                    })
                    .is_err()
            );
            assert!(manager.authorize(&session, &site, &token).is_err());
        }
    }

    #[test]
    fn stale_close_does_not_revoke_a_new_attempt_and_site_deletion_does() {
        let manager = FilemanagerAccessManager::default();
        let site = site();
        let session = Uuid::new_v4().to_string();
        let old = manager.begin(&session, &site).unwrap().challenge_token;
        let current = manager.begin(&session, &site).unwrap().challenge_token;
        manager.close(&session, &site.id, &old);
        assert!(
            manager
                .connect_with(&session, &site, &current, verified_transport)
                .is_ok()
        );
        manager.revoke_site(&site.id);
        assert!(manager.authorize(&session, &site, &current).is_err());
    }

    #[test]
    fn expired_pending_and_active_access_are_rejected() {
        let manager = FilemanagerAccessManager::default();
        let site = site();
        let session = Uuid::new_v4().to_string();
        for active in [false, true] {
            let token = manager.begin(&session, &site).unwrap().challenge_token;
            if active {
                manager
                    .connect_with(&session, &site, &token, verified_transport)
                    .unwrap();
            }
            manager.access.lock().unwrap()[0].expires = Instant::now() - Duration::from_secs(1);
            assert!(manager.authorize(&session, &site, &token).is_err());
            assert!(
                manager
                    .connect_with(&session, &site, &token, || panic!("expired"))
                    .is_err()
            );
            assert!(manager.access.lock().unwrap().is_empty());
        }
    }

    #[test]
    fn repeated_wrong_passwords_use_existing_rate_limit() {
        let manager = FilemanagerAccessManager::default();
        let site = site();
        let session = Uuid::new_v4().to_string();
        for _ in 0..3 {
            let token = manager.begin(&session, &site).unwrap().challenge_token;
            assert!(
                manager
                    .connect_with(&session, &site, &token, || Err(AppError::unauthorized(
                        "ssh_authentication",
                        "denied"
                    )))
                    .is_err()
            );
        }
        let token = manager.begin(&session, &site).unwrap().challenge_token;
        assert_eq!(
            manager
                .connect_with(&session, &site, &token, || panic!("rate limited"))
                .unwrap_err()
                .category,
            "filemanager_ssh_rate_limited"
        );
    }

    #[test]
    fn directory_operations_release_global_lock_and_discard_revoked_results() {
        let manager = FilemanagerAccessManager::default();
        let site = site();
        let session = Uuid::new_v4().to_string();
        let token = manager.install_test_access(&session, &site);
        assert!(
            manager
                .with_connection(&session, &site, &token, &|| Ok(()), |_, check| {
                    // No global mutex is held, so close can complete while I/O is in flight.
                    manager.close(&session, &site.id, &token);
                    assert_eq!(check().unwrap_err().category, "filemanager_auth_required");
                    Ok(())
                })
                .is_err()
        );
    }

    #[test]
    fn same_connection_is_serialized_and_transport_failure_revokes_access() {
        let manager = FilemanagerAccessManager::default();
        let site = site();
        let session = Uuid::new_v4().to_string();
        for category in [
            "filemanager_timeout",
            "filemanager_disconnected",
            "filemanager_invalid_directory_response",
        ] {
            let token = manager.install_test_access(&session, &site);
            let result: Result<(), AppError> =
                manager.with_connection(&session, &site, &token, &|| Ok(()), |_, _| {
                    assert_eq!(
                        manager
                            .with_connection(&session, &site, &token, &|| Ok(()), |_, _| Ok(()))
                            .unwrap_err()
                            .category,
                        "filemanager_busy"
                    );
                    Err(AppError::unauthorized(category, "Test"))
                });
            assert_eq!(result.unwrap_err().category, category);
            assert!(manager.authorize(&session, &site, &token).is_err());
        }
    }

    #[test]
    fn save_rejects_other_site_and_simultaneous_writes_before_transport() {
        let manager = FilemanagerAccessManager::default();
        let site = site();
        let session = Uuid::new_v4().to_string();
        let token = manager.install_test_access(&session, &site);
        let mut other = site.clone();
        other.id = Uuid::new_v4().to_string();
        let input = crate::filemanager_edit::SaveInput {
            path: "/test.php".into(),
            content: "text".into(),
            expected_version: "a".repeat(64),
        };
        assert_eq!(
            manager
                .save_file(&session, &other, &token, &input, || panic!(
                    "cross-site transport"
                ))
                .unwrap_err()
                .category,
            "filemanager_auth_required"
        );
        let _locked = manager.saves.lock().unwrap();
        assert_eq!(
            manager
                .save_file(&session, &site, &token, &input, || panic!(
                    "concurrent transport"
                ))
                .unwrap_err()
                .category,
            "filemanager_busy"
        );
    }

    #[test]
    fn download_rejects_other_site_before_sftp() {
        let manager = FilemanagerAccessManager::default();
        let site = site();
        let session = Uuid::new_v4().to_string();
        let token = manager.install_test_access(&session, &site);
        let mut other = site.clone();
        other.id = Uuid::new_v4().to_string();
        let input = crate::filemanager_mutation::BulkInput {
            directory: "/".into(),
            items: vec![crate::filemanager_mutation::DeleteInput {
                path: "/index.php".into(),
                expected_kind: crate::filemanager_mutation::ItemKind::File,
            }],
        };
        let mut output = std::io::Cursor::new(Vec::new());
        assert_eq!(
            manager
                .download(&session, &other, &token, &input, &mut output, || Ok(()))
                .unwrap_err()
                .category,
            "filemanager_auth_required"
        );
        assert!(output.get_ref().is_empty());
    }

    #[test]
    fn every_filesystem_service_rejects_cross_site_and_expired_access_before_transport() {
        use crate::filemanager_mutation::{
            BulkInput, BulkPermissionInput, CreateInput, DeleteInput, ItemKind, PermissionInput,
        };
        for expired in [false, true] {
            let manager = FilemanagerAccessManager::default();
            let original = site();
            let session = Uuid::new_v4().to_string();
            let token = manager.install_test_access(&session, &original);
            let mut requested = original.clone();
            if expired {
                manager.access.lock().unwrap()[0].expires = Instant::now() - Duration::from_secs(1);
            } else {
                requested.id = Uuid::new_v4().to_string();
            }
            let create = CreateInput {
                directory: "/".into(),
                name: "a.php".into(),
            };
            let item = DeleteInput {
                path: "/a.php".into(),
                expected_kind: ItemKind::File,
            };
            let permission = PermissionInput {
                path: item.path.clone(),
                expected_kind: item.expected_kind,
                mode: "644".into(),
            };
            let bulk = BulkInput {
                directory: "/".into(),
                items: vec![item.clone()],
            };
            let permissions = BulkPermissionInput {
                directory: "/".into(),
                items: bulk.items.clone(),
                mode: "644".into(),
            };
            let save = crate::filemanager_edit::SaveInput {
                path: item.path.clone(),
                content: "test".into(),
                expected_version: "a".repeat(64),
            };
            let mut output = std::io::Cursor::new(Vec::new());
            let results = [
                manager
                    .list_directory(&session, &requested, &token, "/", || Ok(()))
                    .map(|_| ()),
                manager
                    .read_file(&session, &requested, &token, "/a.php", || Ok(()))
                    .map(|_| ()),
                manager
                    .save_file(&session, &requested, &token, &save, || Ok(()))
                    .map(|_| ()),
                manager
                    .create_file(&session, &requested, &token, &create, || Ok(()))
                    .map(|_| ()),
                manager
                    .create_directory(&session, &requested, &token, &create, || Ok(()))
                    .map(|_| ()),
                manager
                    .delete_item(&session, &requested, &token, &item, || Ok(()))
                    .map(|_| ()),
                manager.change_permissions(&session, &requested, &token, &permission, || Ok(())),
                manager
                    .delete_bulk(&session, &requested, &token, &bulk, || Ok(()))
                    .map(|_| ()),
                manager
                    .change_permissions_bulk(&session, &requested, &token, &permissions, || Ok(()))
                    .map(|_| ()),
                manager
                    .download(&session, &requested, &token, &bulk, &mut output, || Ok(()))
                    .map(|_| ()),
            ];
            for result in results {
                assert_eq!(result.unwrap_err().category, "filemanager_auth_required");
            }
            assert!(output.get_ref().is_empty());
        }
    }

    #[test]
    fn operation_guard_rechecks_app_session_and_fixed_access_expiry() {
        let manager = FilemanagerAccessManager::default();
        let site = site();
        let session = Uuid::new_v4().to_string();
        let token = manager.install_test_access(&session, &site);
        let app_active = std::cell::Cell::new(true);
        let validate_app = || {
            if app_active.get() {
                Ok(())
            } else {
                Err(AppError::unauthorized("locked", "Vergrendeld"))
            }
        };
        manager
            .with_connection(&session, &site, &token, &validate_app, |_, check| {
                check()?;
                app_active.set(false);
                assert_eq!(check().unwrap_err().category, "locked");
                app_active.set(true);
                manager.access.lock().unwrap()[0].expires = Instant::now() - Duration::from_secs(1);
                assert_eq!(check().unwrap_err().category, "filemanager_auth_required");
                Ok(())
            })
            .unwrap_err();
    }
}
