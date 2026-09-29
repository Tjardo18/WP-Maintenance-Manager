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
    ) -> Result<crate::filemanager_directory::DirectoryListing, AppError> {
        self.with_connection(session, site, token, |connection| {
            crate::ssh::list_filemanager_directory(connection, &site.wordpress_path, requested)
        })
    }

    fn with_connection<T>(
        &self,
        session: &str,
        site: &Site,
        token: &str,
        operation: impl FnOnce(&ssh2::Session) -> Result<T, AppError>,
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
        let result = operation(&guard);
        drop(guard);
        if result.as_ref().is_err_and(|error| {
            matches!(
                error.category.as_str(),
                "filemanager_timeout"
                    | "filemanager_disconnected"
                    | "filemanager_sftp_failed"
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
                .with_connection(&session, &site, &token, |_| {
                    // No global mutex is held, so close can complete while I/O is in flight.
                    manager.close(&session, &site.id, &token);
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
                manager.with_connection(&session, &site, &token, |_| {
                    assert_eq!(
                        manager
                            .with_connection(&session, &site, &token, |_| Ok(()))
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
}
