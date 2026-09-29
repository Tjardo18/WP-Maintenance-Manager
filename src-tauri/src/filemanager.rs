use crate::{database::Database, error::AppError};
use crate::{
    models::Site,
    terminal_auth::{TerminalAccessManager, TerminalChallengeInfo, hash_secret},
};
use serde::Serialize;
use std::{
    sync::Mutex,
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
    connection: Option<ssh2::Session>,
}

#[derive(Default)]
pub struct FilemanagerAccessManager {
    // Separate instance: terminal challenges can never authorize this feature.
    challenges: TerminalAccessManager,
    access: Mutex<Vec<Access>>,
}

#[derive(Serialize)]
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
            entry.connection = Some(connection);
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
