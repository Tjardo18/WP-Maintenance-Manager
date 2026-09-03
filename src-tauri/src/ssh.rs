use crate::{
    command_catalog::RemoteCommand,
    error::AppError,
    models::{AuthMethod, Site},
    validation::validate_checksum_file_action_path,
};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chrono::{SecondsFormat, Utc};
use sha2::{Digest, Sha256};
use ssh2::Session;
use std::{
    io::Read,
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    time::{Duration, Instant},
};

#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
}

#[derive(Debug, Clone)]
pub struct RemoteFileRead {
    pub bytes: Vec<u8>,
    pub size_bytes: u64,
    pub modified_unix: Option<u64>,
    pub truncated: bool,
}

impl ExecOutput {
    pub fn stdout_text(&self) -> Result<String, AppError> {
        String::from_utf8(self.stdout.clone()).map_err(|error| {
            AppError::ssh(
                "parse_failed",
                "De server stuurde onleesbare tekst terug.",
                error,
                false,
            )
        })
    }
}

pub trait SshExecutor: Send + Sync {
    fn fingerprint(&self, site: &Site) -> Result<String, AppError>;
    fn authenticate(&self, site: &Site, credential: Option<&str>) -> Result<(), AppError>;
    fn execute(
        &self,
        site: &Site,
        credential: Option<&str>,
        command: &RemoteCommand,
    ) -> Result<ExecOutput, AppError>;
    fn download(
        &self,
        site: &Site,
        credential: Option<&str>,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<u64, AppError>;

    fn read_checksum_file(
        &self,
        _site: &Site,
        _credential: Option<&str>,
        _relative_path: &str,
        _max_bytes: usize,
    ) -> Result<RemoteFileRead, AppError> {
        Err(AppError::validation(
            "Bestandspreview wordt niet ondersteund door deze SSH-uitvoerder.",
        ))
    }

    fn delete_checksum_file(
        &self,
        _site: &Site,
        _credential: Option<&str>,
        _relative_path: &str,
    ) -> Result<(), AppError> {
        Err(AppError::validation(
            "Bestandsverwijdering wordt niet ondersteund door deze SSH-uitvoerder.",
        ))
    }
}

#[derive(Debug, Clone, Default)]
pub struct Ssh2Executor;

impl Ssh2Executor {
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
    const HANDSHAKE_RETRY_DELAYS: [Duration; 3] = [
        Duration::ZERO,
        Duration::from_millis(250),
        Duration::from_millis(750),
    ];

    fn handshake(&self, site: &Site, timeout: Duration) -> Result<Session, AppError> {
        let mut last_error = None;
        for delay in Self::HANDSHAKE_RETRY_DELAYS {
            if !delay.is_zero() {
                std::thread::sleep(delay);
            }
            match self.handshake_once(site, timeout) {
                Ok(session) => return Ok(session),
                Err(error) if error.retryable => last_error = Some(error),
                Err(error) => return Err(error),
            }
        }
        Err(last_error.unwrap_or_else(|| {
            AppError::ssh(
                "ssh_protocol",
                "De SSH-handshake is mislukt.",
                "Geen handshakepoging uitgevoerd",
                true,
            )
        }))
    }

    fn handshake_once(&self, site: &Site, timeout: Duration) -> Result<Session, AppError> {
        let addresses = (site.ssh_host.as_str(), site.ssh_port)
            .to_socket_addrs()
            .map_err(|error| {
                AppError::ssh(
                    "dns_host_error",
                    "De SSH-server kan niet worden gevonden.",
                    error,
                    true,
                )
            })?;
        let mut last_error = None;
        let mut tcp = None;
        for address in addresses {
            match TcpStream::connect_timeout(&address, Self::CONNECT_TIMEOUT) {
                Ok(stream) => {
                    tcp = Some(stream);
                    break;
                }
                Err(error) => last_error = Some(error),
            }
        }
        let tcp = tcp.ok_or_else(|| {
            let error = last_error.map_or_else(
                || "Geen netwerkadres gevonden".into(),
                |value| value.to_string(),
            );
            let category = if error.to_ascii_lowercase().contains("timed out") {
                "timeout"
            } else {
                "dns_host_error"
            };
            AppError::ssh(category, "Kan geen SSH-verbinding maken.", error, true)
        })?;
        tcp.set_read_timeout(Some(timeout))
            .map_err(AppError::storage)?;
        tcp.set_write_timeout(Some(timeout))
            .map_err(AppError::storage)?;
        let mut session = Session::new().map_err(|error| {
            map_ssh_error("ssh_protocol", "SSH kon niet worden gestart.", error)
        })?;
        session.set_tcp_stream(tcp);
        session.set_timeout(timeout.as_millis().min(u32::MAX as u128) as u32);
        session.handshake().map_err(|error| {
            map_ssh_error("ssh_protocol", "De SSH-handshake is mislukt.", error)
        })?;
        Ok(session)
    }

    fn fingerprint_from_session(session: &Session) -> Result<String, AppError> {
        let (host_key, _) = session.host_key().ok_or_else(|| {
            AppError::ssh(
                "ssh_protocol",
                "De server stuurde geen host key.",
                "host key ontbreekt",
                false,
            )
        })?;
        Ok(format!(
            "SHA256:{}",
            STANDARD_NO_PAD.encode(Sha256::digest(host_key))
        ))
    }

    fn verified_session(
        &self,
        site: &Site,
        credential: Option<&str>,
        timeout: Duration,
    ) -> Result<Session, AppError> {
        let session = self.handshake(site, timeout)?;
        let actual = Self::fingerprint_from_session(&session)?;
        match site.pinned_host_key.as_deref() {
            None => {
                return Err(AppError::ssh(
                    "host_key_unknown",
                    "De identiteit van deze SSH-server is nog niet geaccepteerd.",
                    actual,
                    false,
                ));
            }
            Some(expected) if expected != actual => {
                return Err(AppError::ssh(
                    "host_key_mismatch",
                    "Waarschuwing: de identiteit van de SSH-server is gewijzigd. De verbinding is geblokkeerd.",
                    format!("Verwacht {expected}; ontvangen {actual}"),
                    false,
                ));
            }
            Some(_) => {}
        }
        match site.auth_method {
            AuthMethod::Password => {
                let password = credential.ok_or_else(|| {
                    AppError::ssh(
                        "authentication_failed",
                        "Geen opgeslagen SSH-wachtwoord gevonden.",
                        "credential ontbreekt",
                        false,
                    )
                })?;
                session
                    .userauth_password(&site.ssh_username, password)
                    .map_err(|error| {
                        map_ssh_error(
                            "authentication_failed",
                            "SSH-authenticatie is mislukt.",
                            error,
                        )
                    })?;
            }
            AuthMethod::KeyFile => {
                let key_path = site
                    .key_path
                    .as_deref()
                    .ok_or_else(|| AppError::validation("Geen SSH-sleutelbestand ingesteld."))?;
                if !Path::new(key_path).is_file() {
                    return Err(AppError::ssh(
                        "authentication_failed",
                        "Het SSH-sleutelbestand is niet gevonden.",
                        key_path,
                        false,
                    ));
                }
                session
                    .userauth_pubkey_file(&site.ssh_username, None, Path::new(key_path), credential)
                    .map_err(|error| {
                        map_ssh_error(
                            "authentication_failed",
                            "SSH-sleutelauthenticatie is mislukt.",
                            error,
                        )
                    })?;
            }
        }
        if !session.authenticated() {
            return Err(AppError::ssh(
                "authentication_failed",
                "SSH-authenticatie is mislukt.",
                "server weigerde authenticatie",
                false,
            ));
        }
        Ok(session)
    }

    fn resolve_regular_checksum_file(
        sftp: &ssh2::Sftp,
        site: &Site,
        relative_path: &str,
    ) -> Result<(String, ssh2::FileStat), AppError> {
        validate_checksum_file_action_path(relative_path)?;
        let canonical_root = sftp
            .realpath(Path::new(&site.wordpress_path))
            .map_err(|error| {
                map_ssh_error(
                    "sftp_path",
                    "De WordPress-root kon niet veilig worden bepaald.",
                    error,
                )
            })?
            .to_string_lossy()
            .into_owned();
        let canonical_root = canonical_root.trim_end_matches('/');
        if canonical_root.is_empty() {
            return Err(AppError::validation(
                "De serverroot mag niet als WordPress-root voor bestandsacties worden gebruikt.",
            ));
        }
        let candidate = format!("{canonical_root}/{relative_path}");
        let initial = sftp.lstat(Path::new(&candidate)).map_err(|error| {
            map_ssh_error(
                "sftp_file",
                "Het checksum-bestand is niet meer beschikbaar.",
                error,
            )
        })?;
        ensure_regular_file(&initial)?;
        let canonical_target = sftp
            .realpath(Path::new(&candidate))
            .map_err(|error| {
                map_ssh_error(
                    "sftp_path",
                    "Het checksum-bestand kon niet veilig worden bepaald.",
                    error,
                )
            })?
            .to_string_lossy()
            .into_owned();
        ensure_contained_remote_path(canonical_root, &canonical_target)?;
        let final_stat = sftp.lstat(Path::new(&canonical_target)).map_err(|error| {
            map_ssh_error(
                "sftp_file",
                "Het checksum-bestand is tijdens de controle gewijzigd.",
                error,
            )
        })?;
        ensure_regular_file(&final_stat)?;
        if !same_file_snapshot(&initial, &final_stat) {
            return Err(AppError::ssh(
                "sftp_file_changed",
                "Het bestand veranderde tijdens de veiligheidscontrole. Probeer opnieuw na een nieuwe scan.",
                relative_path,
                true,
            ));
        }
        Ok((canonical_target, final_stat))
    }
}

impl SshExecutor for Ssh2Executor {
    fn fingerprint(&self, site: &Site) -> Result<String, AppError> {
        let session = self.handshake(site, Self::CONNECT_TIMEOUT)?;
        Self::fingerprint_from_session(&session)
    }

    fn authenticate(&self, site: &Site, credential: Option<&str>) -> Result<(), AppError> {
        self.verified_session(site, credential, Self::CONNECT_TIMEOUT)
            .map(|_| ())
    }

    fn execute(
        &self,
        site: &Site,
        credential: Option<&str>,
        command: &RemoteCommand,
    ) -> Result<ExecOutput, AppError> {
        let started = Instant::now();
        let started_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
        let result = (|| {
            let session = self.verified_session(site, credential, command.timeout)?;
            let mut channel = session.channel_session().map_err(|error| {
                map_ssh_error(
                    "ssh_channel",
                    "De server kon geen uitvoerkanaal openen.",
                    error,
                )
            })?;
            channel.exec(&command.command).map_err(|error| {
                map_ssh_error(
                    "command_failed",
                    "De serveractie kon niet worden gestart.",
                    error,
                )
            })?;
            let mut stdout = Vec::new();
            channel
                .by_ref()
                .take(command.max_output_bytes as u64 + 1)
                .read_to_end(&mut stdout)
                .map_err(|error| {
                    AppError::ssh(
                        "ssh_channel",
                        "Het serverantwoord kon niet worden gelezen.",
                        error,
                        true,
                    )
                })?;
            if stdout.len() > command.max_output_bytes {
                let _ = channel.close();
                return Err(AppError::ssh(
                    "output_limit",
                    "De server stuurde te veel gegevens terug; de actie is veilig afgebroken.",
                    format!("limiet {} bytes", command.max_output_bytes),
                    false,
                ));
            }
            let mut stderr = Vec::new();
            channel
                .stderr()
                .take(256 * 1024)
                .read_to_end(&mut stderr)
                .map_err(|error| {
                    AppError::ssh(
                        "ssh_channel",
                        "De technische servermelding kon niet worden gelezen.",
                        error,
                        true,
                    )
                })?;
            channel.wait_close().map_err(|error| {
                map_ssh_error(
                    "ssh_channel",
                    "De SSH-actie werd niet netjes afgesloten.",
                    error,
                )
            })?;
            let exit_code = channel.exit_status().map_err(|error| {
                map_ssh_error("ssh_channel", "De server gaf geen exitstatus terug.", error)
            })?;
            Ok(ExecOutput {
                stdout,
                stderr,
                exit_code,
            })
        })();
        match &result {
            Ok(output) => eprintln!(
                "site_id={} action={} started_at={} ended_at={} duration_ms={} status=complete exit_code={}",
                site.id,
                command.action_name,
                started_at,
                Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                started.elapsed().as_millis(),
                output.exit_code
            ),
            Err(error) => eprintln!(
                "site_id={} action={} started_at={} ended_at={} duration_ms={} status=failed category={}",
                site.id,
                command.action_name,
                started_at,
                Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
                started.elapsed().as_millis(),
                error.category
            ),
        }
        result
    }

    fn download(
        &self,
        site: &Site,
        credential: Option<&str>,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<u64, AppError> {
        let session = self.verified_session(site, credential, Duration::from_secs(600))?;
        let sftp = session
            .sftp()
            .map_err(|error| map_ssh_error("sftp", "SFTP kon niet worden gestart.", error))?;
        let mut remote = sftp.open(Path::new(remote_path)).map_err(|error| {
            map_ssh_error(
                "sftp",
                "De tijdelijke database-export kon niet worden geopend.",
                error,
            )
        })?;
        let local = std::fs::File::create(local_path).map_err(AppError::storage)?;
        let mut encoder = flate2::write::GzEncoder::new(local, flate2::Compression::default());
        const MAX_BACKUP_BYTES: u64 = 20 * 1024 * 1024 * 1024;
        let copied = std::io::copy(
            &mut remote.by_ref().take(MAX_BACKUP_BYTES + 1),
            &mut encoder,
        )
        .map_err(|error| {
            AppError::ssh(
                "sftp",
                "De databasebackup kon niet worden gedownload.",
                error,
                true,
            )
        })?;
        encoder.finish().map_err(AppError::storage)?;
        if copied > MAX_BACKUP_BYTES {
            return Err(AppError::ssh(
                "backup_size_limit",
                "De databasebackup is groter dan de veilige limiet van 20 GB.",
                format!("meer dan {MAX_BACKUP_BYTES} bytes"),
                false,
            ));
        }
        Ok(copied)
    }

    fn read_checksum_file(
        &self,
        site: &Site,
        credential: Option<&str>,
        relative_path: &str,
        max_bytes: usize,
    ) -> Result<RemoteFileRead, AppError> {
        if max_bytes == 0 || max_bytes > 256 * 1024 {
            return Err(AppError::validation("De previewlimiet is ongeldig."));
        }
        let session = self.verified_session(site, credential, Duration::from_secs(60))?;
        let sftp = session
            .sftp()
            .map_err(|error| map_ssh_error("sftp", "SFTP kon niet worden gestart.", error))?;
        let (canonical_target, stat) =
            Self::resolve_regular_checksum_file(&sftp, site, relative_path)?;
        let mut file = sftp.open(Path::new(&canonical_target)).map_err(|error| {
            map_ssh_error(
                "sftp_file",
                "Het checksum-bestand kon niet alleen-lezen worden geopend.",
                error,
            )
        })?;
        let opened_stat = file.stat().map_err(|error| {
            map_ssh_error(
                "sftp_file",
                "Het geopende bestand kon niet veilig worden gecontroleerd.",
                error,
            )
        })?;
        ensure_regular_file(&opened_stat)?;
        if !same_file_snapshot(&stat, &opened_stat) {
            return Err(AppError::ssh(
                "sftp_file_changed",
                "Het bestand veranderde tijdens het openen. Probeer opnieuw na een nieuwe scan.",
                relative_path,
                true,
            ));
        }
        let mut bytes = Vec::with_capacity(max_bytes.min(stat.size.unwrap_or(0) as usize));
        file.by_ref()
            .take(max_bytes as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|error| {
                AppError::ssh(
                    "sftp_file",
                    "De bestandspreview kon niet worden gelezen.",
                    error,
                    true,
                )
            })?;
        let truncated =
            bytes.len() > max_bytes || stat.size.is_some_and(|size| size > max_bytes as u64);
        bytes.truncate(max_bytes);
        Ok(RemoteFileRead {
            bytes,
            size_bytes: stat.size.unwrap_or(0),
            modified_unix: stat.mtime,
            truncated,
        })
    }

    fn delete_checksum_file(
        &self,
        site: &Site,
        credential: Option<&str>,
        relative_path: &str,
    ) -> Result<(), AppError> {
        let session = self.verified_session(site, credential, Duration::from_secs(60))?;
        let sftp = session
            .sftp()
            .map_err(|error| map_ssh_error("sftp", "SFTP kon niet worden gestart.", error))?;
        let (canonical_target, stat) =
            Self::resolve_regular_checksum_file(&sftp, site, relative_path)?;
        let before_delete = sftp.lstat(Path::new(&canonical_target)).map_err(|error| {
            map_ssh_error(
                "sftp_file",
                "Het checksum-bestand is tijdens de controle gewijzigd.",
                error,
            )
        })?;
        ensure_regular_file(&before_delete)?;
        if !same_file_snapshot(&stat, &before_delete) {
            return Err(AppError::ssh(
                "sftp_file_changed",
                "Het bestand veranderde vlak voor verwijdering. Er is niets verwijderd.",
                relative_path,
                true,
            ));
        }
        sftp.unlink(Path::new(&canonical_target)).map_err(|error| {
            map_ssh_error(
                "sftp_delete",
                "Het checksum-bestand kon niet worden verwijderd.",
                error,
            )
        })
    }
}

fn ensure_regular_file(stat: &ssh2::FileStat) -> Result<(), AppError> {
    const FILE_TYPE_MASK: u32 = 0o170000;
    const REGULAR_FILE: u32 = 0o100000;
    if stat.perm.map(|mode| mode & FILE_TYPE_MASK) != Some(REGULAR_FILE) {
        return Err(AppError::validation(
            "Alleen reguliere bestanden mogen via een checksumfinding worden geopend of verwijderd.",
        ));
    }
    Ok(())
}

fn ensure_contained_remote_path(root: &str, target: &str) -> Result<(), AppError> {
    let root = root.trim_end_matches('/');
    if root.is_empty() || target == root || !target.starts_with(&format!("{root}/")) {
        return Err(AppError::validation(
            "Het bestand valt buiten de vastgelegde WordPress-root.",
        ));
    }
    Ok(())
}

fn same_file_snapshot(left: &ssh2::FileStat, right: &ssh2::FileStat) -> bool {
    left.size == right.size && left.mtime == right.mtime && left.perm == right.perm
}

fn map_ssh_error(category: &str, message: &str, error: ssh2::Error) -> AppError {
    let detail = error.to_string();
    let effective_category = if detail.to_ascii_lowercase().contains("timed out") {
        "timeout"
    } else {
        category
    };
    AppError::ssh(effective_category, message, detail, true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_target_must_remain_below_root() {
        assert!(ensure_contained_remote_path("/srv/site", "/srv/site/wp-admin/x.php").is_ok());
        assert!(
            ensure_contained_remote_path("/srv/site", "/srv/site/wp-admin/x\\literal.php").is_ok()
        );
        assert!(ensure_contained_remote_path("/srv/site", "/srv/site").is_err());
        assert!(ensure_contained_remote_path("/srv/site", "/srv/site-backup/x.php").is_err());
        assert!(ensure_contained_remote_path("/srv/site", "/etc/passwd").is_err());
    }

    #[test]
    fn only_posix_regular_file_modes_are_allowed() {
        let regular = ssh2::FileStat {
            size: Some(12),
            uid: None,
            gid: None,
            perm: Some(0o100644),
            atime: None,
            mtime: None,
        };
        let symlink = ssh2::FileStat {
            perm: Some(0o120777),
            ..regular.clone()
        };
        let directory = ssh2::FileStat {
            perm: Some(0o040755),
            ..regular.clone()
        };
        assert!(ensure_regular_file(&regular).is_ok());
        assert!(ensure_regular_file(&symlink).is_err());
        assert!(ensure_regular_file(&directory).is_err());
    }
}
