use crate::{
    command_catalog::RemoteCommand,
    error::AppError,
    models::{AuthMethod, Site},
};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use sha2::{Digest, Sha256};
use ssh2::Session;
use std::{
    io::Read,
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    time::Duration,
};

#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
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
}

#[derive(Debug, Clone, Default)]
pub struct Ssh2Executor;

impl Ssh2Executor {
    const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

    fn handshake(&self, site: &Site, timeout: Duration) -> Result<Session, AppError> {
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
    }
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
