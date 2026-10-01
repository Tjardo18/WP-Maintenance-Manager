use crate::{
    command_catalog::RemoteCommand,
    error::AppError,
    models::{AuthMethod, Site},
    validation::{validate_checksum_file_action_path, validate_checksum_relative_path},
};
use base64::{Engine, engine::general_purpose::STANDARD_NO_PAD};
use chrono::{SecondsFormat, Utc};
use sha2::{Digest, Sha256};
use ssh2::Session;
use std::{
    io::{Read, Seek, SeekFrom},
    net::{TcpStream, ToSocketAddrs},
    path::Path,
    time::{Duration, Instant},
};

const MAX_TERMINAL_PASSWORD_BYTES: usize = 4 * 1024;
const MAX_FILE_PREVIEW_BYTES: usize = 10 * 1024 * 1024;

// Uses the phase-2 password-authenticated Session; never reconnects with managed credentials.
pub(crate) fn list_filemanager_directory(
    session: &Session,
    root: &str,
    requested: &str,
) -> Result<crate::filemanager_directory::DirectoryListing, AppError> {
    let deadline = Instant::now() + Duration::from_secs(20);
    session.set_timeout(5_000);
    let sftp = session.sftp().map_err(filemanager_sftp_error)?;
    let mut remote = FilemanagerSftp {
        session,
        sftp,
        deadline,
    };
    crate::filemanager_directory::list_directory(&mut remote, root, requested)
}

// Uses the same authenticated phase-2 SFTP session and phase-3 root resolver as listings.
pub(crate) fn read_filemanager_file(
    session: &Session,
    root: &str,
    requested: &str,
) -> Result<crate::models::FileContentPreview, AppError> {
    let deadline = Instant::now() + Duration::from_secs(20);
    session.set_timeout(5_000);
    let sftp = session.sftp().map_err(filemanager_sftp_error)?;
    let mut remote = FilemanagerSftp {
        session,
        sftp,
        deadline,
    };
    let resolved = crate::filemanager_paths::resolve_file(&mut remote, root, requested)?;
    let limit = crate::filemanager_file::preview_limit(resolved.relative().as_str());
    remote.before_call()?;
    let mut file = remote
        .sftp
        .open(Path::new(resolved.absolute()))
        .map_err(filemanager_file_error)?;
    let opened = file.stat().map_err(filemanager_file_error)?;
    if !crate::filemanager_paths::same_file_snapshot(resolved.stat(), &opened) {
        return Err(filemanager_file_changed());
    }
    resolved.revalidate(&mut remote)?;
    let mut bytes = Vec::with_capacity(limit.min(opened.size.unwrap_or(0) as usize));
    let mut buffer = [0; 16 * 1024];
    while bytes.len() <= limit {
        remote.before_call()?;
        let available = buffer.len().min(limit + 1 - bytes.len());
        let n = file.read(&mut buffer[..available]).map_err(|error| {
            let mut result = AppError::unauthorized(
                "filemanager_file_read_failed",
                "Het bestand kon niet veilig worden gelezen.",
            );
            result.technical_details = Some(format!(
                "I/O kind: {:?}; OS code: {:?}",
                error.kind(),
                error.raw_os_error()
            ));
            result.retryable = true;
            result
        })?;
        if n == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..n]);
    }
    let final_stat = resolved.revalidate(&mut remote)?;
    let truncated = bytes.len() > limit || final_stat.size.is_some_and(|size| size > limit as u64);
    bytes.truncate(limit);
    let edit_version = (!truncated
        && final_stat.size == Some(bytes.len() as u64)
        && crate::filemanager_edit::editable(requested, &bytes))
    .then(|| crate::filemanager_edit::version(resolved.absolute(), &bytes, &final_stat));
    let mut preview = crate::filemanager_file::build_preview(
        resolved.relative().as_str(),
        RemoteFileRead {
            bytes,
            size_bytes: final_stat.size.unwrap_or(0),
            modified_unix: final_stat.mtime,
            truncated,
        },
    );
    preview.edit_version = edit_version;
    Ok(preview)
}

pub(crate) fn save_filemanager_file(
    session: &Session,
    root: &str,
    requested: &str,
    content: &str,
    expected: &str,
    authorize: impl Fn() -> Result<(), AppError>,
) -> Result<crate::models::FileContentPreview, AppError> {
    crate::filemanager_edit::validate_input(content, expected)?;
    session.set_timeout(5_000);
    let mut channel = session.channel_session().map_err(filemanager_file_error)?;
    channel.subsystem("sftp").map_err(filemanager_file_error)?;
    crate::sftp_replace::handshake(&mut channel)?;
    let mut remote = FilemanagerSftp {
        session,
        sftp: session.sftp().map_err(filemanager_file_error)?,
        deadline: Instant::now() + Duration::from_secs(30),
    };
    let mut writer = FilemanagerWriter {
        remote: &mut remote,
        channel,
    };
    crate::filemanager_edit::save(&mut writer, root, requested, content, expected, authorize)
}

struct FilemanagerWriter<'a, 'b> {
    remote: &'a mut FilemanagerSftp<'b>,
    channel: ssh2::Channel,
}

impl crate::filemanager_paths::RemotePaths for FilemanagerWriter<'_, '_> {
    fn realpath(&mut self, path: &str) -> Result<String, AppError> {
        self.remote.realpath(path)
    }
    fn lstat(&mut self, path: &str) -> Result<ssh2::FileStat, AppError> {
        self.remote.lstat(path)
    }
}

impl crate::filemanager_edit::EditTransport for FilemanagerWriter<'_, '_> {
    type Temp = Option<ssh2::File>;
    fn read(
        &mut self,
        target: &crate::filemanager_paths::ResolvedFile,
    ) -> Result<Vec<u8>, AppError> {
        self.remote.before_call()?;
        let mut file = self
            .remote
            .sftp
            .open(Path::new(target.absolute()))
            .map_err(filemanager_file_error)?;
        crate::filemanager_edit::verify_handle(
            target,
            &file.stat().map_err(filemanager_file_error)?,
        )?;
        target.revalidate(self.remote)?;
        let mut bytes = Vec::new();
        let mut buffer = [0; 16 * 1024];
        loop {
            self.remote.before_call()?;
            let n = file.read(&mut buffer).map_err(filemanager_write_io_error)?;
            if n == 0 {
                break;
            }
            if bytes.len() + n > crate::filemanager_file::TEXT_PREVIEW_LIMIT_BYTES {
                return Err(crate::filemanager_edit::error(
                    "too_large",
                    "Dit bestand is te groot om te bewerken.",
                ));
            }
            bytes.extend_from_slice(&buffer[..n]);
        }
        crate::filemanager_edit::verify_handle(
            target,
            &file.stat().map_err(filemanager_file_error)?,
        )?;
        if target.stat().size != Some(bytes.len() as u64) {
            return Err(crate::filemanager_edit::conflict());
        }
        Ok(bytes)
    }
    fn check_writable(
        &mut self,
        target: &crate::filemanager_paths::ResolvedFile,
    ) -> Result<(), AppError> {
        self.remote.before_call()?;
        // Probe actual file permissions/ACL without changing contents or creating missing files.
        let mut handle = self
            .remote
            .sftp
            .open_mode(
                Path::new(target.absolute()),
                ssh2::OpenFlags::WRITE,
                0,
                ssh2::OpenType::File,
            )
            .map_err(filemanager_file_error)?;
        crate::filemanager_edit::verify_handle(
            target,
            &handle.stat().map_err(filemanager_file_error)?,
        )?;
        handle.close().map_err(filemanager_file_error)
    }
    fn create_temp(&mut self, path: &str) -> Result<Self::Temp, AppError> {
        self.remote.before_call()?;
        self.remote
            .sftp
            .open_mode(
                Path::new(path),
                ssh2::OpenFlags::READ
                    | ssh2::OpenFlags::WRITE
                    | ssh2::OpenFlags::CREATE
                    | ssh2::OpenFlags::EXCLUSIVE,
                0o600,
                ssh2::OpenType::File,
            )
            .map(Some)
            .map_err(filemanager_file_error)
    }
    fn stage(
        &mut self,
        temp: &mut Self::Temp,
        content: &[u8],
        original: &ssh2::FileStat,
    ) -> Result<(), AppError> {
        let file = temp.as_mut().unwrap();
        for chunk in content.chunks(16 * 1024) {
            self.remote.before_call()?;
            std::io::Write::write_all(file, chunk).map_err(filemanager_write_io_error)?;
        }
        self.remote.before_call()?;
        let current = file.stat().map_err(filemanager_file_error)?;
        let (Some(uid), Some(gid), Some(mode)) = (original.uid, original.gid, original.perm) else {
            return Err(crate::filemanager_edit::error(
                "metadata_invalid",
                "Eigenaarschap en permissies konden niet betrouwbaar worden vastgesteld.",
            ));
        };
        if current.uid != Some(uid) || current.gid != Some(gid) {
            file.setstat(ssh2::FileStat {
                size: None,
                uid: Some(uid),
                gid: Some(gid),
                perm: None,
                atime: None,
                mtime: None,
            })
            .map_err(filemanager_file_error)?;
        }
        file.setstat(ssh2::FileStat {
            size: None,
            uid: None,
            gid: None,
            perm: Some(mode & 0o7777),
            atime: None,
            mtime: None,
        })
        .map_err(filemanager_file_error)?;
        let staged = file.stat().map_err(filemanager_file_error)?;
        if staged.size != Some(content.len() as u64)
            || staged.perm != original.perm
            || staged.uid != original.uid
            || staged.gid != original.gid
        {
            return Err(crate::filemanager_edit::error(
                "metadata_invalid",
                "De oorspronkelijke permissies of het eigenaarschap konden niet behouden worden. Het originele bestand is niet vervangen.",
            ));
        }
        self.remote.before_call()?;
        file.fsync().map_err(filemanager_file_error)?;
        file.seek(SeekFrom::Start(0))
            .map_err(filemanager_write_io_error)?;
        let mut verified = Vec::new();
        file.take(content.len() as u64 + 1)
            .read_to_end(&mut verified)
            .map_err(filemanager_write_io_error)?;
        if verified != content {
            return Err(crate::filemanager_edit::error(
                "write_failed",
                "De tijdelijke inhoud kon niet worden bevestigd; het origineel blijft behouden.",
            ));
        }
        temp.take().unwrap().close().map_err(filemanager_file_error)
    }
    fn replace(
        &mut self,
        temp_path: &str,
        target: &crate::filemanager_paths::ResolvedFile,
    ) -> Result<(), AppError> {
        self.remote.before_call()?;
        crate::sftp_replace::replace(&mut self.channel, temp_path, target.absolute())
    }
    fn cleanup(&mut self, temp_path: &str) -> Result<(), AppError> {
        // One bounded best-effort attempt, even after the operation's deadline elapsed.
        self.remote.session.set_timeout(2_000);
        match self.remote.sftp.unlink(Path::new(temp_path)) {
            Ok(()) => Ok(()),
            Err(error) if matches!(error.code(), ssh2::ErrorCode::SFTP(2 | 10)) => Ok(()),
            Err(error) => Err(filemanager_file_error(error)),
        }
    }
}

fn filemanager_write_io_error(cause: std::io::Error) -> AppError {
    let mut error = crate::filemanager_edit::error(
        "write_failed",
        "De bestandsoverdracht is mislukt. Controleer verbinding, schrijfrechten, schijfruimte en quota. Opslaan is niet bevestigd.",
    );
    error.technical_details = Some(format!(
        "I/O kind: {:?}; OS code: {:?}",
        cause.kind(),
        cause.raw_os_error()
    ));
    error
}

struct FilemanagerSftp<'a> {
    session: &'a Session,
    sftp: ssh2::Sftp,
    deadline: Instant,
}

impl FilemanagerSftp<'_> {
    fn before_call(&self) -> Result<(), AppError> {
        let remaining = self.deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(filemanager_timeout());
        }
        self.session
            .set_timeout(remaining.as_millis().clamp(1, 5_000) as u32);
        Ok(())
    }
}

impl crate::filemanager_paths::RemotePaths for FilemanagerSftp<'_> {
    fn realpath(&mut self, path: &str) -> Result<String, AppError> {
        self.before_call()?;
        let path = decode_sftp_path(|| self.sftp.realpath(Path::new(path)))?;
        path.to_str()
            .map(String::from)
            .ok_or_else(crate::filemanager_directory::malformed_listing)
    }

    fn lstat(&mut self, path: &str) -> Result<ssh2::FileStat, AppError> {
        self.before_call()?;
        self.sftp
            .lstat(Path::new(path))
            .map_err(filemanager_sftp_error)
    }
}

impl crate::filemanager_directory::DirectoryTransport for FilemanagerSftp<'_> {
    type Handle = ssh2::File;

    fn open_directory(
        &mut self,
        path: &crate::filemanager_paths::ResolvedDirectory,
    ) -> Result<Self::Handle, AppError> {
        self.before_call()?;
        self.sftp
            .opendir(Path::new(path.absolute()))
            .map_err(filemanager_sftp_error)
    }

    fn next_entry(
        &mut self,
        handle: &mut Self::Handle,
    ) -> Result<Option<(String, ssh2::FileStat)>, AppError> {
        self.before_call()?;
        // ssh2's Windows filename conversion panics for non-UTF-8 server names.
        // Contain that decoding failure; never return a lossy, potentially different path.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| handle.readdir()))
            .map_err(|_| crate::filemanager_directory::malformed_listing())?;
        match result {
            Ok((path, stat)) => Ok(Some((
                path.to_str()
                    .ok_or_else(crate::filemanager_directory::malformed_listing)?
                    .into(),
                stat,
            ))),
            // ssh2::File::readdir uses LIBSSH2_ERROR_FILE exclusively to signal EOF.
            Err(error) if error.code() == ssh2::ErrorCode::Session(-16) => Ok(None),
            Err(error) => Err(filemanager_sftp_error(error)),
        }
    }
}

fn decode_sftp_path<T>(operation: impl FnOnce() -> Result<T, ssh2::Error>) -> Result<T, AppError> {
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation))
        .map_err(|_| crate::filemanager_directory::malformed_listing())?
        .map_err(filemanager_sftp_error)
}

fn filemanager_timeout() -> AppError {
    let mut error = AppError::unauthorized(
        "filemanager_timeout",
        "De filemanageractie duurde te lang. Verbind opnieuw en controleer de serverinhoud voordat je opnieuw opslaat.",
    );
    error.retryable = true;
    error
}

fn filemanager_sftp_error(error: ssh2::Error) -> AppError {
    use ssh2::ErrorCode::{SFTP, Session};
    let (category, message, retryable) = match error.code() {
        SFTP(2 | 10) => (
            "filemanager_directory_missing",
            "De map bestaat niet meer of is niet toegankelijk.",
            false,
        ),
        SFTP(3) => (
            "filemanager_permission_denied",
            "De SSH-gebruiker heeft geen toegang tot deze map.",
            false,
        ),
        SFTP(19) => (
            "filemanager_not_directory",
            "Het aangevraagde pad is geen map.",
            false,
        ),
        Session(-9 | -37) => return filemanager_timeout(),
        Session(-7 | -13 | -43 | -45) | SFTP(6 | 7) => (
            "filemanager_disconnected",
            "De SSH-verbinding is verbroken. Bevestig beide wachtwoorden opnieuw.",
            true,
        ),
        _ => (
            "filemanager_sftp_failed",
            "De map kon niet veilig via SFTP worden opgehaald. Verbind opnieuw en probeer het nogmaals.",
            true,
        ),
    };
    let mut result = AppError::unauthorized(category, message);
    // Numeric diagnostics only: server messages may contain sensitive paths or other data.
    result.technical_details = Some(format!("SFTP status: {:?}", error.code()));
    result.retryable = retryable;
    result
}

fn filemanager_file_error(error: ssh2::Error) -> AppError {
    let code = error.code();
    let mut mapped = filemanager_sftp_error(error);
    if matches!(code, ssh2::ErrorCode::SFTP(8 | 14 | 15)) {
        mapped.category = "filemanager_write_failed".into();
        mapped.user_message = match code {
            ssh2::ErrorCode::SFTP(8) => "De server ondersteunt een vereiste veilige bestandsactie niet (bij opslaan is ook SFTP fsync vereist).".into(),
            _ => "Opslaan is mislukt door onvoldoende vrije schijfruimte of quota.".into(),
        };
    }
    if mapped.category == "filemanager_permission_denied" {
        mapped.user_message =
            "De SSH-gebruiker heeft onvoldoende rechten voor dit bestand of de bijbehorende map."
                .into();
    }
    if mapped.category == "filemanager_sftp_failed" {
        mapped.user_message = "De bestandsactie via SFTP is mislukt. Opslaan is niet bevestigd; controleer de serverinhoud na opnieuw verbinden.".into();
    }
    match mapped.category.as_str() {
        "filemanager_directory_missing" => AppError::unauthorized(
            "filemanager_file_missing",
            "Het bestand bestaat niet meer of is niet toegankelijk.",
        ),
        "filemanager_not_directory" => AppError::unauthorized(
            "filemanager_not_file",
            "Het aangevraagde pad is geen bestand.",
        ),
        _ => mapped,
    }
}

fn filemanager_file_changed() -> AppError {
    let mut error = AppError::unauthorized(
        "filemanager_file_changed",
        "Het bestand veranderde tijdens het openen. Probeer het opnieuw.",
    );
    error.retryable = true;
    error
}

#[derive(Debug, Clone)]
pub struct ExecOutput {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: i32,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct RemoteFileRead {
    pub bytes: Vec<u8>,
    pub size_bytes: u64,
    pub modified_unix: Option<u64>,
    pub truncated: bool,
}

#[derive(Debug, Clone)]
pub struct RemoteFileFingerprint {
    pub relative_path: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub modified_unix: Option<u64>,
    pub file_type: String,
}

#[derive(Debug, Clone)]
pub struct RemoteFileFingerprintObservation {
    pub relative_path: String,
    pub fingerprint: Option<RemoteFileFingerprint>,
    pub error: Option<AppError>,
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

    fn open_connection<'a>(
        &'a self,
        site: &'a Site,
        credential: Option<&'a str>,
    ) -> Result<Box<dyn SshConnection + 'a>, AppError> {
        self.authenticate(site, credential)?;
        Ok(Box::new(ExecutorConnection {
            executor: self,
            site,
            credential,
        }))
    }
    fn download(
        &self,
        site: &Site,
        credential: Option<&str>,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<u64, AppError>;

    fn read_site_file(
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

    fn fingerprint_file(
        &self,
        _site: &Site,
        _credential: Option<&str>,
        _relative_path: &str,
    ) -> Result<Option<RemoteFileFingerprint>, AppError> {
        Err(AppError::validation(
            "Bestandsvertrouwen wordt niet ondersteund door deze SSH-uitvoerder.",
        ))
    }

    fn fingerprint_files(
        &self,
        site: &Site,
        credential: Option<&str>,
        relative_paths: &[String],
    ) -> Result<Vec<RemoteFileFingerprintObservation>, AppError> {
        Ok(relative_paths
            .iter()
            .map(
                |relative_path| match self.fingerprint_file(site, credential, relative_path) {
                    Ok(fingerprint) => RemoteFileFingerprintObservation {
                        relative_path: relative_path.clone(),
                        fingerprint,
                        error: None,
                    },
                    Err(error) => RemoteFileFingerprintObservation {
                        relative_path: relative_path.clone(),
                        fingerprint: None,
                        error: Some(error),
                    },
                },
            )
            .collect())
    }
}

pub trait SshConnection {
    fn execute(&mut self, command: &RemoteCommand) -> Result<ExecOutput, AppError>;
}

struct ExecutorConnection<'a, E: SshExecutor + ?Sized> {
    executor: &'a E,
    site: &'a Site,
    credential: Option<&'a str>,
}

impl<E: SshExecutor + ?Sized> SshConnection for ExecutorConnection<'_, E> {
    fn execute(&mut self, command: &RemoteCommand) -> Result<ExecOutput, AppError> {
        self.executor.execute(self.site, self.credential, command)
    }
}

struct Ssh2Connection {
    session: Session,
    site_id: String,
}

impl SshConnection for Ssh2Connection {
    fn execute(&mut self, command: &RemoteCommand) -> Result<ExecOutput, AppError> {
        execute_on_session(&self.session, &self.site_id, command)
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
            let lower = error.to_ascii_lowercase();
            let (category, message) = if lower.contains("timed out") {
                (
                    "connection_timeout",
                    "De SSH-server reageerde niet binnen de toegestane tijd.",
                )
            } else if lower.contains("connection refused") || lower.contains("10061") {
                (
                    "network",
                    "De server is bereikbaar, maar weigert de SSH-verbinding.",
                )
            } else {
                ("network", "Kan geen SSH-verbinding maken.")
            };
            AppError::ssh(category, message, error, true)
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
        let session = self.verified_host_session(site, timeout)?;
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

    fn verified_host_session(&self, site: &Site, timeout: Duration) -> Result<Session, AppError> {
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
        Ok(session)
    }

    fn resolve_regular_site_file(
        sftp: &ssh2::Sftp,
        site: &Site,
        relative_path: &str,
    ) -> Result<(String, ssh2::FileStat), AppError> {
        validate_checksum_relative_path(relative_path)?;
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
            map_ssh_error("sftp_file", "Het bestand is niet meer beschikbaar.", error)
        })?;
        ensure_regular_file(&initial)?;
        let canonical_target = sftp
            .realpath(Path::new(&candidate))
            .map_err(|error| {
                map_ssh_error(
                    "sftp_path",
                    "Het bestand kon niet veilig worden bepaald.",
                    error,
                )
            })?
            .to_string_lossy()
            .into_owned();
        ensure_contained_remote_path(canonical_root, &canonical_target)?;
        let final_stat = sftp.lstat(Path::new(&canonical_target)).map_err(|error| {
            map_ssh_error(
                "sftp_file",
                "Het bestand is tijdens de controle gewijzigd.",
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

    fn fingerprint_with_sftp(
        sftp: &ssh2::Sftp,
        site: &Site,
        relative_path: &str,
    ) -> Result<Option<RemoteFileFingerprint>, AppError> {
        validate_checksum_relative_path(relative_path)?;
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
                "De serverroot mag niet als WordPress-root voor bestandsvertrouwen worden gebruikt.",
            ));
        }
        let candidate = format!("{canonical_root}/{relative_path}");
        let initial = match sftp.lstat(Path::new(&candidate)) {
            Ok(stat) => stat,
            Err(error) if is_sftp_missing(&error) => return Ok(None),
            Err(error) => {
                return Err(map_ssh_error(
                    "sftp_file",
                    "Het te vertrouwen bestand kon niet worden gecontroleerd.",
                    error,
                ));
            }
        };
        ensure_regular_file(&initial)?;
        let canonical_target = sftp
            .realpath(Path::new(&candidate))
            .map_err(|error| {
                map_ssh_error(
                    "sftp_path",
                    "Het te vertrouwen bestand kon niet veilig worden bepaald.",
                    error,
                )
            })?
            .to_string_lossy()
            .into_owned();
        ensure_contained_remote_path(canonical_root, &canonical_target)?;
        let before_open = sftp.lstat(Path::new(&canonical_target)).map_err(|error| {
            map_ssh_error(
                "sftp_file",
                "Het bestand veranderde tijdens de veiligheidscontrole.",
                error,
            )
        })?;
        ensure_regular_file(&before_open)?;
        if !same_file_snapshot(&initial, &before_open) {
            return Err(file_changed_error(relative_path));
        }
        let mut file = sftp.open(Path::new(&canonical_target)).map_err(|error| {
            map_ssh_error(
                "sftp_file",
                "Het bestand kon niet alleen-lezen worden geopend voor hashing.",
                error,
            )
        })?;
        let opened = file.stat().map_err(|error| {
            map_ssh_error(
                "sftp_file",
                "Het geopende bestand kon niet veilig worden gecontroleerd.",
                error,
            )
        })?;
        ensure_regular_file(&opened)?;
        if !same_file_snapshot(&before_open, &opened) {
            return Err(file_changed_error(relative_path));
        }

        let (sha256, bytes_read) = stream_sha256(&mut file)?;
        let after_read = sftp.lstat(Path::new(&canonical_target)).map_err(|error| {
            map_ssh_error(
                "sftp_file",
                "Het bestand veranderde tijdens het hashen.",
                error,
            )
        })?;
        ensure_regular_file(&after_read)?;
        if !same_file_snapshot(&opened, &after_read)
            || opened.size.is_some_and(|size| size != bytes_read)
        {
            return Err(file_changed_error(relative_path));
        }
        Ok(Some(RemoteFileFingerprint {
            relative_path: relative_path.into(),
            sha256,
            size_bytes: bytes_read,
            modified_unix: after_read.mtime,
            file_type: "regular".into(),
        }))
    }
}

pub(crate) fn verified_terminal_password_session(
    site: &Site,
    password: &str,
    timeout: Duration,
) -> Result<Session, AppError> {
    validate_terminal_password(password)?;
    let session = Ssh2Executor.verified_host_session(site, timeout)?;
    let methods = match session.auth_methods(&site.ssh_username) {
        Ok(methods) => methods,
        Err(_error) if session.authenticated() => {
            return Err(password_auth_unsupported(
                "server accepteerde authenticatie zonder wachtwoord",
            ));
        }
        Err(error) => {
            return Err(map_ssh_error(
                "ssh_authentication",
                "De beschikbare SSH-authenticatiemethoden konden niet worden gecontroleerd.",
                error,
            ));
        }
    };
    if !password_auth_supported(methods) {
        return Err(password_auth_unsupported(&format!(
            "aangeboden methoden: {}",
            if methods.is_empty() { "geen" } else { methods }
        )));
    }
    session
        .userauth_password(&site.ssh_username, password)
        .map_err(|error| {
            map_ssh_error(
                "ssh_authentication",
                &format!(
                    "Het wachtwoord voor SSH-gebruiker {} werd niet geaccepteerd.",
                    site.ssh_username
                ),
                error,
            )
        })?;
    if !session.authenticated() {
        return Err(AppError::ssh(
            "ssh_authentication",
            format!(
                "Het wachtwoord voor SSH-gebruiker {} werd niet geaccepteerd.",
                site.ssh_username
            ),
            "server weigerde expliciete password-authenticatie",
            false,
        ));
    }
    Ok(session)
}

fn password_auth_supported(methods: &str) -> bool {
    methods.split(',').any(|method| method.trim() == "password")
}

fn validate_terminal_password(password: &str) -> Result<(), AppError> {
    if password.is_empty() || password.len() > MAX_TERMINAL_PASSWORD_BYTES {
        return Err(AppError::validation(
            "Voer een geldig SSH-wachtwoord in voor deze Terminalverbinding.",
        ));
    }
    Ok(())
}

fn password_auth_unsupported(detail: &str) -> AppError {
    AppError::ssh(
        "ssh_password_auth_unsupported",
        "Deze server accepteert geen SSH-wachtwoordauthenticatie. Terminaltoegang kan met de huidige beveiligingsinstelling niet worden geopend.",
        detail,
        false,
    )
}

fn execute_on_session(
    session: &Session,
    site_id: &str,
    command: &RemoteCommand,
) -> Result<ExecOutput, AppError> {
    let started = Instant::now();
    let started_at = Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true);
    session.set_timeout(command.timeout.as_millis().min(u32::MAX as u128) as u32);
    let result = (|| {
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
        let mut truncated = stdout.len() > command.max_output_bytes;
        if truncated {
            if !command.truncate_output {
                let _ = channel.close();
                return Err(AppError::ssh(
                    "output_limit",
                    "De server stuurde te veel gegevens terug; de actie is veilig afgebroken.",
                    format!("limiet {} bytes", command.max_output_bytes),
                    false,
                ));
            }
            stdout.truncate(command.max_output_bytes);
            std::io::copy(&mut channel, &mut std::io::sink()).map_err(|error| {
                AppError::ssh(
                    "ssh_channel",
                    "Het resterende serverantwoord kon niet worden verwerkt.",
                    error,
                    true,
                )
            })?;
        }
        let mut stderr = Vec::new();
        {
            let mut stderr_stream = channel.stderr();
            stderr_stream
                .by_ref()
                .take(256 * 1024 + 1)
                .read_to_end(&mut stderr)
                .map_err(|error| {
                    AppError::ssh(
                        "ssh_channel",
                        "De technische servermelding kon niet worden gelezen.",
                        error,
                        true,
                    )
                })?;
            if stderr.len() > 256 * 1024 {
                if !command.truncate_output {
                    let _ = channel.close();
                    return Err(AppError::ssh(
                        "output_limit",
                        "De server stuurde te veel technische uitvoer terug; de actie is veilig afgebroken.",
                        "stderr-limiet 262144 bytes",
                        false,
                    ));
                }
                stderr.truncate(256 * 1024);
                truncated = true;
                std::io::copy(&mut stderr_stream, &mut std::io::sink()).map_err(|error| {
                    AppError::ssh(
                        "ssh_channel",
                        "De resterende technische uitvoer kon niet worden verwerkt.",
                        error,
                        true,
                    )
                })?;
            }
        }
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
            truncated,
        })
    })();
    match &result {
        Ok(output) => eprintln!(
            "site_id={} action={} started_at={} ended_at={} duration_ms={} status=complete exit_code={}",
            site_id,
            command.action_name,
            started_at,
            Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            started.elapsed().as_millis(),
            output.exit_code
        ),
        Err(error) => eprintln!(
            "site_id={} action={} started_at={} ended_at={} duration_ms={} status=failed category={}",
            site_id,
            command.action_name,
            started_at,
            Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            started.elapsed().as_millis(),
            error.category
        ),
    }
    result
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
        execute_on_session(&session, &site.id, command)
    }

    fn open_connection<'a>(
        &'a self,
        site: &'a Site,
        credential: Option<&'a str>,
    ) -> Result<Box<dyn SshConnection + 'a>, AppError> {
        let session = self.verified_session(site, credential, Self::CONNECT_TIMEOUT)?;
        Ok(Box::new(Ssh2Connection {
            session,
            site_id: site.id.clone(),
        }))
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

    fn read_site_file(
        &self,
        site: &Site,
        credential: Option<&str>,
        relative_path: &str,
        max_bytes: usize,
    ) -> Result<RemoteFileRead, AppError> {
        if max_bytes == 0 || max_bytes > MAX_FILE_PREVIEW_BYTES {
            return Err(AppError::validation("De previewlimiet is ongeldig."));
        }
        let session = self.verified_session(site, credential, Duration::from_secs(60))?;
        let sftp = session
            .sftp()
            .map_err(|error| map_ssh_error("sftp", "SFTP kon niet worden gestart.", error))?;
        let (canonical_target, stat) = Self::resolve_regular_site_file(&sftp, site, relative_path)?;
        let mut file = sftp.open(Path::new(&canonical_target)).map_err(|error| {
            map_ssh_error(
                "sftp_file",
                "Het bestand kon niet alleen-lezen worden geopend.",
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
        validate_checksum_file_action_path(relative_path)?;
        let session = self.verified_session(site, credential, Duration::from_secs(60))?;
        let sftp = session
            .sftp()
            .map_err(|error| map_ssh_error("sftp", "SFTP kon niet worden gestart.", error))?;
        let (canonical_target, stat) = Self::resolve_regular_site_file(&sftp, site, relative_path)?;
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

    fn fingerprint_file(
        &self,
        site: &Site,
        credential: Option<&str>,
        relative_path: &str,
    ) -> Result<Option<RemoteFileFingerprint>, AppError> {
        let session = self.verified_session(site, credential, Duration::from_secs(300))?;
        let sftp = session
            .sftp()
            .map_err(|error| map_ssh_error("sftp", "SFTP kon niet worden gestart.", error))?;
        Self::fingerprint_with_sftp(&sftp, site, relative_path)
    }

    fn fingerprint_files(
        &self,
        site: &Site,
        credential: Option<&str>,
        relative_paths: &[String],
    ) -> Result<Vec<RemoteFileFingerprintObservation>, AppError> {
        if relative_paths.is_empty() {
            return Ok(Vec::new());
        }
        let session = self.verified_session(site, credential, Duration::from_secs(300))?;
        let sftp = session
            .sftp()
            .map_err(|error| map_ssh_error("sftp", "SFTP kon niet worden gestart.", error))?;
        Ok(relative_paths
            .iter()
            .map(
                |relative_path| match Self::fingerprint_with_sftp(&sftp, site, relative_path) {
                    Ok(fingerprint) => RemoteFileFingerprintObservation {
                        relative_path: relative_path.clone(),
                        fingerprint,
                        error: None,
                    },
                    Err(error) => RemoteFileFingerprintObservation {
                        relative_path: relative_path.clone(),
                        fingerprint: None,
                        error: Some(error),
                    },
                },
            )
            .collect())
    }
}

fn is_sftp_missing(error: &ssh2::Error) -> bool {
    matches!(error.code(), ssh2::ErrorCode::SFTP(2 | 10))
}

fn stream_sha256(reader: &mut impl Read) -> Result<(String, u64), AppError> {
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    let mut bytes_read = 0_u64;
    loop {
        let count = reader.read(&mut buffer).map_err(|error| {
            AppError::ssh(
                "sftp_file",
                "Het bestand kon niet volledig worden gehasht.",
                error,
                true,
            )
        })?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        bytes_read = bytes_read.checked_add(count as u64).ok_or_else(|| {
            AppError::validation("Het bestand is te groot om veilig te verwerken.")
        })?;
    }
    let digest = hasher.finalize();
    Ok((
        digest.iter().map(|byte| format!("{byte:02x}")).collect(),
        bytes_read,
    ))
}

fn file_changed_error(relative_path: &str) -> AppError {
    AppError::ssh(
        "sftp_file_changed",
        "Het bestand veranderde tijdens het hashen. Probeer opnieuw na een nieuwe scan.",
        relative_path,
        true,
    )
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
        "connection_timeout"
    } else {
        category
    };
    AppError::ssh(effective_category, message, detail, true)
}

#[cfg(test)]
mod tests {
    #[test]
    fn filemanager_sftp_errors_use_typed_codes_without_server_text() {
        use ssh2::ErrorCode::{SFTP, Session};
        let server_message = "/internal/server/path: test diagnostic";
        for (code, expected) in [
            (SFTP(2), "filemanager_directory_missing"),
            (SFTP(3), "filemanager_permission_denied"),
            (SFTP(19), "filemanager_not_directory"),
            (Session(-9), "filemanager_timeout"),
            (Session(-13), "filemanager_disconnected"),
            (SFTP(7), "filemanager_disconnected"),
            (Session(-31), "filemanager_sftp_failed"),
        ] {
            let error = super::filemanager_sftp_error(ssh2::Error::new(code, server_message));
            assert_eq!(error.category, expected);
            assert!(!format!("{error:?}").contains(server_message));
        }
    }

    #[test]
    fn filemanager_file_errors_distinguish_missing_permission_and_disconnect() {
        use ssh2::ErrorCode::{SFTP, Session};
        let server_message = "permission denied at /internal/secret/path";
        for (code, expected) in [
            (SFTP(2), "filemanager_file_missing"),
            (SFTP(3), "filemanager_permission_denied"),
            (Session(-13), "filemanager_disconnected"),
        ] {
            let error = super::filemanager_file_error(ssh2::Error::new(code, server_message));
            assert_eq!(error.category, expected);
            assert!(!format!("{error:?}").contains(server_message));
        }
    }

    #[test]
    fn filemanager_contains_ssh2_filename_decoding_panics() {
        let result: Result<(), crate::error::AppError> =
            super::decode_sftp_path(|| panic!("simulated filename decoder failure"));
        assert_eq!(
            result.unwrap_err().category,
            "filemanager_invalid_directory_response"
        );
    }
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

    #[test]
    fn hashes_large_files_in_bounded_streaming_chunks() {
        struct BoundedReader {
            remaining: usize,
            largest_request: usize,
        }
        impl Read for BoundedReader {
            fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
                self.largest_request = self.largest_request.max(buffer.len());
                let count = self.remaining.min(buffer.len());
                buffer[..count].fill(b'x');
                self.remaining -= count;
                Ok(count)
            }
        }
        let size = 8 * 1024 * 1024 + 13;
        let mut reader = BoundedReader {
            remaining: size,
            largest_request: 0,
        };
        let (hash, bytes) = stream_sha256(&mut reader).unwrap();
        assert_eq!(bytes, size as u64);
        assert_eq!(hash.len(), 64);
        assert!(reader.largest_request <= 64 * 1024);
    }

    #[test]
    fn interactive_terminal_requires_explicit_password_method() {
        assert!(password_auth_supported("publickey,password"));
        assert!(password_auth_supported("keyboard-interactive, password"));
        assert!(!password_auth_supported("publickey,keyboard-interactive"));
        assert!(!password_auth_supported("password-change"));
        let error = password_auth_unsupported("aangeboden methoden: publickey");
        assert_eq!(error.category, "ssh_password_auth_unsupported");
        assert!(
            error
                .user_message
                .contains("geen SSH-wachtwoordauthenticatie")
        );
        assert!(validate_terminal_password("").is_err());
        assert!(validate_terminal_password(&"x".repeat(MAX_TERMINAL_PASSWORD_BYTES + 1)).is_err());
        assert!(validate_terminal_password("normal password").is_ok());
    }
}
