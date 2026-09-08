use crate::{
    command_catalog::shell_escape, database::Database, error::AppError, error_log, models::Site,
    ssh::verified_terminal_password_session, terminal_auth::hash_secret,
};
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use ssh2::{Channel, Session};
use std::{
    collections::{HashMap, VecDeque},
    io::{ErrorKind, Read, Write},
    sync::{Mutex, mpsc},
    thread,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tauri::{AppHandle, Emitter};
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const MAX_INPUT_BYTES: usize = 256 * 1024;
const CONNECT_WAIT: Duration = Duration::from_secs(45);

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalConnectionInfo {
    pub session_id: String,
    pub authorization_token: String,
    pub site_id: String,
    pub start_path: String,
    pub columns: u32,
    pub rows: u32,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalOpenInput {
    pub site_id: String,
    pub challenge_token: String,
    pub ssh_password: String,
    pub columns: u32,
    pub rows: u32,
}

pub struct TerminalConnectRequest<'a> {
    pub site: Site,
    pub app_session_token: &'a str,
    pub ssh_password: Zeroizing<String>,
    pub columns: u32,
    pub rows: u32,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminalOutputEvent {
    session_id: String,
    data_base64: String,
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct TerminalStatusEvent {
    session_id: String,
    status: &'static str,
    message: Option<String>,
    error: Option<AppError>,
}

pub(crate) enum TerminalControl {
    Input(Vec<u8>),
    Resize { columns: u32, rows: u32 },
    Close,
}

struct TerminalHandle {
    site_id: String,
    app_session_hash: [u8; 32],
    authorization_hash: [u8; 32],
    sender: mpsc::Sender<TerminalControl>,
}

#[derive(Default)]
pub struct TerminalManager {
    sessions: Mutex<HashMap<String, TerminalHandle>>,
}

impl TerminalManager {
    pub fn connect(
        &self,
        app: AppHandle,
        database: Database,
        request: TerminalConnectRequest<'_>,
    ) -> Result<TerminalConnectionInfo, AppError> {
        let TerminalConnectRequest {
            site,
            app_session_token,
            ssh_password,
            columns,
            rows,
        } = request;
        let columns = columns.clamp(20, 500);
        let rows = rows.clamp(5, 300);
        self.close_site(&site.id);
        let session_id = Uuid::new_v4().to_string();
        let mut authorization_bytes = [0_u8; 32];
        getrandom::fill(&mut authorization_bytes).map_err(AppError::storage)?;
        let authorization_token = URL_SAFE_NO_PAD.encode(authorization_bytes);
        authorization_bytes.zeroize();
        let authorization_hash = hash_secret(&authorization_token);
        let app_session_hash = hash_secret(app_session_token);
        let (control_tx, control_rx) = mpsc::channel();
        let (ready_tx, ready_rx) = mpsc::sync_channel(1);
        let worker_session_id = session_id.clone();
        let worker_site = site.clone();
        thread::Builder::new()
            .name(format!("ssh-terminal-{}", &session_id[..8]))
            .spawn(move || {
                run_terminal_worker(
                    app,
                    database,
                    worker_site,
                    ssh_password,
                    worker_session_id,
                    columns,
                    rows,
                    control_rx,
                    ready_tx,
                );
            })
            .map_err(|error| {
                AppError::ssh(
                    "ssh_channel",
                    "De terminal kon niet worden gestart.",
                    error,
                    true,
                )
            })?;

        match ready_rx.recv_timeout(CONNECT_WAIT) {
            Ok(Ok(())) => {
                self.sessions
                    .lock()
                    .map_err(|_| {
                        AppError::ssh(
                            "ssh_channel",
                            "De terminalstatus is niet beschikbaar.",
                            "terminal mutex poisoned",
                            true,
                        )
                    })?
                    .insert(
                        session_id.clone(),
                        TerminalHandle {
                            site_id: site.id.clone(),
                            app_session_hash,
                            authorization_hash,
                            sender: control_tx,
                        },
                    );
                Ok(TerminalConnectionInfo {
                    session_id,
                    authorization_token,
                    site_id: site.id,
                    start_path: site.wordpress_path,
                    columns,
                    rows,
                })
            }
            Ok(Err(error)) => Err(error),
            Err(error) => Err(AppError::ssh(
                "connection_timeout",
                "De SSH-terminal reageerde niet binnen 45 seconden.",
                error,
                true,
            )),
        }
    }

    pub fn write(
        &self,
        session_id: &str,
        app_session_token: &str,
        authorization_token: &str,
        data: String,
    ) -> Result<(), AppError> {
        if data.is_empty() {
            return Ok(());
        }
        if data.len() > MAX_INPUT_BYTES {
            return Err(AppError::validation("De terminalinvoer is te groot."));
        }
        self.send_authorized(
            session_id,
            app_session_token,
            authorization_token,
            TerminalControl::Input(data.into_bytes()),
        )
    }

    pub fn resize(
        &self,
        session_id: &str,
        app_session_token: &str,
        authorization_token: &str,
        columns: u32,
        rows: u32,
    ) -> Result<(), AppError> {
        if !(20..=500).contains(&columns) || !(5..=300).contains(&rows) {
            return Err(AppError::validation("De terminalafmetingen zijn ongeldig."));
        }
        self.send_authorized(
            session_id,
            app_session_token,
            authorization_token,
            TerminalControl::Resize { columns, rows },
        )
    }

    pub fn close_authorized(
        &self,
        session_id: &str,
        app_session_token: &str,
        authorization_token: &str,
    ) -> Result<String, AppError> {
        let site_id = self.authorize(session_id, app_session_token, authorization_token)?;
        self.close(session_id)?;
        Ok(site_id)
    }

    pub fn close(&self, session_id: &str) -> Result<(), AppError> {
        let handle = self
            .sessions
            .lock()
            .map_err(|_| {
                AppError::ssh(
                    "ssh_channel",
                    "De terminalstatus is niet beschikbaar.",
                    "terminal mutex poisoned",
                    true,
                )
            })?
            .remove(session_id);
        if let Some(handle) = handle {
            let _ = handle.sender.send(TerminalControl::Close);
        }
        Ok(())
    }

    pub fn close_all(&self) {
        if let Ok(mut sessions) = self.sessions.lock() {
            for (_, handle) in sessions.drain() {
                let _ = handle.sender.send(TerminalControl::Close);
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn install_test_session(
        &self,
        session_id: &str,
        site_id: &str,
    ) -> mpsc::Receiver<TerminalControl> {
        let (sender, receiver) = mpsc::channel();
        self.sessions.lock().unwrap().insert(
            session_id.to_owned(),
            TerminalHandle {
                site_id: site_id.to_owned(),
                app_session_hash: hash_secret("test-app-session"),
                authorization_hash: hash_secret("test-terminal-authorization"),
                sender,
            },
        );
        receiver
    }

    #[cfg(test)]
    pub(crate) fn active_count(&self) -> usize {
        self.sessions.lock().unwrap().len()
    }

    pub fn close_site(&self, site_id: &str) {
        if let Ok(mut sessions) = self.sessions.lock() {
            let ids: Vec<String> = sessions
                .iter()
                .filter(|(_, handle)| handle.site_id == site_id)
                .map(|(id, _)| id.clone())
                .collect();
            for id in ids {
                if let Some(handle) = sessions.remove(&id) {
                    let _ = handle.sender.send(TerminalControl::Close);
                }
            }
        }
    }

    fn send_authorized(
        &self,
        session_id: &str,
        app_session_token: &str,
        authorization_token: &str,
        control: TerminalControl,
    ) -> Result<(), AppError> {
        let mut sessions = self.sessions.lock().map_err(|_| {
            AppError::ssh(
                "ssh_channel",
                "De terminalstatus is niet beschikbaar.",
                "terminal mutex poisoned",
                true,
            )
        })?;
        let handle = sessions.get(session_id).ok_or_else(missing_terminal)?;
        if handle
            .app_session_hash
            .ct_eq(&hash_secret(app_session_token))
            .unwrap_u8()
            != 1
            || handle
                .authorization_hash
                .ct_eq(&hash_secret(authorization_token))
                .unwrap_u8()
                != 1
        {
            return Err(invalid_terminal_authorization());
        }
        let result = handle.sender.send(control);
        if result.is_err() {
            sessions.remove(session_id);
            return Err(AppError::ssh(
                "ssh_channel",
                "De SSH-terminal is niet meer verbonden.",
                "terminal channel gesloten",
                true,
            ));
        }
        Ok(())
    }

    fn authorize(
        &self,
        session_id: &str,
        app_session_token: &str,
        authorization_token: &str,
    ) -> Result<String, AppError> {
        let sessions = self.sessions.lock().map_err(|_| {
            AppError::ssh(
                "ssh_channel",
                "De terminalstatus is niet beschikbaar.",
                "terminal mutex poisoned",
                true,
            )
        })?;
        let handle = sessions.get(session_id).ok_or_else(missing_terminal)?;
        if handle
            .app_session_hash
            .ct_eq(&hash_secret(app_session_token))
            .unwrap_u8()
            == 1
            && handle
                .authorization_hash
                .ct_eq(&hash_secret(authorization_token))
                .unwrap_u8()
                == 1
        {
            Ok(handle.site_id.clone())
        } else {
            Err(invalid_terminal_authorization())
        }
    }
}

fn missing_terminal() -> AppError {
    AppError::ssh(
        "ssh_channel",
        "De SSH-terminal is niet meer verbonden.",
        "terminal session ontbreekt",
        true,
    )
}

fn invalid_terminal_authorization() -> AppError {
    AppError::unauthorized(
        "terminal_authorization_invalid",
        "De Terminal-autorisatie is niet meer geldig. Open de Terminal opnieuw.",
    )
}

impl Drop for TerminalManager {
    fn drop(&mut self) {
        self.close_all();
    }
}

#[allow(clippy::too_many_arguments)]
fn run_terminal_worker(
    app: AppHandle,
    database: Database,
    site: Site,
    mut ssh_password: Zeroizing<String>,
    session_id: String,
    columns: u32,
    rows: u32,
    controls: mpsc::Receiver<TerminalControl>,
    ready: mpsc::SyncSender<Result<(), AppError>>,
) {
    let started = Instant::now();
    let session_result =
        verified_terminal_password_session(&site, ssh_password.as_str(), Duration::from_secs(30));
    ssh_password.zeroize();
    let session = match session_result {
        Ok(session) => session,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    if let Err(error) = verify_start_directory(&session, &site.wordpress_path) {
        let _ = ready.send(Err(error));
        return;
    }
    let mut channel = match session.channel_session().map_err(|error| {
        AppError::ssh(
            "ssh_channel",
            "De server kon geen terminalkanaal openen.",
            error,
            true,
        )
    }) {
        Ok(channel) => channel,
        Err(error) => {
            let _ = ready.send(Err(error));
            return;
        }
    };
    let shell_command = interactive_shell_command(&site.wordpress_path);
    if let Err(error) = channel
        .request_pty("xterm-256color", None, Some((columns, rows, 0, 0)))
        .map_err(|error| {
            AppError::ssh(
                "ssh_channel",
                "De server weigerde de terminal-PTY.",
                error,
                false,
            )
        })
        .and_then(|_| {
            channel.exec(&shell_command).map_err(|error| {
                AppError::ssh(
                    "ssh_channel",
                    "De interactieve SSH-shell kon niet worden gestart.",
                    error,
                    true,
                )
            })
        })
    {
        let _ = ready.send(Err(error));
        return;
    }
    if ready.send(Ok(())).is_err() {
        let _ = channel.close();
        return;
    }
    let _ = app.emit(
        "terminal-status",
        TerminalStatusEvent {
            session_id: session_id.clone(),
            status: "connected",
            message: None,
            error: None,
        },
    );
    session.set_blocking(false);
    let mut pending = VecDeque::<u8>::new();
    let mut close_requested = false;
    let mut failure: Option<AppError> = None;

    while !close_requested && !channel.eof() {
        while let Ok(control) = controls.try_recv() {
            match control {
                TerminalControl::Input(data) => pending.extend(data),
                TerminalControl::Resize { columns, rows } => {
                    if let Err(error) = channel.request_pty_size(columns, rows, None, None) {
                        failure = Some(AppError::ssh(
                            "ssh_channel",
                            "De terminalgrootte kon niet worden bijgewerkt.",
                            error,
                            true,
                        ));
                        close_requested = true;
                    }
                }
                TerminalControl::Close => close_requested = true,
            }
        }
        if close_requested {
            break;
        }

        if !pending.is_empty() {
            let contiguous = pending.make_contiguous();
            match channel.write(contiguous) {
                Ok(written) => {
                    pending.drain(..written);
                    let _ = channel.flush();
                }
                Err(error) if error.kind() == ErrorKind::WouldBlock => {}
                Err(error) => {
                    failure = Some(AppError::ssh(
                        "ssh_channel",
                        "Terminalinvoer kon niet worden verzonden.",
                        error,
                        true,
                    ));
                    break;
                }
            }
        }

        match read_available(&mut channel) {
            Ok(data) if !data.is_empty() => emit_output(&app, &session_id, &data),
            Ok(_) => {}
            Err(error) => {
                failure = Some(AppError::ssh(
                    "ssh_channel",
                    "Terminaluitvoer kon niet worden gelezen.",
                    error,
                    true,
                ));
                break;
            }
        }
        {
            let mut stderr = channel.stderr();
            match read_available(&mut stderr) {
                Ok(data) if !data.is_empty() => emit_output(&app, &session_id, &data),
                Ok(_) => {}
                Err(error) => {
                    failure = Some(AppError::ssh(
                        "ssh_channel",
                        "Technische terminaluitvoer kon niet worden gelezen.",
                        error,
                        true,
                    ));
                    break;
                }
            }
        }
        thread::sleep(Duration::from_millis(8));
    }
    let _ = channel.close();
    let _ = channel.wait_close();
    if let Some(error) = failure {
        let logged = error_log::persist_error(
            &database,
            Some(&site.id),
            Some(&site.name),
            "SSH-terminalverbinding",
            Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)),
            None,
            error,
        );
        let _ = app.emit(
            "terminal-status",
            TerminalStatusEvent {
                session_id,
                status: "failed",
                message: Some(logged.user_message.clone()),
                error: Some(logged),
            },
        );
    } else {
        let _ = app.emit(
            "terminal-status",
            TerminalStatusEvent {
                session_id,
                status: "disconnected",
                message: close_requested.then(|| "Terminal gesloten.".into()),
                error: None,
            },
        );
    }
}

fn interactive_shell_command(path: &str) -> String {
    format!(
        "cd {} || {{ printf 'WP Maintenance Manager: startdirectory bestaat niet.\\n' >&2; exit 126; }}; exec \"${{SHELL:-/bin/sh}}\" -l",
        shell_escape(path)
    )
}

fn verify_start_directory(session: &Session, path: &str) -> Result<(), AppError> {
    let mut channel = session.channel_session().map_err(|error| {
        AppError::ssh(
            "ssh_channel",
            "De WordPress-root kon niet worden gecontroleerd.",
            error,
            true,
        )
    })?;
    channel
        .exec(&format!("test -d {}", shell_escape(path)))
        .map_err(|error| {
            AppError::ssh(
                "ssh_command",
                "De WordPress-root kon niet worden gecontroleerd.",
                error,
                true,
            )
        })?;
    let status = complete_directory_check(&mut channel)?;
    if status != 0 {
        return Err(AppError::ssh(
            "filesystem",
            "De ingestelde WordPress-root bestaat niet op de server.",
            format!("Startdirectory is niet beschikbaar; exitstatus {status}"),
            false,
        ));
    }
    Ok(())
}

trait DirectoryCheckChannel {
    fn discard_stdout(&mut self) -> Result<(), AppError>;
    fn discard_stderr(&mut self) -> Result<(), AppError>;
    fn wait_remote_eof(&mut self) -> Result<(), AppError>;
    fn close_channel(&mut self) -> Result<(), AppError>;
    fn wait_remote_close(&mut self) -> Result<(), AppError>;
    fn read_exit_status(&mut self) -> Result<i32, AppError>;
}

impl DirectoryCheckChannel for Channel {
    fn discard_stdout(&mut self) -> Result<(), AppError> {
        std::io::copy(self, &mut std::io::sink())
            .map(|_| ())
            .map_err(|error| {
                AppError::ssh(
                    "ssh_channel",
                    "De uitvoer van de WordPress-rootcontrole kon niet worden verwerkt.",
                    error,
                    true,
                )
            })
    }

    fn discard_stderr(&mut self) -> Result<(), AppError> {
        std::io::copy(&mut self.stderr(), &mut std::io::sink())
            .map(|_| ())
            .map_err(|error| {
                AppError::ssh(
                    "ssh_channel",
                    "De technische uitvoer van de WordPress-rootcontrole kon niet worden verwerkt.",
                    error,
                    true,
                )
            })
    }

    fn wait_remote_eof(&mut self) -> Result<(), AppError> {
        self.wait_eof().map_err(directory_check_interrupted)
    }

    fn close_channel(&mut self) -> Result<(), AppError> {
        self.close().map_err(directory_check_interrupted)
    }

    fn wait_remote_close(&mut self) -> Result<(), AppError> {
        self.wait_close().map_err(directory_check_interrupted)
    }

    fn read_exit_status(&mut self) -> Result<i32, AppError> {
        self.exit_status().map_err(directory_check_interrupted)
    }
}

fn directory_check_interrupted(error: ssh2::Error) -> AppError {
    AppError::ssh(
        "ssh_channel",
        "De controle van de WordPress-root werd onderbroken.",
        error,
        true,
    )
}

fn complete_directory_check(channel: &mut impl DirectoryCheckChannel) -> Result<i32, AppError> {
    // libssh2 requires EOF before wait_close. Draining both streams first is
    // important because buffered stderr also keeps the channel out of EOF state.
    channel.discard_stdout()?;
    channel.discard_stderr()?;
    channel.wait_remote_eof()?;
    channel.close_channel()?;
    channel.wait_remote_close()?;
    channel.read_exit_status()
}

fn read_available(reader: &mut impl Read) -> std::io::Result<Vec<u8>> {
    let mut output = Vec::new();
    for _ in 0..16 {
        let mut buffer = [0_u8; 8192];
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => output.extend_from_slice(&buffer[..read]),
            Err(error) if error.kind() == ErrorKind::WouldBlock => break,
            Err(error) => return Err(error),
        }
    }
    Ok(output)
}

fn emit_output(app: &AppHandle, session_id: &str, data: &[u8]) {
    let _ = app.emit(
        "terminal-output",
        TerminalOutputEvent {
            session_id: session_id.into(),
            data_base64: STANDARD.encode(data),
        },
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct TestDirectoryCheckChannel {
        calls: Vec<&'static str>,
        exit_status: i32,
    }

    impl DirectoryCheckChannel for TestDirectoryCheckChannel {
        fn discard_stdout(&mut self) -> Result<(), AppError> {
            self.calls.push("discard_stdout");
            Ok(())
        }

        fn discard_stderr(&mut self) -> Result<(), AppError> {
            self.calls.push("discard_stderr");
            Ok(())
        }

        fn wait_remote_eof(&mut self) -> Result<(), AppError> {
            self.calls.push("wait_eof");
            Ok(())
        }

        fn close_channel(&mut self) -> Result<(), AppError> {
            self.calls.push("close");
            Ok(())
        }

        fn wait_remote_close(&mut self) -> Result<(), AppError> {
            self.calls.push("wait_close");
            Ok(())
        }

        fn read_exit_status(&mut self) -> Result<i32, AppError> {
            self.calls.push("exit_status");
            Ok(self.exit_status)
        }
    }

    #[test]
    fn directory_check_reaches_eof_before_waiting_for_channel_close() {
        let mut channel = TestDirectoryCheckChannel {
            exit_status: 7,
            ..Default::default()
        };

        assert_eq!(complete_directory_check(&mut channel).unwrap(), 7);
        assert_eq!(
            channel.calls,
            [
                "discard_stdout",
                "discard_stderr",
                "wait_eof",
                "close",
                "wait_close",
                "exit_status"
            ]
        );
    }

    #[test]
    fn terminal_input_is_bounded_and_resize_is_validated() {
        let manager = TerminalManager::default();
        assert!(
            manager
                .write(
                    "missing",
                    "app-session",
                    "terminal-authorization",
                    "x".repeat(MAX_INPUT_BYTES + 1),
                )
                .is_err()
        );
        assert!(
            manager
                .resize("missing", "app-session", "terminal-authorization", 5, 1)
                .is_err()
        );
    }

    #[test]
    fn cd_and_pwd_are_routed_to_the_same_persistent_shell_session() {
        let manager = TerminalManager::default();
        let (sender, receiver) = mpsc::channel();
        manager.sessions.lock().unwrap().insert(
            "session-a".into(),
            TerminalHandle {
                site_id: "site-a".into(),
                app_session_hash: hash_secret("app-session"),
                authorization_hash: hash_secret("terminal-authorization"),
                sender,
            },
        );

        manager
            .write(
                "session-a",
                "app-session",
                "terminal-authorization",
                "pwd\r".into(),
            )
            .unwrap();
        manager
            .write(
                "session-a",
                "app-session",
                "terminal-authorization",
                "cd wp-content\r".into(),
            )
            .unwrap();
        manager
            .write(
                "session-a",
                "app-session",
                "terminal-authorization",
                "pwd\r".into(),
            )
            .unwrap();

        let received: Vec<Vec<u8>> = (0..3)
            .map(|_| match receiver.recv().unwrap() {
                TerminalControl::Input(data) => data,
                _ => panic!("verwacht terminalinvoer"),
            })
            .collect();
        assert_eq!(
            received,
            [
                b"pwd\r".to_vec(),
                b"cd wp-content\r".to_vec(),
                b"pwd\r".to_vec()
            ]
        );

        manager.close_all();
        assert!(matches!(receiver.recv().unwrap(), TerminalControl::Close));
    }

    #[test]
    fn terminal_authorization_is_session_bound_and_revoked_on_close() {
        let manager = TerminalManager::default();
        let (sender, _receiver) = mpsc::channel();
        manager.sessions.lock().unwrap().insert(
            "terminal-a".into(),
            TerminalHandle {
                site_id: "site-a".into(),
                app_session_hash: hash_secret("app-session"),
                authorization_hash: hash_secret("authorization-a"),
                sender,
            },
        );
        assert!(
            manager
                .write(
                    "terminal-a",
                    "other-session",
                    "authorization-a",
                    "pwd\r".into(),
                )
                .is_err()
        );
        assert!(
            manager
                .write(
                    "terminal-a",
                    "app-session",
                    "wrong-authorization",
                    "pwd\r".into(),
                )
                .is_err()
        );
        assert_eq!(
            manager
                .close_authorized("terminal-a", "app-session", "authorization-a")
                .unwrap(),
            "site-a"
        );
        assert!(
            manager
                .write(
                    "terminal-a",
                    "app-session",
                    "authorization-a",
                    "pwd\r".into(),
                )
                .is_err()
        );
    }

    #[test]
    fn start_directory_command_is_shell_escaped() {
        let path = "/home/customer/site root/it's-here";
        let command = format!("test -d {}", shell_escape(path));
        assert_eq!(
            command,
            r#"test -d '/home/customer/site root/it'"'"'s-here'"#
        );
    }

    #[test]
    fn interactive_shell_starts_in_root_without_visible_bootstrap_input() {
        let command = interactive_shell_command("/home/customer/site root/it's-here");

        assert_eq!(
            command,
            r#"cd '/home/customer/site root/it'"'"'s-here' || { printf 'WP Maintenance Manager: startdirectory bestaat niet.\n' >&2; exit 126; }; exec "${SHELL:-/bin/sh}" -l"#
        );
        assert!(!command.contains("cd --"));
    }
}
