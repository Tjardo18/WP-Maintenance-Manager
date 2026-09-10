use crate::{
    auth, checksum_files,
    command_catalog::{RemoteAction, RemoteCommand, build},
    core_operations, engine,
    error::AppError,
    error_log, maintenance,
    models::{
        AppSettings, AuditEvent, AuthStatus, BulkScanStart, ChecksumDeleteFailure,
        ChecksumDeleteResult, ConnectionStep, ConnectionTestResult, CoreOperationInfo,
        CoreOperationKind, CoreOperationResult, ErrorLogFilter, ErrorLogPage, ExceptionScope,
        FilePreview, FindingException, FindingExceptionInput, LoginResult, MaintenanceRun,
        MaintenanceStep, PasswordChangeInput, ScanJobState, ScanResult,
        SecurityPolicyMutationResult, Site, SiteInput, SiteStatus, StepStatus, StoredSite,
        TrustedFile, TrustedFileInput, TrustedFileStatus, UpdateItem, VulnerabilityRefreshJobState,
        WordPressUserDeleteInput, WordPressUserUpdateInput, WordPressUsersData,
        WordfenceIntegrationStatus,
    },
    security_policy,
    state::AppState,
    terminal::{TerminalConnectRequest, TerminalConnectionInfo, TerminalOpenInput},
    terminal_auth::TerminalChallengeInfo,
    validation::validate_site,
    wordfence, wordpress_users, wp_cli, wp_cli_catalog,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize;
use std::{
    collections::{HashSet, VecDeque},
    fs,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Instant,
};
use tauri::{AppHandle, Emitter, Manager, State};
use zeroize::Zeroizing;

#[tauri::command(async)]
pub fn get_auth_status(
    session_token: Option<String>,
    state: State<'_, AppState>,
) -> Result<AuthStatus, AppError> {
    let config = state.database.auth_config()?;
    let idle_timeout_minutes = config
        .as_ref()
        .map_or(auth::DEFAULT_IDLE_MINUTES, |config| {
            config.idle_timeout_minutes
        });
    let authenticated = session_token
        .as_deref()
        .is_some_and(|token| state.auth.validate(token, idle_timeout_minutes).is_ok());
    Ok(AuthStatus {
        configured: config.is_some(),
        authenticated,
        idle_timeout_minutes,
        retry_after_seconds: state.auth.retry_after_seconds()?,
    })
}

#[tauri::command(async)]
pub fn setup_password(
    password: String,
    state: State<'_, AppState>,
) -> Result<LoginResult, AppError> {
    if state.database.auth_config()?.is_some() {
        return Err(AppError::validation(
            "De applicatiebeveiliging is al ingesteld.",
        ));
    }
    let password_hash = auth::hash_password(&password)?;
    let config = state.database.create_auth_config(&password_hash)?;
    let session_token = state.auth.create_session()?;
    state.database.save_audit_event(
        None,
        "auth_setup",
        "local_app",
        "success",
        Some("Applicatiewachtwoord ingesteld"),
    )?;
    Ok(LoginResult {
        session_token,
        idle_timeout_minutes: config.idle_timeout_minutes,
    })
}

#[tauri::command(async)]
pub fn login(password: String, state: State<'_, AppState>) -> Result<LoginResult, AppError> {
    state.auth.ensure_login_allowed()?;
    let config = state
        .database
        .auth_config()?
        .ok_or_else(|| AppError::validation("Stel eerst een applicatiewachtwoord in."))?;
    if !auth::verify_password(&password, &config.password_hash) {
        let delay = state.auth.register_login_failure()?;
        if let Err(error) = state.database.save_audit_event(
            None,
            "login",
            "local_app",
            "failed",
            Some("Onjuist applicatiewachtwoord"),
        ) {
            eprintln!("security audit write failed category={}", error.category);
        }
        if delay > 0 {
            return Err(AppError::rate_limited(delay));
        }
        return Err(AppError::unauthorized(
            "invalid_password",
            "Het wachtwoord is niet correct.",
        ));
    }
    let session_token = state.auth.create_session()?;
    state
        .database
        .save_audit_event(None, "login", "local_app", "success", None)?;
    Ok(LoginResult {
        session_token,
        idle_timeout_minutes: config.idle_timeout_minutes,
    })
}

#[tauri::command(async)]
pub fn touch_session(session_token: String, state: State<'_, AppState>) -> Result<(), AppError> {
    require_auth(&state, &session_token)
}

#[tauri::command(async)]
pub fn lock_app(session_token: String, state: State<'_, AppState>) -> Result<(), AppError> {
    require_auth(&state, &session_token)?;
    state.terminals.close_all();
    state.terminal_access.revoke_all();
    state.auth.invalidate()?;
    state.database.save_audit_event(
        None,
        "lock",
        "local_app",
        "success",
        Some("Handmatig of door inactiviteit vergrendeld"),
    )
}

#[tauri::command(async)]
pub fn change_password(
    session_token: String,
    input: PasswordChangeInput,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    require_auth(&state, &session_token)?;
    change_password_internal(state.inner(), &input)
}

fn change_password_internal(state: &AppState, input: &PasswordChangeInput) -> Result<(), AppError> {
    let config = state
        .database
        .auth_config()?
        .ok_or_else(|| AppError::validation("Stel eerst een applicatiewachtwoord in."))?;
    if !auth::verify_password(&input.current_password, &config.password_hash) {
        return Err(AppError::unauthorized(
            "invalid_password",
            "Het huidige wachtwoord is niet correct.",
        ));
    }
    let new_hash = auth::hash_password(&input.new_password)?;
    state.database.update_password_hash(&new_hash)?;
    let audit_result =
        state
            .database
            .save_audit_event(None, "password_change", "local_app", "success", None);
    state.terminals.close_all();
    state.terminal_access.revoke_all();
    state.auth.invalidate()?;
    audit_result
}

#[tauri::command(async)]
pub fn set_idle_timeout(
    session_token: String,
    minutes: u16,
    state: State<'_, AppState>,
) -> Result<AuthStatus, AppError> {
    require_auth(&state, &session_token)?;
    auth::validate_idle_minutes(minutes)?;
    state.database.set_idle_timeout(minutes)?;
    Ok(AuthStatus {
        configured: true,
        authenticated: true,
        idle_timeout_minutes: minutes,
        retry_after_seconds: 0,
    })
}

#[tauri::command(async)]
pub fn list_audit_events(
    session_token: String,
    site_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<AuditEvent>, AppError> {
    require_auth(&state, &session_token)?;
    state.database.list_audit_events(site_id.as_deref())
}

#[tauri::command(async)]
pub fn list_error_logs(
    session_token: String,
    filter: ErrorLogFilter,
    state: State<'_, AppState>,
) -> Result<ErrorLogPage, AppError> {
    require_auth(&state, &session_token)?;
    state.database.list_error_logs(&filter)
}

fn log_operation_error<T>(
    state: &AppState,
    site_id: Option<&str>,
    action: &str,
    started: Instant,
    result: Result<T, AppError>,
) -> Result<T, AppError> {
    result.map_err(|error| {
        let site_name = site_id
            .and_then(|id| state.database.get_site(id).ok())
            .map(|stored| stored.site.name);
        error_log::persist_error(
            &state.database,
            site_id,
            site_name.as_deref(),
            action,
            Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)),
            None,
            error,
        )
    })
}

fn require_auth(state: &AppState, session_token: &str) -> Result<(), AppError> {
    let config = state.database.auth_config()?.ok_or_else(|| {
        AppError::unauthorized(
            "setup_required",
            "Beveilig de applicatie voordat je verdergaat.",
        )
    })?;
    let result = state
        .auth
        .require(session_token, config.idle_timeout_minutes);
    if let Err(error) = &result
        && matches!(
            error.category.as_str(),
            "locked" | "session_expired" | "setup_required"
        )
    {
        state.terminals.close_all();
        state.terminal_access.revoke_all();
    }
    result
}

#[tauri::command(async)]
pub fn get_wp_cli_catalog(
    session_token: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<wp_cli_catalog::WpCliCatalog, AppError> {
    require_auth(&state, &session_token)?;
    Ok(wp_cli_catalog::load_from_app(&app))
}

#[tauri::command(async)]
pub fn inspect_wp_cli_command(
    session_token: String,
    site_id: String,
    command: String,
    state: State<'_, AppState>,
) -> Result<wp_cli::WpCliCommandInspection, AppError> {
    require_auth(&state, &session_token)?;
    let stored = state.database.get_site(&site_id)?;
    wp_cli::inspect_command(&command, &stored.site.wordpress_path)
}

#[tauri::command(async)]
pub fn execute_wp_cli_command(
    session_token: String,
    site_id: String,
    command: String,
    confirmed: bool,
    typed_confirmation: Option<String>,
    state: State<'_, AppState>,
) -> Result<wp_cli::WpCliExecutionResult, AppError> {
    require_auth(&state, &session_token)?;
    let started = Instant::now();
    let result = execute_wp_cli_internal(
        state.inner(),
        &site_id,
        &command,
        confirmed,
        typed_confirmation.as_deref(),
    );
    log_operation_error(
        &state,
        Some(&site_id),
        "WP-CLI command uitvoeren",
        started,
        result,
    )
}

#[tauri::command(async)]
pub fn begin_terminal_reauthentication(
    session_token: String,
    site_id: String,
    app_password: String,
    state: State<'_, AppState>,
) -> Result<TerminalChallengeInfo, AppError> {
    require_auth(&state, &session_token)?;
    begin_terminal_reauthentication_internal(
        state.inner(),
        &session_token,
        &site_id,
        Zeroizing::new(app_password),
    )
}

fn begin_terminal_reauthentication_internal(
    state: &AppState,
    session_token: &str,
    site_id: &str,
    app_password: Zeroizing<String>,
) -> Result<TerminalChallengeInfo, AppError> {
    let stored = state.database.get_site(site_id)?;
    let config = state
        .database
        .auth_config()?
        .ok_or_else(|| AppError::validation("Stel eerst een applicatiewachtwoord in."))?;
    if !auth::verify_password(app_password.as_str(), &config.password_hash) {
        if let Err(error) = state.database.save_audit_event(
            Some(site_id),
            "terminal_reauthentication",
            &stored.site.ssh_username,
            "failed",
            Some("Extra applicatieverificatie voor Terminal mislukt"),
        ) {
            eprintln!("security audit write failed category={}", error.category);
        }
        state.terminals.close_all();
        state.terminal_access.revoke_all();
        if let Err(error) = state.auth.invalidate() {
            eprintln!("session invalidation failed category={}", error.category);
        }
        if let Err(error) = state.database.save_audit_event(
            Some(site_id),
            "app_session_revoked",
            "terminal_reauthentication",
            "success",
            Some("Sessie ingetrokken na mislukte extra Terminal-verificatie"),
        ) {
            eprintln!("security audit write failed category={}", error.category);
        }
        return Err(AppError::unauthorized(
            "app_session_revoked_reauth_failed",
            "Sessie beëindigd. De extra beveiligingscontrole voor de Terminal is mislukt. Log opnieuw in om verder te gaan.",
        ));
    }
    let challenge = state
        .terminal_access
        .create_challenge(session_token, site_id)?;
    if let Err(error) = state.database.save_audit_event(
        Some(site_id),
        "terminal_reauthentication",
        &stored.site.ssh_username,
        "success",
        Some("Extra applicatieverificatie bevestigd; tijdelijke challenge uitgegeven"),
    ) {
        eprintln!("security audit write failed category={}", error.category);
    }
    Ok(challenge)
}

#[tauri::command(async)]
pub fn cancel_terminal_reauthentication(
    session_token: String,
    site_id: String,
    challenge_token: String,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    require_auth(&state, &session_token)?;
    state
        .terminal_access
        .cancel_challenge(&session_token, &site_id, &challenge_token)
}

#[tauri::command(async)]
pub fn open_terminal(
    session_token: String,
    input: TerminalOpenInput,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<TerminalConnectionInfo, AppError> {
    require_auth(&state, &session_token)?;
    let TerminalOpenInput {
        site_id,
        challenge_token,
        ssh_password,
        columns,
        rows,
    } = input;
    let started = Instant::now();
    let result = (|| {
        state
            .terminal_access
            .consume_challenge(&session_token, &site_id, &challenge_token)?;
        let stored = state.database.get_site(&site_id)?;
        state.terminals.connect(
            app,
            state.database.clone(),
            TerminalConnectRequest {
                site: stored.site,
                app_session_token: &session_token,
                ssh_password: Zeroizing::new(ssh_password),
                columns,
                rows,
            },
        )
    })();
    match &result {
        Ok(_) => {
            state
                .terminal_access
                .clear_ssh_failures(&session_token, &site_id);
            if let Err(error) = state.database.save_audit_event(
                Some(&site_id),
                "terminal_opened",
                "interactive_ssh",
                "success",
                Some("App-reauthenticatie en expliciete SSH-passwordauthenticatie geslaagd"),
            ) {
                eprintln!("security audit write failed category={}", error.category);
            }
        }
        Err(error) if error.category == "ssh_authentication" => {
            let delay = state
                .terminal_access
                .register_ssh_failure(&session_token, &site_id)
                .unwrap_or(0);
            let details =
                (delay > 0).then_some("SSH-authenticatie mislukt; korte vertraging actief");
            if let Err(audit_error) = state.database.save_audit_event(
                Some(&site_id),
                "terminal_ssh_auth_failed",
                "interactive_ssh",
                "failed",
                details,
            ) {
                eprintln!(
                    "security audit write failed category={}",
                    audit_error.category
                );
            }
        }
        Err(_) => {}
    }
    log_operation_error(
        &state,
        Some(&site_id),
        "SSH-terminal verbinden",
        started,
        result,
    )
}

#[tauri::command(async)]
pub fn write_terminal(
    session_token: String,
    terminal_session_id: String,
    terminal_authorization: String,
    data: String,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    if let Err(error) = require_auth(&state, &session_token) {
        let _ = state.terminals.close(&terminal_session_id);
        return Err(error);
    }
    state.terminals.write(
        &terminal_session_id,
        &session_token,
        &terminal_authorization,
        data,
    )
}

#[tauri::command(async)]
pub fn resize_terminal(
    session_token: String,
    terminal_session_id: String,
    terminal_authorization: String,
    columns: u32,
    rows: u32,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    if let Err(error) = require_auth(&state, &session_token) {
        let _ = state.terminals.close(&terminal_session_id);
        return Err(error);
    }
    state.terminals.resize(
        &terminal_session_id,
        &session_token,
        &terminal_authorization,
        columns,
        rows,
    )
}

#[tauri::command(async)]
pub fn close_terminal(
    session_token: String,
    terminal_session_id: String,
    terminal_authorization: String,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    require_auth(&state, &session_token)?;
    let site_id = state.terminals.close_authorized(
        &terminal_session_id,
        &session_token,
        &terminal_authorization,
    )?;
    if let Err(error) = state.database.save_audit_event(
        Some(&site_id),
        "terminal_closed",
        "interactive_ssh",
        "success",
        None,
    ) {
        eprintln!("security audit write failed category={}", error.category);
    }
    Ok(())
}

fn execute_wp_cli_internal(
    state: &AppState,
    site_id: &str,
    command: &str,
    confirmed: bool,
    typed_confirmation: Option<&str>,
) -> Result<wp_cli::WpCliExecutionResult, AppError> {
    let stored = state.database.get_site(site_id)?;
    let prepared = wp_cli::prepare_command(command, &stored.site.wordpress_path)?;
    wp_cli::validate_confirmation(&prepared.inspection, confirmed, typed_confirmation)?;
    let credential = stored_credential_from_state(state, &stored)?;
    let started_at = crate::database::utc_now();
    let timer = Instant::now();
    let output = match state.ssh.execute(
        &stored.site,
        credential.as_deref(),
        &prepared.remote_command,
    ) {
        Ok(output) => output,
        Err(error) => {
            let duration_ms = u64::try_from(timer.elapsed().as_millis()).unwrap_or(u64::MAX);
            save_wp_cli_audit(
                state,
                site_id,
                &prepared.inspection,
                "failed",
                &format!(
                    "risk={}; category={}; duration_ms={duration_ms}",
                    prepared.inspection.risk.as_audit(),
                    error.category
                ),
            );
            return Err(error);
        }
    };
    let duration_ms = u64::try_from(timer.elapsed().as_millis()).unwrap_or(u64::MAX);
    let stdout = wp_cli::sanitize_output(&output.stdout);
    let stderr = wp_cli::sanitize_output(&output.stderr);
    let status = if output.exit_code != 0 {
        wp_cli::WpCliExecutionStatus::Failed
    } else if stderr.trim().is_empty() {
        wp_cli::WpCliExecutionStatus::Success
    } else {
        wp_cli::WpCliExecutionStatus::Warning
    };
    if output.exit_code != 0 {
        let error = AppError::command_failed("WP-CLI command", output.exit_code, &stderr);
        let site_name = stored.site.name.as_str();
        let _ = error_log::persist_error(
            &state.database,
            Some(site_id),
            Some(site_name),
            "WP-CLI command uitvoeren",
            Some(duration_ms),
            Some(output.exit_code),
            error,
        );
    }
    save_wp_cli_audit(
        state,
        site_id,
        &prepared.inspection,
        status.as_audit(),
        &format!(
            "risk={}; exit_code={}; duration_ms={duration_ms}; truncated={}",
            prepared.inspection.risk.as_audit(),
            output.exit_code,
            output.truncated
        ),
    );
    Ok(wp_cli::WpCliExecutionResult {
        status,
        risk: prepared.inspection.risk,
        command_family: prepared.inspection.command_family,
        stdout,
        stderr,
        exit_code: output.exit_code,
        duration_ms,
        started_at,
        finished_at: crate::database::utc_now(),
        truncated: output.truncated,
    })
}

fn save_wp_cli_audit(
    state: &AppState,
    site_id: &str,
    inspection: &wp_cli::WpCliCommandInspection,
    status: &str,
    details: &str,
) {
    if let Err(error) = state.database.save_audit_event(
        Some(site_id),
        "wp_cli_console",
        &format!("wp:{}", inspection.command_family),
        status,
        Some(details),
    ) {
        eprintln!("security audit write failed category={}", error.category);
    }
}

#[tauri::command(async)]
pub fn list_sites(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<Vec<Site>, AppError> {
    require_auth(&state, &session_token)?;
    state.database.list_sites()
}

#[tauri::command(async)]
pub fn save_site(
    session_token: String,
    mut input: SiteInput,
    state: State<'_, AppState>,
) -> Result<Site, AppError> {
    require_auth(&state, &session_token)?;
    validate_site(&input)?;
    let is_new = input.id.is_none();
    let is_new_password =
        is_new && matches!(input.auth_method, crate::models::AuthMethod::Password);
    if is_new_password && input.credential_secret.as_deref().is_none_or(str::is_empty) {
        return Err(AppError::validation("Vul het SSH-wachtwoord in."));
    }
    let provisional_id = input
        .id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    input.id = Some(provisional_id.clone());
    let credential_ref = format!("site:{provisional_id}:ssh");
    let has_secret = input
        .credential_secret
        .as_deref()
        .is_some_and(|secret| !secret.is_empty());
    if let Some(secret) = input
        .credential_secret
        .as_deref()
        .filter(|secret| !secret.is_empty())
    {
        state.credentials.set(&credential_ref, secret)?;
    }
    input.credential_secret = None;
    match state
        .database
        .save_site(&input, has_secret.then_some(credential_ref.as_str()))
    {
        Ok(site) => Ok(site),
        Err(error) => {
            if is_new && has_secret {
                let _ = state.credentials.delete(&credential_ref);
            }
            Err(error)
        }
    }
}

#[tauri::command(async)]
pub fn delete_site(
    session_token: String,
    id: String,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    require_auth(&state, &session_token)?;
    uuid::Uuid::parse_str(&id).map_err(|_| AppError::validation("De website-id is ongeldig."))?;
    state.terminals.close_site(&id);
    state.terminal_access.revoke_site(&id);
    if let Some(reference) = state.database.delete_site(&id)? {
        state.credentials.delete(&reference)?;
    }
    Ok(())
}

#[tauri::command(async)]
pub fn accept_host_key(
    session_token: String,
    site_id: String,
    fingerprint: String,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    require_auth(&state, &session_token)?;
    uuid::Uuid::parse_str(&site_id)
        .map_err(|_| AppError::validation("De website-id is ongeldig."))?;
    if !fingerprint.starts_with("SHA256:")
        || fingerprint.len() < 20
        || fingerprint.len() > 100
        || !fingerprint[7..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"+/=_-".contains(&byte))
    {
        return Err(AppError::validation(
            "De SSH-fingerprint heeft een ongeldig formaat.",
        ));
    }
    let stored = state.database.get_site(&site_id)?;
    let actual = state.ssh.fingerprint(&stored.site)?;
    if actual != fingerprint {
        return Err(AppError::ssh(
            "host_key_changed_during_acceptance",
            "De serveridentiteit veranderde tijdens het accepteren. Er is niets opgeslagen.",
            format!("Getoond {fingerprint}; nu ontvangen {actual}"),
            false,
        ));
    }
    state.database.set_host_key(&site_id, &actual)
}

#[tauri::command(async)]
pub fn test_connection(
    session_token: String,
    input: SiteInput,
    state: State<'_, AppState>,
) -> Result<ConnectionTestResult, AppError> {
    require_auth(&state, &session_token)?;
    let started = Instant::now();
    validate_site(&input)?;
    let existing = match input.id.as_deref() {
        Some(id) => Some(state.database.get_site(id)?),
        None => None,
    };
    let mut site = site_from_input(&input, existing.as_ref());
    if existing.as_ref().is_some_and(|stored| {
        stored.site.ssh_host != input.ssh_host || stored.site.ssh_port != input.ssh_port
    }) {
        site.pinned_host_key = None;
    }
    let credential = match input
        .credential_secret
        .as_deref()
        .filter(|secret| !secret.is_empty())
    {
        Some(secret) => Some(secret.to_owned()),
        None => match existing
            .as_ref()
            .and_then(|stored| stored.credential_ref.as_deref())
        {
            Some(reference) => state.credentials.get_optional(reference)?,
            None => None,
        },
    };
    let mut steps = connection_steps();
    let fingerprint = match state.ssh.fingerprint(&site) {
        Ok(fingerprint) => {
            steps[0].status = StepStatus::Success;
            fingerprint
        }
        Err(error) => {
            steps[0].status = StepStatus::Failed;
            return Ok(failed_connection_with_log(
                &state, &site, started, steps, None, error,
            ));
        }
    };
    match site.pinned_host_key.as_deref() {
        None => {
            steps[1].status = StepStatus::Warning;
            steps[1].detail = Some(fingerprint.clone());
            return Ok(ConnectionTestResult {
                success: false,
                steps,
                fingerprint: Some(fingerprint),
                requires_host_key_acceptance: true,
                wordpress_version: None,
                php_version: None,
                wp_cli_version: None,
                detected_url: None,
                error: None,
            });
        }
        Some(expected) if expected != fingerprint => {
            steps[1].status = StepStatus::Failed;
            return Ok(failed_connection_with_log(
                &state,
                &site,
                started,
                steps,
                Some(fingerprint.clone()),
                AppError::ssh(
                    "host_key_mismatch",
                    "Waarschuwing: de identiteit van de SSH-server is gewijzigd. De verbinding is geblokkeerd.",
                    format!("Verwacht {expected}; ontvangen {fingerprint}"),
                    false,
                ),
            ));
        }
        Some(_) => steps[1].status = StepStatus::Success,
    }
    if let Err(error) = state.ssh.authenticate(&site, credential.as_deref()) {
        steps[2].status = StepStatus::Failed;
        return Ok(failed_connection_with_log(
            &state,
            &site,
            started,
            steps,
            Some(fingerprint),
            error,
        ));
    }
    steps[2].status = StepStatus::Success;

    if let Err(error) = run_readonly(
        state.ssh.as_ref(),
        &site,
        credential.as_deref(),
        build(&site.wordpress_path, RemoteAction::TestWordPressPath)?,
    ) {
        steps[3].status = StepStatus::Failed;
        return Ok(failed_connection_with_log(
            &state,
            &site,
            started,
            steps,
            Some(fingerprint),
            error,
        ));
    }
    steps[3].status = StepStatus::Success;

    let wp_cli_version = match run_readonly(
        state.ssh.as_ref(),
        &site,
        credential.as_deref(),
        build(&site.wordpress_path, RemoteAction::GetWpCliVersion)?,
    ) {
        Ok(value) => value.trim().trim_start_matches("WP-CLI ").to_owned(),
        Err(mut error) => {
            error.category = "wp_cli_missing".into();
            error.user_message = "WP-CLI is niet beschikbaar op deze server.".into();
            steps[4].status = StepStatus::Failed;
            return Ok(failed_connection_with_log(
                &state,
                &site,
                started,
                steps,
                Some(fingerprint),
                error,
            ));
        }
    };
    steps[4].status = StepStatus::Success;

    if let Err(mut error) = run_readonly(
        state.ssh.as_ref(),
        &site,
        credential.as_deref(),
        build(&site.wordpress_path, RemoteAction::DetectWordPress)?,
    ) {
        error.category = "invalid_wordpress_path".into();
        error.user_message = "Op dit pad is geen werkende WordPress-installatie gevonden.".into();
        steps[5].status = StepStatus::Failed;
        return Ok(failed_connection_with_log(
            &state,
            &site,
            started,
            steps,
            Some(fingerprint),
            error,
        ));
    }
    steps[5].status = StepStatus::Success;

    if let Err(error) = run_readonly(
        state.ssh.as_ref(),
        &site,
        credential.as_deref(),
        build(&site.wordpress_path, RemoteAction::CheckDatabase)?,
    ) {
        steps[6].status = StepStatus::Failed;
        return Ok(failed_connection_with_log(
            &state,
            &site,
            started,
            steps,
            Some(fingerprint),
            error,
        ));
    }
    steps[6].status = StepStatus::Success;

    let wordpress_version = run_readonly(
        state.ssh.as_ref(),
        &site,
        credential.as_deref(),
        build(&site.wordpress_path, RemoteAction::GetWordPressVersion)?,
    )?
    .trim()
    .to_owned();
    let php_version = run_readonly(
        state.ssh.as_ref(),
        &site,
        credential.as_deref(),
        build(&site.wordpress_path, RemoteAction::GetPhpVersion)?,
    )?
    .trim()
    .to_owned();
    let detected_url = run_readonly(
        state.ssh.as_ref(),
        &site,
        credential.as_deref(),
        build(&site.wordpress_path, RemoteAction::GetSiteUrl)?,
    )?
    .trim()
    .to_owned();
    Ok(ConnectionTestResult {
        success: true,
        steps,
        fingerprint: Some(fingerprint),
        requires_host_key_acceptance: false,
        wordpress_version: Some(wordpress_version),
        php_version: Some(php_version),
        wp_cli_version: Some(wp_cli_version),
        detected_url: Some(detected_url),
        error: None,
    })
}

const SITE_SCAN_STEPS: &[(&str, &str)] = &[
    ("ssh_connect", "SSH-verbinding"),
    ("wordpress_detection", "WordPress detecteren"),
    ("wordpress", "WordPress-informatie"),
    ("checksum", "WordPress core checksum"),
    ("users", "Gebruikersaccounts"),
    ("php", "PHP-bestanden"),
    ("uploads", "PHP in uploads"),
    ("modified", "Gewijzigde bestanden"),
    ("permissions", "Bestandsrechten"),
    ("configuration", "WordPress-configuratie"),
    ("database", "Databasecontrole"),
    ("core_updates", "WordPress-updates"),
    ("plugin_list", "Plugin-updates"),
    ("theme_list", "Thema-updates"),
    ("homepage", "Homepagecontrole"),
    ("persist", "Resultaten opslaan"),
];

#[tauri::command(async)]
pub fn start_site_scan(
    session_token: String,
    site_id: String,
    modified_days: u16,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ScanJobState, AppError> {
    require_auth(&state, &session_token)?;
    crate::validation::validate_days(modified_days)?;
    uuid::Uuid::parse_str(&site_id)
        .map_err(|_| AppError::validation("De website-id is ongeldig."))?;
    let site = state.database.get_site(&site_id)?.site;
    let (job, created) = state
        .scan_jobs
        .create_site_scan(&site.id, &site.name, SITE_SCAN_STEPS)?;
    emit_scan_job(&app, &job);
    if created {
        let job_id = job.id.clone();
        let worker_app = app.clone();
        if let Err(error) = std::thread::Builder::new()
            .name(format!("site-scan-{}", &job_id[..8]))
            .spawn(move || run_scan_job(worker_app, job_id, site_id, modified_days))
        {
            let error = AppError::storage(error);
            let failed = state.scan_jobs.fail(&job.id, error.clone())?;
            emit_scan_job(&app, &failed);
            return Err(error);
        }
    }
    Ok(job)
}

#[tauri::command(async)]
pub fn get_scan_job(
    session_token: String,
    job_id: String,
    state: State<'_, AppState>,
) -> Result<ScanJobState, AppError> {
    require_auth(&state, &session_token)?;
    state.scan_jobs.get(&job_id)
}

#[tauri::command(async)]
pub fn get_site_scan_job(
    session_token: String,
    site_id: String,
    state: State<'_, AppState>,
) -> Result<Option<ScanJobState>, AppError> {
    require_auth(&state, &session_token)?;
    state.scan_jobs.for_site(&site_id)
}

#[tauri::command(async)]
pub fn list_scan_jobs(
    session_token: String,
    active_only: bool,
    state: State<'_, AppState>,
) -> Result<Vec<ScanJobState>, AppError> {
    require_auth(&state, &session_token)?;
    state.scan_jobs.list(active_only)
}

#[tauri::command(async)]
pub fn cancel_site_scan(
    session_token: String,
    job_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ScanJobState, AppError> {
    require_auth(&state, &session_token)?;
    let job = state.scan_jobs.cancel(&job_id)?;
    emit_scan_job(&app, &job);
    Ok(job)
}

#[tauri::command(async)]
pub fn start_all_site_scans(
    session_token: String,
    modified_days: u16,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BulkScanStart, AppError> {
    require_auth(&state, &session_token)?;
    crate::validation::validate_days(modified_days)?;
    let sites = state.database.list_sites()?;
    let mut jobs = Vec::with_capacity(sites.len());
    let mut queued = VecDeque::new();
    for site in sites {
        let (job, created) =
            state
                .scan_jobs
                .create_site_scan(&site.id, &site.name, SITE_SCAN_STEPS)?;
        emit_scan_job(&app, &job);
        if created {
            queued.push_back((job.id.clone(), site.id));
        }
        jobs.push(job);
    }
    if !queued.is_empty() {
        let worker_count = state
            .scan_concurrency
            .load(Ordering::SeqCst)
            .clamp(1, 5)
            .min(queued.len());
        let queued = Arc::new(Mutex::new(queued));
        let worker_app = app.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("bulk-site-scan-coordinator".into())
            .spawn(move || {
                std::thread::scope(|scope| {
                    for _ in 0..worker_count {
                        let queue = Arc::clone(&queued);
                        let app = worker_app.clone();
                        scope.spawn(move || {
                            loop {
                                let next = queue.lock().ok().and_then(|mut jobs| jobs.pop_front());
                                let Some((job_id, site_id)) = next else {
                                    break;
                                };
                                run_scan_job(app.clone(), job_id, site_id, modified_days);
                            }
                        });
                    }
                });
            })
        {
            let error = AppError::storage(error);
            for job in &jobs {
                if job.status.is_active()
                    && let Ok(failed) = state.scan_jobs.fail(&job.id, error.clone())
                {
                    emit_scan_job(&app, &failed);
                }
            }
            return Err(error);
        }
    }
    Ok(BulkScanStart { jobs })
}

#[tauri::command(async)]
pub fn cancel_scan_jobs(
    session_token: String,
    job_ids: Vec<String>,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<Vec<ScanJobState>, AppError> {
    require_auth(&state, &session_token)?;
    if job_ids.len() > 500 {
        return Err(AppError::validation(
            "Er zijn te veel scantaken geselecteerd.",
        ));
    }
    let mut jobs = Vec::with_capacity(job_ids.len());
    for job_id in job_ids {
        let job = state.scan_jobs.cancel(&job_id)?;
        emit_scan_job(&app, &job);
        jobs.push(job);
    }
    Ok(jobs)
}

fn run_scan_job(app: AppHandle, job_id: String, site_id: String, modified_days: u16) {
    let state = app.state::<AppState>();
    let cancellation = match state.scan_jobs.cancellation(&job_id) {
        Ok(cancellation) => cancellation,
        Err(error) => {
            eprintln!(
                "scan job cancellation lookup failed category={}",
                error.category
            );
            return;
        }
    };
    let _permit = match state.scan_jobs.acquire(&cancellation) {
        Ok(Some(permit)) => permit,
        Ok(None) => {
            if let Ok(job) = state.scan_jobs.mark_cancelled(&job_id) {
                emit_scan_job(&app, &job);
            }
            return;
        }
        Err(error) => {
            if let Ok(job) = state.scan_jobs.fail(&job_id, error) {
                emit_scan_job(&app, &job);
            }
            return;
        }
    };
    if cancellation.load(Ordering::SeqCst) {
        if let Ok(job) = state.scan_jobs.mark_cancelled(&job_id) {
            emit_scan_job(&app, &job);
        }
        return;
    }
    match state.scan_jobs.mark_running(&job_id) {
        Ok(job) => emit_scan_job(&app, &job),
        Err(error) => {
            eprintln!("scan job start failed category={}", error.category);
            return;
        }
    }
    let progress_site_name = state
        .scan_jobs
        .get(&job_id)
        .map(|job| job.site_name)
        .unwrap_or_else(|_| site_id.clone());
    let mut progress = JobScanProgress {
        app: &app,
        state: &state,
        job_id: &job_id,
        site_id: &site_id,
        site_name: &progress_site_name,
        cancellation: Arc::clone(&cancellation),
    };
    let started = Instant::now();
    let result = scan_site_internal_with_progress(&state, &site_id, modified_days, &mut progress);
    if cancellation.load(Ordering::SeqCst) {
        if let Ok(job) = state.scan_jobs.mark_cancelled(&job_id) {
            emit_scan_job(&app, &job);
        }
        return;
    }
    match result {
        Ok(scan) => {
            eprintln!(
                "site_id={} job_id={} scan_total_ms={} status=completed",
                site_id,
                job_id,
                started.elapsed().as_millis()
            );
            if let Ok(job) = state.scan_jobs.complete(&job_id, &scan.id) {
                emit_scan_job(&app, &job);
            }
        }
        Err(error) => {
            if error.category == "scan_cancelled" {
                if let Ok(job) = state.scan_jobs.mark_cancelled(&job_id) {
                    emit_scan_job(&app, &job);
                }
                return;
            }
            let site_name = state
                .database
                .get_site(&site_id)
                .ok()
                .map(|stored| stored.site.name);
            eprintln!(
                "site_id={} job_id={} scan_total_ms={} status=failed category={}",
                site_id,
                job_id,
                started.elapsed().as_millis(),
                error.category
            );
            let logged = error_log::persist_error(
                &state.database,
                Some(&site_id),
                site_name.as_deref(),
                "Securityscan uitvoeren",
                Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)),
                None,
                error,
            );
            if let Ok(job) = state.scan_jobs.fail(&job_id, logged) {
                emit_scan_job(&app, &job);
            }
        }
    }
}

struct JobScanProgress<'a> {
    app: &'a AppHandle,
    state: &'a AppState,
    job_id: &'a str,
    site_id: &'a str,
    site_name: &'a str,
    cancellation: Arc<AtomicBool>,
}

impl engine::ScanProgress for JobScanProgress<'_> {
    fn is_cancelled(&self) -> bool {
        self.cancellation.load(Ordering::SeqCst)
    }

    fn step_started(&mut self, key: &str) {
        if let Ok(job) = self.state.scan_jobs.step_started(self.job_id, key) {
            emit_scan_job(self.app, &job);
        }
    }

    fn step_finished(
        &mut self,
        key: &str,
        status: StepStatus,
        duration_ms: u64,
        detail: Option<String>,
    ) {
        if status == StepStatus::Failed {
            let message = detail.as_deref().unwrap_or("De scanstap is mislukt.");
            let _ = error_log::persist_error(
                &self.state.database,
                Some(self.site_id),
                Some(self.site_name),
                &format!("Scan · {key}"),
                Some(duration_ms),
                None,
                AppError::ssh("scan_step_failed", message, key, true),
            );
        }
        if let Ok(job) =
            self.state
                .scan_jobs
                .step_finished(self.job_id, key, status, duration_ms, detail)
        {
            emit_scan_job(self.app, &job);
        }
    }
}

fn emit_scan_job(app: &AppHandle, job: &ScanJobState) {
    if let Err(error) = app.emit("scan-job-updated", job) {
        eprintln!("scan job event failed: {error}");
    }
}

#[tauri::command(async)]
pub fn list_scan_runs(
    session_token: String,
    site_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<ScanResult>, AppError> {
    require_auth(&state, &session_token)?;
    uuid::Uuid::parse_str(&site_id)
        .map_err(|_| AppError::validation("De website-id is ongeldig."))?;
    state.database.list_scans(&site_id)
}

#[tauri::command(async)]
pub fn list_finding_exceptions(
    session_token: String,
    site_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<FindingException>, AppError> {
    require_auth(&state, &session_token)?;
    validate_optional_site_id(site_id.as_deref())?;
    state.database.list_finding_exceptions(site_id.as_deref())
}

#[tauri::command(async)]
pub fn ignore_finding(
    session_token: String,
    input: FindingExceptionInput,
    state: State<'_, AppState>,
) -> Result<SecurityPolicyMutationResult, AppError> {
    require_auth(&state, &session_token)?;
    let started = Instant::now();
    let site_id = input.site_id.clone();
    let result = ignore_finding_internal(&state, input);
    log_operation_error(
        &state,
        Some(&site_id),
        "Securitymelding negeren",
        started,
        result,
    )
}

fn ignore_finding_internal(
    state: &AppState,
    input: FindingExceptionInput,
) -> Result<SecurityPolicyMutationResult, AppError> {
    validate_security_ids(&input.site_id, &input.finding_id)?;
    let note = validate_policy_note(input.note)?;
    let expires_at = validate_expiration(input.expires_at)?;
    let context = state
        .database
        .get_finding_context(&input.site_id, &input.finding_id)?;
    let target = security_policy::finding_target(&context.finding)?;
    let finding_type = security_policy::finding_type(&context.finding);
    let existing = state
        .database
        .list_finding_exceptions(Some(&input.site_id))?
        .into_iter()
        .find(|exception| {
            exception.active
                && exception.check_type == context.check_type
                && exception.finding_type == finding_type
                && exception.target == target
        });
    let now = crate::database::utc_now();
    let exception = FindingException {
        id: existing
            .map(|exception| exception.id)
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        site_id: input.site_id.clone(),
        site_name: state.database.get_site(&input.site_id)?.site.name,
        check_type: context.check_type,
        finding_type,
        target: target.clone(),
        scope: ExceptionScope::Site,
        reason: if expires_at.is_some() {
            "Handmatig tijdelijk genegeerd".into()
        } else {
            "Handmatig genegeerd".into()
        },
        note,
        created_at: now,
        expires_at,
        active: true,
    };
    state.database.save_finding_exception(&exception)?;
    state.database.save_audit_event(
        Some(&input.site_id),
        "finding_ignored",
        &target,
        "success",
        Some(&format!(
            "scan_id={}; check_type={}; finding_type={}; expires_at={}",
            context.scan_run_id,
            exception.check_type,
            exception.finding_type,
            exception.expires_at.as_deref().unwrap_or("never")
        )),
    )?;
    Ok(SecurityPolicyMutationResult {
        scan: reapply_latest_policy(state, &input.site_id)?,
        finding_exception: Some(exception),
        trusted_file: None,
    })
}

#[tauri::command(async)]
pub fn remove_finding_exception(
    session_token: String,
    exception_id: String,
    state: State<'_, AppState>,
) -> Result<SecurityPolicyMutationResult, AppError> {
    require_auth(&state, &session_token)?;
    validate_uuid(&exception_id, "De uitzondering-id is ongeldig.")?;
    let site_id = state.database.deactivate_finding_exception(&exception_id)?;
    state.database.save_audit_event(
        Some(&site_id),
        "finding_unignored",
        &exception_id,
        "success",
        None,
    )?;
    Ok(SecurityPolicyMutationResult {
        scan: reapply_latest_policy(&state, &site_id)?,
        finding_exception: None,
        trusted_file: None,
    })
}

#[tauri::command(async)]
pub fn list_trusted_files(
    session_token: String,
    site_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<TrustedFile>, AppError> {
    require_auth(&state, &session_token)?;
    validate_optional_site_id(site_id.as_deref())?;
    state.database.list_trusted_files(site_id.as_deref())
}

#[tauri::command(async)]
pub fn trust_finding_file(
    session_token: String,
    input: TrustedFileInput,
    state: State<'_, AppState>,
) -> Result<SecurityPolicyMutationResult, AppError> {
    require_auth(&state, &session_token)?;
    let started = Instant::now();
    let site_id = input.site_id.clone();
    let result = trust_finding_file_internal(&state, input);
    log_operation_error(
        &state,
        Some(&site_id),
        "Bestandsfingerprint vertrouwen",
        started,
        result,
    )
}

fn trust_finding_file_internal(
    state: &AppState,
    input: TrustedFileInput,
) -> Result<SecurityPolicyMutationResult, AppError> {
    validate_security_ids(&input.site_id, &input.finding_id)?;
    let note = validate_policy_note(input.note)?;
    let context = state
        .database
        .get_finding_context(&input.site_id, &input.finding_id)?;
    if matches!(
        context.finding.checksum_status,
        Some(crate::models::ChecksumStatus::Missing | crate::models::ChecksumStatus::ScanError)
    ) {
        return Err(AppError::validation(
            "Een ontbrekend of niet gecontroleerd bestand kan niet worden vertrouwd.",
        ));
    }
    let relative_path = context
        .finding
        .path
        .as_deref()
        .ok_or_else(|| AppError::validation("Deze melding verwijst niet naar een bestand."))
        .and_then(security_policy::normalize_relative_path)?;
    let stored = state.database.get_site(&input.site_id)?;
    let credential = stored_credential_from_state(state, &stored)?;
    let fingerprint = state
        .ssh
        .fingerprint_file(&stored.site, credential.as_deref(), &relative_path)?
        .ok_or_else(|| AppError::validation("Het bestand bestaat niet meer op de server."))?;
    let now = crate::database::utc_now();
    let existing = state
        .database
        .active_trusted_file(&input.site_id, &relative_path)?;
    let trusted = TrustedFile {
        id: existing
            .as_ref()
            .map(|trusted| trusted.id.clone())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string()),
        site_id: input.site_id.clone(),
        site_name: stored.site.name,
        relative_path: fingerprint.relative_path,
        trusted_sha256: fingerprint.sha256.clone(),
        current_sha256: Some(fingerprint.sha256),
        size_bytes: fingerprint.size_bytes,
        current_size_bytes: Some(fingerprint.size_bytes),
        modified_at_snapshot: remote_timestamp(fingerprint.modified_unix),
        current_modified_at: remote_timestamp(fingerprint.modified_unix),
        file_type: fingerprint.file_type,
        status: TrustedFileStatus::Trusted,
        trusted_at: now.clone(),
        last_checked_at: Some(now),
        note: note.or_else(|| existing.and_then(|trusted| trusted.note)),
        active: true,
    };
    state.database.save_trusted_file(&trusted)?;
    state.database.save_audit_event(
        Some(&context.site_id),
        "file_trusted",
        &relative_path,
        "success",
        Some(&format!(
            "scan_id={}; finding_id={}; algorithm=sha256",
            context.scan_run_id, input.finding_id
        )),
    )?;
    Ok(SecurityPolicyMutationResult {
        scan: reapply_latest_policy(state, &input.site_id)?,
        finding_exception: None,
        trusted_file: Some(trusted),
    })
}

#[tauri::command(async)]
pub fn retrust_file(
    session_token: String,
    trusted_file_id: String,
    state: State<'_, AppState>,
) -> Result<SecurityPolicyMutationResult, AppError> {
    require_auth(&state, &session_token)?;
    validate_uuid(&trusted_file_id, "De trustregistratie-id is ongeldig.")?;
    let started = Instant::now();
    let initial = state.database.get_trusted_file(&trusted_file_id)?;
    let site_id = initial.site_id.clone();
    let result = (|| {
        if !initial.active {
            return Err(AppError::validation(
                "Deze trustregistratie is al ingetrokken.",
            ));
        }
        let stored = state.database.get_site(&initial.site_id)?;
        let credential = stored_credential_from_state(&state, &stored)?;
        let fingerprint = state
            .ssh
            .fingerprint_file(&stored.site, credential.as_deref(), &initial.relative_path)?
            .ok_or_else(|| AppError::validation("Het bestand bestaat niet meer op de server."))?;
        let now = crate::database::utc_now();
        let mut trusted = initial;
        trusted.trusted_sha256 = fingerprint.sha256.clone();
        trusted.current_sha256 = Some(fingerprint.sha256);
        trusted.size_bytes = fingerprint.size_bytes;
        trusted.current_size_bytes = Some(fingerprint.size_bytes);
        trusted.modified_at_snapshot = remote_timestamp(fingerprint.modified_unix);
        trusted.current_modified_at = remote_timestamp(fingerprint.modified_unix);
        trusted.file_type = fingerprint.file_type;
        trusted.status = TrustedFileStatus::Trusted;
        trusted.trusted_at = now.clone();
        trusted.last_checked_at = Some(now);
        state.database.save_trusted_file(&trusted)?;
        state.database.save_audit_event(
            Some(&trusted.site_id),
            "trusted_fingerprint_updated",
            &trusted.relative_path,
            "success",
            Some("algorithm=sha256"),
        )?;
        Ok(SecurityPolicyMutationResult {
            scan: reapply_latest_policy(&state, &trusted.site_id)?,
            finding_exception: None,
            trusted_file: Some(trusted),
        })
    })();
    log_operation_error(
        &state,
        Some(&site_id),
        "Vertrouwde fingerprint vernieuwen",
        started,
        result,
    )
}

#[tauri::command(async)]
pub fn revoke_trusted_file(
    session_token: String,
    trusted_file_id: String,
    state: State<'_, AppState>,
) -> Result<SecurityPolicyMutationResult, AppError> {
    require_auth(&state, &session_token)?;
    validate_uuid(&trusted_file_id, "De trustregistratie-id is ongeldig.")?;
    let trusted = state.database.get_trusted_file(&trusted_file_id)?;
    let site_id = state.database.deactivate_trusted_file(&trusted_file_id)?;
    state.database.save_audit_event(
        Some(&site_id),
        "trust_revoked",
        &trusted.relative_path,
        "success",
        None,
    )?;
    Ok(SecurityPolicyMutationResult {
        scan: reapply_latest_policy(&state, &site_id)?,
        finding_exception: None,
        trusted_file: None,
    })
}

#[tauri::command(async)]
pub fn preview_checksum_finding(
    session_token: String,
    site_id: String,
    finding_id: String,
    state: State<'_, AppState>,
) -> Result<FilePreview, AppError> {
    require_auth(&state, &session_token)?;
    let started = Instant::now();
    let result = (|| {
        validate_checksum_ids(&site_id, std::slice::from_ref(&finding_id))?;
        let stored = state.database.get_site(&site_id)?;
        let record = state
            .database
            .current_unexpected_checksum_finding(&site_id, &finding_id)?;
        let credential = stored_credential(&state, &stored)?;
        checksum_files::preview(state.ssh.as_ref(), &stored, credential.as_deref(), &record)
    })();
    log_operation_error(
        &state,
        Some(&site_id),
        "Checksum-bestand bekijken",
        started,
        result,
    )
}

#[tauri::command(async)]
pub fn delete_checksum_finding(
    session_token: String,
    site_id: String,
    finding_id: String,
    state: State<'_, AppState>,
) -> Result<ChecksumDeleteResult, AppError> {
    require_auth(&state, &session_token)?;
    let started = Instant::now();
    let result = delete_checksum_findings_internal(&state, &site_id, vec![finding_id], false);
    log_operation_error(
        &state,
        Some(&site_id),
        "Checksum-bestand verwijderen",
        started,
        result,
    )
}

#[tauri::command(async)]
pub fn delete_checksum_findings(
    session_token: String,
    site_id: String,
    finding_ids: Vec<String>,
    state: State<'_, AppState>,
) -> Result<ChecksumDeleteResult, AppError> {
    require_auth(&state, &session_token)?;
    let started = Instant::now();
    let result = delete_checksum_findings_internal(&state, &site_id, finding_ids, true);
    log_operation_error(
        &state,
        Some(&site_id),
        "Checksum-bestanden verwijderen",
        started,
        result,
    )
}

fn delete_checksum_findings_internal(
    state: &AppState,
    site_id: &str,
    finding_ids: Vec<String>,
    bulk: bool,
) -> Result<ChecksumDeleteResult, AppError> {
    if finding_ids.is_empty() || finding_ids.len() > 5_000 {
        return Err(AppError::validation(
            "Selecteer tussen 1 en 5.000 onverwachte checksum-bestanden.",
        ));
    }
    validate_checksum_ids(site_id, &finding_ids)?;
    let mut seen = HashSet::with_capacity(finding_ids.len());
    let finding_ids: Vec<String> = finding_ids
        .into_iter()
        .filter(|finding_id| seen.insert(finding_id.clone()))
        .collect();
    let requested = finding_ids.len();
    let stored = state.database.get_site(site_id)?;
    let credential = stored_credential_from_state(state, &stored)?;
    let mut deleted_paths = Vec::new();
    let mut failures = Vec::new();

    for finding_id in finding_ids {
        let record = match state
            .database
            .current_unexpected_checksum_finding(site_id, &finding_id)
        {
            Ok(record) => record,
            Err(error) => {
                save_checksum_audit(
                    state,
                    site_id,
                    "checksum_file_delete",
                    &finding_id,
                    "failed",
                    &finding_id,
                    &error.category,
                );
                failures.push(ChecksumDeleteFailure {
                    finding_id,
                    path: None,
                    error,
                });
                continue;
            }
        };
        let path = record.finding.path.clone();
        match checksum_files::delete(state.ssh.as_ref(), &stored, credential.as_deref(), &record) {
            Ok(deleted_path) => {
                save_checksum_audit(
                    state,
                    site_id,
                    "checksum_file_delete",
                    &deleted_path,
                    "success",
                    &finding_id,
                    "deleted",
                );
                deleted_paths.push(deleted_path);
            }
            Err(error) => {
                save_checksum_audit(
                    state,
                    site_id,
                    "checksum_file_delete",
                    path.as_deref().unwrap_or(&finding_id),
                    "failed",
                    &finding_id,
                    &error.category,
                );
                failures.push(ChecksumDeleteFailure {
                    finding_id,
                    path,
                    error,
                });
            }
        }
    }

    let (scan, rescan_error) = if deleted_paths.is_empty() {
        (None, None)
    } else {
        match scan_site_internal(state, site_id, 30) {
            Ok(scan) => (Some(scan), None),
            Err(error) => (None, Some(error)),
        }
    };
    if bulk {
        let status = if failures.is_empty() && rescan_error.is_none() {
            "success"
        } else {
            "failed"
        };
        let details = format!(
            "requested={requested}; deleted={}; failures={}; rescan={}",
            deleted_paths.len(),
            failures.len(),
            if rescan_error.is_some() {
                "failed"
            } else {
                "complete"
            }
        );
        if let Err(error) = state.database.save_audit_event(
            Some(site_id),
            "checksum_file_bulk_delete",
            "unexpected_checksum_findings",
            status,
            Some(&details),
        ) {
            eprintln!("security audit write failed category={}", error.category);
        }
    }
    Ok(ChecksumDeleteResult {
        requested,
        deleted: deleted_paths.len(),
        deleted_paths,
        failures,
        scan,
        rescan_error,
    })
}

fn validate_checksum_ids(site_id: &str, finding_ids: &[String]) -> Result<(), AppError> {
    uuid::Uuid::parse_str(site_id)
        .map_err(|_| AppError::validation("De website-id is ongeldig."))?;
    for finding_id in finding_ids {
        uuid::Uuid::parse_str(finding_id)
            .map_err(|_| AppError::validation("Een checksumfinding-id is ongeldig."))?;
    }
    Ok(())
}

fn save_checksum_audit(
    state: &AppState,
    site_id: &str,
    action_type: &str,
    target: &str,
    status: &str,
    finding_id: &str,
    outcome: &str,
) {
    let details = format!("finding_id={finding_id}; outcome={outcome}");
    if let Err(error) =
        state
            .database
            .save_audit_event(Some(site_id), action_type, target, status, Some(&details))
    {
        eprintln!("security audit write failed category={}", error.category);
    }
}

fn validate_optional_site_id(site_id: Option<&str>) -> Result<(), AppError> {
    if let Some(site_id) = site_id {
        validate_uuid(site_id, "De website-id is ongeldig.")?;
    }
    Ok(())
}

fn validate_security_ids(site_id: &str, finding_id: &str) -> Result<(), AppError> {
    validate_uuid(site_id, "De website-id is ongeldig.")?;
    validate_uuid(finding_id, "De securitymelding-id is ongeldig.")
}

fn validate_uuid(value: &str, message: &str) -> Result<(), AppError> {
    uuid::Uuid::parse_str(value)
        .map(|_| ())
        .map_err(|_| AppError::validation(message))
}

fn validate_expiration(expires_at: Option<String>) -> Result<Option<String>, AppError> {
    let Some(expires_at) = expires_at else {
        return Ok(None);
    };
    let parsed = DateTime::parse_from_rfc3339(expires_at.trim()).map_err(|_| {
        AppError::validation("De verloopdatum moet een geldige datum met tijdzone zijn.")
    })?;
    if parsed <= Utc::now() {
        return Err(AppError::validation(
            "De verloopdatum moet in de toekomst liggen.",
        ));
    }
    Ok(Some(
        parsed
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::Millis, true),
    ))
}

fn validate_policy_note(note: Option<String>) -> Result<Option<String>, AppError> {
    let Some(note) = note else {
        return Ok(None);
    };
    let note = note.trim();
    if note.is_empty() {
        return Ok(None);
    }
    if note.chars().count() > 500 || note.chars().any(char::is_control) {
        return Err(AppError::validation(
            "De notitie mag maximaal 500 geldige tekens bevatten.",
        ));
    }
    let lower = note.to_ascii_lowercase();
    if [
        "password",
        "wachtwoord",
        "secret",
        "token",
        "private key",
        "api_key",
        "apikey",
        "db_password",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        return Err(AppError::validation(
            "Sla geen wachtwoorden, tokens, sleutels of andere geheimen op in een notitie.",
        ));
    }
    Ok(Some(note.to_owned()))
}

fn remote_timestamp(timestamp: Option<u64>) -> Option<String> {
    timestamp
        .and_then(|timestamp| i64::try_from(timestamp).ok())
        .and_then(|timestamp| DateTime::from_timestamp(timestamp, 0))
        .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Millis, true))
}

fn reapply_latest_policy(state: &AppState, site_id: &str) -> Result<Option<ScanResult>, AppError> {
    let Some(mut scan) = state.database.latest_scan(site_id)? else {
        return Ok(None);
    };
    let exceptions = state.database.list_finding_exceptions(Some(site_id))?;
    let trusted_files = state.database.list_trusted_files(Some(site_id))?;
    let security_status = security_policy::apply_scan_policy(
        site_id,
        &mut scan.checks,
        &exceptions,
        &trusted_files,
        Utc::now(),
    );
    scan.status = security_policy::calculate_site_status(&scan.checks);
    state.database.update_scan_policy(&scan, &security_status)?;
    Ok(Some(scan))
}

fn refresh_trusted_file_observations(
    state: &AppState,
    stored: &StoredSite,
    credential: Option<&str>,
) -> Result<Vec<TrustedFile>, AppError> {
    let trusted_files: Vec<TrustedFile> = state
        .database
        .list_trusted_files(Some(&stored.site.id))?
        .into_iter()
        .filter(|trusted| trusted.active)
        .collect();
    if trusted_files.is_empty() {
        return Ok(trusted_files);
    }
    let paths: Vec<String> = trusted_files
        .iter()
        .map(|trusted| trusted.relative_path.clone())
        .collect();
    let checked_at = crate::database::utc_now();
    match state
        .ssh
        .fingerprint_files(&stored.site, credential, &paths)
    {
        Ok(observations) => {
            for observation in observations {
                let Some(trusted) = trusted_files
                    .iter()
                    .find(|trusted| trusted.relative_path == observation.relative_path)
                else {
                    continue;
                };
                if let Some(error) = observation.error {
                    state.database.update_trusted_observation(
                        &trusted.id,
                        None,
                        None,
                        None,
                        TrustedFileStatus::Unchecked,
                        &checked_at,
                    )?;
                    persist_trust_hash_error(state, stored, trusted, error);
                } else if let Some(fingerprint) = observation.fingerprint {
                    let status = if fingerprint.sha256 == trusted.trusted_sha256
                        && fingerprint.file_type == trusted.file_type
                    {
                        TrustedFileStatus::Trusted
                    } else {
                        TrustedFileStatus::Changed
                    };
                    state.database.update_trusted_observation(
                        &trusted.id,
                        Some(&fingerprint.sha256),
                        Some(fingerprint.size_bytes),
                        remote_timestamp(fingerprint.modified_unix).as_deref(),
                        status,
                        &checked_at,
                    )?;
                } else {
                    state.database.update_trusted_observation(
                        &trusted.id,
                        None,
                        None,
                        None,
                        TrustedFileStatus::Missing,
                        &checked_at,
                    )?;
                }
            }
        }
        Err(error) => {
            for trusted in &trusted_files {
                state.database.update_trusted_observation(
                    &trusted.id,
                    None,
                    None,
                    None,
                    TrustedFileStatus::Unchecked,
                    &checked_at,
                )?;
                persist_trust_hash_error(state, stored, trusted, error.clone());
            }
        }
    }
    state.database.list_trusted_files(Some(&stored.site.id))
}

fn persist_trust_hash_error(
    state: &AppState,
    stored: &StoredSite,
    trusted: &TrustedFile,
    error: AppError,
) {
    let _ = error_log::persist_error(
        &state.database,
        Some(&stored.site.id),
        Some(&stored.site.name),
        "trust_hash_failed",
        None,
        None,
        error,
    );
    let _ = state.database.save_audit_event(
        Some(&stored.site.id),
        "trust_hash_failed",
        &trusted.relative_path,
        "failed",
        None,
    );
}

fn scan_site_internal(
    state: &AppState,
    site_id: &str,
    modified_days: u16,
) -> Result<ScanResult, AppError> {
    struct SilentProgress;
    impl engine::ScanProgress for SilentProgress {}
    scan_site_internal_with_progress(state, site_id, modified_days, &mut SilentProgress)
}

fn scan_site_internal_with_progress(
    state: &AppState,
    site_id: &str,
    modified_days: u16,
    progress: &mut dyn engine::ScanProgress,
) -> Result<ScanResult, AppError> {
    crate::validation::validate_days(modified_days)?;
    let stored = state.database.get_site(site_id)?;
    let credential = stored_credential_from_state(state, &stored)?;
    let mut outcome = match engine::scan_site_with_progress(
        state.ssh.as_ref(),
        &stored,
        credential.as_deref(),
        modified_days,
        progress,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            if matches!(
                error.category.as_str(),
                "dns_host_error"
                    | "timeout"
                    | "connection_timeout"
                    | "authentication_failed"
                    | "host_key_mismatch"
            ) {
                state.database.mark_unreachable(site_id)?;
            }
            return Err(error);
        }
    };
    let trusted_files = refresh_trusted_file_observations(state, &stored, credential.as_deref())?;
    let exceptions = state.database.list_finding_exceptions(Some(site_id))?;
    outcome.security_status = security_policy::apply_scan_policy(
        site_id,
        &mut outcome.result.checks,
        &exceptions,
        &trusted_files,
        Utc::now(),
    );
    outcome.result.status = security_policy::calculate_site_status(&outcome.result.checks);
    state
        .database
        .update_versions(site_id, &outcome.wordpress_version, &outcome.php_version)?;
    if let Some(updates) = &outcome.updates {
        state.database.save_updates(site_id, updates)?;
    }
    if progress.is_cancelled() {
        return Err(AppError::ssh(
            "scan_cancelled",
            "De scan is geannuleerd.",
            "annulering aangevraagd voor het opslaan",
            false,
        ));
    }
    progress.step_started("persist");
    let persist_started = Instant::now();
    if let Err(error) = state
        .database
        .save_scan(&outcome.result, &outcome.security_status)
    {
        progress.step_finished(
            "persist",
            StepStatus::Failed,
            u64::try_from(persist_started.elapsed().as_millis()).unwrap_or(u64::MAX),
            Some(error.user_message.clone()),
        );
        return Err(error);
    }
    progress.step_finished(
        "persist",
        StepStatus::Success,
        u64::try_from(persist_started.elapsed().as_millis()).unwrap_or(u64::MAX),
        Some("Scanresultaat atomair opgeslagen.".into()),
    );
    Ok(outcome.result)
}

#[tauri::command(async)]
pub fn get_settings(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<AppSettings, AppError> {
    require_auth(&state, &session_token)?;
    Ok(AppSettings {
        scan_concurrency: state.scan_concurrency.load(Ordering::SeqCst),
    })
}

#[tauri::command(async)]
pub fn save_settings(
    session_token: String,
    settings: AppSettings,
    state: State<'_, AppState>,
) -> Result<AppSettings, AppError> {
    require_auth(&state, &session_token)?;
    if !(1..=5).contains(&settings.scan_concurrency) {
        return Err(AppError::validation(
            "Gelijktijdige scans moeten tussen 1 en 5 liggen.",
        ));
    }
    state
        .database
        .set_scan_concurrency(settings.scan_concurrency)?;
    state
        .scan_concurrency
        .store(settings.scan_concurrency, Ordering::SeqCst);
    state.scan_jobs.set_concurrency(settings.scan_concurrency);
    Ok(settings)
}

#[tauri::command(async)]
pub fn get_wordfence_status(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<WordfenceIntegrationStatus, AppError> {
    require_auth(&state, &session_token)?;
    wordfence::integration_status(
        &state.credentials,
        &state.database,
        &state.vulnerability_jobs,
    )
}

#[tauri::command(async)]
pub fn save_wordfence_api_key(
    session_token: String,
    api_key: String,
    state: State<'_, AppState>,
) -> Result<WordfenceIntegrationStatus, AppError> {
    require_auth(&state, &session_token)?;
    let api_key = Zeroizing::new(api_key);
    wordfence::save_api_key(&state.credentials, &api_key)?;
    state.database.save_audit_event(
        None,
        "wordfence_key_saved",
        "wordfence_intelligence",
        "success",
        Some("Wordfence API-sleutel opgeslagen in de beveiligde credentialopslag"),
    )?;
    wordfence::integration_status(
        &state.credentials,
        &state.database,
        &state.vulnerability_jobs,
    )
}

#[tauri::command(async)]
pub fn remove_wordfence_api_key(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<WordfenceIntegrationStatus, AppError> {
    require_auth(&state, &session_token)?;
    wordfence::remove_api_key(&state.credentials)?;
    state.database.save_audit_event(
        None,
        "wordfence_key_removed",
        "wordfence_intelligence",
        "success",
        Some("Wordfence API-sleutel uit de beveiligde credentialopslag verwijderd"),
    )?;
    wordfence::integration_status(
        &state.credentials,
        &state.database,
        &state.vulnerability_jobs,
    )
}

#[tauri::command(async)]
pub fn test_wordfence_connection(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<WordfenceIntegrationStatus, AppError> {
    require_auth(&state, &session_token)?;
    let api_key = Zeroizing::new(
        state
            .credentials
            .get_optional(wordfence::WORDFENCE_CREDENTIAL_REFERENCE)?
            .ok_or_else(|| AppError::validation("Sla eerst een Wordfence API-sleutel op."))?,
    );
    let started = Instant::now();
    let result = wordfence::WordfenceIntelligenceProvider::new().and_then(|provider| {
        wordfence::VulnerabilityProvider::test_connection(&provider, &api_key)
    });
    if let Err(error) = result {
        return Err(error_log::persist_error(
            &state.database,
            None,
            None,
            "Wordfence verbinding testen",
            Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)),
            None,
            error,
        ));
    }
    let mut status = wordfence::integration_status(
        &state.credentials,
        &state.database,
        &state.vulnerability_jobs,
    )?;
    status.connection_status = "connected".into();
    Ok(status)
}

#[tauri::command(async)]
pub fn start_wordfence_feed_refresh(
    session_token: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<VulnerabilityRefreshJobState, AppError> {
    require_auth(&state, &session_token)?;
    start_wordfence_feed_refresh_internal(app, false)
}

#[tauri::command(async)]
pub fn get_wordfence_feed_refresh_job(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<Option<VulnerabilityRefreshJobState>, AppError> {
    require_auth(&state, &session_token)?;
    state.vulnerability_jobs.current()
}

pub(crate) fn start_wordfence_feed_refresh_internal(
    app: AppHandle,
    automatic: bool,
) -> Result<VulnerabilityRefreshJobState, AppError> {
    let state = app.state::<AppState>();
    if state
        .credentials
        .get_optional(wordfence::WORDFENCE_CREDENTIAL_REFERENCE)?
        .is_none()
    {
        return Err(AppError::validation(
            "Sla eerst een Wordfence API-sleutel op.",
        ));
    }
    let cooldown = state.database.vulnerability_feed_cooldown_remaining(
        wordfence::WORDFENCE_PROVIDER,
        wordfence::FEED_COOLDOWN_SECONDS,
    )?;
    if cooldown > 0 {
        return Err(AppError {
            error_id: None,
            category: "vulnerability_feed_cooldown".into(),
            user_message: format!(
                "De vulnerability database kan over {} minuten opnieuw worden vernieuwd.",
                cooldown.div_ceil(60)
            ),
            technical_details: None,
            retryable: true,
        });
    }
    let (job, is_new) = state.vulnerability_jobs.create(automatic)?;
    if !is_new {
        return Ok(job);
    }
    let job_id = job.id.clone();
    let worker_app = app.clone();
    if let Err(error) = std::thread::Builder::new()
        .name("wordfence-feed-refresh".into())
        .spawn(move || run_wordfence_feed_refresh(worker_app, job_id))
    {
        let error = AppError::storage(error);
        let failed = state.vulnerability_jobs.fail(&job.id, error.clone())?;
        emit_wordfence_refresh_job(&app, &failed);
        return Err(error);
    }
    Ok(job)
}

fn run_wordfence_feed_refresh(app: AppHandle, job_id: String) {
    let state = app.state::<AppState>();
    if let Ok(job) = state.vulnerability_jobs.mark_running(&job_id) {
        emit_wordfence_refresh_job(&app, &job);
    }
    let temp_path = state
        .vulnerability_cache_directory
        .join(format!("wordfence-{}.tmp", uuid::Uuid::new_v4()));
    let started = Instant::now();
    let result = (|| {
        fs::create_dir_all(&state.vulnerability_cache_directory).map_err(AppError::storage)?;
        let provider = wordfence::WordfenceIntelligenceProvider::new()?;
        let api_key = Zeroizing::new(
            state
                .credentials
                .get_optional(wordfence::WORDFENCE_CREDENTIAL_REFERENCE)?
                .ok_or_else(|| AppError::validation("De Wordfence API-sleutel is verwijderd."))?,
        );
        let attempted_at = state
            .database
            .record_vulnerability_feed_attempt(wordfence::WORDFENCE_PROVIDER)?;
        let bytes =
            wordfence::VulnerabilityProvider::download_feed(&provider, &api_key, &temp_path)?;
        if let Ok(job) = state
            .vulnerability_jobs
            .phase(&job_id, "validate", Some(bytes))
        {
            emit_wordfence_refresh_job(&app, &job);
        }
        if let Ok(job) = state.vulnerability_jobs.phase(&job_id, "process", None) {
            emit_wordfence_refresh_job(&app, &job);
        }
        let summary = state
            .database
            .import_wordfence_feed(&temp_path, &attempted_at)?;
        if let Ok(job) = state.vulnerability_jobs.phase(&job_id, "database", None) {
            emit_wordfence_refresh_job(&app, &job);
        }
        Ok(summary)
    })();
    let _ = fs::remove_file(&temp_path);
    match result {
        Ok(summary) => {
            if let Ok(job) = state.vulnerability_jobs.complete(&job_id, &summary) {
                emit_wordfence_refresh_job(&app, &job);
            }
        }
        Err(error) => {
            let logged = error_log::persist_error(
                &state.database,
                None,
                None,
                "Wordfence vulnerability database bijwerken",
                Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)),
                None,
                error,
            );
            let _ = state.database.record_vulnerability_feed_failure(
                wordfence::WORDFENCE_PROVIDER,
                &logged.user_message,
            );
            if let Ok(job) = state.vulnerability_jobs.fail(&job_id, logged) {
                emit_wordfence_refresh_job(&app, &job);
            }
        }
    }
}

fn emit_wordfence_refresh_job(app: &AppHandle, job: &VulnerabilityRefreshJobState) {
    if let Err(error) = app.emit("wordfence-feed-refresh-updated", job) {
        eprintln!("wordfence refresh event failed: {error}");
    }
}

#[tauri::command(async)]
pub fn list_cached_updates(
    session_token: String,
    site_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<UpdateItem>, AppError> {
    require_auth(&state, &session_token)?;
    uuid::Uuid::parse_str(&site_id)
        .map_err(|_| AppError::validation("De website-id is ongeldig."))?;
    state.database.list_cached_updates(&site_id)
}

#[tauri::command(async)]
pub fn check_updates(
    session_token: String,
    site_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<UpdateItem>, AppError> {
    require_auth(&state, &session_token)?;
    let started = Instant::now();
    let result = (|| {
        let stored = state.database.get_site(&site_id)?;
        let credential = stored_credential(&state, &stored)?;
        let updates = engine::check_updates(state.ssh.as_ref(), &stored, credential.as_deref())?;
        state.database.save_updates(&site_id, &updates)?;
        Ok(updates)
    })();
    log_operation_error(
        &state,
        Some(&site_id),
        "Updates controleren",
        started,
        result,
    )
}

#[tauri::command(async)]
pub fn list_wordpress_users(
    session_token: String,
    site_id: String,
    state: State<'_, AppState>,
) -> Result<WordPressUsersData, AppError> {
    require_auth(&state, &session_token)?;
    let started = Instant::now();
    let result = (|| {
        uuid::Uuid::parse_str(&site_id)
            .map_err(|_| AppError::validation("De website-id is ongeldig."))?;
        let stored = state.database.get_site(&site_id)?;
        let credential = stored_credential(&state, &stored)?;
        wordpress_users::load(state.ssh.as_ref(), &stored, credential.as_deref())
    })();
    log_operation_error(
        &state,
        Some(&site_id),
        "WordPress-gebruikers laden",
        started,
        result,
    )
}

#[tauri::command(async)]
pub fn update_wordpress_user(
    session_token: String,
    site_id: String,
    input: WordPressUserUpdateInput,
    state: State<'_, AppState>,
) -> Result<WordPressUsersData, AppError> {
    require_auth(&state, &session_token)?;
    let started = Instant::now();
    uuid::Uuid::parse_str(&site_id)
        .map_err(|_| AppError::validation("De website-id is ongeldig."))?;
    let stored = state.database.get_site(&site_id)?;
    let credential = stored_credential(&state, &stored)?;
    let result =
        wordpress_users::update(state.ssh.as_ref(), &stored, credential.as_deref(), &input);
    audit_wordpress_user_action(
        &state,
        &site_id,
        "wordpress_user_update",
        input.user_id,
        result.as_ref().err(),
        Some(&format!(
            "role={}",
            input.role.as_deref().unwrap_or("unchanged")
        )),
    );
    log_operation_error(
        &state,
        Some(&site_id),
        "WordPress-gebruiker bijwerken",
        started,
        result,
    )
}

#[tauri::command(async)]
pub fn delete_wordpress_user(
    session_token: String,
    site_id: String,
    input: WordPressUserDeleteInput,
    state: State<'_, AppState>,
) -> Result<WordPressUsersData, AppError> {
    require_auth(&state, &session_token)?;
    let started = Instant::now();
    uuid::Uuid::parse_str(&site_id)
        .map_err(|_| AppError::validation("De website-id is ongeldig."))?;
    let stored = state.database.get_site(&site_id)?;
    let credential = stored_credential(&state, &stored)?;
    let result =
        wordpress_users::delete(state.ssh.as_ref(), &stored, credential.as_deref(), &input);
    let details = input.reassign_to.map_or_else(
        || "content=deleted".into(),
        |target| format!("content_reassigned_to={target}"),
    );
    audit_wordpress_user_action(
        &state,
        &site_id,
        "wordpress_user_delete",
        input.user_id,
        result.as_ref().err(),
        Some(&details),
    );
    log_operation_error(
        &state,
        Some(&site_id),
        "WordPress-gebruiker verwijderen",
        started,
        result,
    )
}

fn audit_wordpress_user_action(
    state: &AppState,
    site_id: &str,
    action_type: &str,
    user_id: u64,
    error: Option<&AppError>,
    success_details: Option<&str>,
) {
    let target = format!("user:{user_id}");
    let status = if error.is_some() { "failed" } else { "success" };
    let failure_details;
    let details = if let Some(error) = error {
        failure_details = format!("category={}", error.category);
        Some(failure_details.as_str())
    } else {
        success_details
    };
    if let Err(audit_error) =
        state
            .database
            .save_audit_event(Some(site_id), action_type, &target, status, details)
    {
        eprintln!(
            "security audit write failed category={}",
            audit_error.category
        );
    }
}

#[tauri::command(async)]
pub fn run_update(
    session_token: String,
    site_id: String,
    kind: String,
    slug: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    require_auth(&state, &session_token)?;
    let started = Instant::now();
    let result = run_update_internal(&state, &site_id, &kind, slug.as_deref());
    log_operation_error(
        &state,
        Some(&site_id),
        "WordPress-update uitvoeren",
        started,
        result,
    )
}

fn run_update_internal(
    state: &AppState,
    site_id: &str,
    kind: &str,
    slug: Option<&str>,
) -> Result<(), AppError> {
    if matches!(kind, "core" | "all") {
        return Err(AppError::validation(
            "Gebruik voor WordPress core de beveiligde core-updateflow met preflight, backup en nacontrole.",
        ));
    }
    let stored = state.database.get_site(site_id)?;
    let credential = stored_credential_from_state(state, &stored)?;
    engine::run_update(
        state.ssh.as_ref(),
        &stored,
        credential.as_deref(),
        kind,
        slug,
    )?;
    let updates = engine::check_updates(state.ssh.as_ref(), &stored, credential.as_deref())?;
    state.database.save_updates(site_id, &updates)?;
    let wordpress = engine::text_action(
        state.ssh.as_ref(),
        &stored,
        credential.as_deref(),
        RemoteAction::GetWordPressVersion,
    )?;
    let php = engine::text_action(
        state.ssh.as_ref(),
        &stored,
        credential.as_deref(),
        RemoteAction::GetPhpVersion,
    )?;
    state
        .database
        .update_versions(site_id, wordpress.trim(), php.trim())?;
    Ok(())
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MaintenanceProgressEvent {
    site_id: String,
    run_id: String,
    step: MaintenanceStep,
}

#[tauri::command(async)]
pub fn inspect_core_operation(
    session_token: String,
    site_id: String,
    state: State<'_, AppState>,
) -> Result<CoreOperationInfo, AppError> {
    require_auth(&state, &session_token)?;
    let started = Instant::now();
    let result = (|| {
        uuid::Uuid::parse_str(&site_id)
            .map_err(|_| AppError::validation("De website-id is ongeldig."))?;
        let stored = state.database.get_site(&site_id)?;
        let credential = stored_credential(&state, &stored)?;
        core_operations::inspect(state.ssh.as_ref(), &stored, credential.as_deref())
    })();
    log_operation_error(
        &state,
        Some(&site_id),
        "WordPress core inspecteren",
        started,
        result,
    )
}

#[tauri::command(async)]
pub fn repair_wordpress_core(
    session_token: String,
    site_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreOperationResult, AppError> {
    require_auth(&state, &session_token)?;
    let started = Instant::now();
    let result = run_core_operation(&app, &state, &site_id, CoreOperationKind::Repair);
    log_operation_error(
        &state,
        Some(&site_id),
        "WordPress core herstellen",
        started,
        result,
    )
}

#[tauri::command(async)]
pub fn update_wordpress_core(
    session_token: String,
    site_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<CoreOperationResult, AppError> {
    require_auth(&state, &session_token)?;
    let started = Instant::now();
    let result = run_core_operation(&app, &state, &site_id, CoreOperationKind::Update);
    log_operation_error(
        &state,
        Some(&site_id),
        "WordPress core bijwerken",
        started,
        result,
    )
}

fn run_core_operation(
    app: &AppHandle,
    state: &AppState,
    site_id: &str,
    kind: CoreOperationKind,
) -> Result<CoreOperationResult, AppError> {
    uuid::Uuid::parse_str(site_id)
        .map_err(|_| AppError::validation("De website-id is ongeldig."))?;
    let stored = state.database.get_site(site_id)?;
    let credential = stored_credential_from_state(state, &stored)?;
    let run = core_operations::new_run(&stored, kind);
    state.database.start_maintenance(&run)?;
    let run_id = run.id.clone();
    let event_site_id = site_id.to_owned();
    let outcome = core_operations::execute(
        state.ssh.as_ref(),
        &stored,
        credential.as_deref(),
        &state.backup_directory,
        kind,
        run,
        |step| {
            state.database.update_maintenance_step(&run_id, step)?;
            app.emit(
                "maintenance-progress",
                MaintenanceProgressEvent {
                    site_id: event_site_id.clone(),
                    run_id: run_id.clone(),
                    step: step.clone(),
                },
            )
            .map_err(AppError::storage)
        },
    )?;
    if let Some(scan) = &outcome.scan {
        state
            .database
            .save_scan(&scan.result, &scan.security_status)?;
        state
            .database
            .update_versions(site_id, &scan.wordpress_version, &scan.php_version)?;
    }
    let updates_refreshed = outcome.run.steps.iter().any(|step| {
        step.key == "updates" && matches!(step.status, StepStatus::Success | StepStatus::Warning)
    });
    if updates_refreshed {
        state
            .database
            .save_updates(site_id, &outcome.updates_after)?;
    }
    let backup_values = outcome.backup.as_ref().map(|backup| {
        (
            backup.local_path.as_str(),
            backup.size_bytes,
            backup.sha256.as_str(),
        )
    });
    state
        .database
        .finish_maintenance(&outcome.run, backup_values)?;
    let action_type = match kind {
        CoreOperationKind::Repair => "wordpress_core_repair",
        CoreOperationKind::Update => "wordpress_core_update",
    };
    let audit_status = if outcome.run.status == StepStatus::Failed {
        "failed"
    } else {
        "success"
    };
    let audit_details = format!(
        "run_id={}; result={:?}; version={}",
        outcome.run.id, outcome.run.status, outcome.current_version
    );
    if let Err(error) = state.database.save_audit_event(
        Some(site_id),
        action_type,
        "wordpress_core",
        audit_status,
        Some(&audit_details),
    ) {
        eprintln!("security audit write failed category={}", error.category);
    }
    Ok(CoreOperationResult {
        run: outcome.run,
        scan: outcome.scan.map(|scan| scan.result),
        updates_after: outcome.updates_after,
        current_version: outcome.current_version,
    })
}

#[tauri::command(async)]
pub fn run_maintenance(
    session_token: String,
    site_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<MaintenanceRun, AppError> {
    require_auth(&state, &session_token)?;
    let started = Instant::now();
    let result = run_maintenance_internal(&app, &state, &site_id);
    log_operation_error(
        &state,
        Some(&site_id),
        "Onderhoud uitvoeren",
        started,
        result,
    )
}

fn run_maintenance_internal(
    app: &AppHandle,
    state: &AppState,
    site_id: &str,
) -> Result<MaintenanceRun, AppError> {
    let stored = state.database.get_site(site_id)?;
    let credential = stored_credential_from_state(state, &stored)?;
    let run = maintenance::new_run(&stored);
    state.database.start_maintenance(&run)?;
    let run_id = run.id.clone();
    let event_site_id = site_id.to_owned();
    let outcome = maintenance::execute(
        state.ssh.as_ref(),
        &stored,
        credential.as_deref(),
        &state.backup_directory,
        run,
        |step| {
            state.database.update_maintenance_step(&run_id, step)?;
            app.emit(
                "maintenance-progress",
                MaintenanceProgressEvent {
                    site_id: event_site_id.clone(),
                    run_id: run_id.clone(),
                    step: step.clone(),
                },
            )
            .map_err(AppError::storage)
        },
    )?;
    for scan in &outcome.scans {
        state
            .database
            .save_scan(&scan.result, &scan.security_status)?;
        state
            .database
            .update_versions(site_id, &scan.wordpress_version, &scan.php_version)?;
    }
    if outcome.run.before_versions.is_some() {
        state
            .database
            .save_updates(site_id, &outcome.updates_after)?;
    }
    let backup_values = outcome.backup.as_ref().map(|backup| {
        (
            backup.local_path.as_str(),
            backup.size_bytes,
            backup.sha256.as_str(),
        )
    });
    state
        .database
        .finish_maintenance(&outcome.run, backup_values)?;
    Ok(outcome.run)
}

#[tauri::command(async)]
pub fn list_maintenance_runs(
    session_token: String,
    site_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<MaintenanceRun>, AppError> {
    require_auth(&state, &session_token)?;
    state.database.list_maintenance_runs(site_id.as_deref())
}

fn run_readonly(
    executor: &dyn crate::ssh::SshExecutor,
    site: &Site,
    credential: Option<&str>,
    command: RemoteCommand,
) -> Result<String, AppError> {
    if command.mutating {
        return Err(AppError::validation(
            "Een muterende actie is niet toegestaan tijdens een verbindingstest.",
        ));
    }
    let output = executor.execute(site, credential, &command)?;
    if output.exit_code != 0 {
        return Err(AppError::command_failed(
            command.action_name,
            output.exit_code,
            &String::from_utf8_lossy(&output.stderr),
        ));
    }
    output.stdout_text()
}

fn site_from_input(input: &SiteInput, existing: Option<&StoredSite>) -> Site {
    let now = crate::database::utc_now();
    Site {
        id: input.id.clone().unwrap_or_default(),
        name: input.name.clone(),
        url: input.url.clone(),
        ssh_host: input.ssh_host.clone(),
        ssh_port: input.ssh_port,
        ssh_username: input.ssh_username.clone(),
        auth_method: input.auth_method,
        key_path: input.key_path.clone(),
        wordpress_path: input.wordpress_path.clone(),
        pinned_host_key: existing.and_then(|stored| stored.site.pinned_host_key.clone()),
        status: existing.map_or(SiteStatus::Unscanned, |stored| stored.site.status),
        wordpress_version: None,
        php_version: None,
        update_count: 0,
        security_status: None,
        last_scan_at: None,
        last_maintenance_at: None,
        created_at: now.clone(),
        updated_at: now,
    }
}

fn connection_steps() -> Vec<ConnectionStep> {
    [
        ("ssh", "SSH bereikbaar"),
        ("host_key", "Host fingerprint gecontroleerd"),
        ("authentication", "Authenticatie geslaagd"),
        ("wordpress_path", "WordPress-pad gevonden"),
        ("wp_cli", "WP-CLI werkt"),
        ("wordpress", "WordPress-installatie gevonden"),
        ("database", "Database bereikbaar"),
    ]
    .into_iter()
    .map(|(key, label)| ConnectionStep {
        key: key.into(),
        label: label.into(),
        status: StepStatus::Pending,
        detail: None,
    })
    .collect()
}

fn failed_connection(
    steps: Vec<ConnectionStep>,
    fingerprint: Option<String>,
    error: AppError,
) -> ConnectionTestResult {
    ConnectionTestResult {
        success: false,
        steps,
        fingerprint,
        requires_host_key_acceptance: false,
        wordpress_version: None,
        php_version: None,
        wp_cli_version: None,
        detected_url: None,
        error: Some(error),
    }
}

fn failed_connection_with_log(
    state: &AppState,
    site: &Site,
    started: Instant,
    steps: Vec<ConnectionStep>,
    fingerprint: Option<String>,
    error: AppError,
) -> ConnectionTestResult {
    let error = error_log::persist_error(
        &state.database,
        (!site.id.is_empty()).then_some(site.id.as_str()),
        Some(&site.name),
        "SSH verbinding testen",
        Some(u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX)),
        None,
        error,
    );
    failed_connection(steps, fingerprint, error)
}

fn stored_credential(
    state: &State<'_, AppState>,
    stored: &StoredSite,
) -> Result<Option<String>, AppError> {
    match stored.credential_ref.as_deref() {
        Some(reference) => state.credentials.get_optional(reference),
        None => Ok(None),
    }
}

fn stored_credential_from_state(
    state: &AppState,
    stored: &StoredSite,
) -> Result<Option<String>, AppError> {
    match stored.credential_ref.as_deref() {
        Some(reference) => state.credentials.get_optional(reference),
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        auth::AuthManager,
        credentials::CredentialVault,
        database::Database,
        models::{AuthMethod, ChecksumStatus, Finding, FindingSeverity, ScanCheck},
        ssh::{ExecOutput, SshExecutor},
    };
    use std::path::Path;
    use uuid::Uuid;

    #[derive(Default)]
    struct CleanupMockSsh {
        deleted: Mutex<Vec<String>>,
    }

    #[derive(Default)]
    struct WpCliMockSsh {
        commands: Mutex<Vec<String>>,
    }

    impl SshExecutor for WpCliMockSsh {
        fn fingerprint(&self, _: &Site) -> Result<String, AppError> {
            Ok("SHA256:test".into())
        }

        fn authenticate(&self, _: &Site, _: Option<&str>) -> Result<(), AppError> {
            Ok(())
        }

        fn execute(
            &self,
            _: &Site,
            _: Option<&str>,
            command: &RemoteCommand,
        ) -> Result<ExecOutput, AppError> {
            self.commands.lock().unwrap().push(command.command.clone());
            Ok(ExecOutput {
                stdout: b"<script>alert('text only')</script>\n".to_vec(),
                stderr: Vec::new(),
                exit_code: 0,
                truncated: true,
            })
        }

        fn download(&self, _: &Site, _: Option<&str>, _: &str, _: &Path) -> Result<u64, AppError> {
            Err(AppError::validation("Geen downloadfixture"))
        }
    }

    impl SshExecutor for CleanupMockSsh {
        fn fingerprint(&self, _: &Site) -> Result<String, AppError> {
            Ok("SHA256:test".into())
        }

        fn authenticate(&self, _: &Site, _: Option<&str>) -> Result<(), AppError> {
            Ok(())
        }

        fn execute(
            &self,
            _: &Site,
            _: Option<&str>,
            command: &RemoteCommand,
        ) -> Result<ExecOutput, AppError> {
            let stdout = match command.action_name {
                "GetWordPressVersion" => b"6.8.2\n".to_vec(),
                "GetPhpVersion" => b"8.3.12\n".to_vec(),
                "VerifyCoreChecksums" => {
                    b"Success: WordPress installation verifies against checksums.\n".to_vec()
                }
                "ListUsers" | "CheckCoreUpdates" | "ListPluginUpdates"
                | "ListThemeUpdates" => b"[]".to_vec(),
                "CheckSelectedWpConfigConstants" => b"{\"WP_DEBUG\":false,\"DISALLOW_FILE_EDIT\":true,\"WP_ENVIRONMENT_TYPE\":\"production\"}".to_vec(),
                _ => Vec::new(),
            };
            Ok(ExecOutput {
                stdout,
                stderr: Vec::new(),
                exit_code: 0,
                truncated: false,
            })
        }

        fn download(&self, _: &Site, _: Option<&str>, _: &str, _: &Path) -> Result<u64, AppError> {
            Ok(0)
        }

        fn delete_checksum_file(
            &self,
            _: &Site,
            _: Option<&str>,
            relative_path: &str,
        ) -> Result<(), AppError> {
            if relative_path.ends_with("locked.php") {
                return Err(AppError::ssh(
                    "sftp_delete",
                    "Het checksum-bestand kon niet worden verwijderd.",
                    "permission denied",
                    false,
                ));
            }
            self.deleted
                .lock()
                .map_err(|_| AppError::storage("delete lock poisoned"))?
                .push(relative_path.into());
            Ok(())
        }
    }

    fn site_input() -> SiteInput {
        SiteInput {
            id: Some(Uuid::new_v4().to_string()),
            name: "Testsite".into(),
            url: "https://example.test".into(),
            ssh_host: "example.test".into(),
            ssh_port: 22,
            ssh_username: "deploy".into(),
            auth_method: AuthMethod::KeyFile,
            key_path: Some("C:\\keys\\id_ed25519".into()),
            wordpress_path: "/srv/site".into(),
            credential_secret: None,
        }
    }

    fn app_state(database: Database, temp: &Path) -> AppState {
        AppState {
            database,
            credentials: CredentialVault,
            ssh: Arc::new(CleanupMockSsh::default()),
            backup_directory: temp.join("backups"),
            vulnerability_cache_directory: temp.join("vulnerability-cache"),
            scan_concurrency: std::sync::atomic::AtomicUsize::new(1),
            auth: AuthManager::default(),
            terminals: crate::terminal::TerminalManager::default(),
            terminal_access: crate::terminal_auth::TerminalAccessManager::default(),
            scan_jobs: crate::scan_jobs::ScanJobManager::new(2),
            vulnerability_jobs: crate::vulnerability_jobs::VulnerabilityRefreshManager::default(),
        }
    }

    #[test]
    fn protected_tauri_commands_all_enforce_backend_authentication() {
        let public_commands = ["get_auth_status", "setup_password", "login"];
        let source = include_str!("commands.rs");
        let command_attribute = ["#[tauri::", "command"].concat();
        for command in source.split(&command_attribute).skip(1) {
            assert!(
                command.trim_start().starts_with("(async)]"),
                "Ieder Tauri-command moet buiten de UI-eventloop worden uitgevoerd"
            );
            let name = command
                .split_once("pub fn ")
                .and_then(|(_, rest)| rest.split_once('('))
                .map(|(name, _)| name.trim())
                .unwrap();
            if public_commands.contains(&name) {
                continue;
            }
            let function_prefix: String = command.chars().take(900).collect();
            assert!(
                function_prefix.contains("require_auth("),
                "Tauri command {name} mist backend-authenticatie"
            );
        }
    }

    #[test]
    fn locked_state_rejects_protected_operations_and_restart_resets_session() {
        let temp = std::env::temp_dir().join(format!("wpmm-auth-{}", Uuid::new_v4()));
        let database = Database::initialize(temp.with_extension("sqlite3")).unwrap();
        database.create_auth_config("$argon2id$test-only").unwrap();
        let state = app_state(database.clone(), &temp);

        assert!(require_auth(&state, "no-session").is_err());
        let token = state.auth.create_session().unwrap();
        assert!(require_auth(&state, &token).is_ok());
        state.auth.invalidate().unwrap();
        assert!(require_auth(&state, &token).is_err());

        let restarted = app_state(database, &temp);
        assert!(require_auth(&restarted, &token).is_err());
        let _ = std::fs::remove_file(temp.with_extension("sqlite3"));
    }

    #[test]
    fn password_change_rehashes_and_invalidates_the_existing_session() {
        let temp = std::env::temp_dir().join(format!("wpmm-password-{}", Uuid::new_v4()));
        let database = Database::initialize(temp.with_extension("sqlite3")).unwrap();
        let old_password = "oude lange wachtwoordzin";
        let new_password = "nieuwe lange wachtwoordzin";
        database
            .create_auth_config(&auth::hash_password(old_password).unwrap())
            .unwrap();
        let state = app_state(database.clone(), &temp);
        let token = state.auth.create_session().unwrap();

        assert!(
            change_password_internal(
                &state,
                &PasswordChangeInput {
                    current_password: "verkeerde lange wachtwoordzin".into(),
                    new_password: new_password.into(),
                },
            )
            .is_err()
        );
        assert!(require_auth(&state, &token).is_ok());
        change_password_internal(
            &state,
            &PasswordChangeInput {
                current_password: old_password.into(),
                new_password: new_password.into(),
            },
        )
        .unwrap();

        let config = database.auth_config().unwrap().unwrap();
        assert!(!auth::verify_password(old_password, &config.password_hash));
        assert!(auth::verify_password(new_password, &config.password_hash));
        assert!(require_auth(&state, &token).is_err());
        let _ = std::fs::remove_file(temp.with_extension("sqlite3"));
    }

    #[test]
    fn failed_terminal_reauthentication_revokes_the_backend_session() {
        let temp = std::env::temp_dir().join(format!("wpmm-terminal-reauth-{}", Uuid::new_v4()));
        let database = Database::initialize(temp.with_extension("sqlite3")).unwrap();
        let app_password = "correcte lange wachtwoordzin";
        database
            .create_auth_config(&auth::hash_password(app_password).unwrap())
            .unwrap();
        let site = database.save_site(&site_input(), None).unwrap();
        let state = app_state(database.clone(), &temp);
        let token = state.auth.create_session().unwrap();
        let terminal_receiver = state
            .terminals
            .install_test_session("existing-terminal", &site.id);
        let old_challenge = state
            .terminal_access
            .create_challenge(&token, &site.id)
            .unwrap();

        let error = begin_terminal_reauthentication_internal(
            &state,
            &token,
            &site.id,
            Zeroizing::new("verkeerde lange wachtwoordzin".into()),
        )
        .unwrap_err();
        assert_eq!(error.category, "app_session_revoked_reauth_failed");
        assert!(require_auth(&state, &token).is_err());
        assert_eq!(state.terminals.active_count(), 0);
        assert!(matches!(
            terminal_receiver.recv().unwrap(),
            crate::terminal::TerminalControl::Close
        ));
        assert!(
            state
                .terminal_access
                .consume_challenge(&token, &site.id, &old_challenge.challenge_token)
                .is_err()
        );
        assert!(state.database.list_sites().is_ok());
        let events = database.list_audit_events(Some(&site.id)).unwrap();
        assert!(events.iter().any(|event| {
            event.action_type == "terminal_reauthentication" && event.status == "failed"
        }));
        assert!(
            events
                .iter()
                .all(|event| !format!("{:?}", event).contains("verkeerde lange wachtwoordzin"))
        );

        let _ = std::fs::remove_file(temp.with_extension("sqlite3"));
    }

    #[test]
    fn correct_terminal_reauthentication_issues_a_site_bound_challenge() {
        let temp = std::env::temp_dir().join(format!("wpmm-terminal-challenge-{}", Uuid::new_v4()));
        let database = Database::initialize(temp.with_extension("sqlite3")).unwrap();
        let app_password = "correcte lange wachtwoordzin";
        database
            .create_auth_config(&auth::hash_password(app_password).unwrap())
            .unwrap();
        let site = database.save_site(&site_input(), None).unwrap();
        let state = app_state(database, &temp);
        let token = state.auth.create_session().unwrap();

        let challenge = begin_terminal_reauthentication_internal(
            &state,
            &token,
            &site.id,
            Zeroizing::new(app_password.into()),
        )
        .unwrap();
        assert_eq!(challenge.expires_in_seconds, 60);
        assert!(
            state
                .terminal_access
                .consume_challenge(&token, &site.id, &challenge.challenge_token)
                .is_ok()
        );

        let _ = std::fs::remove_file(temp.with_extension("sqlite3"));
    }

    #[test]
    fn wp_cli_execution_is_site_scoped_and_never_audits_the_raw_command() {
        let temp = std::env::temp_dir().join(format!("wpmm-wp-cli-{}", Uuid::new_v4()));
        let database = Database::initialize(temp.with_extension("sqlite3")).unwrap();
        let site = database.save_site(&site_input(), None).unwrap();
        let ssh = Arc::new(WpCliMockSsh::default());
        let mut state = app_state(database.clone(), &temp);
        state.ssh = ssh.clone();

        let result = execute_wp_cli_internal(
            &state,
            &site.id,
            "wp option update api_token super-secret-value",
            true,
            None,
        )
        .unwrap();

        assert_eq!(result.status, wp_cli::WpCliExecutionStatus::Success);
        assert_eq!(result.stdout, "<script>alert('text only')</script>\n");
        assert!(result.truncated);
        let commands = ssh.commands.lock().unwrap();
        assert_eq!(commands.len(), 1);
        assert!(commands[0].contains("--path='/srv/site'"));
        assert!(!commands[0].contains("example.test"));

        let events = database.list_audit_events(Some(&site.id)).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].target, "wp:option");
        let persisted = format!("{} {:?}", events[0].target, events[0].details);
        assert!(!persisted.contains("super-secret-value"));
        assert!(!persisted.contains("api_token"));

        let _ = std::fs::remove_file(temp.with_extension("sqlite3"));
    }

    #[test]
    fn bulk_cleanup_reports_partial_failure_and_rescans_once() {
        let temp = std::env::temp_dir().join(format!("wpmm-cleanup-{}", Uuid::new_v4()));
        let database = Database::initialize(temp.with_extension("sqlite3")).unwrap();
        let site = database.save_site(&site_input(), None).unwrap();
        let first_id = Uuid::new_v4().to_string();
        let second_id = Uuid::new_v4().to_string();
        let finding = |id: String, path: &str| Finding {
            id: Some(id),
            category: "wordpress-core-unexpected".into(),
            severity: FindingSeverity::Attention,
            title: "Hoort niet aanwezig te zijn".into(),
            detail: "File should not exist".into(),
            path: Some(path.into()),
            checksum_status: Some(ChecksumStatus::Unexpected),
            disposition: crate::models::FindingDisposition::Active,
            exception_id: None,
            trusted_file_id: None,
            policy_reason: None,
            observed_at: Some("2026-08-31T10:00:00Z".into()),
        };
        database
            .save_scan(
                &ScanResult {
                    id: Uuid::new_v4().to_string(),
                    site_id: site.id.clone(),
                    started_at: "2026-08-31T10:00:00Z".into(),
                    finished_at: "2026-08-31T10:00:01Z".into(),
                    status: SiteStatus::Attention,
                    checks: vec![ScanCheck {
                        key: "core_checksum".into(),
                        label: "WordPress core".into(),
                        status: StepStatus::Warning,
                        summary: "2 onverwachte bestanden".into(),
                        technical_details: None,
                        findings: vec![
                            finding(first_id.clone(), "wp-admin/delete.php"),
                            finding(second_id.clone(), "wp-admin/locked.php"),
                        ],
                    }],
                    truncated: false,
                },
                "Aandacht nodig",
            )
            .unwrap();
        let ssh = Arc::new(CleanupMockSsh::default());
        let mut state = app_state(database.clone(), &temp);
        state.ssh = ssh.clone();

        let result =
            delete_checksum_findings_internal(&state, &site.id, vec![first_id, second_id], true)
                .unwrap();
        assert_eq!(result.requested, 2);
        assert_eq!(result.deleted, 1);
        assert_eq!(result.failures.len(), 1);
        assert!(result.scan.is_some());
        assert_eq!(
            ssh.deleted.lock().unwrap().as_slice(),
            ["wp-admin/delete.php"]
        );
        assert_eq!(database.list_scans(&site.id).unwrap().len(), 2);
        assert!(
            database
                .list_audit_events(Some(&site.id))
                .unwrap()
                .iter()
                .any(|event| event.action_type == "checksum_file_bulk_delete")
        );

        let _ = std::fs::remove_file(temp.with_extension("sqlite3"));
    }
}
