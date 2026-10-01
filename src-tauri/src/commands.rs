use crate::{
    auth, checksum_files,
    command_catalog::{RemoteAction, RemoteCommand, build},
    core_operations, engine,
    error::AppError,
    error_log, maintenance,
    models::{
        AppSettings, AuditEvent, AuthStatus, BulkScanStart, ChecksumDeleteFailure,
        ChecksumDeletePhase, ChecksumDeleteProgress, ChecksumDeleteResult,
        ComponentVulnerabilityResult, ConnectionStep, ConnectionTestResult, CoreOperationInfo,
        CoreOperationKind, CoreOperationResult, DatabaseCleanupOption, DatabaseCleanupRequest,
        DatabaseCleanupResult, DatabaseCleanupTarget, ErrorLogFilter, ErrorLogPage, ExceptionScope,
        FilePreview, FindingException, FindingExceptionInput, LoginResult, MaintenanceRun,
        MaintenanceStep, PasswordChangeInput, ScanJobState, ScanResult,
        SecurityPolicyMutationResult, Site, SiteInput, SiteStatus, StepStatus, StoredSite,
        TrustedFile, TrustedFileInput, TrustedFileStatus, UpdateItem, VulnerabilityRefreshJobState,
        WordPressUserDeleteInput, WordPressUserUpdateInput, WordPressUsersData,
        WordfenceIntegrationStatus,
    },
    security_policy,
    snapshot_builder::{SnapshotBuildInput, SnapshotBuildSection, SnapshotBuilder},
    snapshot_diff::SnapshotDiffEngine,
    snapshots::{
        SiteChangeHistory, SiteChangeSummary, SnapshotChangeOrigin, SnapshotDiff,
        SnapshotFileState, SnapshotHistoryItem, SnapshotMetadata, SnapshotSource,
    },
    state::AppState,
    terminal::{TerminalConnectRequest, TerminalConnectionInfo, TerminalOpenInput},
    terminal_auth::TerminalChallengeInfo,
    validation::{validate_direct_child_directory, validate_site},
    vulnerability_matcher, wordfence, wordpress_users, wp_cli, wp_cli_catalog,
};
use chrono::{DateTime, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet, VecDeque},
    fs,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::{Duration, Instant, SystemTime},
};
use tauri::{AppHandle, Emitter, Manager, State};
use tauri_plugin_opener::OpenerExt;
use zeroize::Zeroizing;

const INVENTORY_STALE_SECONDS: i64 = 7 * 24 * 60 * 60;
const STAGED_WORDFENCE_FEED_FILE: &str = "wordfence-connection-test.json";

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
    if !authenticated {
        state.filemanager_access.revoke_all();
    } else {
        state.filemanager_access.reap_expired();
    }
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
    state.filemanager_access.revoke_all();
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
    state.filemanager_access.revoke_all();
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
    state.filemanager_access.revoke_all();
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

#[tauri::command(async)]
pub fn delete_error_logs(
    session_token: String,
    error_ids: Vec<String>,
    state: State<'_, AppState>,
) -> Result<u64, AppError> {
    require_auth(&state, &session_token)?;
    validate_error_log_ids(&error_ids)?;
    state.database.delete_error_logs(&error_ids)
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
    if result.is_err() {
        state.filemanager_access.revoke_all();
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
    verify_feature_password(state, site_id, app_password, "terminal_reauthentication")?;
    let stored = state.database.get_site(site_id)?;
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

fn verify_feature_password(
    state: &AppState,
    site_id: &str,
    app_password: Zeroizing<String>,
    purpose: &str,
) -> Result<(), AppError> {
    let stored = state.database.get_site(site_id)?;
    let config = state
        .database
        .auth_config()?
        .ok_or_else(|| AppError::validation("Stel eerst een applicatiewachtwoord in."))?;
    if !auth::verify_password(app_password.as_str(), &config.password_hash) {
        if let Err(error) = state.database.save_audit_event(
            Some(site_id),
            purpose,
            &stored.site.ssh_username,
            "failed",
            Some("Extra applicatieverificatie mislukt"),
        ) {
            eprintln!("security audit write failed category={}", error.category);
        }
        state.terminals.close_all();
        state.terminal_access.revoke_all();
        state.filemanager_access.revoke_all();
        if let Err(error) = state.auth.invalidate() {
            eprintln!("session invalidation failed category={}", error.category);
        }
        if let Err(error) = state.database.save_audit_event(
            Some(site_id),
            "app_session_revoked",
            purpose,
            "success",
            Some("Sessie ingetrokken na mislukte extra verificatie"),
        ) {
            eprintln!("security audit write failed category={}", error.category);
        }
        return Err(AppError::unauthorized(
            "app_session_revoked_reauth_failed",
            "Sessie beëindigd. De extra beveiligingscontrole is mislukt. Log opnieuw in om verder te gaan.",
        ));
    }
    Ok(())
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
pub fn get_filemanager_context(
    session_token: String,
    site_id: String,
    state: State<'_, AppState>,
) -> Result<crate::filemanager::FilemanagerContext, AppError> {
    require_auth(&state, &session_token)?;
    validate_uuid(&site_id, "De website-id is ongeldig.")?;
    crate::filemanager::context(&state.database, &site_id)
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
pub fn begin_filemanager_reauthentication(
    session_token: String,
    site_id: String,
    app_password: String,
    state: State<'_, AppState>,
) -> Result<TerminalChallengeInfo, AppError> {
    let password = Zeroizing::new(app_password);
    require_auth(&state, &session_token)?;
    begin_filemanager_reauthentication_internal(&state, &session_token, &site_id, password)
}

fn begin_filemanager_reauthentication_internal(
    state: &AppState,
    session_token: &str,
    site_id: &str,
    password: Zeroizing<String>,
) -> Result<TerminalChallengeInfo, AppError> {
    require_auth(state, session_token)?;
    validate_uuid(site_id, "De website-id is ongeldig.")?;
    verify_feature_password(state, site_id, password, "filemanager_reauthentication")?;
    // The app can have been locked while Argon2 was running.
    require_auth(state, session_token)?;
    let site = state.database.get_site(site_id)?.site;
    if site.ssh_host.trim().is_empty()
        || site.ssh_username.trim().is_empty()
        || site.ssh_port == 0
        || site.pinned_host_key.is_none()
    {
        return Err(AppError::validation(
            "Controleer eerst de SSH-configuratie en vertrouwde hostsleutel van deze website.",
        ));
    }
    let challenge = state.filemanager_access.begin(session_token, &site)?;
    if let Err(error) = state.database.save_audit_event(
        Some(site_id),
        "filemanager_reauthentication",
        &site.ssh_username,
        "success",
        Some("Extra applicatieverificatie bevestigd; tijdelijke challenge uitgegeven"),
    ) {
        eprintln!("security audit write failed category={}", error.category);
    }
    Ok(challenge)
}

#[tauri::command(async)]
pub fn open_filemanager(
    session_token: String,
    site_id: String,
    challenge_token: String,
    ssh_password: String,
    state: State<'_, AppState>,
) -> Result<crate::filemanager::FilemanagerAuthorization, AppError> {
    let password = Zeroizing::new(ssh_password);
    require_auth(&state, &session_token)?;
    let site = state.database.get_site(&site_id)?.site;
    let result =
        state
            .filemanager_access
            .connect(&session_token, &site, &challenge_token, &password);
    drop(password);
    require_auth(&state, &session_token)?;
    result?;
    require_filemanager_auth(&state, &session_token, &site_id, &challenge_token)
}

// Central boundary for every future filemanager endpoint: app + site + feature authorization.
fn require_filemanager_auth(
    state: &AppState,
    session: &str,
    site_id: &str,
    token: &str,
) -> Result<crate::filemanager::FilemanagerAuthorization, AppError> {
    require_auth(state, session)?;
    let site = state.database.get_site(site_id)?.site;
    state.filemanager_access.authorize(session, &site, token)
}

#[tauri::command(async)]
pub fn get_filemanager_authorization(
    session_token: String,
    site_id: String,
    authorization_token: String,
    state: State<'_, AppState>,
) -> Result<crate::filemanager::FilemanagerAuthorization, AppError> {
    require_auth(&state, &session_token)?;
    require_filemanager_auth(&state, &session_token, &site_id, &authorization_token)
}

#[tauri::command(async)]
pub fn close_filemanager(
    session_token: String,
    site_id: String,
    authorization_token: String,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    require_auth(&state, &session_token)?;
    state
        .filemanager_access
        .close(&session_token, &site_id, &authorization_token);
    Ok(())
}

#[tauri::command(async)]
pub fn list_filemanager_directory(
    session_token: String,
    site_id: String,
    authorization_token: String,
    requested_path: String,
    state: State<'_, AppState>,
) -> Result<crate::filemanager_directory::DirectoryListing, AppError> {
    require_auth(&state, &session_token)?;
    list_filemanager_directory_internal(
        &state,
        &session_token,
        &site_id,
        &authorization_token,
        &requested_path,
        |site, path| {
            state.filemanager_access.list_directory(
                &session_token,
                site,
                &authorization_token,
                path,
            )
        },
    )
}

fn list_filemanager_directory_internal(
    state: &AppState,
    session: &str,
    site_id: &str,
    token: &str,
    requested: &str,
    operation: impl FnOnce(
        &Site,
        &str,
    ) -> Result<crate::filemanager_directory::DirectoryListing, AppError>,
) -> Result<crate::filemanager_directory::DirectoryListing, AppError> {
    require_filemanager_auth(state, session, site_id, token)?;
    let site = state.database.get_site(site_id)?.site;
    let requested = crate::filemanager_paths::VirtualPath::parse(requested)?;
    let result = operation(&site, requested.as_str());
    require_auth(state, session)?;
    if result.is_ok() {
        require_filemanager_auth(state, session, site_id, token)?;
    }
    result
}

#[tauri::command(async)]
pub fn read_filemanager_file(
    session_token: String,
    site_id: String,
    authorization_token: String,
    requested_path: String,
    state: State<'_, AppState>,
) -> Result<crate::models::FileContentPreview, AppError> {
    require_auth(&state, &session_token)?;
    read_filemanager_file_internal(
        &state,
        &session_token,
        &site_id,
        &authorization_token,
        &requested_path,
        |site, path| {
            state
                .filemanager_access
                .read_file(&session_token, site, &authorization_token, path)
        },
    )
}

fn read_filemanager_file_internal(
    state: &AppState,
    session: &str,
    site_id: &str,
    token: &str,
    requested: &str,
    operation: impl FnOnce(&Site, &str) -> Result<crate::models::FileContentPreview, AppError>,
) -> Result<crate::models::FileContentPreview, AppError> {
    require_filemanager_auth(state, session, site_id, token)?;
    let site = state.database.get_site(site_id)?.site;
    let requested = crate::filemanager_paths::VirtualPath::parse(requested)?;
    let result = operation(&site, requested.as_str());
    require_auth(state, session)?;
    if result.is_ok() {
        require_filemanager_auth(state, session, site_id, token)?;
    }
    result
}

#[tauri::command(async)]
pub fn save_filemanager_file(
    session_token: String,
    site_id: String,
    authorization_token: String,
    input: crate::filemanager_edit::SaveInput,
    state: State<'_, AppState>,
) -> Result<crate::models::FileContentPreview, AppError> {
    require_auth(&state, &session_token)?;
    crate::filemanager_edit::validate_input(&input.content, &input.expected_version)?;
    read_filemanager_file_internal(
        &state,
        &session_token,
        &site_id,
        &authorization_token,
        &input.path,
        |site, path| {
            let normalized = crate::filemanager_edit::SaveInput {
                path: path.into(),
                content: input.content.clone(),
                expected_version: input.expected_version.clone(),
            };
            state.filemanager_access.save_file(
                &session_token,
                site,
                &authorization_token,
                &normalized,
                || {
                    require_filemanager_auth(&state, &session_token, &site_id, &authorization_token)
                        .map(|_| ())
                },
            )
        },
    )
}

#[tauri::command(async)]
pub fn create_filemanager_file(
    session_token: String,
    site_id: String,
    authorization_token: String,
    input: crate::filemanager_mutation::CreateInput,
    state: State<'_, AppState>,
) -> Result<crate::filemanager_mutation::MutationResult, AppError> {
    mutate_filemanager_item(
        &state,
        &session_token,
        &site_id,
        &authorization_token,
        &input.directory,
        |site, directory| {
            let input = crate::filemanager_mutation::CreateInput {
                directory: directory.into(),
                name: input.name.clone(),
            };
            state
                .filemanager_access
                .create_file(&session_token, site, &authorization_token, &input)
        },
    )
}

#[tauri::command(async)]
pub fn create_filemanager_directory(
    session_token: String,
    site_id: String,
    authorization_token: String,
    input: crate::filemanager_mutation::CreateInput,
    state: State<'_, AppState>,
) -> Result<crate::filemanager_mutation::MutationResult, AppError> {
    mutate_filemanager_item(
        &state,
        &session_token,
        &site_id,
        &authorization_token,
        &input.directory,
        |site, directory| {
            let input = crate::filemanager_mutation::CreateInput {
                directory: directory.into(),
                name: input.name.clone(),
            };
            state.filemanager_access.create_directory(
                &session_token,
                site,
                &authorization_token,
                &input,
            )
        },
    )
}

#[tauri::command(async)]
pub fn delete_filemanager_item(
    session_token: String,
    site_id: String,
    authorization_token: String,
    input: crate::filemanager_mutation::DeleteInput,
    state: State<'_, AppState>,
) -> Result<crate::filemanager_mutation::MutationResult, AppError> {
    mutate_filemanager_item(
        &state,
        &session_token,
        &site_id,
        &authorization_token,
        &input.path,
        |site, path| {
            let input = crate::filemanager_mutation::DeleteInput {
                path: path.into(),
                expected_kind: input.expected_kind,
            };
            state
                .filemanager_access
                .delete_item(&session_token, site, &authorization_token, &input)
        },
    )
}

fn mutate_filemanager_item<T>(
    state: &AppState,
    session: &str,
    site_id: &str,
    token: &str,
    requested: &str,
    operation: impl FnOnce(&Site, &str) -> Result<T, AppError>,
) -> Result<T, AppError> {
    require_auth(state, session)?;
    require_filemanager_auth(state, session, site_id, token)?;
    let site = state.database.get_site(site_id)?.site;
    let requested = crate::filemanager_paths::VirtualPath::parse(requested)?;
    let result = operation(&site, requested.as_str());
    require_auth(state, session)?;
    if result.is_ok() {
        require_filemanager_auth(state, session, site_id, token)?;
    }
    result
}

#[tauri::command(async)]
pub fn save_site(
    session_token: String,
    mut input: SiteInput,
    state: State<'_, AppState>,
) -> Result<Site, AppError> {
    require_auth(&state, &session_token)?;
    validate_site(&input)?;
    validate_site_identity_and_relationship(&state.database, &mut input)?;
    let is_new = input.id.is_none();
    let has_secret = input
        .credential_secret
        .as_deref()
        .is_some_and(|secret| !secret.is_empty());
    let inherited_credential_ref =
        inherited_credential_ref_for_new_site(&state.database, &input, is_new, has_secret)?;
    let is_new_password =
        is_new && matches!(input.auth_method, crate::models::AuthMethod::Password);
    if is_new_password && !has_secret && inherited_credential_ref.is_none() {
        return Err(AppError::validation("Vul het SSH-wachtwoord in."));
    }
    let provisional_id = input
        .id
        .clone()
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    input.id = Some(provisional_id.clone());
    let existing = if is_new {
        None
    } else {
        Some(state.database.get_site(&provisional_id)?)
    };
    let endpoint_changed = existing.as_ref().is_some_and(|stored| {
        !stored
            .site
            .ssh_host
            .eq_ignore_ascii_case(input.ssh_host.trim())
            || stored.site.ssh_port != input.ssh_port
    });
    if (is_new || endpoint_changed) && input.pinned_host_key.is_none() {
        return Err(AppError::validation(
            "Test eerst de SSH-verbinding en accepteer de serverfingerprint.",
        ));
    }
    if let Some(expected) = input.pinned_host_key.as_deref()
        && (is_new || endpoint_changed)
    {
        validate_host_fingerprint(expected)?;
        let candidate = site_from_input(&input, existing.as_ref());
        let actual = state.ssh.fingerprint(&candidate)?;
        if actual != expected {
            return Err(AppError::ssh(
                "host_key_changed_before_save",
                "De serveridentiteit veranderde vóór het opslaan. Test de verbinding opnieuw.",
                format!("Verwacht {expected}; ontvangen {actual}"),
                false,
            ));
        }
    }
    let credential_ref = format!("site:{provisional_id}:ssh");
    if let Some(secret) = input
        .credential_secret
        .as_deref()
        .filter(|secret| !secret.is_empty())
    {
        state.credentials.set(&credential_ref, secret)?;
    }
    input.credential_secret = None;
    let credential_ref_for_save = has_secret
        .then_some(credential_ref.as_str())
        .or(inherited_credential_ref.as_deref());
    match state.database.save_site(&input, credential_ref_for_save) {
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
    state.filemanager_access.revoke_site(&id);
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
    validate_host_fingerprint(&fingerprint)?;
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
        let endpoint_changed = !stored
            .site
            .ssh_host
            .eq_ignore_ascii_case(input.ssh_host.trim())
            || stored.site.ssh_port != input.ssh_port;
        let still_uses_previous_fingerprint = input.pinned_host_key == stored.site.pinned_host_key;
        endpoint_changed && still_uses_previous_fingerprint
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
                unexpected_directories: Vec::new(),
                unexpected_directories_truncated: false,
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
    let directory_output = match run_readonly(
        state.ssh.as_ref(),
        &site,
        credential.as_deref(),
        build(
            &site.wordpress_path,
            RemoteAction::ListUnexpectedRootDirectories,
        )?,
    ) {
        Ok(output) => output,
        Err(error) => {
            steps[7].status = StepStatus::Failed;
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
    let directories = match parse_unexpected_root_directories(&directory_output) {
        Ok(directories) => directories,
        Err(error) => {
            steps[7].status = StepStatus::Failed;
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
    steps[7].status = if directories.truncated {
        StepStatus::Warning
    } else {
        StepStatus::Success
    };
    steps[7].detail = Some(if directories.truncated {
        "De eerste 200 onbekende hoofdmappen zijn geladen; de lijst is begrensd.".into()
    } else {
        format!(
            "{} onbekende hoofdmappen gevonden.",
            directories.directories.len()
        )
    });
    Ok(ConnectionTestResult {
        success: true,
        steps,
        fingerprint: Some(fingerprint),
        requires_host_key_acceptance: false,
        wordpress_version: Some(wordpress_version),
        php_version: Some(php_version),
        wp_cli_version: Some(wp_cli_version),
        detected_url: Some(detected_url),
        unexpected_directories: directories.directories,
        unexpected_directories_truncated: directories.truncated,
        error: None,
    })
}

const SITE_SCAN_STEPS: &[(&str, &str)] = &[
    ("ssh_connect", "SSH-verbinding"),
    ("wordpress_detection", "WordPress detecteren"),
    ("wordpress", "WordPress-informatie"),
    ("wp_cli_version", "WP-CLI-versie"),
    ("checksum", "WordPress core checksum"),
    ("users", "Gebruikersaccounts"),
    ("php", "PHP-bestanden"),
    ("uploads", "PHP in uploads"),
    ("modified", "Gewijzigde bestanden"),
    ("permissions", "Bestandsrechten"),
    ("configuration", "WordPress-configuratie"),
    ("cron", "WordPress-cron"),
    ("database", "Databasecontrole"),
    ("core_updates", "WordPress-updates"),
    ("plugin_list", "Plugin-updates"),
    ("theme_list", "Thema-updates"),
    ("homepage", "Homepagecontrole"),
    ("vulnerabilities", "Kwetsbaarheden"),
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
        if let Ok(job) =
            self.state
                .scan_jobs
                .step_finished(self.job_id, key, status, duration_ms, detail)
        {
            emit_scan_job(self.app, &job);
        }
    }

    fn step_failed_diagnostic(
        &mut self,
        key: &str,
        user_message: &str,
        technical_details: Option<&str>,
        duration_ms: u64,
    ) {
        let diagnostic = technical_details.map(str::to_owned).unwrap_or_else(|| {
            format!("Scanonderdeel: {key}; geen aanvullende details ontvangen.")
        });
        let _ = error_log::persist_error(
            &self.state.database,
            Some(self.site_id),
            Some(self.site_name),
            &format!("Scan · {key}"),
            Some(duration_ms),
            None,
            AppError::ssh("scan_step_failed", user_message, diagnostic, true),
        );
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
pub fn get_site_changes(
    session_token: String,
    site_id: String,
    state: State<'_, AppState>,
) -> Result<SiteChangeHistory, AppError> {
    require_auth(&state, &session_token)?;
    uuid::Uuid::parse_str(&site_id)
        .map_err(|_| AppError::validation("De website-id is ongeldig."))?;
    state.database.get_site(&site_id)?;
    state
        .database
        .snapshot_repository()
        .site_change_history(&site_id)
}

#[tauri::command(async)]
pub fn mark_site_changes_seen(
    session_token: String,
    site_id: String,
    snapshot_id: String,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    require_auth(&state, &session_token)?;
    uuid::Uuid::parse_str(&site_id)
        .map_err(|_| AppError::validation("De website-id is ongeldig."))?;
    uuid::Uuid::parse_str(&snapshot_id)
        .map_err(|_| AppError::validation("De snapshot-id is ongeldig."))?;
    state
        .database
        .snapshot_repository()
        .mark_changes_seen(&site_id, &snapshot_id)
}

#[tauri::command(async)]
pub fn list_site_snapshots(
    session_token: String,
    site_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<SnapshotMetadata>, AppError> {
    require_auth(&state, &session_token)?;
    uuid::Uuid::parse_str(&site_id)
        .map_err(|_| AppError::validation("De website-id is ongeldig."))?;
    state.database.get_site(&site_id)?;
    state
        .database
        .snapshot_repository()
        .list_snapshot_metadata(&site_id, 100)
}

#[tauri::command(async)]
pub fn list_site_snapshot_history(
    session_token: String,
    site_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<SnapshotHistoryItem>, AppError> {
    require_auth(&state, &session_token)?;
    uuid::Uuid::parse_str(&site_id)
        .map_err(|_| AppError::validation("De website-id is ongeldig."))?;
    state.database.get_site(&site_id)?;
    state
        .database
        .snapshot_repository()
        .list_snapshot_history(&site_id, 100)
}

#[tauri::command(async)]
pub fn list_site_change_summaries(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<Vec<SiteChangeSummary>, AppError> {
    require_auth(&state, &session_token)?;
    state
        .database
        .snapshot_repository()
        .list_site_change_summaries()
}

#[tauri::command(async)]
pub fn compare_site_snapshots(
    session_token: String,
    site_id: String,
    from_snapshot_id: String,
    to_snapshot_id: String,
    state: State<'_, AppState>,
) -> Result<SnapshotDiff, AppError> {
    require_auth(&state, &session_token)?;
    uuid::Uuid::parse_str(&site_id)
        .map_err(|_| AppError::validation("De website-id is ongeldig."))?;
    for snapshot_id in [&from_snapshot_id, &to_snapshot_id] {
        uuid::Uuid::parse_str(snapshot_id)
            .map_err(|_| AppError::validation("De snapshot-id is ongeldig."))?;
    }
    state.database.get_site(&site_id)?;
    state.database.snapshot_repository().compare_snapshots(
        &site_id,
        &from_snapshot_id,
        &to_snapshot_id,
    )
}

#[tauri::command(async)]
pub fn set_site_snapshot_baseline(
    session_token: String,
    site_id: String,
    snapshot_id: String,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    require_auth(&state, &session_token)?;
    uuid::Uuid::parse_str(&site_id)
        .map_err(|_| AppError::validation("De website-id is ongeldig."))?;
    uuid::Uuid::parse_str(&snapshot_id)
        .map_err(|_| AppError::validation("De snapshot-id is ongeldig."))?;
    state
        .database
        .snapshot_repository()
        .mark_as_baseline(&site_id, &snapshot_id)?;
    state.database.save_audit_event(
        Some(&site_id),
        "snapshot_baseline_set",
        &snapshot_id,
        "success",
        None,
    )
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
pub fn remove_finding_exceptions(
    session_token: String,
    exception_ids: Vec<String>,
    state: State<'_, AppState>,
) -> Result<u64, AppError> {
    require_auth(&state, &session_token)?;
    validate_bulk_uuid_ids(&exception_ids, "uitzonderingen")?;
    let site_ids = state
        .database
        .deactivate_finding_exceptions(&exception_ids)?;
    for (exception_id, site_id) in exception_ids.iter().zip(&site_ids) {
        state.database.save_audit_event(
            Some(site_id),
            "finding_unignored",
            exception_id,
            "success",
            Some("bulk_action=true"),
        )?;
    }
    reapply_policy_for_sites(&state, &site_ids)?;
    Ok(exception_ids.len() as u64)
}

#[tauri::command(async)]
pub fn cleanup_expired_finding_exceptions(
    session_token: String,
    exception_ids: Vec<String>,
    state: State<'_, AppState>,
) -> Result<u64, AppError> {
    require_auth(&state, &session_token)?;
    validate_bulk_uuid_ids(&exception_ids, "verlopen uitzonderingen")?;
    let site_ids = state
        .database
        .delete_expired_finding_exceptions(&exception_ids, Utc::now())?;
    for (exception_id, site_id) in exception_ids.iter().zip(&site_ids) {
        state.database.save_audit_event(
            Some(site_id),
            "expired_exception_deleted",
            exception_id,
            "success",
            Some("bulk_action=true"),
        )?;
    }
    reapply_policy_for_sites(&state, &site_ids)?;
    Ok(exception_ids.len() as u64)
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
pub fn revoke_trusted_files(
    session_token: String,
    trusted_file_ids: Vec<String>,
    state: State<'_, AppState>,
) -> Result<u64, AppError> {
    require_auth(&state, &session_token)?;
    validate_bulk_uuid_ids(&trusted_file_ids, "vertrouwde bestanden")?;
    let trusted_files = trusted_file_ids
        .iter()
        .map(|id| state.database.get_trusted_file(id))
        .collect::<Result<Vec<_>, _>>()?;
    if trusted_files.iter().any(|trusted| !trusted.active) {
        return Err(AppError::validation(
            "Een geselecteerde trustregistratie is al ingetrokken.",
        ));
    }
    let site_ids = state.database.deactivate_trusted_files(&trusted_file_ids)?;
    for (trusted, site_id) in trusted_files.iter().zip(&site_ids) {
        state.database.save_audit_event(
            Some(site_id),
            "trust_revoked",
            &trusted.relative_path,
            "success",
            Some("bulk_action=true"),
        )?;
    }
    reapply_policy_for_sites(&state, &site_ids)?;
    Ok(trusted_file_ids.len() as u64)
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
        let context = state.database.get_finding_context(&site_id, &finding_id)?;
        let credential = stored_credential(&state, &stored)?;
        checksum_files::preview(state.ssh.as_ref(), &stored, credential.as_deref(), &context)
    })();
    log_operation_error(
        &state,
        Some(&site_id),
        "Scanbestand bekijken",
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
    operation_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<ChecksumDeleteResult, AppError> {
    require_auth(&state, &session_token)?;
    uuid::Uuid::parse_str(&operation_id)
        .map_err(|_| AppError::validation("De bulkverwijdering-id is ongeldig."))?;
    let started = Instant::now();
    let result = delete_checksum_findings_with_progress(
        &state,
        &site_id,
        finding_ids,
        true,
        &operation_id,
        |progress| {
            if let Err(error) = app.emit("checksum-delete-progress", progress) {
                eprintln!("checksum delete progress emit failed: {error}");
            }
        },
    );
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
    delete_checksum_findings_with_progress(state, site_id, finding_ids, bulk, "", |_| {})
}

fn delete_checksum_findings_with_progress<F>(
    state: &AppState,
    site_id: &str,
    finding_ids: Vec<String>,
    bulk: bool,
    operation_id: &str,
    mut on_progress: F,
) -> Result<ChecksumDeleteResult, AppError>
where
    F: FnMut(ChecksumDeleteProgress),
{
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
    emit_checksum_delete_progress(
        &mut on_progress,
        operation_id,
        site_id,
        ChecksumDeletePhase::Deleting,
        0,
        requested,
        0,
        0,
    );

    for (index, finding_id) in finding_ids.into_iter().enumerate() {
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
                emit_checksum_delete_progress(
                    &mut on_progress,
                    operation_id,
                    site_id,
                    ChecksumDeletePhase::Deleting,
                    index + 1,
                    requested,
                    deleted_paths.len(),
                    failures.len(),
                );
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
        emit_checksum_delete_progress(
            &mut on_progress,
            operation_id,
            site_id,
            ChecksumDeletePhase::Deleting,
            index + 1,
            requested,
            deleted_paths.len(),
            failures.len(),
        );
    }

    let (scan, rescan_error) = if deleted_paths.is_empty() {
        (None, None)
    } else {
        emit_checksum_delete_progress(
            &mut on_progress,
            operation_id,
            site_id,
            ChecksumDeletePhase::Rescanning,
            requested,
            requested,
            deleted_paths.len(),
            failures.len(),
        );
        match scan_site_internal(state, site_id, 30) {
            Ok(scan) => (Some(scan), None),
            Err(error) => (None, Some(error)),
        }
    };
    emit_checksum_delete_progress(
        &mut on_progress,
        operation_id,
        site_id,
        ChecksumDeletePhase::Completed,
        requested,
        requested,
        deleted_paths.len(),
        failures.len(),
    );
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

#[allow(clippy::too_many_arguments)]
fn emit_checksum_delete_progress<F>(
    on_progress: &mut F,
    operation_id: &str,
    site_id: &str,
    phase: ChecksumDeletePhase,
    processed: usize,
    total: usize,
    deleted: usize,
    failed: usize,
) where
    F: FnMut(ChecksumDeleteProgress),
{
    if operation_id.is_empty() {
        return;
    }
    on_progress(ChecksumDeleteProgress {
        operation_id: operation_id.into(),
        site_id: site_id.into(),
        phase,
        processed,
        total,
        deleted,
        failed,
    });
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

fn validate_bulk_uuid_ids(ids: &[String], label: &str) -> Result<(), AppError> {
    if ids.is_empty() || ids.len() > 1_000 {
        return Err(AppError::validation(format!(
            "Selecteer tussen 1 en 1000 {label}.",
        )));
    }
    let mut unique = HashSet::with_capacity(ids.len());
    for id in ids {
        validate_uuid(id, "Een geselecteerde registratie-id is ongeldig.")?;
        if !unique.insert(id) {
            return Err(AppError::validation(
                "De selectie bevat een dubbele registratie-id.",
            ));
        }
    }
    Ok(())
}

fn validate_error_log_ids(ids: &[String]) -> Result<(), AppError> {
    if ids.is_empty() || ids.len() > 1_000 {
        return Err(AppError::validation(
            "Selecteer tussen 1 en 1000 foutregels.",
        ));
    }
    let mut unique = HashSet::with_capacity(ids.len());
    for id in ids {
        let suffix = id.strip_prefix("ERR-").unwrap_or_default();
        if suffix.len() != 12 || !suffix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(AppError::validation("Een fout-ID is ongeldig."));
        }
        if !unique.insert(id) {
            return Err(AppError::validation(
                "De selectie bevat een dubbel fout-ID.",
            ));
        }
    }
    Ok(())
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

fn reapply_policy_for_sites(state: &AppState, site_ids: &[String]) -> Result<(), AppError> {
    let mut reapplied = HashSet::with_capacity(site_ids.len());
    for site_id in site_ids {
        if reapplied.insert(site_id) {
            reapply_latest_policy(state, site_id)?;
        }
    }
    Ok(())
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
    let excluded_root_directories = state.database.child_installation_directories(site_id)?;
    let mut outcome = match engine::scan_site_with_progress_and_exclusions(
        state.ssh.as_ref(),
        &stored,
        credential.as_deref(),
        modified_days,
        &excluded_root_directories,
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
    progress.step_started("vulnerabilities");
    let vulnerability_started = Instant::now();
    let vulnerability_check = state
        .database
        .save_software_inventory(site_id, &outcome.inventory)
        .and_then(|()| state.database.software_inventory(site_id))
        .and_then(|inventory| vulnerability_matcher::scan_inventory(&state.database, &inventory));
    let vulnerability_check = match vulnerability_check {
        Ok(check) => {
            progress.step_finished(
                "vulnerabilities",
                check.status,
                u64::try_from(vulnerability_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                Some(check.summary.clone()),
            );
            check
        }
        Err(error) => {
            let logged = error_log::persist_error(
                &state.database,
                Some(site_id),
                Some(&stored.site.name),
                "Lokale vulnerability controle",
                Some(
                    u64::try_from(vulnerability_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                ),
                None,
                error,
            );
            progress.step_finished(
                "vulnerabilities",
                StepStatus::Skipped,
                u64::try_from(vulnerability_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                Some("Kwetsbaarheidscontrole is overgeslagen; overige scans gaan door.".into()),
            );
            crate::models::ScanCheck {
                key: "vulnerabilities".into(),
                label: "Kwetsbaarheden".into(),
                status: StepStatus::Skipped,
                summary: "Kwetsbaarheidscontrole niet beschikbaar; overige controles zijn normaal uitgevoerd."
                    .into(),
                technical_details: logged.safe_diagnostic(),
                findings: Vec::new(),
            }
        }
    };
    outcome.result.checks.push(vulnerability_check);
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
    let snapshot_files = scan_snapshot_files(&outcome.result, &trusted_files);
    let repository = state.database.snapshot_repository();
    let baseline = repository.baseline_snapshot(site_id)?;
    let previous = repository.latest_snapshot(site_id)?;
    let mut snapshot = build_scan_snapshot(
        &stored,
        &outcome,
        SnapshotSource::Scan,
        None,
        previous
            .as_ref()
            .map(|snapshot| snapshot.metadata.snapshot_id.clone()),
        snapshot_files,
    )?;
    if baseline.is_none() && snapshot.completeness.baseline_eligible() {
        snapshot.metadata.source = SnapshotSource::Baseline;
        snapshot.metadata.is_baseline = true;
        snapshot.metadata.previous_snapshot_id = None;
    }
    let diff = if snapshot.metadata.is_baseline {
        None
    } else {
        previous
            .as_ref()
            .map(|previous| {
                SnapshotDiffEngine::compare(previous, &snapshot, SnapshotChangeOrigin::Scan, None)
            })
            .transpose()?
    };
    state.database.update_versions(
        site_id,
        &outcome.wordpress_version,
        &outcome.php_version,
        outcome.wp_cli_version.as_deref(),
    )?;
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
    if let Err(error) = state.database.save_scan_with_snapshot(
        &outcome.result,
        &outcome.security_status,
        Some(&snapshot),
        diff.as_ref(),
    ) {
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

fn scan_snapshot_files(
    scan: &ScanResult,
    trusted_files: &[TrustedFile],
) -> SnapshotBuildSection<Vec<SnapshotFileState>> {
    let relevant_checks = ["core_checksum", "php_files", "php_uploads"];
    let reliable_checks = relevant_checks.iter().all(|key| {
        scan.checks
            .iter()
            .find(|check| check.key == *key)
            .is_some_and(|check| check.status != StepStatus::Failed)
    });
    if scan.truncated
        || !reliable_checks
        || trusted_files
            .iter()
            .any(|trusted| trusted.active && trusted.status == TrustedFileStatus::Unchecked)
    {
        return SnapshotBuildSection::Failed;
    }
    let mut files = BTreeMap::new();
    for trusted in trusted_files
        .iter()
        .filter(|trusted| trusted.active && trusted.status != TrustedFileStatus::Missing)
    {
        files.insert(
            trusted.relative_path.clone(),
            SnapshotFileState {
                relative_path: trusted.relative_path.clone(),
                category: "trusted".into(),
                file_type: trusted.file_type.clone(),
                size_bytes: trusted.current_size_bytes,
                modified_at: trusted.current_modified_at.clone(),
                sha256: trusted.current_sha256.clone(),
            },
        );
    }
    for check in scan
        .checks
        .iter()
        .filter(|check| relevant_checks.contains(&check.key.as_str()))
    {
        for finding in &check.findings {
            let Some(path) = finding.path.as_deref() else {
                continue;
            };
            files
                .entry(path.to_owned())
                .or_insert_with(|| SnapshotFileState {
                    relative_path: path.to_owned(),
                    category: finding.category.clone(),
                    file_type: path.rsplit_once('.').map_or_else(
                        || "bestand".into(),
                        |(_, extension)| extension.to_ascii_lowercase(),
                    ),
                    size_bytes: None,
                    modified_at: finding.observed_at.clone(),
                    sha256: None,
                });
        }
    }
    SnapshotBuildSection::Complete(files.into_values().collect())
}

fn build_scan_snapshot(
    stored: &StoredSite,
    outcome: &engine::ScanOutcome,
    source: SnapshotSource,
    maintenance_run_id: Option<String>,
    previous_snapshot_id: Option<String>,
    files: SnapshotBuildSection<Vec<SnapshotFileState>>,
) -> Result<crate::snapshots::SiteSnapshot, AppError> {
    SnapshotBuilder::build(SnapshotBuildInput {
        site_id: stored.site.id.clone(),
        scan_run_id: Some(outcome.result.id.clone()),
        maintenance_run_id,
        source,
        previous_snapshot_id,
        wordpress_path: stored.site.wordpress_path.clone(),
        scan_timestamp: outcome.result.finished_at.clone(),
        core: outcome.snapshot_sections.core.clone(),
        plugins: outcome.snapshot_sections.plugins.clone(),
        themes: outcome.snapshot_sections.themes.clone(),
        users: outcome.snapshot_sections.users.clone(),
        configuration: outcome.snapshot_sections.configuration.clone(),
        cron: outcome.snapshot_sections.cron.clone(),
        files,
    })
}

#[tauri::command(async)]
pub fn get_settings(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<AppSettings, AppError> {
    require_auth(&state, &session_token)?;
    Ok(AppSettings {
        scan_concurrency: state.scan_concurrency.load(Ordering::SeqCst),
        file_preview_mode: state.database.file_preview_mode()?,
        markdown_preview_mode: state.database.markdown_preview_mode()?,
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
    state.database.save_settings(&settings)?;
    state
        .scan_concurrency
        .store(settings.scan_concurrency, Ordering::SeqCst);
    state.scan_jobs.set_concurrency(settings.scan_concurrency);
    Ok(settings)
}

#[tauri::command(async)]
pub fn list_database_cleanup_options(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<Vec<DatabaseCleanupOption>, AppError> {
    require_auth(&state, &session_token)?;
    state.database.database_cleanup_options()
}

#[tauri::command(async)]
pub fn cleanup_database(
    session_token: String,
    request: DatabaseCleanupRequest,
    state: State<'_, AppState>,
) -> Result<DatabaseCleanupResult, AppError> {
    require_auth(&state, &session_token)?;
    if request.confirmation.trim() != request.target.confirmation_phrase() {
        return Err(AppError::validation(format!(
            "De bevestiging voor tabel '{}' is niet correct.",
            request.target.table_name()
        )));
    }
    if request.target.requires_idle_scans() && !state.scan_jobs.list(true)?.is_empty() {
        return Err(AppError::validation(
            "Wacht tot alle actieve scans zijn afgerond of annuleer ze voordat je deze tabel opschoont.",
        ));
    }
    if matches!(
        request.target,
        DatabaseCleanupTarget::Sites | DatabaseCleanupTarget::ScanRuns
    ) && state
        .vulnerability_jobs
        .current()?
        .is_some_and(|job| job.status.is_active())
    {
        return Err(AppError::validation(
            "Wacht tot het vernieuwen van de Wordfence-database is afgerond voordat je deze tabel opschoont.",
        ));
    }

    let mut execution = state.database.execute_database_cleanup(&request)?;
    for site_id in &execution.site_ids {
        state.terminals.close_site(site_id);
        state.terminal_access.revoke_site(site_id);
        state.filemanager_access.revoke_site(site_id);
    }
    let credential_total = u64::try_from(execution.credential_references.len()).unwrap_or(u64::MAX);
    let mut credential_failures = 0_u64;
    for reference in execution.credential_references {
        if let Err(error) = state.credentials.delete(&reference) {
            credential_failures += 1;
            eprintln!("site credential cleanup failed category={}", error.category);
        }
    }
    if credential_failures > 0 {
        if let Some(impact) = execution
            .result
            .impacts
            .iter_mut()
            .find(|impact| impact.key == "credential_references")
        {
            impact.count = credential_total.saturating_sub(credential_failures);
        }
        execution.result.warnings.push(format!(
            "{credential_failures} opgeslagen SSH-credential(s) konden niet uit de beveiligde Windows-opslag worden verwijderd. De SQLite-database is wel volledig en consistent opgeschoond."
        ));
    }

    if request.target != DatabaseCleanupTarget::AuditEvents {
        let affected = execution
            .result
            .impacts
            .iter()
            .filter(|impact| impact.effect != "bewaard")
            .map(|impact| impact.count)
            .sum::<u64>();
        if let Err(error) = state.database.save_audit_event(
            None,
            "database_cleanup",
            request.target.table_name(),
            "success",
            Some(&format!("affected_records={affected}")),
        ) {
            eprintln!("database cleanup audit failed category={}", error.category);
            execution.result.warnings.push(
                "De opschoonactie is uitgevoerd, maar kon niet in het auditlog worden vastgelegd."
                    .into(),
            );
        }
    }
    if !execution.result.warnings.is_empty() {
        execution.result.status = "completed_with_warnings".into();
    }
    Ok(execution.result)
}

#[tauri::command(async)]
pub fn get_wordfence_status(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<WordfenceIntegrationStatus, AppError> {
    require_auth(&state, &session_token)?;
    wordfence_status_for_state(&state)
}

#[tauri::command(async)]
pub fn save_wordfence_api_key(
    session_token: String,
    api_key: String,
    state: State<'_, AppState>,
) -> Result<WordfenceIntegrationStatus, AppError> {
    require_auth(&state, &session_token)?;
    let api_key = Zeroizing::new(api_key);
    remove_staged_wordfence_feed(&state);
    wordfence::save_api_key(&state.credentials, &api_key)?;
    state.database.save_audit_event(
        None,
        "wordfence_key_saved",
        "wordfence_intelligence",
        "success",
        Some("Wordfence API-sleutel opgeslagen in de beveiligde credentialopslag"),
    )?;
    wordfence_status_for_state(&state)
}

#[tauri::command(async)]
pub fn remove_wordfence_api_key(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<WordfenceIntegrationStatus, AppError> {
    require_auth(&state, &session_token)?;
    wordfence::remove_api_key(&state.credentials)?;
    remove_staged_wordfence_feed(&state);
    state.database.save_audit_event(
        None,
        "wordfence_key_removed",
        "wordfence_intelligence",
        "success",
        Some("Wordfence API-sleutel uit de beveiligde credentialopslag verwijderd"),
    )?;
    wordfence_status_for_state(&state)
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
    let staged_path = staged_wordfence_feed_path(&state);
    let staging_path = staged_path.with_extension("download");
    let result = (|| {
        let cooldown = state.database.vulnerability_feed_cooldown_remaining(
            wordfence::WORDFENCE_PROVIDER,
            wordfence::FEED_COOLDOWN_SECONDS,
        )?;
        if cooldown > 0 && !staged_wordfence_feed_is_fresh(&staged_path, SystemTime::now()) {
            return Err(wordfence_cooldown_error(cooldown));
        }
        fs::create_dir_all(&state.vulnerability_cache_directory).map_err(AppError::storage)?;
        if staged_wordfence_feed_is_fresh(&staged_path, SystemTime::now()) {
            return Ok(());
        }
        let _ = fs::remove_file(&staging_path);
        let provider = wordfence::WordfenceIntelligenceProvider::new()?;
        state
            .database
            .record_vulnerability_feed_attempt(wordfence::WORDFENCE_PROVIDER)?;
        wordfence::VulnerabilityProvider::download_feed(&provider, &api_key, &staging_path)?;
        let _ = fs::remove_file(&staged_path);
        fs::rename(&staging_path, &staged_path).map_err(AppError::storage)
    })();
    let _ = fs::remove_file(&staging_path);
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
    let mut status = wordfence_status_for_state(&state)?;
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

#[tauri::command(async)]
pub fn match_cached_component_vulnerabilities(
    session_token: String,
    software_type: String,
    software_slug: String,
    installed_version: String,
    state: State<'_, AppState>,
) -> Result<ComponentVulnerabilityResult, AppError> {
    require_auth(&state, &session_token)?;
    if software_slug.len() > 500 || installed_version.len() > 200 {
        return Err(AppError::validation("Software-identiteit is te lang."));
    }
    vulnerability_matcher::match_component(
        &state.database,
        &software_type,
        &software_slug,
        &installed_version,
    )
}

#[tauri::command(async)]
pub fn open_vulnerability_reference(
    session_token: String,
    url: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    require_auth(&state, &session_token)?;
    let reference = validate_external_reference(&url)?;
    app.opener()
        .open_url(reference.as_str(), None::<&str>)
        .map_err(|error| AppError {
            error_id: None,
            category: "application".into(),
            user_message: "De externe referentie kon niet veilig worden geopend.".into(),
            technical_details: Some(error.to_string()),
            retryable: true,
        })
}

fn validate_external_reference(value: &str) -> Result<url::Url, AppError> {
    if value.len() > 4_096 || value.chars().any(char::is_control) {
        return Err(AppError::validation("De externe referentie is ongeldig."));
    }
    let parsed = url::Url::parse(value)
        .map_err(|_| AppError::validation("De externe referentie is ongeldig."))?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
    {
        return Err(AppError::validation(
            "Alleen veilige HTTP- en HTTPS-referenties kunnen worden geopend.",
        ));
    }
    Ok(parsed)
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
    let staged_path = staged_wordfence_feed_path(&state);
    let staged_feed_available = staged_wordfence_feed_is_fresh(&staged_path, SystemTime::now());
    let cooldown = state.database.vulnerability_feed_cooldown_remaining(
        wordfence::WORDFENCE_PROVIDER,
        wordfence::FEED_COOLDOWN_SECONDS,
    )?;
    if cooldown > 0 && !staged_feed_available {
        return Err(wordfence_cooldown_error(cooldown));
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

pub(crate) fn start_due_wordfence_feed_refresh(
    app: AppHandle,
) -> Result<Option<VulnerabilityRefreshJobState>, AppError> {
    let should_refresh = {
        let state = app.state::<AppState>();
        let configured = state
            .credentials
            .get_optional(wordfence::WORDFENCE_CREDENTIAL_REFERENCE)?
            .is_some();
        let feed = state
            .database
            .vulnerability_feed_state(wordfence::WORDFENCE_PROVIDER)?;
        configured
            && wordfence::feed_refresh_due(feed.last_successful_update_at.as_deref(), Utc::now())
    };
    if !should_refresh {
        return Ok(None);
    }
    start_wordfence_feed_refresh_internal(app, true).map(Some)
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
        let staged_path = staged_wordfence_feed_path(&state);
        let bytes = if staged_wordfence_feed_is_fresh(&staged_path, SystemTime::now()) {
            fs::rename(&staged_path, &temp_path).map_err(AppError::storage)?;
            fs::metadata(&temp_path).map_err(AppError::storage)?.len()
        } else {
            let _ = fs::remove_file(&staged_path);
            wordfence::VulnerabilityProvider::download_feed(&provider, &api_key, &temp_path)?
        };
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
        recalculate_cached_vulnerability_sites(&state)?;
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

fn staged_wordfence_feed_path(state: &AppState) -> std::path::PathBuf {
    state
        .vulnerability_cache_directory
        .join(STAGED_WORDFENCE_FEED_FILE)
}

fn staged_wordfence_feed_is_fresh(path: &std::path::Path, now: SystemTime) -> bool {
    path.metadata()
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|modified| now.duration_since(modified).ok())
        .is_some_and(|age| age <= Duration::from_secs(wordfence::FEED_REFRESH_SECONDS as u64))
}

fn remove_staged_wordfence_feed(state: &AppState) {
    let staged_path = staged_wordfence_feed_path(state);
    let _ = fs::remove_file(&staged_path);
    let _ = fs::remove_file(staged_path.with_extension("download"));
}

fn wordfence_status_for_state(state: &AppState) -> Result<WordfenceIntegrationStatus, AppError> {
    let mut status = wordfence::integration_status(
        &state.credentials,
        &state.database,
        &state.vulnerability_jobs,
    )?;
    if staged_wordfence_feed_is_fresh(&staged_wordfence_feed_path(state), SystemTime::now()) {
        status.cooldown_remaining_seconds = 0;
    }
    Ok(status)
}

fn wordfence_cooldown_error(cooldown: u64) -> AppError {
    AppError {
        error_id: None,
        category: "vulnerability_feed_cooldown".into(),
        user_message: format!(
            "De vulnerability database kan over {} minuten opnieuw worden vernieuwd.",
            cooldown.div_ceil(60)
        ),
        technical_details: None,
        retryable: true,
    }
}

fn recalculate_cached_vulnerability_sites(state: &AppState) -> Result<usize, AppError> {
    let sites = state.database.list_sites()?;
    let feed = state
        .database
        .vulnerability_feed_state(wordfence::WORDFENCE_PROVIDER)?;
    let mut recalculated = 0;
    for site in sites {
        match recalculate_cached_vulnerability_site(
            state,
            &site.id,
            feed.last_successful_update_at.as_deref(),
            Utc::now(),
        ) {
            Ok(true) => recalculated += 1,
            Ok(false) => {}
            Err(error) => {
                let _ = error_log::persist_error(
                    &state.database,
                    Some(&site.id),
                    Some(&site.name),
                    "Vulnerability-status lokaal herberekenen",
                    None,
                    None,
                    error,
                );
            }
        }
    }
    Ok(recalculated)
}

fn recalculate_cached_vulnerability_site(
    state: &AppState,
    site_id: &str,
    feed_updated_at: Option<&str>,
    now: DateTime<Utc>,
) -> Result<bool, AppError> {
    let inventory = state.database.software_inventory(site_id)?;
    if inventory.is_empty() {
        return Ok(false);
    }
    let inventory_observed_at = inventory
        .iter()
        .filter_map(|item| {
            DateTime::parse_from_rfc3339(&item.observed_at)
                .ok()
                .map(|timestamp| (timestamp.timestamp(), item.observed_at.as_str()))
        })
        .max_by_key(|(timestamp, _)| *timestamp)
        .map(|(_, value)| value);
    let inventory_stale = inventory_snapshot_is_stale(inventory_observed_at, now);
    let mut vulnerability_check =
        vulnerability_matcher::scan_inventory(&state.database, &inventory)?;
    if inventory_stale {
        vulnerability_check.summary = format!(
            "Mogelijk verouderd op basis van de laatst bekende softwareversies. {} Scan de website opnieuw voor actuele versies.",
            vulnerability_check.summary
        );
        let stale_details = "De opgeslagen software-inventaris is ouder dan zeven dagen; voor deze lokale herberekening is geen SSH-verbinding gemaakt.";
        vulnerability_check.technical_details = Some(match vulnerability_check.technical_details {
            Some(details) => format!("{details} · {stale_details}"),
            None => stale_details.into(),
        });
    }
    let exceptions = state.database.list_finding_exceptions(Some(site_id))?;
    let mut vulnerability_checks = vec![vulnerability_check];
    security_policy::apply_scan_policy(site_id, &mut vulnerability_checks, &exceptions, &[], now);
    let vulnerability_check = vulnerability_checks
        .pop()
        .ok_or_else(|| AppError::storage("Vulnerability-check ontbreekt na policytoepassing"))?;
    let Some(mut latest_scan) = state.database.latest_scan(site_id)? else {
        return Ok(false);
    };
    if let Some(index) = latest_scan
        .checks
        .iter()
        .position(|check| check.key == "vulnerabilities")
    {
        latest_scan.checks[index] = vulnerability_check.clone();
    } else {
        latest_scan.checks.push(vulnerability_check.clone());
    }
    latest_scan.status = security_policy::calculate_site_status(&latest_scan.checks);
    let security_status = security_policy::security_summary(&latest_scan.checks);
    state.database.save_current_vulnerability_state(
        &crate::database::CurrentVulnerabilityState {
            site_id,
            check: &vulnerability_check,
            site_status: latest_scan.status,
            security_status: &security_status,
            feed_updated_at,
            inventory_observed_at,
            inventory_stale,
        },
    )?;
    Ok(true)
}

fn inventory_snapshot_is_stale(observed_at: Option<&str>, now: DateTime<Utc>) -> bool {
    let Some(observed_at) = observed_at.and_then(|value| DateTime::parse_from_rfc3339(value).ok())
    else {
        return true;
    };
    now.timestamp() - observed_at.timestamp() > INVENTORY_STALE_SECONDS
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
    let wp_cli = engine::text_action(
        state.ssh.as_ref(),
        &stored,
        credential.as_deref(),
        RemoteAction::GetWpCliVersion,
    )
    .ok()
    .and_then(|value| engine::normalize_wp_cli_version(&value));
    state
        .database
        .update_versions(site_id, wordpress.trim(), php.trim(), wp_cli.as_deref())?;
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
    let excluded_root_directories = state.database.child_installation_directories(site_id)?;
    let run = core_operations::new_run(&stored, kind);
    state.database.start_maintenance(&run)?;
    let run_id = run.id.clone();
    let event_site_id = site_id.to_owned();
    let outcome = core_operations::execute_with_exclusions(
        state.ssh.as_ref(),
        &stored,
        credential.as_deref(),
        &state.backup_directory,
        kind,
        &excluded_root_directories,
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
        state.database.update_versions(
            site_id,
            &scan.wordpress_version,
            &scan.php_version,
            scan.wp_cli_version.as_deref(),
        )?;
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
    let excluded_root_directories = state.database.child_installation_directories(site_id)?;
    let run = maintenance::new_run(&stored);
    state.database.start_maintenance(&run)?;
    let run_id = run.id.clone();
    let event_site_id = site_id.to_owned();
    let outcome = maintenance::execute_with_exclusions(
        state.ssh.as_ref(),
        &stored,
        credential.as_deref(),
        &state.backup_directory,
        &excluded_root_directories,
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
    let mut pre_maintenance_snapshot = None;
    let baseline_missing = state
        .database
        .snapshot_repository()
        .baseline_snapshot(site_id)?
        .is_none();
    for (index, scan) in outcome.scans.iter().enumerate() {
        let source = if index == 0 {
            SnapshotSource::PreMaintenance
        } else {
            SnapshotSource::PostMaintenance
        };
        let previous_snapshot_id = if source == SnapshotSource::PostMaintenance {
            pre_maintenance_snapshot
                .as_ref()
                .map(|snapshot: &crate::snapshots::SiteSnapshot| {
                    snapshot.metadata.snapshot_id.clone()
                })
        } else {
            None
        };
        let prepared = build_scan_snapshot(
            &stored,
            scan,
            source,
            Some(outcome.run.id.clone()),
            previous_snapshot_id,
            SnapshotBuildSection::NotCollected,
        );
        let snapshot = match prepared {
            Ok(mut snapshot) => {
                if source == SnapshotSource::PreMaintenance
                    && baseline_missing
                    && snapshot.completeness.baseline_eligible()
                {
                    snapshot.metadata.is_baseline = true;
                }
                Some(snapshot)
            }
            Err(error) => {
                let _ = error_log::persist_error(
                    &state.database,
                    Some(site_id),
                    Some(&stored.site.name),
                    "Onderhoudsmomentopname opbouwen",
                    None,
                    None,
                    error,
                );
                None
            }
        };
        let diff = match (source, pre_maintenance_snapshot.as_ref(), snapshot.as_ref()) {
            (SnapshotSource::PostMaintenance, Some(previous), Some(current)) => {
                match SnapshotDiffEngine::compare(
                    previous,
                    current,
                    SnapshotChangeOrigin::Maintenance,
                    Some(outcome.run.id.clone()),
                ) {
                    Ok(diff) => Some(diff),
                    Err(error) => {
                        let _ = error_log::persist_error(
                            &state.database,
                            Some(site_id),
                            Some(&stored.site.name),
                            "Onderhoudswijzigingen vergelijken",
                            None,
                            None,
                            error,
                        );
                        None
                    }
                }
            }
            _ => None,
        };
        let snapshot_save = snapshot.as_ref().map_or_else(
            || {
                state
                    .database
                    .save_scan(&scan.result, &scan.security_status)
            },
            |snapshot| {
                state.database.save_scan_with_snapshot(
                    &scan.result,
                    &scan.security_status,
                    Some(snapshot),
                    diff.as_ref(),
                )
            },
        );
        if let Err(error) = snapshot_save {
            let _ = error_log::persist_error(
                &state.database,
                Some(site_id),
                Some(&stored.site.name),
                "Onderhoudsmomentopname opslaan",
                None,
                None,
                error,
            );
            state
                .database
                .save_scan(&scan.result, &scan.security_status)?;
        } else if source == SnapshotSource::PreMaintenance {
            pre_maintenance_snapshot = snapshot;
        }
        state.database.update_versions(
            site_id,
            &scan.wordpress_version,
            &scan.php_version,
            scan.wp_cli_version.as_deref(),
        )?;
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

#[derive(Deserialize)]
struct UnexpectedRootDirectoryOutput {
    directories: Vec<String>,
    truncated: bool,
}

fn parse_unexpected_root_directories(
    output: &str,
) -> Result<UnexpectedRootDirectoryOutput, AppError> {
    let mut parsed: UnexpectedRootDirectoryOutput =
        serde_json::from_str(output.trim()).map_err(|error| AppError {
            error_id: None,
            category: "parse".into(),
            user_message: "De lijst met onbekende hoofdmappen kon niet worden gelezen.".into(),
            technical_details: Some(error.to_string()),
            retryable: true,
        })?;
    if parsed.directories.len() > 200 {
        return Err(AppError::validation(
            "De server retourneerde te veel onbekende hoofdmappen.",
        ));
    }
    let mut unique = HashSet::new();
    for directory in &parsed.directories {
        validate_direct_child_directory(directory)?;
        if !unique.insert(directory.clone()) {
            return Err(AppError::validation(
                "De server retourneerde een dubbele onbekende hoofdmap.",
            ));
        }
    }
    parsed.directories.sort();
    Ok(parsed)
}

fn validate_host_fingerprint(fingerprint: &str) -> Result<(), AppError> {
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
    Ok(())
}

fn normalized_wordpress_path(path: &str) -> String {
    let trimmed = path.trim().trim_end_matches('/');
    if trimmed.is_empty() {
        "/".into()
    } else {
        trimmed.into()
    }
}

fn inherited_credential_ref_for_new_site(
    database: &crate::database::Database,
    input: &SiteInput,
    is_new: bool,
    has_secret: bool,
) -> Result<Option<String>, AppError> {
    if !is_new || has_secret {
        return Ok(None);
    }
    input
        .parent_site_id
        .as_deref()
        .map(|parent_id| database.get_site(parent_id))
        .transpose()
        .map(|parent| parent.and_then(|stored| stored.credential_ref))
}

fn child_wordpress_path(parent_path: &str, directory: &str) -> String {
    let parent = normalized_wordpress_path(parent_path);
    if parent == "/" {
        format!("/{directory}")
    } else {
        format!("{parent}/{directory}")
    }
}

fn normalized_site_url(value: &str) -> Result<String, AppError> {
    let mut url = url::Url::parse(value.trim())
        .map_err(|_| AppError::validation("Vul een geldige website-URL in."))?;
    url.set_fragment(None);
    url.set_query(None);
    let normalized = url.to_string();
    Ok(normalized.trim_end_matches('/').to_owned())
}

fn validate_site_identity_and_relationship(
    database: &crate::database::Database,
    input: &mut SiteInput,
) -> Result<(), AppError> {
    let existing = input
        .id
        .as_deref()
        .map(|id| database.get_site(id))
        .transpose()?;
    if let Some(stored) = &existing {
        let has_children = !database
            .child_installation_directories(&stored.site.id)?
            .is_empty();
        let connection_changed = !stored
            .site
            .ssh_host
            .eq_ignore_ascii_case(input.ssh_host.trim())
            || stored.site.ssh_port != input.ssh_port
            || stored.site.ssh_username != input.ssh_username.trim()
            || stored.site.auth_method != input.auth_method
            || stored.site.key_path.as_deref().unwrap_or_default()
                != input.key_path.as_deref().unwrap_or_default()
            || normalized_wordpress_path(&stored.site.wordpress_path)
                != normalized_wordpress_path(&input.wordpress_path);
        if has_children && connection_changed {
            return Err(AppError::validation(
                "Deze website heeft gekoppelde child-installaties. Pas eerst die relaties aan voordat je de SSH-verbinding of WordPress-root wijzigt.",
            ));
        }
    }

    match (
        input.parent_site_id.clone(),
        input.relation_type,
        input.parent_directory.clone(),
    ) {
        (None, None, None) => {}
        (Some(parent_id), Some(_relation_type), Some(directory)) => {
            uuid::Uuid::parse_str(&parent_id)
                .map_err(|_| AppError::validation("De parentwebsite-id is ongeldig."))?;
            validate_direct_child_directory(&directory)?;
            if matches!(
                directory.to_ascii_lowercase().as_str(),
                "wp-admin" | "wp-content" | "wp-includes"
            ) {
                return Err(AppError::validation(
                    "Een vaste WordPress-coremap kan niet als child-installatie worden gekoppeld.",
                ));
            }
            if input.id.as_deref() == Some(parent_id.as_str()) {
                return Err(AppError::validation(
                    "Een website kan niet haar eigen parent zijn.",
                ));
            }
            let parent = database.get_site(&parent_id)?;
            if !parent
                .site
                .ssh_host
                .eq_ignore_ascii_case(input.ssh_host.trim())
                || parent.site.ssh_port != input.ssh_port
                || parent.site.ssh_username != input.ssh_username.trim()
                || parent.site.auth_method != input.auth_method
                || parent.site.key_path.as_deref().unwrap_or_default()
                    != input.key_path.as_deref().unwrap_or_default()
            {
                return Err(AppError::validation(
                    "Een child-installatie moet exact dezelfde SSH-verbinding als de parent gebruiken.",
                ));
            }
            let expected_path = child_wordpress_path(&parent.site.wordpress_path, &directory);
            if normalized_wordpress_path(&input.wordpress_path) != expected_path {
                return Err(AppError::validation(
                    "Het WordPress-pad van de child-installatie is niet de gekozen directe parentmap.",
                ));
            }
            input.wordpress_path = expected_path;
            input.parent_directory = Some(directory);
            input.pinned_host_key = parent.site.pinned_host_key.clone();

            let mut ancestor_id = Some(parent_id);
            let mut visited = HashSet::new();
            while let Some(id) = ancestor_id {
                if !visited.insert(id.clone()) || input.id.as_deref() == Some(id.as_str()) {
                    return Err(AppError::validation(
                        "De gekozen parentrelatie zou een cirkel veroorzaken.",
                    ));
                }
                ancestor_id = database.get_site(&id)?.site.parent_site_id;
            }
        }
        _ => {
            return Err(AppError::validation(
                "Parentwebsite, relatietype en parentmap moeten samen worden ingesteld.",
            ));
        }
    }

    let input_url = normalized_site_url(&input.url)?;
    let input_path = normalized_wordpress_path(&input.wordpress_path);
    for site in database.list_sites()? {
        if input.id.as_deref() == Some(site.id.as_str()) {
            continue;
        }
        let same_installation = site.ssh_host.eq_ignore_ascii_case(input.ssh_host.trim())
            && site.ssh_port == input.ssh_port
            && normalized_wordpress_path(&site.wordpress_path) == input_path;
        let same_url = normalized_site_url(&site.url)? == input_url;
        if same_installation || same_url {
            return Err(AppError::validation(format!(
                "Deze WordPress-installatie bestaat al als ‘{}’.",
                site.name
            )));
        }
    }
    Ok(())
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
        parent_site_id: input.parent_site_id.clone(),
        relation_type: input.relation_type,
        parent_directory: input.parent_directory.clone(),
        pinned_host_key: input
            .pinned_host_key
            .clone()
            .or_else(|| existing.and_then(|stored| stored.site.pinned_host_key.clone())),
        status: existing.map_or(SiteStatus::Unscanned, |stored| stored.site.status),
        wordpress_version: None,
        php_version: None,
        wp_cli_version: existing.and_then(|stored| stored.site.wp_cli_version.clone()),
        wp_cli_version_checked_at: existing
            .and_then(|stored| stored.site.wp_cli_version_checked_at.clone()),
        update_count: 0,
        security_status: None,
        last_scan_at: None,
        last_maintenance_at: None,
        created_at: now.clone(),
        updated_at: now,
        vulnerability_summary: existing
            .and_then(|stored| stored.site.vulnerability_summary.clone()),
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
        ("root_directories", "Onbekende hoofdmappen gecontroleerd"),
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
        unexpected_directories: Vec::new(),
        unexpected_directories_truncated: false,
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
                "GetWpCliVersion" => b"WP-CLI 2.12.0\n".to_vec(),
                "VerifyCoreChecksums" => {
                    b"Success: WordPress installation verifies against checksums.\n".to_vec()
                }
                "FindUnexpectedRootFiles" => {
                    b"{\"files\":[],\"truncated\":false,\"scanned_entries\":12}".to_vec()
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
            pinned_host_key: None,
            parent_site_id: None,
            relation_type: None,
            parent_directory: None,
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
            filemanager_access: crate::filemanager::FilemanagerAccessManager::default(),
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
    fn vulnerability_references_only_allow_safe_web_urls() {
        assert!(validate_external_reference("https://www.wordfence.com/threat-intel/test").is_ok());
        assert!(validate_external_reference("http://legacy.example.test/advisory").is_ok());
        for unsafe_url in [
            "javascript:alert(1)",
            "file:///C:/Windows/System32/calc.exe",
            "custom://execute",
            "https://user:password@example.test/private",
            "https://example.test/path\nnext",
        ] {
            assert!(
                validate_external_reference(unsafe_url).is_err(),
                "{unsafe_url}"
            );
        }
    }

    #[test]
    fn unexpected_root_directory_output_is_sorted_and_strictly_validated() {
        let parsed = parse_unexpected_root_directories(
            r#"{"directories":["portal","academy","dev"],"truncated":false}"#,
        )
        .unwrap();
        assert_eq!(parsed.directories, ["academy", "dev", "portal"]);
        assert!(!parsed.truncated);

        for invalid in [
            r#"{"directories":["dev","dev"],"truncated":false}"#,
            r#"{"directories":["../dev"],"truncated":false}"#,
            r#"{"directories":["nested/dev"],"truncated":false}"#,
        ] {
            assert!(parse_unexpected_root_directories(invalid).is_err());
        }
    }

    #[test]
    fn child_wordpress_paths_never_duplicate_the_joining_separator() {
        assert_eq!(
            child_wordpress_path("/home/ctlvu/domains/ctl-vu.nl/public_html/", "edudatabase"),
            "/home/ctlvu/domains/ctl-vu.nl/public_html/edudatabase"
        );
        assert_eq!(
            child_wordpress_path("/home/ctlvu/domains/ctl-vu.nl/public_html", "edudatabase"),
            "/home/ctlvu/domains/ctl-vu.nl/public_html/edudatabase"
        );
        assert_eq!(
            child_wordpress_path(
                "/home/ctlvu/domains/ctl-vu.nl/public_html/edudatabase/",
                "portal"
            ),
            "/home/ctlvu/domains/ctl-vu.nl/public_html/edudatabase/portal"
        );
    }

    #[test]
    fn child_relationship_inherits_the_parent_identity_and_rejects_duplicates() {
        let path = std::env::temp_dir().join(format!("wpmm-relations-{}.sqlite3", Uuid::new_v4()));
        let database = Database::initialize(path.clone()).unwrap();
        let mut parent_input = site_input();
        parent_input.pinned_host_key = Some("SHA256:abcdefghijklmnopqrstuv".into());
        let parent = database.save_site(&parent_input, None).unwrap();

        let mut child = site_input();
        child.id = None;
        child.name = "dev example".into();
        child.url = "https://dev.example.test/".into();
        child.wordpress_path = "/srv/site/dev/".into();
        child.parent_site_id = Some(parent.id.clone());
        child.relation_type = Some(crate::models::SiteRelationType::Subdomain);
        child.parent_directory = Some("dev".into());
        validate_site_identity_and_relationship(&database, &mut child).unwrap();
        assert_eq!(child.wordpress_path, "/srv/site/dev");
        assert_eq!(child.pinned_host_key, parent_input.pinned_host_key);
        database.save_site(&child, None).unwrap();

        let mut duplicate = site_input();
        duplicate.id = None;
        duplicate.name = "Duplicate".into();
        let error = validate_site_identity_and_relationship(&database, &mut duplicate).unwrap_err();
        assert!(error.user_message.contains("bestaat al"));

        let mut wrong_path = site_input();
        wrong_path.id = None;
        wrong_path.name = "portal example".into();
        wrong_path.url = "https://portal.example.test/".into();
        wrong_path.wordpress_path = "/srv/elsewhere".into();
        wrong_path.parent_site_id = Some(parent.id);
        wrong_path.relation_type = Some(crate::models::SiteRelationType::Subdomain);
        wrong_path.parent_directory = Some("portal".into());
        assert!(validate_site_identity_and_relationship(&database, &mut wrong_path).is_err());

        drop(database);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn new_child_without_a_new_secret_inherits_the_parent_credential_reference() {
        let path = std::env::temp_dir().join(format!(
            "wpmm-inherited-child-credential-{}.sqlite3",
            Uuid::new_v4()
        ));
        let database = Database::initialize(path.clone()).unwrap();
        let parent = database
            .save_site(&site_input(), Some("site:existing-parent:ssh"))
            .unwrap();
        let mut child = site_input();
        child.id = None;
        child.parent_site_id = Some(parent.id);

        assert_eq!(
            inherited_credential_ref_for_new_site(&database, &child, true, false)
                .unwrap()
                .as_deref(),
            Some("site:existing-parent:ssh")
        );
        assert_eq!(
            inherited_credential_ref_for_new_site(&database, &child, true, true).unwrap(),
            None
        );
        drop(database);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn cached_inventory_becomes_stale_only_after_seven_days() {
        let now = Utc::now();
        assert!(!inventory_snapshot_is_stale(
            Some(&(now - chrono::Duration::days(7)).to_rfc3339()),
            now
        ));
        assert!(inventory_snapshot_is_stale(
            Some(&(now - chrono::Duration::days(7) - chrono::Duration::seconds(1)).to_rfc3339()),
            now
        ));
        assert!(inventory_snapshot_is_stale(None, now));
        assert!(inventory_snapshot_is_stale(Some("invalid"), now));
    }

    #[test]
    fn completed_site_scan_persists_its_first_reliable_snapshot_as_baseline() {
        let temp = std::env::temp_dir().join(format!("wpmm-scan-snapshot-{}", Uuid::new_v4()));
        let database = Database::initialize(temp.with_extension("sqlite3")).unwrap();
        let mut input = site_input();
        input.url = "http://127.0.0.1:9".into();
        let site = database.save_site(&input, None).unwrap();
        let state = app_state(database.clone(), &temp);

        let scan = scan_site_internal(&state, &site.id, 30).unwrap();
        let snapshot = database
            .snapshot_repository()
            .baseline_snapshot(&site.id)
            .unwrap()
            .unwrap();
        assert_eq!(
            snapshot.metadata.scan_run_id.as_deref(),
            Some(scan.id.as_str())
        );
        assert_eq!(snapshot.metadata.source, SnapshotSource::Baseline);
        assert!(snapshot.metadata.is_baseline);
        assert_eq!(database.list_scans(&site.id).unwrap().len(), 1);

        let _ = std::fs::remove_file(temp.with_extension("sqlite3"));
    }

    #[test]
    fn successful_connection_test_feed_can_be_reused_without_a_second_request() {
        let path =
            std::env::temp_dir().join(format!("wpmm-wordfence-staged-{}.json", Uuid::new_v4()));
        std::fs::write(&path, "fixture").unwrap();
        let now = SystemTime::now();
        assert!(staged_wordfence_feed_is_fresh(&path, now));
        assert!(!staged_wordfence_feed_is_fresh(
            &path,
            now + Duration::from_secs(u64::try_from(wordfence::FEED_REFRESH_SECONDS).unwrap() + 1)
        ));
        std::fs::remove_file(path).unwrap();
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
    fn filemanager_requires_app_session_password_site_configuration_and_ssh() {
        let temp = std::env::temp_dir().join(format!("wpmm-filemanager-auth-{}", Uuid::new_v4()));
        let database = Database::initialize(temp.with_extension("sqlite3")).unwrap();
        let password = Uuid::new_v4().to_string();
        database
            .create_auth_config(&auth::hash_password(&password).unwrap())
            .unwrap();
        let mut input = site_input();
        let site = database.save_site(&input, None).unwrap();
        let state = app_state(database.clone(), &temp);
        let begin = |session: &str, id: &str| {
            begin_filemanager_reauthentication_internal(
                &state,
                session,
                id,
                Zeroizing::new(password.clone()),
            )
        };
        assert!(begin("", &site.id).is_err());
        assert!(require_filemanager_auth(&state, "", &site.id, "").is_err());
        let session = state.auth.create_session().unwrap();
        assert!(begin(&session, &Uuid::new_v4().to_string()).is_err());
        assert!(
            begin(&session, &site.id)
                .unwrap_err()
                .user_message
                .contains("SSH-configuratie")
        );
        input.pinned_host_key = Some("test-fingerprint".into());
        database.save_site(&input, None).unwrap();
        let token = begin(&session, &site.id).unwrap().challenge_token;
        assert!(require_filemanager_auth(&state, &session, &site.id, &token).is_err());
        assert!(
            state
                .terminal_access
                .consume_challenge(&session, &site.id, &token)
                .is_err()
        );
        let error = begin_filemanager_reauthentication_internal(
            &state,
            &session,
            &site.id,
            Zeroizing::new(Uuid::new_v4().to_string()),
        )
        .unwrap_err();
        assert_eq!(error.category, "app_session_revoked_reauth_failed");
        assert!(require_auth(&state, &session).is_err());
        assert!(
            database
                .list_audit_events(Some(&site.id))
                .unwrap()
                .iter()
                .any(|event| event.action_type == "filemanager_reauthentication"
                    && event.status == "failed")
        );
        drop(state);
        drop(database);
        let _ = std::fs::remove_file(temp.with_extension("sqlite3"));
    }

    #[test]
    fn filemanager_guard_rechecks_app_session_site_existence_and_password_changes() {
        let temp = std::env::temp_dir().join(format!("wpmm-filemanager-guard-{}", Uuid::new_v4()));
        let database = Database::initialize(temp.with_extension("sqlite3")).unwrap();
        let password = Uuid::new_v4().to_string();
        database
            .create_auth_config(&auth::hash_password(&password).unwrap())
            .unwrap();
        let site = database.save_site(&site_input(), None).unwrap();
        let state = app_state(database.clone(), &temp);
        let session = state.auth.create_session().unwrap();
        let token = state
            .filemanager_access
            .install_test_access(&session, &site);
        assert!(require_filemanager_auth(&state, &session, &site.id, &token).is_ok());
        assert!(
            require_filemanager_auth(&state, &session, &Uuid::new_v4().to_string(), &token)
                .is_err()
        );
        let new_session = state.auth.create_session().unwrap();
        assert!(require_filemanager_auth(&state, &new_session, &site.id, &token).is_err());
        assert!(require_filemanager_auth(&state, &session, &site.id, &token).is_err());
        let token = state
            .filemanager_access
            .install_test_access(&new_session, &site);
        change_password_internal(
            &state,
            &PasswordChangeInput {
                current_password: password,
                new_password: Uuid::new_v4().to_string(),
            },
        )
        .unwrap();
        assert!(require_filemanager_auth(&state, &new_session, &site.id, &token).is_err());
        assert!(
            state
                .filemanager_access
                .authorize(&new_session, &site, &token)
                .is_err()
        );
        let session = state.auth.create_session().unwrap();
        let token = state
            .filemanager_access
            .install_test_access(&session, &site);
        database.delete_site(&site.id).unwrap();
        assert!(require_filemanager_auth(&state, &session, &site.id, &token).is_err());
        drop(state);
        drop(database);
        let _ = std::fs::remove_file(temp.with_extension("sqlite3"));
    }

    #[test]
    fn directory_endpoint_authorizes_before_transport_and_rechecks_afterwards() {
        use std::cell::Cell;
        let temp = std::env::temp_dir().join(format!("wpmm-directory-auth-{}", Uuid::new_v4()));
        let database = Database::initialize(temp.with_extension("sqlite3")).unwrap();
        database
            .create_auth_config(&auth::hash_password(&Uuid::new_v4().to_string()).unwrap())
            .unwrap();
        let a = database.save_site(&site_input(), None).unwrap();
        let b = database.save_site(&site_input(), None).unwrap();
        let state = app_state(database.clone(), &temp);
        let session = state.auth.create_session().unwrap();
        let token = state.filemanager_access.install_test_access(&session, &a);
        let calls = Cell::new(0);
        let response = || crate::filemanager_directory::DirectoryListing {
            current_path: "/".into(),
            is_root: true,
            parent_path: None,
            items: vec![],
            truncated: false,
        };
        let operation = |site: &Site, path: &str| {
            calls.set(calls.get() + 1);
            assert_eq!(site.id, a.id);
            assert_eq!(site.wordpress_path, a.wordpress_path);
            assert_eq!(path, "/");
            Ok(response())
        };
        for (app_session, site_id, auth_token, path) in [
            (session.as_str(), a.id.as_str(), "", "/"),
            (session.as_str(), b.id.as_str(), token.as_str(), "/"),
            (session.as_str(), "missing", token.as_str(), "/"),
            (session.as_str(), a.id.as_str(), token.as_str(), "../../etc"),
        ] {
            assert!(
                list_filemanager_directory_internal(
                    &state,
                    app_session,
                    site_id,
                    auth_token,
                    path,
                    operation
                )
                .is_err()
            );
        }
        assert_eq!(calls.get(), 0);
        assert!(
            list_filemanager_directory_internal(&state, &session, &a.id, &token, "/", operation)
                .is_ok()
        );
        assert_eq!(calls.get(), 1);
        assert!(
            list_filemanager_directory_internal(&state, &session, &a.id, &token, "/", |_, _| {
                state.filemanager_access.close(&session, &a.id, &token);
                Ok(response())
            })
            .is_err()
        );
        let token = state.filemanager_access.install_test_access(&session, &a);
        assert!(
            list_filemanager_directory_internal(&state, &session, &a.id, &token, "/", |_, _| {
                state.auth.invalidate().unwrap();
                Ok(response())
            })
            .is_err()
        );
        assert!(
            list_filemanager_directory_internal(&state, "", &a.id, &token, "/", operation).is_err()
        );
        assert_eq!(calls.get(), 1);
        drop(state);
        drop(database);
        let _ = std::fs::remove_file(temp.with_extension("sqlite3"));
    }

    #[test]
    fn file_read_endpoint_is_site_scoped_normalizes_paths_and_rechecks_authorization() {
        use std::cell::Cell;
        let temp = std::env::temp_dir().join(format!("wpmm-file-read-auth-{}", Uuid::new_v4()));
        let database = Database::initialize(temp.with_extension("sqlite3")).unwrap();
        database
            .create_auth_config(&auth::hash_password(&Uuid::new_v4().to_string()).unwrap())
            .unwrap();
        let a = database.save_site(&site_input(), None).unwrap();
        let b = database.save_site(&site_input(), None).unwrap();
        let state = app_state(database.clone(), &temp);
        let session = state.auth.create_session().unwrap();
        let token = state.filemanager_access.install_test_access(&session, &a);
        let calls = Cell::new(0);
        let operation = |site: &Site, path: &str| {
            calls.set(calls.get() + 1);
            assert_eq!(site.id, a.id);
            assert_eq!(path, "/my plugin.php");
            Ok(crate::models::FileContentPreview {
                edit_version: None,
                file_name: "my plugin.php".into(),
                relative_path: path.into(),
                size_bytes: 4,
                modified_at: None,
                file_type: "php-bestand".into(),
                extension: Some("php".into()),
                text_content: Some("test".into()),
                image_mime_type: None,
                image_data_base64: None,
                raw_data_base64: None,
                binary: false,
                truncated: false,
            })
        };
        for (site_id, auth_token, path) in [
            (a.id.as_str(), "", "/my plugin.php"),
            (b.id.as_str(), token.as_str(), "/my plugin.php"),
            (a.id.as_str(), token.as_str(), "../../../etc/passwd"),
        ] {
            assert!(
                read_filemanager_file_internal(
                    &state, &session, site_id, auth_token, path, operation,
                )
                .is_err()
            );
        }
        assert_eq!(calls.get(), 0);
        assert!(
            read_filemanager_file_internal(
                &state,
                &session,
                &a.id,
                &token,
                "/my plugin.php",
                operation,
            )
            .is_ok()
        );
        assert_eq!(calls.get(), 1);
        let token = state.filemanager_access.install_test_access(&session, &a);
        assert!(
            read_filemanager_file_internal(
                &state,
                &session,
                &a.id,
                &token,
                "/my plugin.php",
                |_, path| {
                    state.filemanager_access.close(&session, &a.id, &token);
                    operation(&a, path)
                },
            )
            .is_err()
        );

        drop(state);
        drop(database);
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
            policy_target: None,
            vulnerability: None,
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

        let operation_id = Uuid::new_v4().to_string();
        let mut progress = Vec::new();
        let result = delete_checksum_findings_with_progress(
            &state,
            &site.id,
            vec![first_id, second_id],
            true,
            &operation_id,
            |event| progress.push(event),
        )
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
        assert_eq!(progress.len(), 5);
        assert_eq!(progress[0].phase, ChecksumDeletePhase::Deleting);
        assert_eq!((progress[0].processed, progress[0].total), (0, 2));
        assert_eq!((progress[2].processed, progress[2].total), (2, 2));
        assert_eq!(progress[3].phase, ChecksumDeletePhase::Rescanning);
        assert_eq!(progress[4].phase, ChecksumDeletePhase::Completed);
        assert_eq!((progress[4].deleted, progress[4].failed), (1, 1));
        assert!(
            progress
                .iter()
                .all(|event| event.operation_id == operation_id)
        );
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
