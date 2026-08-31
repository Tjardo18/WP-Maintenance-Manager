use crate::{
    auth,
    command_catalog::{RemoteAction, RemoteCommand, build},
    engine,
    error::AppError,
    maintenance,
    models::{
        AppSettings, AuditEvent, AuthStatus, BulkScanFailure, BulkScanProgress, BulkScanResult,
        ConnectionStep, ConnectionTestResult, LoginResult, MaintenanceRun, MaintenanceStep,
        PasswordChangeInput, ScanResult, Site, SiteInput, SiteStatus, StepStatus, StoredSite,
        UpdateItem,
    },
    state::AppState,
    validation::validate_site,
};
use serde::Serialize;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex, atomic::Ordering},
};
use tauri::{AppHandle, Emitter, State};

#[tauri::command]
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

#[tauri::command]
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

#[tauri::command]
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

#[tauri::command]
pub fn touch_session(session_token: String, state: State<'_, AppState>) -> Result<(), AppError> {
    require_auth(&state, &session_token)
}

#[tauri::command]
pub fn lock_app(session_token: String, state: State<'_, AppState>) -> Result<(), AppError> {
    require_auth(&state, &session_token)?;
    state.auth.invalidate()?;
    state.database.save_audit_event(
        None,
        "lock",
        "local_app",
        "success",
        Some("Handmatig of door inactiviteit vergrendeld"),
    )
}

#[tauri::command]
pub fn change_password(
    session_token: String,
    input: PasswordChangeInput,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    require_auth(&state, &session_token)?;
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
    state
        .database
        .save_audit_event(None, "password_change", "local_app", "success", None)?;
    state.auth.invalidate()
}

#[tauri::command]
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

#[tauri::command]
pub fn list_audit_events(
    session_token: String,
    site_id: Option<String>,
    state: State<'_, AppState>,
) -> Result<Vec<AuditEvent>, AppError> {
    require_auth(&state, &session_token)?;
    state.database.list_audit_events(site_id.as_deref())
}

fn require_auth(state: &AppState, session_token: &str) -> Result<(), AppError> {
    let config = state.database.auth_config()?.ok_or_else(|| {
        AppError::unauthorized(
            "setup_required",
            "Beveilig de applicatie voordat je verdergaat.",
        )
    })?;
    state
        .auth
        .require(session_token, config.idle_timeout_minutes)
}

#[tauri::command]
pub fn list_sites(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<Vec<Site>, AppError> {
    require_auth(&state, &session_token)?;
    state.database.list_sites()
}

#[tauri::command]
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

#[tauri::command]
pub fn delete_site(
    session_token: String,
    id: String,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    require_auth(&state, &session_token)?;
    uuid::Uuid::parse_str(&id).map_err(|_| AppError::validation("De website-id is ongeldig."))?;
    if let Some(reference) = state.database.delete_site(&id)? {
        state.credentials.delete(&reference)?;
    }
    Ok(())
}

#[tauri::command]
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

#[tauri::command]
pub fn test_connection(
    session_token: String,
    input: SiteInput,
    state: State<'_, AppState>,
) -> Result<ConnectionTestResult, AppError> {
    require_auth(&state, &session_token)?;
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
            return Ok(failed_connection(steps, None, error));
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
            return Ok(failed_connection(
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
        return Ok(failed_connection(steps, Some(fingerprint), error));
    }
    steps[2].status = StepStatus::Success;

    if let Err(error) = run_readonly(
        state.ssh.as_ref(),
        &site,
        credential.as_deref(),
        build(&site.wordpress_path, RemoteAction::TestWordPressPath)?,
    ) {
        steps[3].status = StepStatus::Failed;
        return Ok(failed_connection(steps, Some(fingerprint), error));
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
            return Ok(failed_connection(steps, Some(fingerprint), error));
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
        return Ok(failed_connection(steps, Some(fingerprint), error));
    }
    steps[5].status = StepStatus::Success;

    if let Err(error) = run_readonly(
        state.ssh.as_ref(),
        &site,
        credential.as_deref(),
        build(&site.wordpress_path, RemoteAction::CheckDatabase)?,
    ) {
        steps[6].status = StepStatus::Failed;
        return Ok(failed_connection(steps, Some(fingerprint), error));
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

#[tauri::command]
pub fn scan_site(
    session_token: String,
    site_id: String,
    modified_days: u16,
    state: State<'_, AppState>,
) -> Result<ScanResult, AppError> {
    require_auth(&state, &session_token)?;
    scan_site_internal(&state, &site_id, modified_days)
}

#[tauri::command]
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

fn scan_site_internal(
    state: &AppState,
    site_id: &str,
    modified_days: u16,
) -> Result<ScanResult, AppError> {
    crate::validation::validate_days(modified_days)?;
    let stored = state.database.get_site(site_id)?;
    let credential = stored_credential_from_state(state, &stored)?;
    let mut outcome = match engine::scan_site(
        state.ssh.as_ref(),
        &stored,
        credential.as_deref(),
        modified_days,
    ) {
        Ok(outcome) => outcome,
        Err(error) => {
            if matches!(
                error.category.as_str(),
                "dns_host_error" | "timeout" | "authentication_failed" | "host_key_mismatch"
            ) {
                state.database.mark_unreachable(site_id)?;
            }
            return Err(error);
        }
    };
    state
        .database
        .update_versions(site_id, &outcome.wordpress_version, &outcome.php_version)?;
    match engine::check_updates(state.ssh.as_ref(), &stored, credential.as_deref()) {
        Ok(updates) => state.database.save_updates(site_id, &updates)?,
        Err(error) => {
            outcome.result.checks.push(crate::models::ScanCheck {
                key: "updates".into(),
                label: "Updatecontrole".into(),
                status: StepStatus::Failed,
                summary: error.user_message,
                findings: Vec::new(),
            });
            if outcome.result.status == SiteStatus::Healthy {
                outcome.result.status = SiteStatus::Attention;
            }
        }
    }
    state
        .database
        .save_scan(&outcome.result, &outcome.security_status)?;
    Ok(outcome.result)
}

#[tauri::command]
pub fn scan_all_sites(
    session_token: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<BulkScanResult, AppError> {
    require_auth(&state, &session_token)?;
    let sites = state.database.list_sites()?;
    let total = sites.len();
    state.bulk_scan_cancelled.store(false, Ordering::SeqCst);
    let queue = Arc::new(Mutex::new(VecDeque::from(
        sites
            .iter()
            .map(|site| (site.id.clone(), site.name.clone()))
            .collect::<Vec<_>>(),
    )));
    let active = Arc::new(Mutex::new(Vec::<String>::new()));
    let failures = Arc::new(Mutex::new(Vec::<BulkScanFailure>::new()));
    let completed = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let worker_count = state
        .scan_concurrency
        .load(Ordering::SeqCst)
        .clamp(1, 5)
        .min(total.max(1));
    std::thread::scope(|scope| {
        for _ in 0..worker_count {
            let queue = Arc::clone(&queue);
            let active = Arc::clone(&active);
            let failures = Arc::clone(&failures);
            let completed = Arc::clone(&completed);
            let app = app.clone();
            let state_ref: &AppState = &state;
            scope.spawn(move || {
                loop {
                    if state_ref.bulk_scan_cancelled.load(Ordering::SeqCst) {
                        break;
                    }
                    let next = match queue.lock() {
                        Ok(mut items) => items.pop_front(),
                        Err(error) => {
                            eprintln!("bulk scan queue lock failed: {error}");
                            break;
                        }
                    };
                    let Some((site_id, site_name)) = next else {
                        break;
                    };
                    match active.lock() {
                        Ok(mut active_sites) => active_sites.push(site_name.clone()),
                        Err(error) => eprintln!("bulk scan active-sites lock failed: {error}"),
                    }
                    emit_bulk_progress(&app, total, &completed, &active, &failures);
                    if let Err(error) = scan_site_internal(state_ref, &site_id, 30) {
                        match failures.lock() {
                            Ok(mut failed) => failed.push(BulkScanFailure {
                                site_id,
                                site_name: site_name.clone(),
                                error,
                            }),
                            Err(lock_error) => {
                                eprintln!("bulk scan failures lock failed: {lock_error}")
                            }
                        }
                    }
                    match active.lock() {
                        Ok(mut active_sites) => active_sites.retain(|name| name != &site_name),
                        Err(error) => eprintln!("bulk scan active-sites lock failed: {error}"),
                    }
                    completed.fetch_add(1, Ordering::SeqCst);
                    emit_bulk_progress(&app, total, &completed, &active, &failures);
                }
            });
        }
    });
    let completed = completed.load(Ordering::SeqCst);
    let failures = failures
        .lock()
        .map_err(|_| AppError::storage("Bulk scan failure lock poisoned"))?
        .clone();
    Ok(BulkScanResult {
        total,
        completed,
        cancelled: state.bulk_scan_cancelled.load(Ordering::SeqCst),
        failures,
    })
}

#[tauri::command]
pub fn cancel_bulk_scan(session_token: String, state: State<'_, AppState>) -> Result<(), AppError> {
    require_auth(&state, &session_token)?;
    state.bulk_scan_cancelled.store(true, Ordering::SeqCst);
    Ok(())
}

#[tauri::command]
pub fn get_settings(
    session_token: String,
    state: State<'_, AppState>,
) -> Result<AppSettings, AppError> {
    require_auth(&state, &session_token)?;
    Ok(AppSettings {
        scan_concurrency: state.scan_concurrency.load(Ordering::SeqCst),
    })
}

#[tauri::command]
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
    Ok(settings)
}

fn emit_bulk_progress(
    app: &AppHandle,
    total: usize,
    completed: &std::sync::atomic::AtomicUsize,
    active: &Mutex<Vec<String>>,
    failures: &Mutex<Vec<BulkScanFailure>>,
) {
    let active_sites = active
        .lock()
        .map_or_else(|_| Vec::new(), |items| items.clone());
    let failed_sites = failures.lock().map_or_else(
        |_| Vec::new(),
        |items| {
            items
                .iter()
                .map(|failure| failure.site_name.clone())
                .collect()
        },
    );
    if let Err(error) = app.emit(
        "bulk-scan-progress",
        BulkScanProgress {
            total,
            completed: completed.load(Ordering::SeqCst),
            active_sites,
            failed_sites,
        },
    ) {
        eprintln!("bulk scan progress event failed: {error}");
    }
}

#[tauri::command]
pub fn check_updates(
    session_token: String,
    site_id: String,
    state: State<'_, AppState>,
) -> Result<Vec<UpdateItem>, AppError> {
    require_auth(&state, &session_token)?;
    let stored = state.database.get_site(&site_id)?;
    let credential = stored_credential(&state, &stored)?;
    let updates = engine::check_updates(state.ssh.as_ref(), &stored, credential.as_deref())?;
    state.database.save_updates(&site_id, &updates)?;
    Ok(updates)
}

#[tauri::command]
pub fn run_update(
    session_token: String,
    site_id: String,
    kind: String,
    slug: Option<String>,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
    require_auth(&state, &session_token)?;
    let stored = state.database.get_site(&site_id)?;
    let credential = stored_credential(&state, &stored)?;
    engine::run_update(
        state.ssh.as_ref(),
        &stored,
        credential.as_deref(),
        &kind,
        slug.as_deref(),
    )?;
    let updates = engine::check_updates(state.ssh.as_ref(), &stored, credential.as_deref())?;
    state.database.save_updates(&site_id, &updates)?;
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
        .update_versions(&site_id, wordpress.trim(), php.trim())?;
    Ok(())
}

#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct MaintenanceProgressEvent {
    site_id: String,
    run_id: String,
    step: MaintenanceStep,
}

#[tauri::command]
pub fn run_maintenance(
    session_token: String,
    site_id: String,
    app: AppHandle,
    state: State<'_, AppState>,
) -> Result<MaintenanceRun, AppError> {
    require_auth(&state, &session_token)?;
    let stored = state.database.get_site(&site_id)?;
    let credential = stored_credential(&state, &stored)?;
    let run = maintenance::new_run(&stored);
    state.database.start_maintenance(&run)?;
    let run_id = run.id.clone();
    let event_site_id = site_id.clone();
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
            .update_versions(&site_id, &scan.wordpress_version, &scan.php_version)?;
    }
    if outcome.run.before_versions.is_some() {
        state
            .database
            .save_updates(&site_id, &outcome.updates_after)?;
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

#[tauri::command]
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
