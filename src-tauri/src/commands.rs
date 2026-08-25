use crate::{
    command_catalog::{RemoteAction, RemoteCommand, build},
    error::AppError,
    models::{
        ConnectionStep, ConnectionTestResult, Site, SiteInput, SiteStatus, StepStatus, StoredSite,
    },
    state::AppState,
    validation::validate_site,
};
use tauri::State;

#[tauri::command]
pub fn list_sites(state: State<'_, AppState>) -> Result<Vec<Site>, AppError> {
    state.database.list_sites()
}

#[tauri::command]
pub fn save_site(mut input: SiteInput, state: State<'_, AppState>) -> Result<Site, AppError> {
    validate_site(&input)?;
    let is_new_password =
        input.id.is_none() && matches!(input.auth_method, crate::models::AuthMethod::Password);
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
            if has_secret {
                let _ = state.credentials.delete(&credential_ref);
            }
            Err(error)
        }
    }
}

#[tauri::command]
pub fn delete_site(id: String, state: State<'_, AppState>) -> Result<(), AppError> {
    uuid::Uuid::parse_str(&id).map_err(|_| AppError::validation("De website-id is ongeldig."))?;
    if let Some(reference) = state.database.delete_site(&id)? {
        state.credentials.delete(&reference)?;
    }
    Ok(())
}

#[tauri::command]
pub fn accept_host_key(
    site_id: String,
    fingerprint: String,
    state: State<'_, AppState>,
) -> Result<(), AppError> {
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
    input: SiteInput,
    state: State<'_, AppState>,
) -> Result<ConnectionTestResult, AppError> {
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
