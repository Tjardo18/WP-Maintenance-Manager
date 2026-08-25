use crate::{
    error::AppError,
    models::{Site, SiteInput},
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
    state.database.set_host_key(&site_id, &fingerprint)
}
