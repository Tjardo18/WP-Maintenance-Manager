use crate::{
    error::AppError,
    models::{AuthMethod, SiteInput},
};

pub fn validate_site(input: &SiteInput) -> Result<(), AppError> {
    let name = input.name.trim();
    if name.is_empty() || name.chars().count() > 100 {
        return Err(AppError::validation(
            "Vul een naam van maximaal 100 tekens in.",
        ));
    }
    let parsed = url::Url::parse(input.url.trim())
        .map_err(|_| AppError::validation("Vul een geldige website-URL in."))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(AppError::validation(
            "De website-URL moet met http:// of https:// beginnen.",
        ));
    }
    validate_host(&input.ssh_host)?;
    if input.ssh_port == 0 {
        return Err(AppError::validation(
            "De SSH-poort moet tussen 1 en 65535 liggen.",
        ));
    }
    if input.ssh_username.is_empty()
        || input.ssh_username.len() > 64
        || !input
            .ssh_username
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte))
    {
        return Err(AppError::validation(
            "De SSH-gebruikersnaam bevat niet-ondersteunde tekens.",
        ));
    }
    validate_wordpress_path(&input.wordpress_path)?;
    if input.auth_method == AuthMethod::KeyFile
        && input.key_path.as_deref().is_none_or(str::is_empty)
    {
        return Err(AppError::validation("Kies een SSH private-keybestand."));
    }
    if input
        .key_path
        .as_deref()
        .is_some_and(|path| path.contains('\0') || path.contains('\n') || path.contains('\r'))
    {
        return Err(AppError::validation(
            "Het lokale sleutelpad bevat ongeldige tekens.",
        ));
    }
    if input
        .credential_secret
        .as_ref()
        .is_some_and(|secret| secret.len() > 4096)
    {
        return Err(AppError::validation("Het credential is onverwacht lang."));
    }
    Ok(())
}

pub fn validate_host(host: &str) -> Result<(), AppError> {
    if host.is_empty()
        || host.len() > 253
        || !host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b".-:".contains(&byte))
    {
        return Err(AppError::validation("De SSH-host bevat ongeldige tekens."));
    }
    Ok(())
}

pub fn validate_wordpress_path(path: &str) -> Result<(), AppError> {
    if !path.starts_with('/')
        || path.len() > 4096
        || path.contains('\0')
        || path.contains('\n')
        || path.contains('\r')
    {
        return Err(AppError::validation(
            "Het WordPress-pad moet een veilig absoluut POSIX-pad zijn.",
        ));
    }
    Ok(())
}

pub fn validate_checksum_relative_path(path: &str) -> Result<(), AppError> {
    if path.is_empty()
        || path.len() > 4096
        || path.starts_with('/')
        || path.chars().any(char::is_control)
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(AppError::validation(
            "Het checksum-bestandspad is geen veilig relatief pad.",
        ));
    }
    Ok(())
}

pub fn validate_checksum_file_action_path(path: &str) -> Result<(), AppError> {
    validate_checksum_relative_path(path)?;
    let lower = path.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "wp-config.php" | ".env" | ".htaccess" | ".maintenance"
    ) || lower == "wp-content"
        || lower.starts_with("wp-content/")
    {
        return Err(AppError::validation(
            "Dit configuratie- of contentpad mag niet via een checksumactie worden geopend of verwijderd.",
        ));
    }
    Ok(())
}

pub fn validate_slug(slug: &str) -> Result<(), AppError> {
    if slug.is_empty()
        || slug.len() > 200
        || !slug
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(AppError::validation(
            "De plugin- of themanaam bevat ongeldige tekens.",
        ));
    }
    Ok(())
}

pub fn validate_days(days: u16) -> Result<(), AppError> {
    if !(1..=365).contains(&days) {
        return Err(AppError::validation(
            "Het aantal dagen moet tussen 1 en 365 liggen.",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_relative_and_control_character_paths() {
        assert!(validate_wordpress_path("var/www").is_err());
        assert!(validate_wordpress_path("/var/www\nrm -rf /").is_err());
    }
    #[test]
    fn accepts_normal_wordpress_path() {
        assert!(validate_wordpress_path("/var/www/example/public").is_ok());
    }
    #[test]
    fn validates_checksum_paths_without_treating_them_as_shell_input() {
        assert!(validate_checksum_relative_path("wp-includes/version.php").is_ok());
        assert!(validate_checksum_relative_path("odd; but valid.txt").is_ok());
        assert!(validate_checksum_relative_path("../wp-config.php").is_err());
        assert!(validate_checksum_relative_path("wp-admin/../../etc/passwd").is_err());
        assert!(validate_checksum_relative_path("/etc/passwd").is_err());
    }
    #[test]
    fn protects_configuration_and_content_from_checksum_file_actions() {
        assert!(validate_checksum_file_action_path("wp-admin/extra.php").is_ok());
        assert!(validate_checksum_file_action_path("wp-config.php").is_err());
        assert!(validate_checksum_file_action_path("wp-content/cache/file.php").is_err());
        assert!(validate_checksum_file_action_path(".env").is_err());
    }
    #[test]
    fn rejects_shell_metacharacters_in_hosts() {
        assert!(validate_host("host; reboot").is_err());
        assert!(validate_host("example.org").is_ok());
    }
    #[test]
    fn validates_plugin_and_theme_slugs() {
        assert!(validate_slug("wordpress-seo").is_ok());
        assert!(validate_slug("seo;reboot").is_err());
        assert!(validate_slug("../plugin").is_err());
    }
    #[test]
    fn bounds_modified_days() {
        assert!(validate_days(1).is_ok());
        assert!(validate_days(365).is_ok());
        assert!(validate_days(0).is_err());
        assert!(validate_days(366).is_err());
    }
}
