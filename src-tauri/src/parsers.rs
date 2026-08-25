use crate::{
    command_catalog::MAX_SCAN_RESULTS,
    error::AppError,
    models::{Finding, FindingSeverity, UpdateItem, UpdateKind},
    validation::validate_slug,
};
use chrono::{Duration, NaiveDateTime, Utc};
use serde_json::Value;

pub fn parse_nul_paths(
    output: &[u8],
    wordpress_path: &str,
    attention_uploads: bool,
) -> (Vec<Finding>, bool) {
    let mut paths: Vec<String> = output
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    let truncated = paths.len() > MAX_SCAN_RESULTS;
    paths.truncate(MAX_SCAN_RESULTS);
    let findings = paths
        .into_iter()
        .map(|path| {
            let category = categorize_path(&path, wordpress_path);
            let is_upload_php = attention_uploads
                && category == "uploads"
                && path.to_ascii_lowercase().ends_with(".php");
            Finding {
                category,
                severity: if is_upload_php {
                    FindingSeverity::Attention
                } else {
                    FindingSeverity::Info
                },
                title: if is_upload_php {
                    "PHP-bestand gevonden in uploads".into()
                } else {
                    "PHP-bestand geïnventariseerd".into()
                },
                detail: if is_upload_php {
                    "PHP-bestanden horen normaal gesproken niet in de uploadmap. Controleer dit bestand voordat je actie onderneemt.".into()
                } else {
                    "Dit bestand is alleen geïnventariseerd; PHP in plugins en thema's is normaal.".into()
                },
                path: Some(display_path(&path, wordpress_path)),
            }
        })
        .collect();
    (findings, truncated)
}

pub fn parse_modified_files(output: &[u8], wordpress_path: &str) -> (Vec<Finding>, bool) {
    let fields: Vec<&[u8]> = output
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .collect();
    let count = fields.len() / 3;
    let truncated = count > MAX_SCAN_RESULTS;
    let mut findings = Vec::with_capacity(count.min(MAX_SCAN_RESULTS));
    for record in fields.chunks(3).take(MAX_SCAN_RESULTS) {
        if record.len() != 3 {
            continue;
        }
        let path = String::from_utf8_lossy(record[0]).into_owned();
        let category = categorize_path(&path, wordpress_path);
        let display = display_path(&path, wordpress_path);
        let lower = display.to_ascii_lowercase();
        let attention = lower == "wp-config.php"
            || lower == ".htaccess"
            || (category == "root" && lower.ends_with(".php"))
            || (category == "uploads" && lower.ends_with(".php"));
        findings.push(Finding {
            category,
            severity: if attention {
                FindingSeverity::Attention
            } else {
                FindingSeverity::Info
            },
            title: if attention {
                "Recent gewijzigd bestand vraagt aandacht".into()
            } else {
                "Recent gewijzigd bestand".into()
            },
            detail: format!(
                "Gewijzigd op Unix-tijd {} met permissiemodus {}. Een recente wijziging is niet automatisch kwaadaardig.",
                String::from_utf8_lossy(record[1]),
                String::from_utf8_lossy(record[2])
            ),
            path: Some(display),
        });
    }
    (findings, truncated)
}

pub fn parse_users(output: &str) -> Result<Vec<Finding>, AppError> {
    let users: Vec<Value> = serde_json::from_str(output).map_err(|error| {
        AppError::ssh(
            "parse_failed",
            "De WordPress-gebruikers konden niet worden gelezen.",
            error,
            false,
        )
    })?;
    Ok(users
        .into_iter()
        .map(|user| {
            let login = string_field(&user, "user_login", "Onbekende gebruiker");
            let email = string_field(&user, "user_email", "Geen e-mailadres");
            let registered = string_field(&user, "user_registered", "Onbekend");
            let roles = user.get("roles").map(role_strings).unwrap_or_default();
            let administrator = roles.iter().any(|role| role == "administrator");
            let recent = NaiveDateTime::parse_from_str(&registered, "%Y-%m-%d %H:%M:%S")
                .ok()
                .is_some_and(|date| date > (Utc::now() - Duration::days(30)).naive_utc());
            Finding {
                category: if administrator {
                    "administrator".into()
                } else {
                    "user".into()
                },
                severity: if administrator && recent {
                    FindingSeverity::Attention
                } else {
                    FindingSeverity::Info
                },
                title: if administrator {
                    format!("{login} · beheerder")
                } else {
                    login
                },
                detail: format!(
                    "E-mail: {email} · Rollen: {} · Aangemaakt: {registered}",
                    if roles.is_empty() {
                        "geen".into()
                    } else {
                        roles.join(", ")
                    }
                ),
                path: None,
            }
        })
        .collect())
}

pub fn parse_config(output: &str) -> Result<Vec<Finding>, AppError> {
    let config: Value = serde_json::from_str(output).map_err(|error| {
        AppError::ssh(
            "parse_failed",
            "De geselecteerde WordPress-instellingen konden niet worden gelezen.",
            error,
            false,
        )
    })?;
    let mut findings = Vec::new();
    if config.get("WP_DEBUG").and_then(Value::as_bool) == Some(true) {
        findings.push(config_finding(
            "WP_DEBUG",
            "WP_DEBUG staat aan",
            "Op een productiewebsite kan debuguitvoer gevoelige technische details tonen.",
        ));
    }
    if config.get("DISALLOW_FILE_EDIT").and_then(Value::as_bool) != Some(true) {
        findings.push(config_finding(
            "DISALLOW_FILE_EDIT",
            "Bestandsbewerking via wp-admin is niet uitgeschakeld",
            "Overweeg DISALLOW_FILE_EDIT op productie, na controle met de beheerder.",
        ));
    }
    let environment = config
        .get("WP_ENVIRONMENT_TYPE")
        .and_then(Value::as_str)
        .unwrap_or("niet ingesteld");
    findings.push(Finding {
        category: "configuration".into(),
        severity: FindingSeverity::Info,
        title: "WordPress-omgevingstype".into(),
        detail: environment.into(),
        path: None,
    });
    Ok(findings)
}

pub fn parse_update_list(output: &str, kind: UpdateKind) -> Result<Vec<UpdateItem>, AppError> {
    let rows: Vec<Value> = if output.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(output).map_err(|error| {
            AppError::ssh(
                "parse_failed",
                "De beschikbare updates konden niet worden gelezen.",
                error,
                false,
            )
        })?
    };
    let mut updates = Vec::with_capacity(rows.len());
    for row in rows {
        let slug = string_field(&row, "name", "");
        validate_slug(&slug)?;
        updates.push(UpdateItem {
            kind: kind.clone(),
            name: string_field(&row, "title", &slug),
            slug,
            current_version: string_field(&row, "version", "onbekend"),
            new_version: string_field(&row, "update_version", "onbekend"),
            status: "available".into(),
        });
    }
    Ok(updates)
}

pub fn parse_core_updates(
    output: &str,
    current_version: &str,
) -> Result<Vec<UpdateItem>, AppError> {
    let rows: Vec<Value> = if output.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(output).map_err(|error| {
            AppError::ssh(
                "parse_failed",
                "De WordPress-core-update kon niet worden gelezen.",
                error,
                false,
            )
        })?
    };
    Ok(rows
        .first()
        .and_then(|row| row.get("version").and_then(Value::as_str))
        .map(|version| {
            vec![UpdateItem {
                kind: UpdateKind::Core,
                slug: "wordpress".into(),
                name: "WordPress".into(),
                current_version: current_version.into(),
                new_version: version.into(),
                status: "available".into(),
            }]
        })
        .unwrap_or_default())
}

pub fn permission_findings(output: &[u8], wordpress_path: &str) -> (Vec<Finding>, bool) {
    let (mut findings, truncated) = parse_nul_paths(output, wordpress_path, false);
    for finding in &mut findings {
        finding.category = "permissions".into();
        finding.severity = FindingSeverity::Problem;
        finding.title = "World-writable bestand of map".into();
        finding.detail = "Iedere servergebruiker kan dit object wijzigen. De app past rechten niet automatisch aan.".into();
    }
    (findings, truncated)
}

pub fn categorize_path(path: &str, wordpress_path: &str) -> String {
    let relative = display_path(path, wordpress_path).replace('\\', "/");
    if relative.starts_with("wp-content/mu-plugins/") {
        "mu-plugins"
    } else if relative.starts_with("wp-content/plugins/") {
        "plugins"
    } else if relative.starts_with("wp-content/themes/") {
        "themes"
    } else if relative.starts_with("wp-content/uploads/") {
        "uploads"
    } else if relative.starts_with("wp-admin/") || relative.starts_with("wp-includes/") {
        "wordpress-core"
    } else if !relative.contains('/') {
        "root"
    } else {
        "overige"
    }
    .into()
}

fn display_path(path: &str, wordpress_path: &str) -> String {
    path.strip_prefix(wordpress_path)
        .unwrap_or(path)
        .trim_start_matches('/')
        .to_owned()
}

fn string_field(value: &Value, key: &str, fallback: &str) -> String {
    value
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or(fallback)
        .to_owned()
}

fn role_strings(value: &Value) -> Vec<String> {
    match value {
        Value::Array(values) => values
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        Value::String(value) => value
            .split(',')
            .map(str::trim)
            .filter(|role| !role.is_empty())
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    }
}

fn config_finding(category: &str, title: &str, detail: &str) -> Finding {
    Finding {
        category: category.into(),
        severity: FindingSeverity::Attention,
        title: title.into(),
        detail: detail.into(),
        path: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn categorizes_normal_plugin_php_without_suspicion() {
        let (findings, truncated) = parse_nul_paths(
            b"/var/www/wp-content/plugins/seo/main.php\0/var/www/wp-content/uploads/x.php\0",
            "/var/www",
            true,
        );
        assert!(!truncated);
        assert_eq!(findings[0].category, "plugins");
        assert_eq!(findings[0].severity, FindingSeverity::Info);
        assert_eq!(findings[1].severity, FindingSeverity::Attention);
    }

    #[test]
    fn parses_users_and_marks_recent_admin_as_attention() {
        let recent = Utc::now().format("%Y-%m-%d %H:%M:%S");
        let json = format!(
            r#"[{{"ID":1,"user_login":"admin","user_email":"a@example.test","roles":["administrator"],"user_registered":"{recent}"}}]"#
        );
        let users = parse_users(&json).unwrap();
        assert_eq!(users[0].severity, FindingSeverity::Attention);
        assert!(users[0].title.contains("beheerder"));
    }

    #[test]
    fn rejects_untrusted_slug_returned_by_wp_cli() {
        let json = r#"[{"name":"safe;id","title":"Bad","version":"1","update_version":"2"}]"#;
        assert!(parse_update_list(json, UpdateKind::Plugin).is_err());
    }

    #[test]
    fn highlights_sensitive_modified_root_files_neutrally() {
        let (items, _) = parse_modified_files(
            b"/var/www/wp-config.php\x001720000000.0\x00644\0",
            "/var/www",
        );
        assert_eq!(items[0].severity, FindingSeverity::Attention);
        assert!(items[0].detail.contains("niet automatisch kwaadaardig"));
    }
}
