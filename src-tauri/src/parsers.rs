use crate::{
    command_catalog::MAX_SCAN_RESULTS,
    error::AppError,
    models::{
        ChecksumStatus, Finding, FindingSeverity, InstalledSoftware, UpdateItem, UpdateKind,
        WordPressRole, WordPressUser,
    },
    snapshot_builder::SnapshotCronInput,
    validation::{
        validate_checksum_relative_path, validate_role, validate_software_identifier,
        validate_user_id,
    },
};
use chrono::{DateTime, Datelike, Duration, NaiveDateTime, SecondsFormat, Timelike, Utc};
use chrono_tz::Europe::Amsterdam;
use serde_json::Value;
use std::collections::{BTreeMap, HashSet};
use uuid::Uuid;

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
                id: None,
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
                checksum_status: None,
                disposition: crate::models::FindingDisposition::Active,
                exception_id: None,
                trusted_file_id: None,
                policy_reason: None,
                policy_target: None,
                vulnerability: None,
                observed_at: None,
            }
        })
        .collect();
    (findings, truncated)
}

pub fn parse_php_inventory(output: &[u8], wordpress_path: &str) -> (Vec<Finding>, bool) {
    let mut fields: Vec<&[u8]> = output.split(|byte| *byte == 0).collect();
    if fields.last().is_some_and(|field| field.is_empty()) {
        fields.pop();
    }
    let count = fields.len() / 4;
    let truncated = count > MAX_SCAN_RESULTS;
    let mut findings = Vec::with_capacity(count.min(MAX_SCAN_RESULTS));
    for record in fields.chunks(4).take(MAX_SCAN_RESULTS) {
        if record.len() != 4 {
            continue;
        }
        let path = String::from_utf8_lossy(record[0]).into_owned();
        let modified_at = String::from_utf8_lossy(record[1]).parse::<i64>().ok();
        let size = String::from_utf8_lossy(record[2])
            .parse::<u64>()
            .unwrap_or(0);
        let indicators: HashSet<String> = String::from_utf8_lossy(record[3])
            .split(',')
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
            .collect();
        findings.push(classify_php_file(
            &path,
            wordpress_path,
            modified_at,
            size,
            &indicators,
        ));
    }
    (findings, truncated)
}

fn classify_php_file(
    path: &str,
    wordpress_path: &str,
    modified_at: Option<i64>,
    _size: u64,
    indicators: &HashSet<String>,
) -> Finding {
    let display = display_path(path, wordpress_path).replace('\\', "/");
    let category = categorize_path(&display, "");
    let lower = display.to_ascii_lowercase();
    let file_name = lower.rsplit('/').next().unwrap_or(&lower);
    let stem = file_name.strip_suffix(".php").unwrap_or(file_name);
    let mut score = 0_u8;
    let mut reasons = Vec::new();

    match category.as_str() {
        "uploads" => {
            score += 5;
            reasons.push("PHP-bestand bevindt zich in uploads");
        }
        "wp-content-root" if file_name != "index.php" => {
            score += 2;
            reasons.push("PHP-bestand staat direct onder wp-content");
        }
        "cache" | "backup" | "temp" | "upgrade" => {
            score += 2;
            reasons.push("PHP-bestand staat in een locatie die controle verdient");
        }
        "overige" => {
            score += 2;
            reasons.push("PHP-bestand staat buiten plugins, themes en mu-plugins");
        }
        _ => {}
    }

    if display
        .split('/')
        .any(|component| component.starts_with('.') && component.len() > 1)
        || file_name == ".php"
    {
        score += 3;
        reasons.push("Verborgen PHP-bestandsnaam of directory");
    }
    if has_suspicious_double_extension(file_name) {
        score += 3;
        reasons.push("Bestandsnaam heeft een opvallende dubbele extensie");
    }
    if looks_random(stem) {
        score += 2;
        reasons.push("Bestandsnaam oogt willekeurig of sterk gegenereerd");
    }
    if ["shell", "backdoor", "b374k", "wso", "r57", "cmd"]
        .iter()
        .any(|candidate| stem == *candidate || stem.starts_with(&format!("{candidate}-")))
    {
        score += 2;
        reasons.push("Bestandsnaam lijkt op een tijdelijk beheer- of shellbestand");
    }

    let encoded = indicators.contains("base64_decode")
        || indicators.contains("gzinflate")
        || indicators.contains("gzuncompress")
        || indicators.contains("str_rot13");
    let compression_combo = indicators.contains("base64_decode")
        && (indicators.contains("gzinflate") || indicators.contains("gzuncompress"));
    if indicators.contains("eval") && encoded || compression_combo {
        score += 3;
        reasons.push("Combinatie van code-evaluatie en decoding/obfuscatie");
    }
    let execution_count = [
        "shell_exec",
        "exec",
        "system",
        "passthru",
        "proc_open",
        "popen",
    ]
    .iter()
    .filter(|indicator| indicators.contains(**indicator))
    .count();
    if execution_count >= 2 {
        score += 3;
        reasons.push("Meerdere functies voor proces- of shelluitvoering aangetroffen");
    }
    if indicators.contains("dynamic_call") && encoded {
        score += 2;
        reasons.push("Dynamische functieaanroep gecombineerd met decoding");
    }
    if indicators.contains("long_encoded") || indicators.contains("long_line") {
        score += 2;
        reasons.push("Sterk geobfusceerde of gecodeerde lange payload aangetroffen");
    }
    if score >= 2
        && modified_at.is_some_and(|timestamp| Utc::now().timestamp() - timestamp <= 7 * 86_400)
    {
        reasons.push("Bestand is in de afgelopen 7 dagen gewijzigd");
    }

    let attention = score >= 2;
    Finding {
        id: None,
        category,
        severity: if attention {
            FindingSeverity::Attention
        } else {
            FindingSeverity::Info
        },
        title: if attention {
            if lower.starts_with("wp-content/uploads/") {
                "PHP-bestand in uploads".into()
            } else {
                "Controle aanbevolen".into()
            }
        } else {
            "Normaal PHP-bestand".into()
        },
        detail: if attention {
            format!(
                "Redenen: {}. Dit is een heuristische melding en geen bewijs van malware.",
                reasons.join("; ")
            )
        } else {
            "Geen combinatie van opvallende locatie-, naam- of inhoudsindicatoren gevonden.".into()
        },
        path: Some(display),
        checksum_status: None,
        disposition: crate::models::FindingDisposition::Active,
        exception_id: None,
        trusted_file_id: None,
        policy_reason: None,
        policy_target: None,
        vulnerability: None,
        observed_at: modified_at.and_then(|timestamp| {
            chrono::DateTime::from_timestamp(timestamp, 0).map(|value| value.to_rfc3339())
        }),
    }
}

fn has_suspicious_double_extension(file_name: &str) -> bool {
    let Some(stem) = file_name.strip_suffix(".php") else {
        return false;
    };
    [
        ".jpg", ".jpeg", ".png", ".gif", ".webp", ".ico", ".svg", ".txt", ".pdf", ".zip",
    ]
    .iter()
    .any(|extension| stem.ends_with(extension))
}

fn looks_random(stem: &str) -> bool {
    if stem.len() < 14
        || !stem
            .chars()
            .all(|character| character.is_ascii_alphanumeric())
    {
        return false;
    }
    let letters = stem
        .chars()
        .filter(|character| character.is_ascii_alphabetic())
        .count();
    let digits = stem
        .chars()
        .filter(|character| character.is_ascii_digit())
        .count();
    let vowels = stem
        .chars()
        .filter(|character| matches!(character.to_ascii_lowercase(), 'a' | 'e' | 'i' | 'o' | 'u'))
        .count();
    letters > 0 && digits > 0 && vowels * 5 <= stem.len()
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
        let modified_at = parse_find_unix_timestamp(record[1]);
        let permission_mode = String::from_utf8_lossy(record[2]);
        let permission_mode = permission_mode.trim();
        let permission_mode = if (3..=4).contains(&permission_mode.len())
            && permission_mode
                .chars()
                .all(|character| matches!(character, '0'..='7'))
        {
            permission_mode
        } else {
            "onbekend"
        };
        let modified_label = modified_at.as_ref().map_or_else(
            || "een onbekend tijdstip".into(),
            format_dutch_modified_timestamp,
        );
        findings.push(Finding {
            id: None,
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
            detail: format!("Gewijzigd op {modified_label} en heeft permissies {permission_mode}."),
            path: Some(display),
            checksum_status: None,
            disposition: crate::models::FindingDisposition::Active,
            exception_id: None,
            trusted_file_id: None,
            policy_reason: None,
            policy_target: None,
            vulnerability: None,
            observed_at: modified_at
                .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Nanos, true)),
        });
    }
    (findings, truncated)
}

fn parse_find_unix_timestamp(value: &[u8]) -> Option<DateTime<Utc>> {
    let value = std::str::from_utf8(value).ok()?.trim();
    let (seconds, fraction) = value.split_once('.').unwrap_or((value, ""));
    let seconds = seconds.parse::<i64>().ok()?;
    if !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let mut nanoseconds = fraction.chars().take(9).collect::<String>();
    while nanoseconds.len() < 9 {
        nanoseconds.push('0');
    }
    let nanoseconds = if nanoseconds.is_empty() {
        0
    } else {
        nanoseconds.parse::<u32>().ok()?
    };
    DateTime::<Utc>::from_timestamp(seconds, nanoseconds)
}

fn format_dutch_modified_timestamp(timestamp: &DateTime<Utc>) -> String {
    const MONTHS: [&str; 12] = [
        "januari",
        "februari",
        "maart",
        "april",
        "mei",
        "juni",
        "juli",
        "augustus",
        "september",
        "oktober",
        "november",
        "december",
    ];
    let local = timestamp.with_timezone(&Amsterdam);
    format!(
        "{} {} {} om {:02}:{:02} uur",
        local.day(),
        MONTHS[local.month0() as usize],
        local.year(),
        local.hour(),
        local.minute()
    )
}

pub fn parse_checksum_output(output: &str, observed_at: &str) -> Result<Vec<Finding>, AppError> {
    let trimmed = output.trim();
    if trimmed.is_empty() || trimmed.starts_with("Success:") {
        return Ok(Vec::new());
    }
    let mut stream = serde_json::Deserializer::from_str(trimmed).into_iter::<Vec<Value>>();
    let rows = stream
        .next()
        .transpose()
        .map_err(|error| {
            AppError::ssh(
                "checksum_parse_failed",
                "De checksumresultaten konden niet veilig worden gelezen.",
                error,
                false,
            )
        })?
        .ok_or_else(|| AppError::validation("De checksumuitvoer is leeg."))?;
    let trailing = &trimmed[stream.byte_offset()..];
    if !trailing.trim().is_empty()
        && !trailing.trim_start().starts_with("Success:")
        && !trailing.trim_start().starts_with("Error:")
    {
        return Err(AppError::validation(
            "De checksumuitvoer bevat onverwachte gegevens.",
        ));
    }
    let mut findings = Vec::with_capacity(rows.len().min(MAX_SCAN_RESULTS));
    for row in rows.into_iter().take(MAX_SCAN_RESULTS) {
        let path = row.get("file").and_then(Value::as_str).ok_or_else(|| {
            AppError::validation("Een checksumresultaat bevat geen geldig bestandspad.")
        })?;
        let message = row
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("Onbekende checksummelding");
        findings.push(checksum_finding(path, message, observed_at)?);
    }
    Ok(findings)
}

pub fn parse_checksum_plain_output(
    output: &str,
    observed_at: &str,
) -> Result<Vec<Finding>, AppError> {
    let mut findings = Vec::new();
    let mut success = false;
    for raw_line in output.lines() {
        let line = raw_line.trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("Success:") {
            success = true;
            continue;
        }
        if line.starts_with("Error:") {
            continue;
        }
        let message = line.strip_prefix("Warning: ").unwrap_or(line);
        let path = [
            "File should not exist: ",
            "File shouldn't exist: ",
            "File doesn't verify against checksum: ",
            "File does not verify against checksum: ",
            "File doesn't exist: ",
            "File does not exist: ",
            "File is missing: ",
        ]
        .iter()
        .find_map(|prefix| message.strip_prefix(prefix));
        if let Some(path) = path
            && findings.len() < MAX_SCAN_RESULTS
        {
            findings.push(checksum_finding(path.trim(), message, observed_at)?);
        }
    }
    if success || !findings.is_empty() {
        Ok(findings)
    } else {
        Err(AppError::ssh(
            "checksum_parse_failed",
            "De checksumresultaten konden niet veilig worden gelezen.",
            output,
            false,
        ))
    }
}

fn checksum_finding(path: &str, message: &str, observed_at: &str) -> Result<Finding, AppError> {
    validate_checksum_relative_path(path)?;
    let lower = message.to_ascii_lowercase();
    let (status, title, severity, category) =
        if lower.contains("should not exist") || lower.contains("shouldn't exist") {
            (
                ChecksumStatus::Unexpected,
                "Hoort niet aanwezig te zijn",
                FindingSeverity::Attention,
                "wordpress-core-unexpected",
            )
        } else if lower.contains("doesn't verify against checksum")
            || lower.contains("does not verify against checksum")
            || lower.contains("checksum mismatch")
        {
            (
                ChecksumStatus::Modified,
                "Gewijzigd",
                FindingSeverity::Problem,
                "wordpress-core-modified",
            )
        } else if lower.contains("doesn't exist")
            || lower.contains("does not exist")
            || lower.contains("is missing")
        {
            (
                ChecksumStatus::Missing,
                "Ontbreekt",
                FindingSeverity::Problem,
                "wordpress-core-missing",
            )
        } else {
            (
                ChecksumStatus::ScanError,
                "Scanmelding niet herkend",
                FindingSeverity::Problem,
                "wordpress-core-scan-error",
            )
        };
    Ok(Finding {
        id: Some(Uuid::new_v4().to_string()),
        category: category.into(),
        severity,
        title: title.into(),
        detail: message.into(),
        path: Some(path.into()),
        checksum_status: Some(status),
        disposition: crate::models::FindingDisposition::Active,
        exception_id: None,
        trusted_file_id: None,
        policy_reason: None,
        policy_target: None,
        vulnerability: None,
        observed_at: Some(observed_at.into()),
    })
}

pub fn unexpected_checksum_finding(path: &str, observed_at: &str) -> Result<Finding, AppError> {
    checksum_finding(path, "File should not exist", observed_at)
}

#[cfg(test)]
pub fn parse_users(output: &str) -> Result<Vec<Finding>, AppError> {
    Ok(user_findings(&parse_wordpress_users(output)?))
}

pub fn user_findings(users: &[WordPressUser]) -> Vec<Finding> {
    users
        .iter()
        .map(|user| {
            let administrator = user.roles.iter().any(|role| role == "administrator");
            let recent = NaiveDateTime::parse_from_str(&user.registered_at, "%Y-%m-%d %H:%M:%S")
                .ok()
                .is_some_and(|date| date > (Utc::now() - Duration::days(30)).naive_utc());
            Finding {
                id: None,
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
                    format!("{} · beheerder", user.username)
                } else {
                    user.username.clone()
                },
                detail: format!(
                    "E-mail: {} · Rollen: {} · Aangemaakt: {}",
                    user.email,
                    if user.roles.is_empty() {
                        "geen".into()
                    } else {
                        user.roles.join(", ")
                    },
                    user.registered_at
                ),
                path: None,
                checksum_status: None,
                disposition: crate::models::FindingDisposition::Active,
                exception_id: None,
                trusted_file_id: None,
                policy_reason: None,
                policy_target: None,
                vulnerability: None,
                observed_at: None,
            }
        })
        .collect()
}

pub fn parse_wordpress_users(output: &str) -> Result<Vec<WordPressUser>, AppError> {
    let rows: Vec<Value> = serde_json::from_str(output).map_err(|error| {
        AppError::ssh(
            "parse_failed",
            "De WordPress-gebruikers konden niet worden gelezen.",
            error,
            false,
        )
    })?;
    let mut users = Vec::with_capacity(rows.len());
    for row in rows {
        let id = unsigned_field(&row, "ID")?;
        validate_user_id(id)?;
        let username = required_string_field(&row, "user_login", "gebruikersnaam")?;
        let email = required_string_field(&row, "user_email", "e-mailadres")?;
        let registered_at = required_string_field(&row, "user_registered", "registratiedatum")?;
        let display_name = row
            .get("display_name")
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .unwrap_or(&username)
            .to_owned();
        let roles = row.get("roles").map(role_strings).unwrap_or_default();
        for role in &roles {
            validate_role(role)?;
        }
        users.push(WordPressUser {
            id,
            username,
            display_name,
            email,
            roles,
            registered_at,
        });
    }
    Ok(users)
}

pub fn parse_wordpress_roles(output: &str) -> Result<Vec<WordPressRole>, AppError> {
    let rows: Vec<Value> = serde_json::from_str(output).map_err(|error| {
        AppError::ssh(
            "parse_failed",
            "De WordPress-rollen konden niet worden gelezen.",
            error,
            false,
        )
    })?;
    let mut roles = Vec::with_capacity(rows.len());
    for row in rows {
        let role = required_string_field(&row, "role", "rol-id")?;
        validate_role(&role)?;
        let name = required_string_field(&row, "name", "rolnaam")?;
        if name.chars().count() > 250 || name.chars().any(char::is_control) {
            return Err(AppError::validation(
                "WordPress retourneerde een ongeldige rolnaam.",
            ));
        }
        roles.push(WordPressRole { role, name });
    }
    Ok(roles)
}

pub fn parse_multisite(output: &str) -> Result<bool, AppError> {
    match output.trim() {
        "1" => Ok(true),
        "0" | "" => Ok(false),
        _ => Err(AppError::validation(
            "De WordPress multisite-status kon niet betrouwbaar worden vastgesteld.",
        )),
    }
}

#[cfg(test)]
pub fn parse_config(output: &str) -> Result<Vec<Finding>, AppError> {
    Ok(config_findings(&parse_selected_config(output)?))
}

pub fn parse_selected_config(output: &str) -> Result<BTreeMap<String, Value>, AppError> {
    let config: Value = serde_json::from_str(output).map_err(|error| {
        AppError::ssh(
            "parse_failed",
            "De geselecteerde WordPress-instellingen konden niet worden gelezen.",
            error,
            false,
        )
    })?;
    let object = config.as_object().ok_or_else(|| {
        AppError::ssh(
            "parse_failed",
            "De geselecteerde WordPress-instellingen konden niet worden gelezen.",
            "WP-CLI retourneerde geen JSON-object.",
            false,
        )
    })?;
    let mut selected = BTreeMap::new();
    for (key, value) in object {
        if [
            "site_url",
            "home_url",
            "active_theme",
            "wp_environment_type",
            "WP_ENVIRONMENT_TYPE",
            "WP_ENVIRONMENT_TYPE_EXPLICIT",
            "WP_DEBUG",
            "WP_DEBUG_LOG",
            "WP_DEBUG_DISPLAY",
            "DISALLOW_FILE_EDIT",
            "DISALLOW_FILE_MODS",
            "permalink_structure",
            "multisite",
            "locale",
        ]
        .contains(&key.as_str())
        {
            selected.insert(key.clone(), value.clone());
        }
    }
    if let Some(value) = selected.remove("WP_ENVIRONMENT_TYPE") {
        selected
            .entry("wp_environment_type".into())
            .or_insert(value);
    }
    Ok(selected)
}

pub fn config_findings(config: &BTreeMap<String, Value>) -> Vec<Finding> {
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
        .get("wp_environment_type")
        .and_then(Value::as_str)
        .unwrap_or("production");
    let environment_is_explicit = config
        .get("WP_ENVIRONMENT_TYPE_EXPLICIT")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    findings.push(Finding {
        id: None,
        category: "configuration".into(),
        severity: FindingSeverity::Info,
        title: "Effectief WordPress-omgevingstype".into(),
        detail: if environment_is_explicit {
            environment.into()
        } else {
            format!("{environment} (WordPress-standaard; niet expliciet ingesteld)")
        },
        path: None,
        checksum_status: None,
        disposition: crate::models::FindingDisposition::Active,
        exception_id: None,
        trusted_file_id: None,
        policy_reason: None,
        policy_target: None,
        vulnerability: None,
        observed_at: None,
    });
    findings
}

pub fn parse_snapshot_cron(output: &str) -> Result<Vec<SnapshotCronInput>, AppError> {
    let rows: Vec<Value> = if output.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(output).map_err(|error| {
            AppError::ssh(
                "parse_failed",
                "De WordPress-cronplanning kon niet worden gelezen.",
                error,
                false,
            )
        })?
    };
    if rows.len() > MAX_SCAN_RESULTS {
        return Err(AppError::ssh(
            "output_limit",
            "De WordPress-cronplanning is te groot voor een betrouwbare momentopname.",
            format!("meer dan {MAX_SCAN_RESULTS} cronregels"),
            false,
        ));
    }
    rows.into_iter()
        .map(|row| {
            let hook = required_string_field(&row, "hook", "cronhook")?;
            if hook.chars().count() > 250 || hook.chars().any(char::is_control) {
                return Err(AppError::validation(
                    "WordPress retourneerde een ongeldige cronhook.",
                ));
            }
            let timestamp = row
                .get("timestamp")
                .and_then(|value| value.as_i64().or_else(|| value.as_str()?.parse().ok()))
                .and_then(|timestamp| DateTime::<Utc>::from_timestamp(timestamp, 0))
                .map(|timestamp| timestamp.to_rfc3339_opts(SecondsFormat::Secs, true));
            let schedule = row
                .get("schedule")
                .and_then(Value::as_str)
                .filter(|value| !value.is_empty())
                .map(str::to_owned);
            let recurrence = row
                .get("interval")
                .and_then(|value| value.as_i64().or_else(|| value.as_str()?.parse().ok()))
                .map(|value| value.to_string());
            Ok(SnapshotCronInput {
                hook,
                schedule,
                recurrence,
                args: row.get("args").cloned(),
                next_run_at: timestamp,
            })
        })
        .collect()
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
        let update_version = string_field(&row, "update_version", "");
        let update_state = string_field(&row, "update", "");
        if update_version.is_empty()
            || update_version == "none"
            || (!update_state.is_empty() && update_state != "available")
        {
            continue;
        }
        let slug = string_field(&row, "name", "").trim().to_owned();
        validate_software_identifier(&slug)
            .map_err(|error| with_software_context(error, &kind, "name", &slug, None))?;
        updates.push(UpdateItem {
            kind: kind.clone(),
            name: software_display_name(&row, &slug, &kind)?,
            slug,
            current_version: string_field(&row, "version", "onbekend"),
            new_version: update_version,
            status: "available".into(),
        });
    }
    Ok(updates)
}

pub fn parse_software_inventory(
    output: &str,
    kind: UpdateKind,
    observed_at: &str,
) -> Result<Vec<InstalledSoftware>, AppError> {
    let rows: Vec<Value> = if output.trim().is_empty() {
        Vec::new()
    } else {
        serde_json::from_str(output).map_err(|error| {
            AppError::ssh(
                "parse_failed",
                "De geïnstalleerde software kon niet worden gelezen.",
                error,
                false,
            )
        })?
    };
    let software_type = match kind {
        UpdateKind::Plugin => "plugin",
        UpdateKind::Theme => "theme",
        _ => {
            return Err(AppError::validation(
                "Alleen plugin- en thema-inventory kan uit deze lijst worden gelezen.",
            ));
        }
    };
    rows.into_iter()
        .map(|row| {
            let slug = string_field(&row, "name", "").trim().to_ascii_lowercase();
            validate_software_identifier(&slug)
                .map_err(|error| with_software_context(error, &kind, "name", &slug, None))?;
            let version = string_field(&row, "version", "").trim().to_owned();
            if version.len() > 200 || version.chars().any(char::is_control) {
                return Err(with_software_context(
                    AppError::validation("WP-CLI gaf een ongeldige softwareversie terug."),
                    &kind,
                    "version",
                    &version,
                    Some(&slug),
                ));
            }
            let version = if version.is_empty() {
                "onbekend".into()
            } else {
                version
            };
            let update_version = string_field(&row, "update_version", "");
            Ok(InstalledSoftware {
                software_type: software_type.into(),
                name: software_display_name(&row, &slug, &kind)?,
                slug,
                version,
                status: string_field(&row, "status", "unknown"),
                update_version: (!update_version.is_empty() && update_version != "none")
                    .then_some(update_version),
                observed_at: observed_at.into(),
            })
        })
        .collect()
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
    } else if relative == "wp-content"
        || relative.starts_with("wp-content/") && !relative[11..].contains('/')
    {
        "wp-content-root"
    } else if relative.starts_with("wp-content/cache/") {
        "cache"
    } else if relative.starts_with("wp-content/backup/")
        || relative.starts_with("wp-content/backups/")
    {
        "backup"
    } else if relative.starts_with("wp-content/tmp/") || relative.starts_with("wp-content/temp/") {
        "temp"
    } else if relative.starts_with("wp-content/upgrade/") {
        "upgrade"
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

fn software_display_name(value: &Value, slug: &str, kind: &UpdateKind) -> Result<String, AppError> {
    let name = string_field(value, "title", "").trim().to_owned();
    if name.is_empty() {
        return Ok(slug.to_owned());
    }
    if name.chars().count() > 250 || name.chars().any(char::is_control) {
        return Err(with_software_context(
            AppError::validation("WP-CLI gaf een ongeldige plugin- of themanaam terug."),
            kind,
            "title",
            &name,
            Some(slug),
        ));
    }
    Ok(name)
}

fn with_software_context(
    mut error: AppError,
    kind: &UpdateKind,
    field: &str,
    value: &str,
    identifier: Option<&str>,
) -> AppError {
    let item_type = match kind {
        UpdateKind::Plugin => "plugin",
        UpdateKind::Theme => "thema",
        UpdateKind::Core => "WordPress-core",
        UpdateKind::Language => "vertaling",
    };
    let mut details = format!(
        "WP-CLI-itemtype: {item_type}\nVeld: {field}\nOntvangen waarde: {}",
        diagnostic_value(value)
    );
    if let Some(identifier) = identifier {
        details.push_str(&format!(
            "\nBijbehorende identiteit: {}",
            diagnostic_value(identifier)
        ));
    }
    error.technical_details = Some(details);
    error
}

fn diagnostic_value(value: &str) -> String {
    const MAX_CHARACTERS: usize = 200;
    let character_count = value.chars().count();
    let bounded = value.chars().take(MAX_CHARACTERS).collect::<String>();
    let quoted = serde_json::to_string(&bounded).unwrap_or_else(|_| "\"<onleesbaar>\"".into());
    if character_count > MAX_CHARACTERS {
        format!("{quoted}… ({character_count} tekens)")
    } else {
        quoted
    }
}

fn required_string_field(value: &Value, key: &str, label: &str) -> Result<String, AppError> {
    value
        .get(key)
        .and_then(Value::as_str)
        .filter(|value| !value.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or_else(|| {
            AppError::validation(format!(
                "WordPress retourneerde geen geldige {label} voor een gebruiker of rol."
            ))
        })
}

fn unsigned_field(value: &Value, key: &str) -> Result<u64, AppError> {
    value
        .get(key)
        .and_then(|field| {
            field
                .as_u64()
                .or_else(|| field.as_str().and_then(|value| value.parse().ok()))
        })
        .ok_or_else(|| AppError::validation("WordPress retourneerde een ongeldige user-id."))
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
        id: None,
        category: category.into(),
        severity: FindingSeverity::Attention,
        title: title.into(),
        detail: detail.into(),
        path: None,
        checksum_status: None,
        disposition: crate::models::FindingDisposition::Active,
        exception_id: None,
        trusted_file_id: None,
        policy_reason: None,
        policy_target: None,
        vulnerability: None,
        observed_at: None,
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

    fn php_record(path: &str, modified: i64, size: u64, indicators: &str) -> Vec<u8> {
        format!("{path}\0{modified}\0{size}\0{indicators}\0").into_bytes()
    }

    #[test]
    fn php_classifier_hides_normal_plugin_theme_and_mu_plugin_files() {
        for path in [
            "/var/www/wp-content/plugins/example/plugin.php",
            "/var/www/wp-content/themes/theme/functions.php",
            "/var/www/wp-content/mu-plugins/custom.php",
        ] {
            let (findings, truncated) =
                parse_php_inventory(&php_record(path, 0, 120, ""), "/var/www");
            assert!(!truncated);
            assert_eq!(findings[0].severity, FindingSeverity::Info, "{path}");
        }
    }

    #[test]
    fn php_classifier_explains_upload_double_extension_hidden_and_unusual_locations() {
        let mut output = Vec::new();
        output.extend(php_record(
            "/var/www/wp-content/uploads/2026/image.jpg.php",
            Utc::now().timestamp(),
            10,
            "",
        ));
        output.extend(php_record(
            "/var/www/wp-content/plugins/example/.hidden.php",
            0,
            10,
            "",
        ));
        output.extend(php_record("/var/www/wp-content/cache/cache.php", 0, 10, ""));
        output.extend(php_record("/var/www/wp-content/random123.php", 0, 10, ""));
        let (findings, _) = parse_php_inventory(&output, "/var/www");
        assert!(
            findings
                .iter()
                .all(|finding| finding.severity == FindingSeverity::Attention)
        );
        assert!(findings[0].detail.contains("uploads"));
        assert!(findings[0].detail.contains("dubbele extensie"));
        assert!(findings[0].detail.contains("afgelopen 7 dagen"));
        assert!(findings[1].detail.contains("Verborgen"));
        assert_eq!(findings[2].category, "cache");
        assert_eq!(findings[3].category, "wp-content-root");
    }

    #[test]
    fn php_classifier_requires_indicator_combinations_for_normal_locations() {
        let cases = [
            ("base64_decode", FindingSeverity::Info),
            ("eval,base64_decode", FindingSeverity::Attention),
            ("gzinflate,base64_decode", FindingSeverity::Attention),
            ("system", FindingSeverity::Info),
            ("system,shell_exec", FindingSeverity::Attention),
            ("dynamic_call,base64_decode", FindingSeverity::Attention),
            ("long_encoded", FindingSeverity::Attention),
            ("non_text,huge", FindingSeverity::Info),
        ];
        for (indicators, expected) in cases {
            let (findings, _) = parse_php_inventory(
                &php_record(
                    "/var/www/wp-content/plugins/example/normal.php",
                    0,
                    8_000_000,
                    indicators,
                ),
                "/var/www",
            );
            assert_eq!(findings[0].severity, expected, "{indicators}");
        }
        let (empty, _) = parse_php_inventory(
            &php_record("/var/www/wp-content/plugins/example/empty.php", 0, 0, ""),
            "/var/www",
        );
        assert_eq!(empty[0].severity, FindingSeverity::Info);
    }

    #[test]
    fn php_classifier_detects_random_names_and_bounds_large_inventories() {
        let (random, _) = parse_php_inventory(
            &php_record(
                "/var/www/wp-content/plugins/example/x9k2m7q4z8p1n6.php",
                0,
                10,
                "",
            ),
            "/var/www",
        );
        assert_eq!(random[0].severity, FindingSeverity::Attention);
        let mut many = Vec::new();
        for index in 0..=MAX_SCAN_RESULTS {
            many.extend(php_record(
                &format!("/var/www/wp-content/plugins/example/{index}.php"),
                0,
                10,
                "",
            ));
        }
        let (findings, truncated) = parse_php_inventory(&many, "/var/www");
        assert_eq!(findings.len(), MAX_SCAN_RESULTS);
        assert!(truncated);
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
    fn parses_typed_users_roles_and_multisite() {
        let users = parse_wordpress_users(
            r#"[{"ID":"12","user_login":"editor","display_name":"Site Editor","user_email":"editor@example.test","roles":["editor","shop_manager"],"user_registered":"2020-01-02 03:04:05"}]"#,
        )
        .unwrap();
        assert_eq!(users[0].id, 12);
        assert_eq!(users[0].display_name, "Site Editor");
        assert_eq!(users[0].roles, ["editor", "shop_manager"]);
        let roles = parse_wordpress_roles(
            r#"[{"role":"administrator","name":"Administrator"},{"role":"shop_manager","name":"Winkelmanager"}]"#,
        )
        .unwrap();
        assert_eq!(roles[1].role, "shop_manager");
        assert!(parse_multisite("1\n").unwrap());
        assert!(!parse_multisite("0").unwrap());
        assert!(parse_multisite("maybe").is_err());
    }

    #[test]
    fn rejects_untrusted_slug_returned_by_wp_cli() {
        let json = r#"[{"name":"safe;id","title":"Bad","version":"1","update_version":"2"}]"#;
        let error = parse_update_list(json, UpdateKind::Plugin).unwrap_err();
        assert_eq!(error.category, "validation");
        let details = error.technical_details.unwrap();
        assert!(details.contains("WP-CLI-itemtype: plugin"));
        assert!(details.contains("Veld: name"));
        assert!(details.contains(r#"Ontvangen waarde: "safe;id""#));
    }

    #[test]
    fn update_list_accepts_safe_wordpress_identifiers_beyond_repository_slugs() {
        let json = r#"[
            {"name":"Plugin_Loader-1.php","title":"Custom Loader","version":"1.0.0","update":"available","update_version":"1.1.0"},
            {"name":"theme_with_underscores","title":"Custom Theme","version":"2.0.0","update":"available","update_version":"2.1.0"}
        ]"#;

        let plugins = parse_update_list(json, UpdateKind::Plugin).unwrap();

        assert_eq!(plugins.len(), 2);
        assert_eq!(plugins[0].slug, "Plugin_Loader-1.php");
        assert_eq!(plugins[1].slug, "theme_with_underscores");
    }

    #[test]
    fn invalid_software_title_reports_the_related_identifier() {
        let json = "[{\"name\":\"example-plugin\",\"title\":\"Bad\\nTitle\",\"version\":\"1\",\"update\":\"available\",\"update_version\":\"2\"}]";

        let error = parse_update_list(json, UpdateKind::Plugin).unwrap_err();

        assert!(error.technical_details.as_deref().is_some_and(|details| {
            details.contains("Bijbehorende identiteit: \"example-plugin\"")
        }));
    }

    #[test]
    fn full_wp_cli_list_yields_inventory_but_only_available_updates() {
        let json = r#"[
            {"name":"safe-plugin","title":"Safe Plugin","status":"active","version":"2.0.0","update":"none","update_version":""},
            {"name":"object-cache.php","title":"","status":"dropin","version":"","update":"none","update_version":""},
            {"name":"needs-update","title":"Needs Update","status":"inactive","version":"1.2.3","update":"available","update_version":"1.2.4"}
        ]"#;
        let updates = parse_update_list(json, UpdateKind::Plugin).unwrap();
        let inventory =
            parse_software_inventory(json, UpdateKind::Plugin, "2026-09-10T08:00:00Z").unwrap();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].slug, "needs-update");
        assert_eq!(inventory.len(), 3);
        assert_eq!(inventory[0].status, "active");
        assert_eq!(inventory[1].slug, "object-cache.php");
        assert_eq!(inventory[1].name, "object-cache.php");
        assert_eq!(inventory[1].status, "dropin");
        assert_eq!(inventory[1].version, "onbekend");
        assert_eq!(inventory[2].status, "inactive");
        assert_eq!(inventory[2].update_version.as_deref(), Some("1.2.4"));
    }

    #[test]
    fn configuration_reports_effective_default_environment() {
        let findings = parse_config(
            r#"{"WP_DEBUG":false,"DISALLOW_FILE_EDIT":true,"WP_ENVIRONMENT_TYPE":"production","WP_ENVIRONMENT_TYPE_EXPLICIT":false}"#,
        )
        .unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].title, "Effectief WordPress-omgevingstype");
        assert_eq!(
            findings[0].detail,
            "production (WordPress-standaard; niet expliciet ingesteld)"
        );

        let explicit = parse_config(
            r#"{"WP_DEBUG":false,"DISALLOW_FILE_EDIT":true,"WP_ENVIRONMENT_TYPE":"staging","WP_ENVIRONMENT_TYPE_EXPLICIT":true}"#,
        )
        .unwrap();
        assert_eq!(explicit[0].detail, "staging");
    }

    #[test]
    fn selected_configuration_keeps_only_explicit_safe_snapshot_keys() {
        let configuration = parse_selected_config(
            r#"{"site_url":"https://example.test","WP_ENVIRONMENT_TYPE":"staging","DB_PASSWORD":"never-store","AUTH_KEY":"never-store-either"}"#,
        )
        .unwrap();
        assert_eq!(
            configuration
                .get("wp_environment_type")
                .and_then(Value::as_str),
            Some("staging")
        );
        assert!(!configuration.contains_key("WP_ENVIRONMENT_TYPE"));
        assert!(!configuration.contains_key("DB_PASSWORD"));
        assert!(!configuration.contains_key("AUTH_KEY"));
    }

    #[test]
    fn cron_parser_keeps_args_only_for_later_fingerprinting() {
        let events = parse_snapshot_cron(
            r#"[{"hook":"wp_update_plugins","timestamp":1789462800,"schedule":"twicedaily","interval":43200,"args":{"site":"primary"}}]"#,
        )
        .unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].hook, "wp_update_plugins");
        assert_eq!(events[0].recurrence.as_deref(), Some("43200"));
        assert_eq!(
            events[0].args.as_ref().and_then(|args| args.get("site")),
            Some(&Value::String("primary".into()))
        );
        assert!(events[0].next_run_at.as_deref().unwrap().ends_with('Z'));
    }

    #[test]
    fn parses_typed_checksum_findings() {
        let findings = parse_checksum_output(
            r#"[{"file":"index.php","message":"File doesn't verify against checksum"},{"file":"wp-admin/old.php","message":"File should not exist"},{"file":"wp-includes/version.php","message":"File doesn't exist"}]"#,
            "2026-08-31T10:00:00Z",
        )
        .unwrap();
        assert_eq!(findings[0].checksum_status, Some(ChecksumStatus::Modified));
        assert_eq!(
            findings[1].checksum_status,
            Some(ChecksumStatus::Unexpected)
        );
        assert_eq!(findings[2].checksum_status, Some(ChecksumStatus::Missing));
        assert!(findings.iter().all(|finding| finding.id.is_some()));
        assert!(findings.iter().all(|finding| finding.observed_at.is_some()));
    }

    #[test]
    fn parses_success_and_known_status_after_json() {
        assert!(
            parse_checksum_output(
                "Success: WordPress installation verifies against checksums.",
                "2026-08-31T10:00:00Z"
            )
            .unwrap()
            .is_empty()
        );
        let findings = parse_checksum_output(
            "[{\"file\":\"extra.php\",\"message\":\"File should not exist\"}]\nSuccess: WordPress installation verifies against checksums.",
            "2026-08-31T10:00:00Z",
        )
        .unwrap();
        assert_eq!(
            findings[0].checksum_status,
            Some(ChecksumStatus::Unexpected)
        );
    }

    #[test]
    fn parses_plain_checksum_fallback_output() {
        let findings = parse_checksum_plain_output(
            "Warning: File doesn't verify against checksum: wp-admin/admin.php\nWarning: File should not exist: wp-admin/extra.php\nWarning: File doesn't exist: wp-includes/version.php\nError: WordPress installation doesn't verify against checksums.",
            "2026-08-31T10:00:00Z",
        )
        .unwrap();
        assert_eq!(findings.len(), 3);
        assert_eq!(findings[0].checksum_status, Some(ChecksumStatus::Modified));
        assert_eq!(
            findings[1].checksum_status,
            Some(ChecksumStatus::Unexpected)
        );
        assert_eq!(findings[2].checksum_status, Some(ChecksumStatus::Missing));
    }

    #[test]
    fn plain_checksum_fallback_rejects_unsafe_paths_and_unknown_output() {
        assert!(
            parse_checksum_plain_output(
                "Warning: File should not exist: ../wp-config.php",
                "2026-08-31T10:00:00Z"
            )
            .is_err()
        );
        assert!(
            parse_checksum_plain_output("wp-cli produced something new", "2026-08-31T10:00:00Z")
                .is_err()
        );
    }

    #[test]
    fn rejects_unsafe_checksum_paths() {
        let json = r#"[{"file":"../wp-config.php","message":"File should not exist"}]"#;
        assert!(parse_checksum_output(json, "2026-08-31T10:00:00Z").is_err());
    }

    #[test]
    fn highlights_sensitive_modified_root_files_neutrally() {
        let (items, _) = parse_modified_files(
            b"/var/www/wp-config.php\x001720000000.0\x00644\0",
            "/var/www",
        );
        assert_eq!(items[0].severity, FindingSeverity::Attention);
        assert!(items[0].detail.contains("heeft permissies 644"));
        assert!(!items[0].detail.contains("Unix-tijd"));
        assert!(!items[0].detail.contains("kwaadaardig"));
    }

    #[test]
    fn modified_file_timestamp_is_shown_in_dutch_amsterdam_time() {
        let (items, _) = parse_modified_files(
            b"/var/www/wp-content/example.php\x001789627074.9670225510\x00644\0",
            "/var/www",
        );

        assert_eq!(
            items[0].detail,
            "Gewijzigd op 17 september 2026 om 08:37 uur en heeft permissies 644."
        );
        assert_eq!(
            items[0].observed_at.as_deref(),
            Some("2026-09-17T06:37:54.967022551Z")
        );
    }
}
