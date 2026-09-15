use crate::{
    error::AppError,
    models::{InstalledSoftware, WordPressUser},
    security_policy::normalize_relative_path,
    snapshots::{
        SNAPSHOT_SCHEMA_VERSION, SiteSnapshot, SnapshotCompleteness, SnapshotConfiguration,
        SnapshotCore, SnapshotCronEvent, SnapshotFileState, SnapshotMetadata, SnapshotPlugin,
        SnapshotSectionStatus, SnapshotSource, SnapshotTheme, SnapshotUser, SnapshotValue,
    },
};
use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use uuid::Uuid;

pub const SNAPSHOT_CONFIG_ALLOWLIST: [&str; 12] = [
    "site_url",
    "home_url",
    "active_theme",
    "wp_environment_type",
    "WP_DEBUG",
    "WP_DEBUG_LOG",
    "WP_DEBUG_DISPLAY",
    "DISALLOW_FILE_EDIT",
    "DISALLOW_FILE_MODS",
    "php_version",
    "permalink_structure",
    "multisite",
];
const BOOLEAN_CONFIG_KEYS: [&str; 6] = [
    "WP_DEBUG",
    "WP_DEBUG_LOG",
    "WP_DEBUG_DISPLAY",
    "DISALLOW_FILE_EDIT",
    "DISALLOW_FILE_MODS",
    "multisite",
];
const MAX_SNAPSHOT_FILES: usize = 5_000;

#[derive(Debug, Clone)]
pub enum SnapshotBuildSection<T> {
    Complete(T),
    Failed,
    NotCollected,
}

impl<T> SnapshotBuildSection<T> {
    fn status(&self) -> SnapshotSectionStatus {
        match self {
            Self::Complete(_) => SnapshotSectionStatus::Complete,
            Self::Failed => SnapshotSectionStatus::Failed,
            Self::NotCollected => SnapshotSectionStatus::NotCollected,
        }
    }
}

#[derive(Debug, Clone)]
pub struct SnapshotCronInput {
    pub hook: String,
    pub schedule: Option<String>,
    pub recurrence: Option<String>,
    pub args: Option<Value>,
    pub next_run_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct SnapshotBuildInput {
    pub site_id: String,
    pub scan_run_id: Option<String>,
    pub maintenance_run_id: Option<String>,
    pub source: SnapshotSource,
    pub previous_snapshot_id: Option<String>,
    pub wordpress_path: String,
    pub scan_timestamp: String,
    pub core: SnapshotBuildSection<SnapshotCore>,
    pub plugins: SnapshotBuildSection<Vec<InstalledSoftware>>,
    pub themes: SnapshotBuildSection<Vec<InstalledSoftware>>,
    pub users: SnapshotBuildSection<Vec<WordPressUser>>,
    pub configuration: SnapshotBuildSection<BTreeMap<String, Value>>,
    pub cron: SnapshotBuildSection<Vec<SnapshotCronInput>>,
    pub files: SnapshotBuildSection<Vec<SnapshotFileState>>,
}

pub struct SnapshotBuilder;

impl SnapshotBuilder {
    pub fn build(input: SnapshotBuildInput) -> Result<SiteSnapshot, AppError> {
        let scan_timestamp = normalize_timestamp(&input.scan_timestamp)
            .ok_or_else(|| snapshot_build_error("De scantijd van de momentopname is ongeldig."))?;
        let completeness = SnapshotCompleteness {
            core: input.core.status(),
            plugins: input.plugins.status(),
            themes: input.themes.status(),
            users: input.users.status(),
            configuration: input.configuration.status(),
            cron: input.cron.status(),
            files: input.files.status(),
        };
        let core = match input.core {
            SnapshotBuildSection::Complete(core) => Some(normalize_core(core)?),
            SnapshotBuildSection::Failed | SnapshotBuildSection::NotCollected => None,
        };
        let plugins = match input.plugins {
            SnapshotBuildSection::Complete(items) => normalize_plugins(items)?,
            SnapshotBuildSection::Failed | SnapshotBuildSection::NotCollected => Vec::new(),
        };
        let themes = match input.themes {
            SnapshotBuildSection::Complete(items) => normalize_themes(items)?,
            SnapshotBuildSection::Failed | SnapshotBuildSection::NotCollected => Vec::new(),
        };
        let users = match input.users {
            SnapshotBuildSection::Complete(items) => normalize_users(items)?,
            SnapshotBuildSection::Failed | SnapshotBuildSection::NotCollected => Vec::new(),
        };
        let configuration = match input.configuration {
            SnapshotBuildSection::Complete(values) => normalize_configuration(values)?,
            SnapshotBuildSection::Failed | SnapshotBuildSection::NotCollected => Vec::new(),
        };
        let cron = match input.cron {
            SnapshotBuildSection::Complete(events) => normalize_cron(events)?,
            SnapshotBuildSection::Failed | SnapshotBuildSection::NotCollected => Vec::new(),
        };
        let files = match input.files {
            SnapshotBuildSection::Complete(files) => normalize_files(files)?,
            SnapshotBuildSection::Failed | SnapshotBuildSection::NotCollected => Vec::new(),
        };
        let snapshot_id = Uuid::new_v4().to_string();
        let status = completeness.overall_status();
        let source = input.source;
        Ok(SiteSnapshot {
            metadata: SnapshotMetadata {
                snapshot_id,
                site_id: input.site_id.clone(),
                created_at: scan_timestamp.clone(),
                scan_run_id: input.scan_run_id,
                maintenance_run_id: input.maintenance_run_id,
                source,
                schema_version: SNAPSHOT_SCHEMA_VERSION,
                status,
                wordpress_root_identity: Some(root_identity(
                    &input.site_id,
                    input.wordpress_path.trim(),
                )),
                scan_timestamp,
                app_version: Some(env!("CARGO_PKG_VERSION").to_owned()),
                is_baseline: source == SnapshotSource::Baseline,
                previous_snapshot_id: input.previous_snapshot_id,
            },
            completeness,
            core,
            plugins,
            themes,
            users,
            configuration,
            cron,
            files,
        })
    }
}

fn normalize_core(mut core: SnapshotCore) -> Result<SnapshotCore, AppError> {
    core.version = bounded_text(&core.version, "WordPress-versie", 200)?;
    core.locale = normalize_optional_text(core.locale, "WordPress-locale", 50)?;
    core.php_version = normalize_optional_text(core.php_version, "PHP-versie", 200)?;
    Ok(core)
}

fn normalize_plugins(items: Vec<InstalledSoftware>) -> Result<Vec<SnapshotPlugin>, AppError> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::with_capacity(items.len());
    for item in items {
        if item.software_type != "plugin" {
            return Err(snapshot_build_error(
                "De pluginsectie bevat een ongeldig softwaretype.",
            ));
        }
        let slug = normalize_slug(&item.slug)?;
        ensure_unique(&mut seen, &slug, "plugin")?;
        let available_version = normalize_optional_text(item.update_version, "updateversie", 200)?;
        normalized.push(SnapshotPlugin {
            slug,
            name: bounded_text(&item.name, "pluginnaam", 250)?,
            version: bounded_text(&item.version, "pluginversie", 200)?,
            status: normalize_status(&item.status),
            auto_update: None,
            update_available: available_version.is_some(),
            available_version,
        });
    }
    normalized.sort_by(|left, right| left.slug.cmp(&right.slug));
    Ok(normalized)
}

fn normalize_themes(items: Vec<InstalledSoftware>) -> Result<Vec<SnapshotTheme>, AppError> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::with_capacity(items.len());
    for item in items {
        if item.software_type != "theme" {
            return Err(snapshot_build_error(
                "De themasectie bevat een ongeldig softwaretype.",
            ));
        }
        let slug = normalize_slug(&item.slug)?;
        ensure_unique(&mut seen, &slug, "thema")?;
        let status = normalize_status(&item.status);
        let available_version = normalize_optional_text(item.update_version, "updateversie", 200)?;
        normalized.push(SnapshotTheme {
            slug,
            name: bounded_text(&item.name, "themanaam", 250)?,
            version: bounded_text(&item.version, "themaversie", 200)?,
            active: status == "active",
            status,
            auto_update: None,
            update_available: available_version.is_some(),
            available_version,
        });
    }
    normalized.sort_by(|left, right| left.slug.cmp(&right.slug));
    Ok(normalized)
}

fn normalize_users(items: Vec<WordPressUser>) -> Result<Vec<SnapshotUser>, AppError> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::with_capacity(items.len());
    for user in items {
        ensure_unique(&mut seen, &user.id, "gebruiker")?;
        let mut roles = user
            .roles
            .into_iter()
            .map(|role| role.trim().to_ascii_lowercase())
            .filter(|role| !role.is_empty())
            .collect::<Vec<_>>();
        roles.sort();
        roles.dedup();
        normalized.push(SnapshotUser {
            id: user.id,
            login: bounded_text(&user.username, "gebruikerslogin", 60)?,
            display_name: normalize_optional_text(Some(user.display_name), "weergavenaam", 250)?,
            email: bounded_text(&user.email, "e-mailadres", 254)?,
            roles,
            registered_at: normalize_timestamp(&user.registered_at),
        });
    }
    normalized.sort_by_key(|user| user.id);
    Ok(normalized)
}

fn normalize_configuration(
    values: BTreeMap<String, Value>,
) -> Result<Vec<SnapshotConfiguration>, AppError> {
    let mut configuration = Vec::new();
    for key in SNAPSHOT_CONFIG_ALLOWLIST {
        let Some(value) = values.get(key) else {
            continue;
        };
        configuration.push(SnapshotConfiguration {
            key: key.to_owned(),
            value: normalize_config_value(key, value)?,
        });
    }
    Ok(configuration)
}

fn normalize_config_value(key: &str, value: &Value) -> Result<SnapshotValue, AppError> {
    if BOOLEAN_CONFIG_KEYS.contains(&key) {
        return normalize_boolean(value)
            .map(SnapshotValue::Boolean)
            .ok_or_else(|| {
                snapshot_build_error(format!(
                    "De veilige configuratiewaarde {key} is geen boolean."
                ))
            });
    }
    match value {
        Value::Null => Ok(SnapshotValue::Null),
        Value::Bool(value) => Ok(SnapshotValue::Boolean(*value)),
        Value::Number(value) => Ok(SnapshotValue::Number(value.clone())),
        Value::String(value) => Ok(SnapshotValue::String(bounded_text(
            value,
            "configuratiewaarde",
            2_000,
        )?)),
        Value::Array(_) | Value::Object(_) => Err(snapshot_build_error(format!(
            "De veilige configuratiewaarde {key} heeft een niet-ondersteund type."
        ))),
    }
}

fn normalize_boolean(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(value) => Some(*value),
        Value::Number(value) => match value.as_i64() {
            Some(1) => Some(true),
            Some(0) => Some(false),
            _ => None,
        },
        Value::String(value) => match value.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" | "on" => Some(true),
            "false" | "0" | "no" | "off" | "" => Some(false),
            _ => None,
        },
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

fn normalize_cron(events: Vec<SnapshotCronInput>) -> Result<Vec<SnapshotCronEvent>, AppError> {
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::with_capacity(events.len());
    for event in events {
        let hook = bounded_text(&event.hook, "cronhook", 250)?;
        let schedule = normalize_optional_text(event.schedule, "cronschema", 250)?;
        let recurrence = normalize_optional_text(event.recurrence, "cronherhaling", 250)?;
        let args_fingerprint = event.args.as_ref().map(json_fingerprint).transpose()?;
        let identity = cron_identity(&hook, args_fingerprint.as_deref());
        ensure_unique(&mut seen, &identity, "cronjob")?;
        normalized.push(SnapshotCronEvent {
            identity,
            hook,
            schedule,
            recurrence,
            args_fingerprint,
            next_run_at: event.next_run_at.as_deref().and_then(normalize_timestamp),
        });
    }
    normalized.sort_by(|left, right| left.identity.cmp(&right.identity));
    Ok(normalized)
}

fn normalize_files(files: Vec<SnapshotFileState>) -> Result<Vec<SnapshotFileState>, AppError> {
    if files.len() > MAX_SNAPSHOT_FILES {
        return Err(snapshot_build_error(
            "De relevante bestandsmetadata overschrijdt de veilige snapshotlimiet.",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::with_capacity(files.len());
    for mut file in files {
        file.relative_path = normalize_relative_path(&file.relative_path)?;
        ensure_unique(&mut seen, &file.relative_path, "bestand")?;
        file.category = bounded_text(&file.category, "bestandscategorie", 100)?;
        file.file_type = bounded_text(&file.file_type, "bestandstype", 100)?;
        file.modified_at = file.modified_at.as_deref().and_then(normalize_timestamp);
        file.sha256 = normalize_sha256(file.sha256)?;
        normalized.push(file);
    }
    normalized.sort_by(|left, right| left.relative_path.cmp(&right.relative_path));
    Ok(normalized)
}

fn normalize_sha256(value: Option<String>) -> Result<Option<String>, AppError> {
    let Some(value) = value else {
        return Ok(None);
    };
    let value = value.trim().to_ascii_lowercase();
    if value.len() != 64 || !value.chars().all(|character| character.is_ascii_hexdigit()) {
        return Err(snapshot_build_error(
            "De SHA-256-fingerprint in de momentopname is ongeldig.",
        ));
    }
    Ok(Some(value))
}

fn normalize_slug(value: &str) -> Result<String, AppError> {
    let slug = value.trim().to_ascii_lowercase();
    crate::validation::validate_slug(&slug)?;
    Ok(slug)
}

fn normalize_status(value: &str) -> String {
    value.trim().to_ascii_lowercase()
}

fn bounded_text(value: &str, field: &str, maximum: usize) -> Result<String, AppError> {
    let value = value.trim();
    if value.is_empty() || value.chars().count() > maximum || value.chars().any(char::is_control) {
        return Err(snapshot_build_error(format!(
            "De waarde voor {field} is ongeldig."
        )));
    }
    Ok(value.to_owned())
}

fn normalize_optional_text(
    value: Option<String>,
    field: &str,
    maximum: usize,
) -> Result<Option<String>, AppError> {
    value
        .filter(|value| !value.trim().is_empty())
        .map(|value| bounded_text(&value, field, maximum))
        .transpose()
}

fn ensure_unique<T: Ord + Clone + std::fmt::Display>(
    seen: &mut BTreeSet<T>,
    identity: &T,
    entity: &str,
) -> Result<(), AppError> {
    if !seen.insert(identity.clone()) {
        return Err(snapshot_build_error(format!(
            "De momentopname bevat een dubbele {entity}-identiteit: {identity}."
        )));
    }
    Ok(())
}

fn normalize_timestamp(value: &str) -> Option<String> {
    DateTime::parse_from_rfc3339(value)
        .map(|timestamp| {
            timestamp
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Secs, true)
        })
        .ok()
        .or_else(|| {
            NaiveDateTime::parse_from_str(value.trim(), "%Y-%m-%d %H:%M:%S")
                .ok()
                .map(|timestamp| {
                    timestamp
                        .and_utc()
                        .to_rfc3339_opts(SecondsFormat::Secs, true)
                })
        })
}

fn root_identity(site_id: &str, wordpress_path: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(site_id.as_bytes());
    hasher.update([0]);
    hasher.update(wordpress_path.as_bytes());
    format!("sha256:{}", hex_digest(&hasher.finalize()))
}

fn json_fingerprint(value: &Value) -> Result<String, AppError> {
    let bytes = serde_json::to_vec(value).map_err(AppError::storage)?;
    Ok(format!("sha256:{}", hex_digest(&Sha256::digest(bytes))))
}

fn cron_identity(hook: &str, args_fingerprint: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    hasher.update(hook.as_bytes());
    hasher.update([0]);
    if let Some(fingerprint) = args_fingerprint {
        hasher.update(fingerprint.as_bytes());
    }
    format!("cron:{}", hex_digest(&hasher.finalize()))
}

fn hex_digest(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn snapshot_build_error(message: impl Into<String>) -> AppError {
    AppError {
        error_id: None,
        category: "snapshot_build".into(),
        user_message: message.into(),
        technical_details: None,
        retryable: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn software(kind: &str, slug: &str, status: &str) -> InstalledSoftware {
        InstalledSoftware {
            software_type: kind.into(),
            slug: slug.into(),
            name: slug.replace('-', " "),
            version: "1.2.3".into(),
            status: status.into(),
            update_version: None,
            observed_at: "2026-09-15T08:00:00Z".into(),
        }
    }

    fn input() -> SnapshotBuildInput {
        SnapshotBuildInput {
            site_id: "site-1".into(),
            scan_run_id: Some("scan-1".into()),
            maintenance_run_id: None,
            source: SnapshotSource::Baseline,
            previous_snapshot_id: None,
            wordpress_path: "/var/www/public_html".into(),
            scan_timestamp: "2026-09-15T10:00:00+02:00".into(),
            core: SnapshotBuildSection::Complete(SnapshotCore {
                version: " 6.8.2 ".into(),
                locale: Some("nl_NL".into()),
                multisite: Some(false),
                php_version: Some("8.3.1".into()),
            }),
            plugins: SnapshotBuildSection::Complete(vec![
                software("plugin", "Z-Plugin", "INACTIVE"),
                software("plugin", "a-plugin", "ACTIVE"),
            ]),
            themes: SnapshotBuildSection::Complete(vec![software("theme", "Theme-A", "ACTIVE")]),
            users: SnapshotBuildSection::Complete(vec![WordPressUser {
                id: 42,
                username: "editor".into(),
                display_name: "Site Editor".into(),
                email: "editor@example.test".into(),
                roles: vec!["shop_manager".into(), "editor".into(), "editor".into()],
                registered_at: "2020-01-02 03:04:05".into(),
            }]),
            configuration: SnapshotBuildSection::Complete(BTreeMap::new()),
            cron: SnapshotBuildSection::Complete(Vec::new()),
            files: SnapshotBuildSection::Complete(Vec::new()),
        }
    }

    #[test]
    fn normalizes_entity_order_roles_paths_and_timestamps() {
        let mut input = input();
        input.files = SnapshotBuildSection::Complete(vec![SnapshotFileState {
            relative_path: "./wp-content\\uploads/test.php".into(),
            category: "uploads".into(),
            file_type: "regular".into(),
            size_bytes: Some(12),
            modified_at: Some("2026-09-15T10:00:00+02:00".into()),
            sha256: Some("A".repeat(64)),
        }]);
        let snapshot = SnapshotBuilder::build(input).unwrap();
        assert_eq!(snapshot.metadata.scan_timestamp, "2026-09-15T08:00:00Z");
        assert_eq!(snapshot.plugins[0].slug, "a-plugin");
        assert_eq!(snapshot.users[0].roles, ["editor", "shop_manager"]);
        assert_eq!(
            snapshot.files[0].relative_path,
            "wp-content/uploads/test.php"
        );
        assert_eq!(snapshot.files[0].sha256, Some("a".repeat(64)));
        assert!(
            snapshot
                .metadata
                .wordpress_root_identity
                .unwrap()
                .starts_with("sha256:")
        );
    }

    #[test]
    fn stores_only_allowlisted_typed_configuration() {
        let mut input = input();
        input.configuration = SnapshotBuildSection::Complete(BTreeMap::from([
            ("WP_DEBUG".into(), Value::String("false".into())),
            ("DISALLOW_FILE_EDIT".into(), Value::Bool(true)),
            (
                "site_url".into(),
                Value::String("https://example.test".into()),
            ),
            (
                "DB_PASSWORD".into(),
                Value::String("never-store-this".into()),
            ),
            (
                "AUTH_KEY".into(),
                Value::String("never-store-this-either".into()),
            ),
        ]));
        let snapshot = SnapshotBuilder::build(input).unwrap();
        let serialized = serde_json::to_string(&snapshot).unwrap();
        assert!(!serialized.contains("DB_PASSWORD"));
        assert!(!serialized.contains("AUTH_KEY"));
        assert!(!serialized.contains("never-store"));
        assert_eq!(snapshot.configuration.len(), 3);
        assert_eq!(
            snapshot
                .configuration
                .iter()
                .find(|item| item.key == "WP_DEBUG")
                .map(|item| &item.value),
            Some(&SnapshotValue::Boolean(false))
        );
    }

    #[test]
    fn partial_sections_are_explicit_and_contain_no_phantom_entities() {
        let mut input = input();
        input.users = SnapshotBuildSection::Failed;
        input.cron = SnapshotBuildSection::NotCollected;
        let snapshot = SnapshotBuilder::build(input).unwrap();
        assert!(snapshot.users.is_empty());
        assert!(snapshot.cron.is_empty());
        assert_eq!(snapshot.completeness.users, SnapshotSectionStatus::Failed);
        assert_eq!(
            snapshot.completeness.cron,
            SnapshotSectionStatus::NotCollected
        );
        assert_eq!(
            snapshot.metadata.status,
            crate::snapshots::SnapshotStatus::Partial
        );
    }

    #[test]
    fn cron_arguments_are_fingerprinted_but_never_stored() {
        let mut input = input();
        input.cron = SnapshotBuildSection::Complete(vec![SnapshotCronInput {
            hook: "send_private_report".into(),
            schedule: Some("hourly".into()),
            recurrence: Some("3600".into()),
            args: Some(serde_json::json!({"recipient": "secret@example.test"})),
            next_run_at: Some("2026-09-15T08:30:00Z".into()),
        }]);
        let snapshot = SnapshotBuilder::build(input).unwrap();
        let serialized = serde_json::to_string(&snapshot).unwrap();
        assert!(!serialized.contains("secret@example.test"));
        assert!(snapshot.cron[0].identity.starts_with("cron:"));
        assert!(
            snapshot.cron[0]
                .args_fingerprint
                .as_deref()
                .is_some_and(|value| value.starts_with("sha256:"))
        );
    }

    #[test]
    fn duplicate_stable_identity_is_rejected() {
        let mut input = input();
        input.plugins = SnapshotBuildSection::Complete(vec![
            software("plugin", "WooCommerce", "active"),
            software("plugin", "woocommerce", "inactive"),
        ]);
        let error = SnapshotBuilder::build(input).unwrap_err();
        assert_eq!(error.category, "snapshot_build");
        assert!(error.user_message.contains("dubbele plugin-identiteit"));
    }
}
