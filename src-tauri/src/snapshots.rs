use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;
pub const MAX_SNAPSHOTS_PER_SITE: usize = 100;

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSource {
    Scan,
    Baseline,
    PreMaintenance,
    PostMaintenance,
    Manual,
}

impl SnapshotSource {
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Baseline => "baseline",
            Self::PreMaintenance => "pre_maintenance",
            Self::PostMaintenance => "post_maintenance",
            Self::Manual => "manual",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotStatus {
    Complete,
    Partial,
}

impl SnapshotStatus {
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Complete => "complete",
            Self::Partial => "partial",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSection {
    Core,
    Plugins,
    Themes,
    Users,
    Configuration,
    Cron,
    Files,
}

impl SnapshotSection {
    pub const ALL: [Self; 7] = [
        Self::Core,
        Self::Plugins,
        Self::Themes,
        Self::Users,
        Self::Configuration,
        Self::Cron,
        Self::Files,
    ];

    pub fn as_db(self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Plugins => "plugins",
            Self::Themes => "themes",
            Self::Users => "users",
            Self::Configuration => "configuration",
            Self::Cron => "cron",
            Self::Files => "files",
        }
    }

    pub fn entity_key(self, identity: impl std::fmt::Display) -> String {
        let prefix = match self {
            Self::Core => "core",
            Self::Plugins => "plugin",
            Self::Themes => "theme",
            Self::Users => "user",
            Self::Configuration => "config",
            Self::Cron => "cron",
            Self::Files => "file",
        };
        format!("{prefix}:{identity}")
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotSectionStatus {
    Complete,
    Failed,
    NotCollected,
}

impl SnapshotSectionStatus {
    pub fn is_reliable(self) -> bool {
        self == Self::Complete
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotCompleteness {
    pub core: SnapshotSectionStatus,
    pub plugins: SnapshotSectionStatus,
    pub themes: SnapshotSectionStatus,
    pub users: SnapshotSectionStatus,
    pub configuration: SnapshotSectionStatus,
    pub cron: SnapshotSectionStatus,
    pub files: SnapshotSectionStatus,
}

impl SnapshotCompleteness {
    pub fn status_for(&self, section: SnapshotSection) -> SnapshotSectionStatus {
        match section {
            SnapshotSection::Core => self.core,
            SnapshotSection::Plugins => self.plugins,
            SnapshotSection::Themes => self.themes,
            SnapshotSection::Users => self.users,
            SnapshotSection::Configuration => self.configuration,
            SnapshotSection::Cron => self.cron,
            SnapshotSection::Files => self.files,
        }
    }

    pub fn overall_status(&self) -> SnapshotStatus {
        if SnapshotSection::ALL
            .into_iter()
            .all(|section| self.status_for(section).is_reliable())
        {
            SnapshotStatus::Complete
        } else {
            SnapshotStatus::Partial
        }
    }

    pub fn baseline_eligible(&self) -> bool {
        [
            SnapshotSection::Core,
            SnapshotSection::Plugins,
            SnapshotSection::Themes,
            SnapshotSection::Users,
            SnapshotSection::Configuration,
        ]
        .into_iter()
        .all(|section| self.status_for(section).is_reliable())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotMetadata {
    pub snapshot_id: String,
    pub site_id: String,
    pub created_at: String,
    pub scan_run_id: Option<String>,
    pub maintenance_run_id: Option<String>,
    pub source: SnapshotSource,
    pub schema_version: u32,
    pub status: SnapshotStatus,
    pub wordpress_root_identity: Option<String>,
    pub scan_timestamp: String,
    pub app_version: Option<String>,
    pub is_baseline: bool,
    pub previous_snapshot_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotCore {
    pub version: String,
    pub locale: Option<String>,
    pub multisite: Option<bool>,
    pub php_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotPlugin {
    pub slug: String,
    pub name: String,
    pub version: String,
    pub status: String,
    pub auto_update: Option<bool>,
    pub update_available: bool,
    pub available_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotTheme {
    pub slug: String,
    pub name: String,
    pub version: String,
    pub status: String,
    pub active: bool,
    pub auto_update: Option<bool>,
    pub update_available: bool,
    pub available_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotUser {
    pub id: u64,
    pub login: String,
    pub display_name: Option<String>,
    pub email: String,
    pub roles: Vec<String>,
    pub registered_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum SnapshotValue {
    String(String),
    Boolean(bool),
    Number(serde_json::Number),
    Null,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotConfiguration {
    pub key: String,
    pub value: SnapshotValue,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotCronEvent {
    pub identity: String,
    pub hook: String,
    pub schedule: Option<String>,
    pub recurrence: Option<String>,
    pub args_fingerprint: Option<String>,
    pub next_run_at: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotFileState {
    pub relative_path: String,
    pub category: String,
    pub file_type: String,
    pub size_bytes: Option<u64>,
    pub modified_at: Option<String>,
    pub sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SiteSnapshot {
    pub metadata: SnapshotMetadata,
    pub completeness: SnapshotCompleteness,
    pub core: Option<SnapshotCore>,
    pub plugins: Vec<SnapshotPlugin>,
    pub themes: Vec<SnapshotTheme>,
    pub users: Vec<SnapshotUser>,
    pub configuration: Vec<SnapshotConfiguration>,
    pub cron: Vec<SnapshotCronEvent>,
    pub files: Vec<SnapshotFileState>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotChangeType {
    Added,
    Removed,
    Updated,
    Enabled,
    Disabled,
    Activated,
    Deactivated,
    RoleChanged,
    VersionChanged,
    ConfigurationChanged,
    Scheduled,
    Unscheduled,
    Unknown,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotChangeSeverity {
    Info,
    Attention,
    Warning,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotChangeOrigin {
    Scan,
    Maintenance,
    Manual,
    Unknown,
}

impl SnapshotChangeOrigin {
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Scan => "scan",
            Self::Maintenance => "maintenance",
            Self::Manual => "manual",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotChange {
    pub id: String,
    pub site_id: String,
    pub from_snapshot_id: String,
    pub to_snapshot_id: String,
    pub category: SnapshotSection,
    pub entity_type: String,
    pub entity_key: String,
    pub change_type: SnapshotChangeType,
    pub field: Option<String>,
    pub old_value: Option<SnapshotValue>,
    pub new_value: Option<SnapshotValue>,
    pub severity: SnapshotChangeSeverity,
    pub summary: String,
    pub metadata: BTreeMap<String, SnapshotValue>,
    pub origin: SnapshotChangeOrigin,
    pub seen: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SnapshotComparisonStatus {
    Compared,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotDiffSection {
    pub category: SnapshotSection,
    pub status: SnapshotComparisonStatus,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotDiff {
    pub id: String,
    pub site_id: String,
    pub from_snapshot_id: String,
    pub to_snapshot_id: String,
    pub created_at: String,
    pub schema_version: u32,
    pub origin: SnapshotChangeOrigin,
    pub maintenance_run_id: Option<String>,
    pub sections: Vec<SnapshotDiffSection>,
    pub changes: Vec<SnapshotChange>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn completeness_requires_every_section_to_be_reliable() {
        let mut completeness = SnapshotCompleteness {
            core: SnapshotSectionStatus::Complete,
            plugins: SnapshotSectionStatus::Complete,
            themes: SnapshotSectionStatus::Complete,
            users: SnapshotSectionStatus::Complete,
            configuration: SnapshotSectionStatus::Complete,
            cron: SnapshotSectionStatus::Complete,
            files: SnapshotSectionStatus::Complete,
        };
        assert_eq!(completeness.overall_status(), SnapshotStatus::Complete);
        completeness.cron = SnapshotSectionStatus::Failed;
        assert_eq!(completeness.overall_status(), SnapshotStatus::Partial);
        assert!(completeness.baseline_eligible());
        assert!(!completeness.status_for(SnapshotSection::Cron).is_reliable());
        completeness.users = SnapshotSectionStatus::Failed;
        assert!(!completeness.baseline_eligible());
    }

    #[test]
    fn snapshot_schema_is_typed_and_versioned() {
        let metadata = SnapshotMetadata {
            snapshot_id: "snapshot-1".into(),
            site_id: "site-1".into(),
            created_at: "2026-09-15T08:00:00Z".into(),
            scan_run_id: Some("scan-1".into()),
            maintenance_run_id: None,
            source: SnapshotSource::Baseline,
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            status: SnapshotStatus::Partial,
            wordpress_root_identity: Some("sha256:root-identity".into()),
            scan_timestamp: "2026-09-15T08:00:00Z".into(),
            app_version: Some("0.11.0-beta.1".into()),
            is_baseline: true,
            previous_snapshot_id: None,
        };
        let serialized = serde_json::to_value(metadata).unwrap();
        assert_eq!(serialized["schemaVersion"], SNAPSHOT_SCHEMA_VERSION);
        assert_eq!(serialized["source"], "baseline");
        assert_eq!(serialized["status"], "partial");
        assert_eq!(
            serde_json::to_value(SnapshotValue::Boolean(true)).unwrap(),
            serde_json::json!({"type": "boolean", "value": true})
        );
    }

    #[test]
    fn change_types_remain_specific_and_stably_serialized() {
        assert_eq!(
            serde_json::to_string(&SnapshotChangeType::RoleChanged).unwrap(),
            "\"role_changed\""
        );
        assert_eq!(
            serde_json::to_string(&SnapshotChangeType::VersionChanged).unwrap(),
            "\"version_changed\""
        );
        assert_eq!(SnapshotSection::Plugins.as_db(), "plugins");
        assert_eq!(SnapshotSource::PreMaintenance.as_db(), "pre_maintenance");
        assert_eq!(
            SnapshotSection::Plugins.entity_key("woocommerce"),
            "plugin:woocommerce"
        );
        assert_eq!(SnapshotSection::Users.entity_key(42), "user:42");
    }
}
