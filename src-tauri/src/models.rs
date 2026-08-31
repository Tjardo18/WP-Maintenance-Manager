use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub password_hash: String,
    pub idle_timeout_minutes: u16,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthStatus {
    pub configured: bool,
    pub authenticated: bool,
    pub idle_timeout_minutes: u16,
    pub retry_after_seconds: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResult {
    pub session_token: String,
    pub idle_timeout_minutes: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PasswordChangeInput {
    pub current_password: String,
    pub new_password: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditEvent {
    pub id: String,
    pub site_id: Option<String>,
    pub action_type: String,
    pub target: String,
    pub status: String,
    pub details: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AuthMethod {
    KeyFile,
    Password,
}
impl AuthMethod {
    pub fn as_db(self) -> &'static str {
        match self {
            Self::KeyFile => "key_file",
            Self::Password => "password",
        }
    }
    pub fn from_db(value: &str) -> Self {
        if value == "password" {
            Self::Password
        } else {
            Self::KeyFile
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SiteStatus {
    Healthy,
    Updates,
    Attention,
    Problem,
    Unreachable,
    Unscanned,
}
impl SiteStatus {
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Healthy => "healthy",
            Self::Updates => "updates",
            Self::Attention => "attention",
            Self::Problem => "problem",
            Self::Unreachable => "unreachable",
            Self::Unscanned => "unscanned",
        }
    }
    pub fn from_db(value: &str) -> Self {
        match value {
            "healthy" => Self::Healthy,
            "updates" => Self::Updates,
            "attention" => Self::Attention,
            "problem" => Self::Problem,
            "unreachable" => Self::Unreachable,
            _ => Self::Unscanned,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Site {
    pub id: String,
    pub name: String,
    pub url: String,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub ssh_username: String,
    pub auth_method: AuthMethod,
    pub key_path: Option<String>,
    pub wordpress_path: String,
    pub pinned_host_key: Option<String>,
    pub status: SiteStatus,
    pub wordpress_version: Option<String>,
    pub php_version: Option<String>,
    pub update_count: u32,
    pub security_status: Option<String>,
    pub last_scan_at: Option<String>,
    pub last_maintenance_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SiteInput {
    pub id: Option<String>,
    pub name: String,
    pub url: String,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub ssh_username: String,
    pub auth_method: AuthMethod,
    pub key_path: Option<String>,
    pub wordpress_path: String,
    pub credential_secret: Option<String>,
}

#[derive(Debug, Clone)]
pub struct StoredSite {
    pub site: Site,
    pub credential_ref: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum StepStatus {
    Pending,
    Running,
    Success,
    Warning,
    Failed,
    Skipped,
}

impl StepStatus {
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Running => "running",
            Self::Success => "success",
            Self::Warning => "warning",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }

    pub fn from_db(value: &str) -> Self {
        match value {
            "running" => Self::Running,
            "success" => Self::Success,
            "warning" => Self::Warning,
            "failed" => Self::Failed,
            "skipped" => Self::Skipped,
            _ => Self::Pending,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionStep {
    pub key: String,
    pub label: String,
    pub status: StepStatus,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConnectionTestResult {
    pub success: bool,
    pub steps: Vec<ConnectionStep>,
    pub fingerprint: Option<String>,
    pub requires_host_key_acceptance: bool,
    pub wordpress_version: Option<String>,
    pub php_version: Option<String>,
    pub wp_cli_version: Option<String>,
    pub detected_url: Option<String>,
    pub error: Option<crate::error::AppError>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum FindingSeverity {
    Info,
    Attention,
    Problem,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumStatus {
    Modified,
    Missing,
    Unexpected,
    ScanError,
}

impl ChecksumStatus {
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Modified => "modified",
            Self::Missing => "missing",
            Self::Unexpected => "unexpected",
            Self::ScanError => "scan_error",
        }
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "modified" => Some(Self::Modified),
            "missing" => Some(Self::Missing),
            "unexpected" => Some(Self::Unexpected),
            "scan_error" => Some(Self::ScanError),
            _ => None,
        }
    }
}

impl FindingSeverity {
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Attention => "attention",
            Self::Problem => "problem",
        }
    }

    pub fn from_db(value: &str) -> Self {
        match value {
            "attention" => Self::Attention,
            "problem" => Self::Problem,
            _ => Self::Info,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub category: String,
    pub severity: FindingSeverity,
    pub title: String,
    pub detail: String,
    pub path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub checksum_status: Option<ChecksumStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_at: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChecksumFindingRecord {
    pub site_id: String,
    pub scan_run_id: String,
    pub finding: Finding,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FilePreview {
    pub finding: Finding,
    pub file_name: String,
    pub relative_path: String,
    pub size_bytes: u64,
    pub modified_at: Option<String>,
    pub file_type: String,
    pub extension: Option<String>,
    pub text_content: Option<String>,
    pub binary: bool,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumDeleteFailure {
    pub finding_id: String,
    pub path: Option<String>,
    pub error: crate::error::AppError,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ChecksumDeleteResult {
    pub requested: usize,
    pub deleted: usize,
    pub deleted_paths: Vec<String>,
    pub failures: Vec<ChecksumDeleteFailure>,
    pub scan: Option<ScanResult>,
    pub rescan_error: Option<crate::error::AppError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WordPressUser {
    pub id: u64,
    pub username: String,
    pub display_name: String,
    pub email: String,
    pub roles: Vec<String>,
    pub registered_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WordPressRole {
    pub role: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WordPressUsersData {
    pub users: Vec<WordPressUser>,
    pub roles: Vec<WordPressRole>,
    pub multisite: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WordPressUserUpdateInput {
    pub user_id: u64,
    pub display_name: String,
    pub email: String,
    pub role: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WordPressUserDeleteInput {
    pub user_id: u64,
    pub reassign_to: Option<u64>,
    pub delete_content: bool,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoreOperationKind {
    Repair,
    Update,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreOperationInfo {
    pub current_version: String,
    pub locale: String,
    pub wordpress_path: String,
    pub available_version: Option<String>,
    pub disk_available_mb: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct CoreOperationResult {
    pub run: MaintenanceRun,
    pub scan: Option<ScanResult>,
    pub updates_after: Vec<UpdateItem>,
    pub current_version: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanCheck {
    pub key: String,
    pub label: String,
    pub status: StepStatus,
    pub summary: String,
    pub findings: Vec<Finding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanResult {
    pub id: String,
    pub site_id: String,
    pub started_at: String,
    pub finished_at: String,
    pub status: SiteStatus,
    pub checks: Vec<ScanCheck>,
    pub truncated: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum UpdateKind {
    Core,
    Plugin,
    Theme,
    Language,
}

impl UpdateKind {
    pub fn as_db(&self) -> &'static str {
        match self {
            Self::Core => "core",
            Self::Plugin => "plugin",
            Self::Theme => "theme",
            Self::Language => "language",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct UpdateItem {
    pub kind: UpdateKind,
    pub slug: String,
    pub name: String,
    pub current_version: String,
    pub new_version: String,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaintenanceStep {
    pub key: String,
    pub label: String,
    pub status: StepStatus,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MaintenanceRun {
    pub id: String,
    pub site_id: String,
    pub site_name: Option<String>,
    pub started_at: String,
    pub finished_at: Option<String>,
    pub status: StepStatus,
    pub duration_ms: Option<u64>,
    pub backup_path: Option<String>,
    pub steps: Vec<MaintenanceStep>,
    pub before_versions: Option<String>,
    pub after_versions: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkScanFailure {
    pub site_id: String,
    pub site_name: String,
    pub error: crate::error::AppError,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkScanResult {
    pub total: usize,
    pub completed: usize,
    pub cancelled: bool,
    pub failures: Vec<BulkScanFailure>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkScanProgress {
    pub total: usize,
    pub completed: usize,
    pub active_sites: Vec<String>,
    pub failed_sites: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    pub scan_concurrency: usize,
}
