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
#[serde(rename_all = "snake_case")]
pub enum ErrorSeverity {
    Warning,
    Error,
    Critical,
}

impl ErrorSeverity {
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Warning => "warning",
            Self::Error => "error",
            Self::Critical => "critical",
        }
    }

    pub fn from_db(value: &str) -> Self {
        match value {
            "warning" => Self::Warning,
            "critical" => Self::Critical,
            _ => Self::Error,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCategory {
    Network,
    Dns,
    ConnectionTimeout,
    SshAuthentication,
    SshHostKey,
    SshChannel,
    SshCommand,
    WpCli,
    Database,
    Http,
    Filesystem,
    Backup,
    Update,
    Parse,
    Authentication,
    Application,
    WordfenceApi,
    VulnerabilityFeed,
    VulnerabilityParse,
    VulnerabilityMatch,
    SnapshotBuild,
    SnapshotPersist,
    SnapshotDiff,
    SnapshotSchema,
    Unknown,
}

impl ErrorCategory {
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Network => "network",
            Self::Dns => "dns",
            Self::ConnectionTimeout => "connection_timeout",
            Self::SshAuthentication => "ssh_authentication",
            Self::SshHostKey => "ssh_host_key",
            Self::SshChannel => "ssh_channel",
            Self::SshCommand => "ssh_command",
            Self::WpCli => "wp_cli",
            Self::Database => "database",
            Self::Http => "http",
            Self::Filesystem => "filesystem",
            Self::Backup => "backup",
            Self::Update => "update",
            Self::Parse => "parse",
            Self::Authentication => "authentication",
            Self::Application => "application",
            Self::WordfenceApi => "wordfence_api",
            Self::VulnerabilityFeed => "vulnerability_feed",
            Self::VulnerabilityParse => "vulnerability_parse",
            Self::VulnerabilityMatch => "vulnerability_match",
            Self::SnapshotBuild => "snapshot_build",
            Self::SnapshotPersist => "snapshot_persist",
            Self::SnapshotDiff => "snapshot_diff",
            Self::SnapshotSchema => "snapshot_schema",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_db(value: &str) -> Self {
        match value {
            "network" => Self::Network,
            "dns" => Self::Dns,
            "connection_timeout" => Self::ConnectionTimeout,
            "ssh_authentication" => Self::SshAuthentication,
            "ssh_host_key" => Self::SshHostKey,
            "ssh_channel" => Self::SshChannel,
            "ssh_command" => Self::SshCommand,
            "wp_cli" => Self::WpCli,
            "database" => Self::Database,
            "http" => Self::Http,
            "filesystem" => Self::Filesystem,
            "backup" => Self::Backup,
            "update" => Self::Update,
            "parse" => Self::Parse,
            "authentication" => Self::Authentication,
            "application" => Self::Application,
            "wordfence_api" => Self::WordfenceApi,
            "vulnerability_feed" => Self::VulnerabilityFeed,
            "vulnerability_parse" => Self::VulnerabilityParse,
            "vulnerability_match" => Self::VulnerabilityMatch,
            "snapshot_build" => Self::SnapshotBuild,
            "snapshot_persist" => Self::SnapshotPersist,
            "snapshot_diff" => Self::SnapshotDiff,
            "snapshot_schema" => Self::SnapshotSchema,
            _ => Self::Unknown,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ErrorLogRecord {
    pub id: String,
    pub created_at: String,
    pub severity: ErrorSeverity,
    pub category: ErrorCategory,
    pub site_id: Option<String>,
    pub site_name: Option<String>,
    pub action: String,
    pub summary: String,
    pub technical_details: Option<String>,
    pub exit_code: Option<i32>,
    pub cause_chain: Vec<String>,
    pub duration_ms: Option<u64>,
    pub retryable: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorLogFilter {
    pub site_id: Option<String>,
    pub category: Option<ErrorCategory>,
    pub severity: Option<ErrorSeverity>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub query: Option<String>,
    pub limit: Option<u32>,
    pub offset: Option<u32>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ErrorLogPage {
    pub records: Vec<ErrorLogRecord>,
    pub total: u64,
    pub limit: u32,
    pub offset: u32,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum SiteRelationType {
    Subdomain,
    Subdirectory,
}

impl SiteRelationType {
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Subdomain => "subdomain",
            Self::Subdirectory => "subdirectory",
        }
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "subdomain" => Some(Self::Subdomain),
            "subdirectory" => Some(Self::Subdirectory),
            _ => None,
        }
    }
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
    pub parent_site_id: Option<String>,
    pub relation_type: Option<SiteRelationType>,
    pub parent_directory: Option<String>,
    pub pinned_host_key: Option<String>,
    pub status: SiteStatus,
    pub wordpress_version: Option<String>,
    pub php_version: Option<String>,
    pub wp_cli_version: Option<String>,
    pub wp_cli_version_checked_at: Option<String>,
    pub update_count: u32,
    pub security_status: Option<String>,
    pub last_scan_at: Option<String>,
    pub last_maintenance_at: Option<String>,
    pub created_at: String,
    pub updated_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerability_summary: Option<SiteVulnerabilitySummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SiteVulnerabilitySummary {
    pub critical_count: i64,
    pub high_count: i64,
    pub medium_count: i64,
    pub low_count: i64,
    pub info_count: i64,
    pub unknown_count: i64,
    pub last_checked_at: String,
    pub feed_updated_at: Option<String>,
    pub inventory_observed_at: Option<String>,
    pub inventory_stale: bool,
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
    pub pinned_host_key: Option<String>,
    pub parent_site_id: Option<String>,
    pub relation_type: Option<SiteRelationType>,
    pub parent_directory: Option<String>,
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
    pub unexpected_directories: Vec<String>,
    pub unexpected_directories_truncated: bool,
    pub error: Option<crate::error::AppError>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum FindingSeverity {
    Info,
    Attention,
    Warning,
    Critical,
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
            Self::Warning => "warning",
            Self::Critical => "critical",
            Self::Problem => "problem",
        }
    }

    pub fn from_db(value: &str) -> Self {
        match value {
            "attention" => Self::Attention,
            "warning" => Self::Warning,
            "critical" => Self::Critical,
            "problem" => Self::Problem,
            _ => Self::Info,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FindingDisposition {
    #[default]
    Active,
    Ignored,
    Trusted,
    ExpiredException,
    TrustedChanged,
    TrustedMissing,
}

impl FindingDisposition {
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Ignored => "ignored",
            Self::Trusted => "trusted",
            Self::ExpiredException => "expired_exception",
            Self::TrustedChanged => "trusted_changed",
            Self::TrustedMissing => "trusted_missing",
        }
    }

    pub fn from_db(value: &str) -> Self {
        match value {
            "ignored" => Self::Ignored,
            "trusted" => Self::Trusted,
            "expired_exception" => Self::ExpiredException,
            "trusted_changed" => Self::TrustedChanged,
            "trusted_missing" => Self::TrustedMissing,
            _ => Self::Active,
        }
    }

    pub fn counts_as_active(self) -> bool {
        matches!(
            self,
            Self::Active | Self::ExpiredException | Self::TrustedChanged
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    #[serde(default)]
    pub disposition: FindingDisposition,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exception_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trusted_file_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy_target: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vulnerability: Option<VulnerabilityMatch>,
}

#[derive(Debug, Clone)]
pub struct FindingContext {
    pub site_id: String,
    pub scan_run_id: String,
    pub check_type: String,
    pub finding: Finding,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionScope {
    Site,
}

impl ExceptionScope {
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Site => "site",
        }
    }

    pub fn from_db(_value: &str) -> Self {
        Self::Site
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct FindingException {
    pub id: String,
    pub site_id: String,
    pub site_name: String,
    pub check_type: String,
    pub finding_type: String,
    pub target: String,
    pub scope: ExceptionScope,
    pub reason: String,
    pub note: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
    pub active: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FindingExceptionInput {
    pub site_id: String,
    pub finding_id: String,
    pub expires_at: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TrustedFileStatus {
    Trusted,
    Changed,
    Missing,
    Unchecked,
}

impl TrustedFileStatus {
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Trusted => "trusted",
            Self::Changed => "changed",
            Self::Missing => "missing",
            Self::Unchecked => "unchecked",
        }
    }

    pub fn from_db(value: &str) -> Self {
        match value {
            "trusted" => Self::Trusted,
            "changed" => Self::Changed,
            "missing" => Self::Missing,
            _ => Self::Unchecked,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct TrustedFile {
    pub id: String,
    pub site_id: String,
    pub site_name: String,
    pub relative_path: String,
    pub trusted_sha256: String,
    pub current_sha256: Option<String>,
    pub size_bytes: u64,
    pub current_size_bytes: Option<u64>,
    pub modified_at_snapshot: Option<String>,
    pub current_modified_at: Option<String>,
    pub file_type: String,
    pub status: TrustedFileStatus,
    pub trusted_at: String,
    pub last_checked_at: Option<String>,
    pub note: Option<String>,
    pub active: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TrustedFileInput {
    pub site_id: String,
    pub finding_id: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SecurityPolicyMutationResult {
    pub scan: Option<ScanResult>,
    pub finding_exception: Option<FindingException>,
    pub trusted_file: Option<TrustedFile>,
}

#[derive(Debug, Clone)]
pub struct ChecksumFindingRecord {
    pub site_id: String,
    pub scan_run_id: String,
    pub finding: Finding,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    pub image_mime_type: Option<String>,
    pub image_data_base64: Option<String>,
    pub raw_data_base64: Option<String>,
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
    pub disk_available_mb: Option<u64>,
    pub disk_space_warning: Option<String>,
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub technical_details: Option<String>,
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

    pub fn from_db(value: &str) -> Self {
        match value {
            "plugin" => Self::Plugin,
            "theme" => Self::Theme,
            "language" => Self::Language,
            _ => Self::Core,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct InstalledSoftware {
    pub software_type: String,
    pub slug: String,
    pub name: String,
    pub version: String,
    pub status: String,
    pub update_version: Option<String>,
    pub observed_at: String,
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

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ScanJobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Cancelled,
}

impl ScanJobStatus {
    pub fn is_active(self) -> bool {
        matches!(self, Self::Queued | Self::Running)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ScanJobStep {
    pub key: String,
    pub label: String,
    pub status: StepStatus,
    pub started_at: Option<String>,
    pub duration_ms: Option<u64>,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ScanJobState {
    pub id: String,
    pub job_type: String,
    pub site_id: String,
    pub site_name: String,
    pub status: ScanJobStatus,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub current_step: Option<String>,
    pub completed_steps: usize,
    pub total_steps: usize,
    pub cancellation_requested: bool,
    pub result_scan_id: Option<String>,
    pub error: Option<crate::error::AppError>,
    pub steps: Vec<ScanJobStep>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BulkScanStart {
    pub jobs: Vec<ScanJobState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppSettings {
    pub scan_concurrency: usize,
    pub file_preview_mode: FilePreviewMode,
    pub markdown_preview_mode: MarkdownPreviewMode,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum DatabaseCleanupTarget {
    Sites,
    ScanRuns,
    SiteSnapshots,
    MaintenanceRuns,
    ErrorLogs,
    AuditEvents,
}

impl DatabaseCleanupTarget {
    pub fn table_name(self) -> &'static str {
        match self {
            Self::Sites => "sites",
            Self::ScanRuns => "scan_runs",
            Self::SiteSnapshots => "site_snapshots",
            Self::MaintenanceRuns => "maintenance_runs",
            Self::ErrorLogs => "error_logs",
            Self::AuditEvents => "audit_events",
        }
    }

    pub fn requires_idle_scans(self) -> bool {
        matches!(self, Self::Sites | Self::ScanRuns | Self::SiteSnapshots)
    }

    pub fn typed_confirmation(self) -> bool {
        matches!(self, Self::Sites)
    }

    pub fn confirmation_phrase(self) -> &'static str {
        if self.typed_confirmation() {
            "VERWIJDEREN"
        } else {
            self.table_name()
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseCleanupImpact {
    pub key: String,
    pub label: String,
    pub count: u64,
    pub effect: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseCleanupOption {
    pub target: DatabaseCleanupTarget,
    pub table_name: String,
    pub title: String,
    pub description: String,
    pub stored_data: Vec<String>,
    pub dependencies: Vec<String>,
    pub cleanup_effect: String,
    pub record_count: u64,
    pub impacts: Vec<DatabaseCleanupImpact>,
    pub preview_token: String,
    pub confirmation_mode: String,
    pub confirmation_phrase: String,
    pub irreversible: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseCleanupRequest {
    pub target: DatabaseCleanupTarget,
    pub confirmation: String,
    pub preview_token: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct DatabaseCleanupResult {
    pub target: DatabaseCleanupTarget,
    pub table_name: String,
    pub status: String,
    pub impacts: Vec<DatabaseCleanupImpact>,
    pub warnings: Vec<String>,
    pub completed_at: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MarkdownPreviewMode {
    Raw,
    Preview,
}

impl MarkdownPreviewMode {
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Raw => "raw",
            Self::Preview => "preview",
        }
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "raw" => Some(Self::Raw),
            "preview" => Some(Self::Preview),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FilePreviewMode {
    Normal,
    Fullscreen,
}

impl FilePreviewMode {
    pub fn as_db(self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Fullscreen => "fullscreen",
        }
    }

    pub fn from_db(value: &str) -> Option<Self> {
        match value {
            "normal" => Some(Self::Normal),
            "fullscreen" => Some(Self::Fullscreen),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct WordfenceIntegrationStatus {
    pub configured: bool,
    pub connection_status: String,
    pub feed_status: String,
    pub last_successful_update_at: Option<String>,
    pub next_automatic_update_at: Option<String>,
    pub vulnerability_count: u64,
    pub software_record_count: u64,
    pub refresh_running: bool,
    pub refresh_phase: Option<String>,
    pub cooldown_remaining_seconds: u64,
    pub last_error: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VulnerabilityFeedState {
    pub active_dataset_id: Option<String>,
    pub last_attempt_at: Option<String>,
    pub last_successful_update_at: Option<String>,
    pub last_error: Option<String>,
    pub vulnerability_count: u64,
    pub software_record_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VulnerabilityImportSummary {
    pub dataset_id: String,
    pub vulnerability_count: u64,
    pub software_record_count: u64,
    pub parsed_at: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VulnerabilityRefreshStatus {
    Queued,
    Running,
    Completed,
    Failed,
}

impl VulnerabilityRefreshStatus {
    pub fn is_active(&self) -> bool {
        matches!(self, Self::Queued | Self::Running)
    }
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct VulnerabilityRefreshJobState {
    pub id: String,
    pub status: VulnerabilityRefreshStatus,
    pub phase: Option<String>,
    pub created_at: String,
    pub started_at: Option<String>,
    pub finished_at: Option<String>,
    pub downloaded_bytes: u64,
    pub vulnerability_count: u64,
    pub software_record_count: u64,
    pub automatic: bool,
    pub error: Option<crate::error::AppError>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AffectedVersionRange {
    pub label: String,
    pub from_version: String,
    pub from_inclusive: bool,
    pub to_version: String,
    pub to_inclusive: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VulnerabilityCandidate {
    pub provider: String,
    pub vulnerability_id: String,
    pub title: String,
    pub description: Option<String>,
    pub informational: bool,
    pub cve: Option<String>,
    pub cve_link: Option<String>,
    pub published: Option<String>,
    pub updated: Option<String>,
    pub cvss_vector: Option<String>,
    pub cvss_score: Option<f64>,
    pub cvss_rating: Option<String>,
    pub cwe_id: Option<i64>,
    pub cwe_name: Option<String>,
    pub cwe_description: Option<String>,
    pub researchers: Vec<String>,
    pub references: Vec<String>,
    pub copyrights: Option<serde_json::Value>,
    pub software_type: String,
    pub software_slug: String,
    pub software_name: String,
    pub affected_ranges: Vec<AffectedVersionRange>,
    pub patched: bool,
    pub patched_versions: Vec<String>,
    pub remediation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VulnerabilityMatch {
    #[serde(flatten)]
    pub vulnerability: VulnerabilityCandidate,
    pub installed_version: String,
    #[serde(default = "unknown_software_status")]
    pub installed_status: String,
    #[serde(default)]
    pub update_version: Option<String>,
    pub matched_ranges: Vec<String>,
}

fn unknown_software_status() -> String {
    "unknown".into()
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct ComponentVulnerabilityResult {
    pub matches: Vec<VulnerabilityMatch>,
    pub provider_match_found: bool,
    pub version_comparison_failed: bool,
}
