use serde::{Deserialize, Serialize};

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
