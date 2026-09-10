use crate::{
    credentials::CredentialVault, database::Database, error::AppError,
    models::WordfenceIntegrationStatus, vulnerability_jobs::VulnerabilityRefreshManager,
};
use reqwest::{StatusCode, blocking::Client, header::RETRY_AFTER};
use serde::Deserialize;
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::File,
    io::{Read, Write},
    path::Path,
    time::Duration,
};

pub const WORDFENCE_CREDENTIAL_REFERENCE: &str = "integration:wordfence-intelligence:api-key";
pub const WORDFENCE_PRODUCTION_FEED_URL: &str =
    "https://www.wordfence.com/api/intelligence/v3/vulnerabilities/production";
pub const WORDFENCE_PROVIDER: &str = "wordfence";
pub const FEED_REFRESH_SECONDS: i64 = 24 * 60 * 60;
pub const FEED_COOLDOWN_SECONDS: i64 = 30 * 60;
const MAX_FEED_BYTES: u64 = 512 * 1024 * 1024;

pub trait VulnerabilityProvider: Send + Sync {
    fn test_connection(&self, api_key: &str) -> Result<(), AppError>;
    fn download_feed(&self, api_key: &str, destination: &Path) -> Result<u64, AppError>;
}

#[derive(Debug, Deserialize)]
pub(crate) struct WordfenceVulnerability {
    pub id: String,
    pub title: String,
    #[serde(default)]
    pub software: Vec<WordfenceSoftware>,
    #[serde(default)]
    pub informational: bool,
    pub description: Option<String>,
    #[serde(default)]
    pub references: Vec<String>,
    pub cwe: Option<WordfenceCwe>,
    pub cvss: Option<WordfenceCvss>,
    pub cve: Option<String>,
    pub cve_link: Option<String>,
    #[serde(default)]
    pub researchers: Vec<String>,
    pub published: Option<String>,
    pub updated: Option<String>,
    pub copyrights: Option<Value>,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WordfenceSoftware {
    #[serde(rename = "type")]
    pub software_type: String,
    pub name: String,
    pub slug: String,
    #[serde(default)]
    pub affected_versions: BTreeMap<String, WordfenceAffectedRange>,
    #[serde(default)]
    pub patched: bool,
    #[serde(default)]
    pub patched_versions: Vec<String>,
    pub remediation: Option<String>,
}

#[derive(Debug, Deserialize, serde::Serialize, PartialEq, Eq)]
pub(crate) struct WordfenceAffectedRange {
    pub from_version: String,
    pub from_inclusive: bool,
    pub to_version: String,
    pub to_inclusive: bool,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WordfenceCwe {
    pub id: i64,
    pub name: String,
    pub description: String,
}

#[derive(Debug, Deserialize)]
pub(crate) struct WordfenceCvss {
    pub vector: String,
    pub score: f64,
    pub rating: String,
}

pub struct WordfenceIntelligenceProvider {
    client: Client,
    endpoint: String,
}

impl WordfenceIntelligenceProvider {
    pub fn new() -> Result<Self, AppError> {
        Self::with_endpoint_and_timeout(WORDFENCE_PRODUCTION_FEED_URL, Duration::from_secs(120))
    }

    fn with_endpoint_and_timeout(
        endpoint: impl Into<String>,
        timeout: Duration,
    ) -> Result<Self, AppError> {
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(15))
            .timeout(timeout)
            .user_agent(concat!(
                "WP-Maintenance-Manager/",
                env!("CARGO_PKG_VERSION")
            ))
            .build()
            .map_err(map_transport_error)?;
        Ok(Self {
            client,
            endpoint: endpoint.into(),
        })
    }

    fn request(&self, api_key: &str) -> Result<reqwest::blocking::Response, AppError> {
        let response = self
            .client
            .get(&self.endpoint)
            .bearer_auth(api_key)
            .send()
            .map_err(map_transport_error)?;
        match response.status() {
            StatusCode::OK => Ok(response),
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => Err(AppError {
                error_id: None,
                category: "wordfence_api".into(),
                user_message: "De Wordfence API-sleutel is niet geaccepteerd.".into(),
                technical_details: Some(format!("Wordfence HTTP-status {}", response.status())),
                retryable: false,
            }),
            StatusCode::TOO_MANY_REQUESTS => {
                let retry_after = response
                    .headers()
                    .get(RETRY_AFTER)
                    .and_then(|value| value.to_str().ok())
                    .filter(|value| value.len() <= 100);
                Err(AppError {
                    error_id: None,
                    category: "vulnerability_feed_rate_limited".into(),
                    user_message: "De Wordfence rate limit is bereikt. Probeer het later opnieuw."
                        .into(),
                    technical_details: Some(match retry_after {
                        Some(value) => format!("Wordfence HTTP-status 429; Retry-After: {value}"),
                        None => "Wordfence HTTP-status 429".into(),
                    }),
                    retryable: true,
                })
            }
            status if status.is_server_error() => Err(AppError {
                error_id: None,
                category: "wordfence_api".into(),
                user_message: "Wordfence Intelligence is tijdelijk niet beschikbaar.".into(),
                technical_details: Some(format!("Wordfence HTTP-status {status}")),
                retryable: true,
            }),
            status => Err(AppError {
                error_id: None,
                category: "wordfence_api".into(),
                user_message: "Wordfence Intelligence kon niet worden bereikt.".into(),
                technical_details: Some(format!("Onverwachte Wordfence HTTP-status {status}")),
                retryable: false,
            }),
        }
    }
}

impl VulnerabilityProvider for WordfenceIntelligenceProvider {
    fn test_connection(&self, api_key: &str) -> Result<(), AppError> {
        let response = self.request(api_key)?;
        drop(response);
        Ok(())
    }

    fn download_feed(&self, api_key: &str, destination: &Path) -> Result<u64, AppError> {
        let mut response = self.request(api_key)?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_FEED_BYTES)
        {
            return Err(feed_too_large());
        }
        let mut file = File::create(destination).map_err(AppError::storage)?;
        let mut bounded = (&mut response).take(MAX_FEED_BYTES + 1);
        let copied = std::io::copy(&mut bounded, &mut file).map_err(map_download_error)?;
        if copied > MAX_FEED_BYTES {
            return Err(feed_too_large());
        }
        file.flush().map_err(AppError::storage)?;
        file.sync_all().map_err(AppError::storage)?;
        Ok(copied)
    }
}

fn map_transport_error(error: reqwest::Error) -> AppError {
    if error.is_timeout() {
        return AppError {
            error_id: None,
            category: "connection_timeout".into(),
            user_message: "Wordfence Intelligence kon niet op tijd worden bereikt.".into(),
            technical_details: Some(
                "De HTTPS-aanvraag naar Wordfence heeft de time-out bereikt.".into(),
            ),
            retryable: true,
        };
    }
    AppError {
        error_id: None,
        category: "wordfence_api".into(),
        user_message: "Wordfence Intelligence kon niet worden bereikt.".into(),
        technical_details: Some(error.without_url().to_string()),
        retryable: true,
    }
}

fn map_download_error(error: std::io::Error) -> AppError {
    AppError {
        error_id: None,
        category: "vulnerability_feed".into(),
        user_message: "De Wordfence vulnerability database kon niet volledig worden gedownload."
            .into(),
        technical_details: Some(error.to_string()),
        retryable: true,
    }
}

fn feed_too_large() -> AppError {
    AppError {
        error_id: None,
        category: "vulnerability_feed".into(),
        user_message: "De Wordfence vulnerability database is onverwacht groot en is geweigerd."
            .into(),
        technical_details: Some(format!("Maximale feedgrootte: {MAX_FEED_BYTES} bytes")),
        retryable: false,
    }
}

pub fn integration_status(
    vault: &CredentialVault,
    database: &Database,
    jobs: &VulnerabilityRefreshManager,
) -> Result<WordfenceIntegrationStatus, AppError> {
    let feed = database.vulnerability_feed_state(WORDFENCE_PROVIDER)?;
    let now = chrono::Utc::now();
    let last_success = feed
        .last_successful_update_at
        .as_deref()
        .and_then(|value| chrono::DateTime::parse_from_rfc3339(value).ok());
    let age_seconds = last_success
        .as_ref()
        .map_or(i64::MAX, |updated| now.timestamp() - updated.timestamp());
    let current_job = jobs.current()?;
    let refresh_running = current_job
        .as_ref()
        .is_some_and(|job| job.status.is_active());
    let cooldown_remaining_seconds = database
        .vulnerability_feed_cooldown_remaining(WORDFENCE_PROVIDER, FEED_COOLDOWN_SECONDS)?;
    Ok(WordfenceIntegrationStatus {
        configured: vault
            .get_optional(WORDFENCE_CREDENTIAL_REFERENCE)?
            .is_some(),
        connection_status: "not_tested".into(),
        feed_status: if refresh_running {
            "refreshing"
        } else if feed.active_dataset_id.is_none() {
            "missing"
        } else if age_seconds > FEED_REFRESH_SECONDS {
            "stale"
        } else {
            "current"
        }
        .into(),
        last_successful_update_at: feed.last_successful_update_at,
        next_automatic_update_at: last_success.map(|updated| {
            (updated + chrono::Duration::seconds(FEED_REFRESH_SECONDS)).to_rfc3339()
        }),
        vulnerability_count: feed.vulnerability_count,
        software_record_count: feed.software_record_count,
        refresh_running,
        refresh_phase: current_job.and_then(|job| job.phase),
        cooldown_remaining_seconds,
        last_error: feed.last_error,
    })
}

pub fn save_api_key(vault: &CredentialVault, api_key: &str) -> Result<(), AppError> {
    let api_key = validate_api_key(api_key)?;
    vault.set(WORDFENCE_CREDENTIAL_REFERENCE, api_key)
}

pub fn remove_api_key(vault: &CredentialVault) -> Result<(), AppError> {
    vault.delete(WORDFENCE_CREDENTIAL_REFERENCE)
}

fn validate_api_key(api_key: &str) -> Result<&str, AppError> {
    let trimmed = api_key.trim();
    if trimmed.is_empty() {
        return Err(AppError::validation("Voer een Wordfence API-sleutel in."));
    }
    if trimmed.len() > 512 || trimmed.chars().any(char::is_control) {
        return Err(AppError::validation(
            "De Wordfence API-sleutel heeft geen geldig formaat.",
        ));
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        io::{Read, Write},
        net::TcpListener,
        sync::mpsc,
        thread,
    };

    fn mock_server(
        status: u16,
        extra_headers: &str,
        body: &str,
        response_delay: Duration,
    ) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let (sender, receiver) = mpsc::channel();
        let extra_headers = extra_headers.to_owned();
        let body = body.to_owned();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            loop {
                let count = stream.read(&mut buffer).unwrap();
                request.extend_from_slice(&buffer[..count]);
                if request.windows(4).any(|window| window == b"\r\n\r\n") || count == 0 {
                    break;
                }
            }
            let _ = sender.send(String::from_utf8(request).unwrap());
            thread::sleep(response_delay);
            let reason = match status {
                200 => "OK",
                401 => "Unauthorized",
                403 => "Forbidden",
                429 => "Too Many Requests",
                _ => "Server Error",
            };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\nContent-Length: {}\r\n{extra_headers}Connection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
        });
        (format!("http://{address}/production"), receiver)
    }

    #[test]
    fn api_key_validation_accepts_an_opaque_secret_without_exposing_it() {
        assert_eq!(
            validate_api_key("  opaque-test-key  ").unwrap(),
            "opaque-test-key"
        );
    }

    #[test]
    fn api_key_validation_rejects_empty_control_and_oversized_values() {
        assert!(validate_api_key("   ").is_err());
        assert!(validate_api_key("key\nvalue").is_err());
        assert!(validate_api_key(&"x".repeat(513)).is_err());
    }

    #[test]
    fn client_sends_only_the_expected_bearer_authorization() {
        let (endpoint, request) = mock_server(200, "", "{}", Duration::ZERO);
        let provider = WordfenceIntelligenceProvider::with_endpoint_and_timeout(
            endpoint,
            Duration::from_secs(2),
        )
        .unwrap();
        provider.test_connection("test-api-key").unwrap();
        let request = request.recv().unwrap();
        assert!(request.starts_with("GET /production HTTP/1.1\r\n"));
        assert!(request.contains("authorization: Bearer test-api-key\r\n"));
        assert!(!format!("{:?}", provider.endpoint).contains("test-api-key"));
    }

    #[test]
    fn client_maps_auth_rate_limit_and_server_failures_without_secrets() {
        for (status, category, retryable) in [
            (401, "wordfence_api", false),
            (403, "wordfence_api", false),
            (429, "vulnerability_feed_rate_limited", true),
            (500, "wordfence_api", true),
        ] {
            let headers = if status == 429 {
                "Retry-After: 1800\r\n"
            } else {
                ""
            };
            let (endpoint, _) = mock_server(status, headers, "", Duration::ZERO);
            let provider = WordfenceIntelligenceProvider::with_endpoint_and_timeout(
                endpoint,
                Duration::from_secs(2),
            )
            .unwrap();
            let error = provider.test_connection("never-log-this-key").unwrap_err();
            assert_eq!(error.category, category);
            assert_eq!(error.retryable, retryable);
            assert!(!format!("{error:?}").contains("never-log-this-key"));
            if status == 429 {
                assert!(error.technical_details.unwrap().contains("1800"));
            }
        }
    }

    #[test]
    fn client_maps_timeouts_without_including_the_request_url_or_secret() {
        let (endpoint, _) = mock_server(200, "", "{}", Duration::from_millis(100));
        let provider = WordfenceIntelligenceProvider::with_endpoint_and_timeout(
            endpoint,
            Duration::from_millis(20),
        )
        .unwrap();
        let error = provider.test_connection("timeout-secret").unwrap_err();
        assert_eq!(error.category, "connection_timeout");
        assert!(!format!("{error:?}").contains("timeout-secret"));
    }

    #[test]
    fn feed_download_streams_the_response_to_a_bounded_file() {
        let body = "{\"fixture\":true}";
        let (endpoint, _) = mock_server(200, "", body, Duration::ZERO);
        let provider = WordfenceIntelligenceProvider::with_endpoint_and_timeout(
            endpoint,
            Duration::from_secs(2),
        )
        .unwrap();
        let path = std::env::temp_dir().join(format!("wordfence-{}.tmp", uuid::Uuid::new_v4()));
        let bytes = provider.download_feed("test-key", &path).unwrap();
        assert_eq!(bytes, u64::try_from(body.len()).unwrap());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), body);
        std::fs::remove_file(path).unwrap();
    }
}
