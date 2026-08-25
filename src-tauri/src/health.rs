use crate::error::AppError;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct HealthCheck {
    pub reachable: bool,
    pub status_code: Option<u16>,
    pub response_time_ms: u128,
    pub detail: String,
}

pub fn check_homepage(url: &str) -> Result<HealthCheck, AppError> {
    let parsed = url::Url::parse(url)
        .map_err(|_| AppError::validation("De website-URL voor de homepagecheck is ongeldig."))?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(AppError::validation(
            "Alleen HTTP(S)-homepagechecks zijn toegestaan.",
        ));
    }
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(20))
        .redirect(reqwest::redirect::Policy::limited(5))
        .user_agent("WP-Maintenance-Manager/0.1")
        .build()
        .map_err(|error| {
            AppError::ssh(
                "http_client",
                "De homepagecontrole kon niet worden voorbereid.",
                error,
                true,
            )
        })?;
    let started = Instant::now();
    match client.get(parsed).send() {
        Ok(response) => {
            let status = response.status().as_u16();
            let elapsed = started.elapsed().as_millis();
            Ok(HealthCheck {
                reachable: true,
                status_code: Some(status),
                response_time_ms: elapsed,
                detail: format!(
                    "Homepage bereikbaar met HTTP {status} in circa {elapsed} ms. Dit controleert alleen de homepage."
                ),
            })
        }
        Err(error) => Ok(HealthCheck {
            reachable: false,
            status_code: None,
            response_time_ms: started.elapsed().as_millis(),
            detail: format!("Homepage niet bereikbaar: {error}"),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_non_http_health_checks() {
        assert!(check_homepage("file:///etc/passwd").is_err());
    }
}
