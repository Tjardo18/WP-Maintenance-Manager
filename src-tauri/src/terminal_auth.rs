use crate::error::AppError;
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

const CHALLENGE_TTL: Duration = Duration::from_secs(60);
const ATTEMPT_WINDOW: Duration = Duration::from_secs(15 * 60);
const MAX_CHALLENGES: usize = 128;
const MAX_TOKEN_LENGTH: usize = 512;

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TerminalChallengeInfo {
    pub challenge_token: String,
    pub expires_in_seconds: u64,
}

#[derive(Debug)]
struct Challenge {
    token_hash: [u8; 32],
    session_hash: [u8; 32],
    site_id: String,
    expires_at: Instant,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct AttemptKey {
    session_hash: [u8; 32],
    site_id: String,
}

#[derive(Debug, Default)]
struct AttemptState {
    failures: VecDeque<Instant>,
    blocked_until: Option<Instant>,
}

#[derive(Debug, Default)]
struct RuntimeState {
    challenges: Vec<Challenge>,
    attempts: HashMap<AttemptKey, AttemptState>,
}

#[derive(Debug, Default)]
pub struct TerminalAccessManager {
    runtime: Mutex<RuntimeState>,
}

impl TerminalAccessManager {
    pub fn create_challenge(
        &self,
        session_token: &str,
        site_id: &str,
    ) -> Result<TerminalChallengeInfo, AppError> {
        self.create_challenge_with_ttl(session_token, site_id, CHALLENGE_TTL)
    }

    fn create_challenge_with_ttl(
        &self,
        session_token: &str,
        site_id: &str,
        ttl: Duration,
    ) -> Result<TerminalChallengeInfo, AppError> {
        validate_binding(session_token, site_id)?;
        let session_hash = hash_secret(session_token);
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(AppError::storage)?;
        let token = URL_SAFE_NO_PAD.encode(bytes);
        let now = Instant::now();
        let mut runtime = self.lock_runtime()?;
        cleanup(&mut runtime, now);
        runtime.challenges.retain(|challenge| {
            challenge.site_id != site_id
                || challenge.session_hash.ct_eq(&session_hash).unwrap_u8() != 1
        });
        if runtime.challenges.len() >= MAX_CHALLENGES {
            runtime.challenges.remove(0);
        }
        runtime.challenges.push(Challenge {
            token_hash: hash_secret(&token),
            session_hash,
            site_id: site_id.to_owned(),
            expires_at: now + ttl,
        });
        Ok(TerminalChallengeInfo {
            challenge_token: token,
            expires_in_seconds: ttl.as_secs(),
        })
    }

    pub fn consume_challenge(
        &self,
        session_token: &str,
        site_id: &str,
        challenge_token: &str,
    ) -> Result<(), AppError> {
        validate_binding(session_token, site_id)?;
        if challenge_token.is_empty() || challenge_token.len() > MAX_TOKEN_LENGTH {
            return Err(invalid_challenge());
        }
        let now = Instant::now();
        let session_hash = hash_secret(session_token);
        let token_hash = hash_secret(challenge_token);
        let mut runtime = self.lock_runtime()?;
        let position = runtime
            .challenges
            .iter()
            .position(|challenge| challenge.token_hash.ct_eq(&token_hash).unwrap_u8() == 1)
            .ok_or_else(invalid_challenge)?;
        let challenge = runtime.challenges.remove(position);
        ensure_ssh_allowed(&mut runtime, &session_hash, site_id, now)?;
        if challenge.expires_at <= now {
            return Err(AppError::unauthorized(
                "terminal_challenge_expired",
                "De Terminal-verificatie is verlopen. Bevestig beide wachtwoorden opnieuw.",
            ));
        }
        if challenge.site_id != site_id
            || challenge.session_hash.ct_eq(&session_hash).unwrap_u8() != 1
        {
            return Err(invalid_challenge());
        }
        cleanup(&mut runtime, now);
        Ok(())
    }

    pub fn cancel_challenge(
        &self,
        session_token: &str,
        site_id: &str,
        challenge_token: &str,
    ) -> Result<(), AppError> {
        validate_binding(session_token, site_id)?;
        if challenge_token.is_empty() || challenge_token.len() > MAX_TOKEN_LENGTH {
            return Ok(());
        }
        let session_hash = hash_secret(session_token);
        let token_hash = hash_secret(challenge_token);
        let mut runtime = self.lock_runtime()?;
        runtime.challenges.retain(|challenge| {
            challenge.token_hash.ct_eq(&token_hash).unwrap_u8() != 1
                || challenge.site_id != site_id
                || challenge.session_hash.ct_eq(&session_hash).unwrap_u8() != 1
        });
        Ok(())
    }

    pub fn register_ssh_failure(
        &self,
        session_token: &str,
        site_id: &str,
    ) -> Result<u64, AppError> {
        validate_binding(session_token, site_id)?;
        let now = Instant::now();
        let mut runtime = self.lock_runtime()?;
        let attempts = runtime
            .attempts
            .entry(attempt_key(session_token, site_id))
            .or_default();
        attempts
            .failures
            .retain(|attempt| now.duration_since(*attempt) <= ATTEMPT_WINDOW);
        attempts.failures.push_back(now);
        let count = attempts.failures.len();
        let delay = if count < 3 {
            0
        } else {
            2_u64.pow((count - 3).min(5) as u32).min(30)
        };
        attempts.blocked_until = (delay > 0).then_some(now + Duration::from_secs(delay));
        Ok(delay)
    }

    pub fn clear_ssh_failures(&self, session_token: &str, site_id: &str) {
        if let Ok(mut runtime) = self.runtime.lock() {
            runtime
                .attempts
                .remove(&attempt_key(session_token, site_id));
        }
    }

    pub fn revoke_site(&self, site_id: &str) {
        if let Ok(mut runtime) = self.runtime.lock() {
            runtime
                .challenges
                .retain(|challenge| challenge.site_id != site_id);
            runtime.attempts.retain(|key, _| key.site_id != site_id);
        }
    }

    pub fn revoke_all(&self) {
        if let Ok(mut runtime) = self.runtime.lock() {
            runtime.challenges.clear();
            runtime.attempts.clear();
        }
    }

    fn lock_runtime(&self) -> Result<std::sync::MutexGuard<'_, RuntimeState>, AppError> {
        self.runtime
            .lock()
            .map_err(|_| AppError::storage("Terminal access state lock poisoned"))
    }
}

pub(crate) fn hash_secret(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

fn attempt_key(session_token: &str, site_id: &str) -> AttemptKey {
    AttemptKey {
        session_hash: hash_secret(session_token),
        site_id: site_id.to_owned(),
    }
}

fn validate_binding(session_token: &str, site_id: &str) -> Result<(), AppError> {
    if session_token.is_empty()
        || session_token.len() > MAX_TOKEN_LENGTH
        || uuid::Uuid::parse_str(site_id).is_err()
    {
        return Err(invalid_challenge());
    }
    Ok(())
}

fn ensure_ssh_allowed(
    runtime: &mut RuntimeState,
    session_hash: &[u8; 32],
    site_id: &str,
    now: Instant,
) -> Result<(), AppError> {
    let key = AttemptKey {
        session_hash: *session_hash,
        site_id: site_id.to_owned(),
    };
    let Some(attempts) = runtime.attempts.get_mut(&key) else {
        return Ok(());
    };
    if let Some(until) = attempts.blocked_until {
        if until > now {
            let seconds = until.duration_since(now).as_secs().max(1);
            return Err(AppError::ssh(
                "terminal_ssh_rate_limited",
                format!(
                    "Te veel mislukte SSH-pogingen. Probeer het over {seconds} seconden opnieuw."
                ),
                "SSH password attempt rate limit actief",
                true,
            ));
        }
        attempts.blocked_until = None;
    }
    Ok(())
}

fn cleanup(runtime: &mut RuntimeState, now: Instant) {
    runtime
        .challenges
        .retain(|challenge| challenge.expires_at > now);
    runtime.attempts.retain(|_, attempts| {
        attempts
            .failures
            .retain(|attempt| now.duration_since(*attempt) <= ATTEMPT_WINDOW);
        !attempts.failures.is_empty() || attempts.blocked_until.is_some_and(|until| until > now)
    });
}

fn invalid_challenge() -> AppError {
    AppError::unauthorized(
        "terminal_challenge_invalid",
        "De Terminal-verificatie is ongeldig. Bevestig beide wachtwoorden opnieuw.",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn site() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    #[test]
    fn challenges_are_random_site_bound_session_bound_and_single_use() {
        let manager = TerminalAccessManager::default();
        let site_a = site();
        let site_b = site();
        let first = manager.create_challenge("session-a", &site_a).unwrap();
        let second = manager.create_challenge("session-a", &site_b).unwrap();
        assert_ne!(first.challenge_token, second.challenge_token);
        assert!(
            manager
                .consume_challenge("session-b", &site_a, &first.challenge_token)
                .is_err()
        );
        assert!(
            manager
                .consume_challenge("session-a", &site_a, &first.challenge_token)
                .is_err()
        );

        let wrong_site = manager.create_challenge("session-a", &site_a).unwrap();
        assert!(
            manager
                .consume_challenge("session-a", &site_b, &wrong_site.challenge_token)
                .is_err()
        );

        let valid = manager.create_challenge("session-a", &site_a).unwrap();
        assert!(
            manager
                .consume_challenge("session-a", &site_a, &valid.challenge_token)
                .is_ok()
        );
        assert!(
            manager
                .consume_challenge("session-a", &site_a, &valid.challenge_token)
                .is_err()
        );
    }

    #[test]
    fn expired_and_cancelled_challenges_cannot_be_used() {
        let manager = TerminalAccessManager::default();
        let site_id = site();
        let expired = manager
            .create_challenge_with_ttl("session-a", &site_id, Duration::ZERO)
            .unwrap();
        assert!(
            manager
                .consume_challenge("session-a", &site_id, &expired.challenge_token)
                .is_err()
        );

        let cancelled = manager.create_challenge("session-a", &site_id).unwrap();
        manager
            .cancel_challenge("session-a", &site_id, &cancelled.challenge_token)
            .unwrap();
        assert!(
            manager
                .consume_challenge("session-a", &site_id, &cancelled.challenge_token)
                .is_err()
        );
    }

    #[test]
    fn ssh_failures_are_rate_limited_per_session_and_site() {
        let manager = TerminalAccessManager::default();
        let site_id = site();
        assert_eq!(
            manager.register_ssh_failure("session-a", &site_id).unwrap(),
            0
        );
        assert_eq!(
            manager.register_ssh_failure("session-a", &site_id).unwrap(),
            0
        );
        assert_eq!(
            manager.register_ssh_failure("session-a", &site_id).unwrap(),
            1
        );
        let challenge = manager.create_challenge("session-a", &site_id).unwrap();
        let error = manager
            .consume_challenge("session-a", &site_id, &challenge.challenge_token)
            .unwrap_err();
        assert_eq!(error.category, "terminal_ssh_rate_limited");

        let other_site = site();
        let other = manager.create_challenge("session-a", &other_site).unwrap();
        assert!(
            manager
                .consume_challenge("session-a", &other_site, &other.challenge_token)
                .is_ok()
        );
    }
}
