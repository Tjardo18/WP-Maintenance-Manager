use crate::error::AppError;
use argon2::{
    Algorithm, Argon2, Params, Version,
    password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
};
use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use std::{
    collections::VecDeque,
    sync::Mutex,
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;

pub const DEFAULT_IDLE_MINUTES: u16 = 15;
pub const ALLOWED_IDLE_MINUTES: [u16; 5] = [5, 10, 15, 30, 60];
const MIN_PASSWORD_CHARS: usize = 12;
const MAX_PASSWORD_BYTES: usize = 1024;
const ARGON2_MEMORY_KIB: u32 = 19 * 1024;
const ARGON2_ITERATIONS: u32 = 2;
const ARGON2_PARALLELISM: u32 = 1;

#[derive(Debug)]
struct Session {
    token_hash: [u8; 32],
    last_activity: Instant,
}

#[derive(Debug, Default)]
struct RuntimeState {
    session: Option<Session>,
    failures: VecDeque<Instant>,
    blocked_until: Option<Instant>,
}

#[derive(Debug, Default)]
pub struct AuthManager {
    runtime: Mutex<RuntimeState>,
}

impl AuthManager {
    pub fn create_session(&self) -> Result<String, AppError> {
        let mut bytes = [0_u8; 32];
        getrandom::fill(&mut bytes).map_err(AppError::storage)?;
        let token = URL_SAFE_NO_PAD.encode(bytes);
        let mut runtime = self.lock_runtime()?;
        runtime.session = Some(Session {
            token_hash: token_hash(&token),
            last_activity: Instant::now(),
        });
        runtime.failures.clear();
        runtime.blocked_until = None;
        Ok(token)
    }

    pub fn require(&self, token: &str, idle_minutes: u16) -> Result<(), AppError> {
        self.require_with_timeout(
            token,
            Duration::from_secs(u64::from(idle_minutes) * 60),
            true,
        )
    }

    pub fn validate(&self, token: &str, idle_minutes: u16) -> Result<(), AppError> {
        self.require_with_timeout(
            token,
            Duration::from_secs(u64::from(idle_minutes) * 60),
            false,
        )
    }

    fn require_with_timeout(
        &self,
        token: &str,
        timeout: Duration,
        touch: bool,
    ) -> Result<(), AppError> {
        if token.is_empty() || token.len() > 512 {
            return Err(AppError::unauthorized(
                "locked",
                "WP Maintenance Manager is vergrendeld.",
            ));
        }
        let mut runtime = self.lock_runtime()?;
        let Some(session) = runtime.session.as_mut() else {
            return Err(AppError::unauthorized(
                "locked",
                "WP Maintenance Manager is vergrendeld.",
            ));
        };
        if session.last_activity.elapsed() >= timeout {
            runtime.session = None;
            return Err(AppError::unauthorized(
                "session_expired",
                "De sessie is verlopen. Log opnieuw in.",
            ));
        }
        if token_hash(token).ct_eq(&session.token_hash).unwrap_u8() != 1 {
            return Err(AppError::unauthorized(
                "invalid_session",
                "WP Maintenance Manager is vergrendeld.",
            ));
        }
        if touch {
            session.last_activity = Instant::now();
        }
        Ok(())
    }

    pub fn invalidate(&self) -> Result<(), AppError> {
        self.lock_runtime()?.session = None;
        Ok(())
    }

    pub fn ensure_login_allowed(&self) -> Result<(), AppError> {
        let mut runtime = self.lock_runtime()?;
        if let Some(until) = runtime.blocked_until {
            let now = Instant::now();
            if until > now {
                return Err(AppError::rate_limited(
                    until.duration_since(now).as_secs().max(1),
                ));
            }
            runtime.blocked_until = None;
        }
        Ok(())
    }

    pub fn register_login_failure(&self) -> Result<u64, AppError> {
        let mut runtime = self.lock_runtime()?;
        let now = Instant::now();
        let window = Duration::from_secs(15 * 60);
        runtime
            .failures
            .retain(|attempt| now.duration_since(*attempt) <= window);
        runtime.failures.push_back(now);
        let count = runtime.failures.len();
        let delay = if count < 3 {
            0
        } else {
            2_u64.pow((count - 3).min(5) as u32).min(30)
        };
        if delay > 0 {
            runtime.blocked_until = Some(now + Duration::from_secs(delay));
        }
        Ok(delay)
    }

    pub fn retry_after_seconds(&self) -> Result<u64, AppError> {
        let runtime = self.lock_runtime()?;
        Ok(runtime
            .blocked_until
            .and_then(|until| until.checked_duration_since(Instant::now()))
            .map_or(0, |duration| duration.as_secs().max(1)))
    }

    fn lock_runtime(&self) -> Result<std::sync::MutexGuard<'_, RuntimeState>, AppError> {
        self.runtime
            .lock()
            .map_err(|_| AppError::storage("Auth state lock poisoned"))
    }
}

pub fn validate_password(password: &str) -> Result<(), AppError> {
    if password.chars().count() < MIN_PASSWORD_CHARS {
        return Err(AppError::validation(
            "Gebruik minimaal 12 tekens. Een lange wachtwoordzin is toegestaan.",
        ));
    }
    if password.len() > MAX_PASSWORD_BYTES {
        return Err(AppError::validation("Het wachtwoord is te lang."));
    }
    Ok(())
}

pub fn validate_idle_minutes(minutes: u16) -> Result<(), AppError> {
    if !ALLOWED_IDLE_MINUTES.contains(&minutes) {
        return Err(AppError::validation(
            "Kies 5, 10, 15, 30 of 60 minuten voor automatisch vergrendelen.",
        ));
    }
    Ok(())
}

pub fn hash_password(password: &str) -> Result<String, AppError> {
    validate_password(password)?;
    let mut salt_bytes = [0_u8; 16];
    getrandom::fill(&mut salt_bytes).map_err(AppError::storage)?;
    let salt = SaltString::encode_b64(&salt_bytes).map_err(AppError::storage)?;
    argon2id()?
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(AppError::storage)
}

pub fn verify_password(password: &str, encoded_hash: &str) -> bool {
    let Ok(hash) = PasswordHash::new(encoded_hash) else {
        return false;
    };
    argon2id()
        .and_then(|argon2| {
            argon2
                .verify_password(password.as_bytes(), &hash)
                .map_err(AppError::storage)
        })
        .is_ok()
}

fn argon2id() -> Result<Argon2<'static>, AppError> {
    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_ITERATIONS,
        ARGON2_PARALLELISM,
        Some(32),
    )
    .map_err(AppError::storage)?;
    Ok(Argon2::new(Algorithm::Argon2id, Version::V0x13, params))
}

fn token_hash(token: &str) -> [u8; 32] {
    Sha256::digest(token.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hashes_with_argon2id_without_plaintext() {
        let password = "dit is een lange testzin";
        let encoded = hash_password(password).unwrap();
        assert!(encoded.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(!encoded.contains(password));
        assert!(verify_password(password, &encoded));
        assert!(!verify_password("verkeerd wachtwoord", &encoded));
    }

    #[test]
    fn session_tokens_are_random_and_invalidated() {
        let manager = AuthManager::default();
        let first = manager.create_session().unwrap();
        let second = manager.create_session().unwrap();
        assert_ne!(first, second);
        assert!(manager.require(&second, 15).is_ok());
        assert!(manager.require(&first, 15).is_err());
        manager.invalidate().unwrap();
        assert!(manager.require(&second, 15).is_err());
    }

    #[test]
    fn sessions_expire_without_activity() {
        let manager = AuthManager::default();
        let token = manager.create_session().unwrap();
        assert!(
            manager
                .require_with_timeout(&token, Duration::ZERO, false)
                .is_err()
        );
    }

    #[test]
    fn repeated_failures_are_rate_limited() {
        let manager = AuthManager::default();
        assert_eq!(manager.register_login_failure().unwrap(), 0);
        assert_eq!(manager.register_login_failure().unwrap(), 0);
        assert_eq!(manager.register_login_failure().unwrap(), 1);
        assert!(manager.ensure_login_allowed().is_err());
    }
}
