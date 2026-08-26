//! Duckvis mode: authenticated, project-scoped sessions backed by duckvis-api.
//!
//! [`DuckvisAuth`] holds the parsed configuration, a shared `reqwest::Client`, a
//! cached service-account token, and a JWKS cache. It validates inbound user
//! tokens (see [`jwt`]) and makes authorization decisions against duckvis-api
//! (see [`api`]). Every failure mode maps to a `tonic::Status` per contract C4
//! via [`DuckvisError::into_status`]; the messages are deliberately generic so no
//! failure-mode detail leaks to clients.

pub mod api;
pub mod attach;
pub mod jwks;
pub mod jwt;
pub mod sa;

use std::sync::Arc;

use tonic::Status;
use tracing::warn;

use crate::config::ServerConfig;

pub use api::ResolvedAttachment;
pub use jwt::{ActorKind, DuckvisClaims};

/// Failure modes in duckvis mode, mapped to `tonic::Status` per contract C4.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DuckvisError {
    /// Missing/malformed/expired/bad-signature token, unknown kid after JWKS
    /// refresh, wrong iss/aud. Generic — no failure-mode split (C4).
    Unauthenticated,
    /// Authorization denied: authz-check deny, token sub ≠ session subject,
    /// project header ≠ session project, resolve deny, or a raw ATTACH in
    /// user SQL (C6).
    PermissionDenied,
    /// Missing `x-duckvis-project-id` at session creation, or a malformed
    /// `duckvis_attach` body.
    InvalidArgument,
    /// The resolved/normalized ATTACH statement was not a single ATTACH.
    AttachInvalid,
    /// duckvis-api unreachable / 5xx — client-retryable.
    Unavailable,
}

impl DuckvisError {
    /// Map to a `tonic::Status` exactly per contract C4. Messages are generic; in
    /// particular the unauthenticated message never reveals *why* a token failed.
    pub fn into_status(self) -> Status {
        match self {
            DuckvisError::Unauthenticated => Status::unauthenticated("authentication required"),
            DuckvisError::PermissionDenied => Status::permission_denied("permission denied"),
            DuckvisError::InvalidArgument => Status::invalid_argument("invalid argument"),
            DuckvisError::AttachInvalid => {
                Status::invalid_argument("invalid attachment configuration")
            }
            DuckvisError::Unavailable => {
                Status::unavailable("authorization service unavailable")
            }
        }
    }
}

impl std::fmt::Display for DuckvisError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            DuckvisError::Unauthenticated => "unauthenticated",
            DuckvisError::PermissionDenied => "permission denied",
            DuckvisError::InvalidArgument => "invalid argument",
            DuckvisError::AttachInvalid => "invalid attachment configuration",
            DuckvisError::Unavailable => "service unavailable",
        };
        f.write_str(s)
    }
}

impl std::error::Error for DuckvisError {}

/// Holder for duckvis-mode authentication state and duckvis-api clients.
pub struct DuckvisAuth {
    pub(crate) api_url: String,
    pub(crate) issuer: String,
    pub(crate) client_id: String,
    /// Ed25519 key used to sign the RFC 7523 client assertion (C5). Parsed
    /// once at construction from the configured base64 seed.
    pub(crate) signing_key: ed25519_dalek::SigningKey,
    pub(crate) client: reqwest::Client,
    pub(crate) sa_token: tokio::sync::Mutex<Option<sa::SaToken>>,
    pub(crate) jwks: tokio::sync::RwLock<jwks::JwksCache>,
}

impl DuckvisAuth {
    /// Build a [`DuckvisAuth`] from configuration. Returns `Ok(None)` when
    /// duckvis mode is disabled, `Err` when enabled but misconfigured (the
    /// config layer already validates required fields, but this constructor is
    /// defensive).
    pub fn from_config(config: &ServerConfig) -> Result<Option<Arc<Self>>, String> {
        if !config.duckvis_enabled {
            return Ok(None);
        }

        let api_url = config
            .duckvis_api_url
            .clone()
            .ok_or_else(|| "duckvis_api_url is required in duckvis mode".to_string())?;
        let issuer = config
            .duckvis_issuer
            .clone()
            .ok_or_else(|| "duckvis_issuer is required in duckvis mode".to_string())?;
        let client_id = config
            .duckvis_client_id
            .clone()
            .ok_or_else(|| "duckvis_client_id is required in duckvis mode".to_string())?;
        let seed = config
            .duckvis_private_key
            .as_ref()
            .ok_or_else(|| "duckvis_private_key is required in duckvis mode".to_string())?
            .decode_seed()
            .map_err(|e| e.to_string())?;
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let max_age = config.duckvis_jwks_max_age_secs.unwrap_or(300);

        let client = reqwest::Client::builder()
            .build()
            .map_err(|e| format!("failed to build duckvis HTTP client: {e}"))?;

        Ok(Some(Arc::new(Self {
            api_url,
            issuer,
            client_id,
            signing_key,
            client,
            sa_token: tokio::sync::Mutex::new(None),
            jwks: tokio::sync::RwLock::new(jwks::JwksCache::new(max_age)),
        })))
    }

    /// Current unix time in seconds.
    fn now_secs() -> i64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0)
    }

    /// Validate a bearer JWT and return its claims. Handles JWKS refresh on a
    /// stale cache and one refresh-and-retry when the kid is unknown.
    pub async fn validate_token(&self, jwt: &str) -> Result<DuckvisClaims, DuckvisError> {
        let now = Self::now_secs();

        // Ensure the cache has at least been populated once (or is refreshed if
        // past its max-age) before the first lookup.
        {
            let stale = self.jwks.read().await.is_stale();
            if stale {
                // Best-effort refresh; a failure here still lets us try the
                // existing (possibly empty) cache, which will surface as an
                // unknown-kid path below.
                if let Err(e) = jwks::refresh(&self.jwks, &self.client, &self.api_url, false).await {
                    warn!(error = %e, "jwks refresh failed (stale cache)");
                }
            }
        }

        // First attempt with the current cache.
        let attempt = {
            let cache = self.jwks.read().await;
            jwt::verify_and_decode(jwt, &self.issuer, now, |kid| cache.get(kid))
        };
        match attempt {
            Ok(claims) => return Ok(claims),
            Err(DuckvisError::Unauthenticated) => {}
            Err(other) => return Err(other),
        }

        // The failure may be an unknown kid. If a forced refresh is allowed,
        // refresh and retry once. If the kid is still unknown or the token is
        // otherwise invalid, this collapses to Unauthenticated.
        let can_force = self.jwks.read().await.can_force_refresh();
        if can_force {
            if let Err(e) = jwks::refresh(&self.jwks, &self.client, &self.api_url, true).await {
                warn!(error = %e, "forced jwks refresh failed");
            }
            let cache = self.jwks.read().await;
            return jwt::verify_and_decode(jwt, &self.issuer, now, |kid| cache.get(kid));
        }

        Err(DuckvisError::Unauthenticated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    #[test]
    fn error_maps_to_status_per_c4() {
        assert_eq!(
            DuckvisError::Unauthenticated.into_status().code(),
            Code::Unauthenticated
        );
        assert_eq!(
            DuckvisError::PermissionDenied.into_status().code(),
            Code::PermissionDenied
        );
        assert_eq!(
            DuckvisError::InvalidArgument.into_status().code(),
            Code::InvalidArgument
        );
        assert_eq!(
            DuckvisError::AttachInvalid.into_status().code(),
            Code::InvalidArgument
        );
        assert_eq!(
            DuckvisError::Unavailable.into_status().code(),
            Code::Unavailable
        );
    }

    #[test]
    fn unauthenticated_status_message_is_generic() {
        let msg = DuckvisError::Unauthenticated.into_status();
        // Must not leak any failure-mode detail (no "expired", "signature", etc.)
        assert!(!msg.message().to_lowercase().contains("expired"));
        assert!(!msg.message().to_lowercase().contains("signature"));
        assert!(!msg.message().to_lowercase().contains("kid"));
    }

    #[test]
    fn from_config_returns_none_when_disabled() {
        let config = ServerConfig::default();
        let result = DuckvisAuth::from_config(&config).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn from_config_builds_when_enabled() {
        use base64::engine::general_purpose::STANDARD as BASE64_STD;
        use base64::Engine as _;

        let config = ServerConfig {
            duckvis_enabled: true,
            duckvis_api_url: Some("https://api.example".to_string()),
            duckvis_issuer: Some("https://api.example".to_string()),
            duckvis_client_id: Some("swanlake-test".to_string()),
            duckvis_private_key: Some(crate::config::DuckvisPrivateKey::new(
                BASE64_STD.encode([0x11u8; 32]),
            )),
            ..ServerConfig::default()
        };
        let result = DuckvisAuth::from_config(&config).unwrap();
        assert!(result.is_some());
    }

    #[test]
    fn from_config_rejects_bad_length_private_key() {
        use base64::engine::general_purpose::STANDARD as BASE64_STD;
        use base64::Engine as _;

        let config = ServerConfig {
            duckvis_enabled: true,
            duckvis_api_url: Some("https://api.example".to_string()),
            duckvis_issuer: Some("https://api.example".to_string()),
            duckvis_client_id: Some("swanlake-test".to_string()),
            duckvis_private_key: Some(crate::config::DuckvisPrivateKey::new(
                BASE64_STD.encode([0x11u8; 16]),
            )),
            ..ServerConfig::default()
        };
        let err = match DuckvisAuth::from_config(&config) {
            Err(e) => e,
            Ok(_) => panic!("16-byte seed must be rejected"),
        };
        assert!(err.contains("32 bytes"));
    }
}
