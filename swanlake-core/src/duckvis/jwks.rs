//! JWKS (JSON Web Key Set) cache for Ed25519 signing keys.
//!
//! Fetches `GET {api_url}/.well-known/jwks.json`, honoring `ETag` (via
//! `If-None-Match`) and `Cache-Control: max-age`. On an unknown `kid` the cache
//! forces a refresh (rate-limited to at most once per 10s) and retries once.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use tracing::{debug, warn};

use super::DuckvisError;

/// Minimum gap between forced (unknown-kid) refreshes, to resist refresh storms.
const FORCED_REFRESH_FLOOR: Duration = Duration::from_secs(10);

/// One JWKS entry as served by duckvis-api.
#[derive(Debug, Deserialize)]
struct JwkEntry {
    kty: String,
    crv: Option<String>,
    kid: String,
    x: String,
}

#[derive(Debug, Deserialize)]
struct JwksBody {
    keys: Vec<JwkEntry>,
}

/// Cached JWKS state.
pub struct JwksCache {
    keys: HashMap<String, VerifyingKey>,
    etag: Option<String>,
    fetched_at: Option<Instant>,
    last_forced_refresh: Option<Instant>,
    max_age: Duration,
}

impl JwksCache {
    /// Create an empty cache with the configured fallback max-age (used when a
    /// JWKS response omits `Cache-Control: max-age`).
    pub fn new(fallback_max_age_secs: u64) -> Self {
        Self {
            keys: HashMap::new(),
            etag: None,
            fetched_at: None,
            last_forced_refresh: None,
            max_age: Duration::from_secs(fallback_max_age_secs),
        }
    }

    /// Look up a verifying key by kid, without triggering a refresh.
    pub fn get(&self, kid: &str) -> Option<VerifyingKey> {
        self.keys.get(kid).copied()
    }

    /// Whether the cache has never been populated or is past its max-age.
    pub fn is_stale(&self) -> bool {
        match self.fetched_at {
            None => true,
            Some(at) => at.elapsed() >= self.max_age,
        }
    }

    /// Whether a forced refresh is currently permitted (rate-limit floor).
    pub fn can_force_refresh(&self) -> bool {
        match self.last_forced_refresh {
            None => true,
            Some(at) => at.elapsed() >= FORCED_REFRESH_FLOOR,
        }
    }

    fn mark_forced(&mut self) {
        self.last_forced_refresh = Some(Instant::now());
    }

    /// Apply a fresh JWKS fetch outcome to the cache.
    fn apply(&mut self, outcome: FetchOutcome) {
        match outcome {
            FetchOutcome::NotModified => {
                // Keep existing keys; refresh the freshness clock.
                self.fetched_at = Some(Instant::now());
            }
            FetchOutcome::Updated {
                keys,
                etag,
                max_age,
            } => {
                self.keys = keys;
                self.etag = etag;
                self.fetched_at = Some(Instant::now());
                if let Some(ma) = max_age {
                    self.max_age = ma;
                }
            }
        }
    }
}

enum FetchOutcome {
    NotModified,
    Updated {
        keys: HashMap<String, VerifyingKey>,
        etag: Option<String>,
        max_age: Option<Duration>,
    },
}

/// Parse a base64url-unpadded 32-byte Ed25519 public key into a verifying key.
fn parse_okp_key(entry: &JwkEntry) -> Option<VerifyingKey> {
    if entry.kty != "OKP" {
        return None;
    }
    if let Some(crv) = &entry.crv {
        if crv != "Ed25519" {
            return None;
        }
    }
    let bytes = URL_SAFE_NO_PAD.decode(&entry.x).ok()?;
    let arr: [u8; 32] = bytes.try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

fn parse_max_age(cache_control: Option<&str>) -> Option<Duration> {
    let cc = cache_control?;
    for directive in cc.split(',') {
        let directive = directive.trim();
        if let Some(rest) = directive.strip_prefix("max-age=") {
            if let Ok(secs) = rest.trim().parse::<u64>() {
                return Some(Duration::from_secs(secs));
            }
        }
    }
    None
}

/// Perform an HTTP fetch of the JWKS, using `If-None-Match` when an ETag is known.
async fn fetch(
    client: &reqwest::Client,
    api_url: &str,
    current_etag: Option<&str>,
) -> Result<FetchOutcome, DuckvisError> {
    let url = format!("{}/.well-known/jwks.json", api_url.trim_end_matches('/'));
    let mut req = client.get(&url);
    if let Some(etag) = current_etag {
        req = req.header(reqwest::header::IF_NONE_MATCH, etag);
    }

    let resp = req.send().await.map_err(|e| {
        warn!(error = %e, "jwks fetch failed");
        DuckvisError::Unavailable
    })?;

    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        debug!("jwks not modified (304)");
        return Ok(FetchOutcome::NotModified);
    }

    if !resp.status().is_success() {
        warn!(status = %resp.status(), "jwks fetch non-success status");
        return Err(DuckvisError::Unavailable);
    }

    let etag = resp
        .headers()
        .get(reqwest::header::ETAG)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let max_age = parse_max_age(
        resp.headers()
            .get(reqwest::header::CACHE_CONTROL)
            .and_then(|v| v.to_str().ok()),
    );

    let body: JwksBody = resp.json().await.map_err(|e| {
        warn!(error = %e, "jwks body parse failed");
        DuckvisError::Unavailable
    })?;

    let mut keys = HashMap::new();
    for entry in &body.keys {
        if let Some(vk) = parse_okp_key(entry) {
            keys.insert(entry.kid.clone(), vk);
        } else {
            debug!(kid = %entry.kid, "skipping unusable jwk entry");
        }
    }

    Ok(FetchOutcome::Updated {
        keys,
        etag,
        max_age,
    })
}

/// Refresh the cache from the network. `forced` indicates an unknown-kid refresh,
/// which is rate-limited by [`FORCED_REFRESH_FLOOR`] via `can_force_refresh`.
pub async fn refresh(
    cache: &tokio::sync::RwLock<JwksCache>,
    client: &reqwest::Client,
    api_url: &str,
    forced: bool,
) -> Result<(), DuckvisError> {
    let current_etag = {
        let guard = cache.read().await;
        guard.etag.clone()
    };

    let outcome = fetch(client, api_url, current_etag.as_deref()).await?;

    let mut guard = cache.write().await;
    if forced {
        guard.mark_forced();
    }
    guard.apply(outcome);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_max_age_extracts_value() {
        assert_eq!(
            parse_max_age(Some("public, max-age=300")),
            Some(Duration::from_secs(300))
        );
        assert_eq!(
            parse_max_age(Some("max-age=42, must-revalidate")),
            Some(Duration::from_secs(42))
        );
        assert_eq!(parse_max_age(Some("no-cache")), None);
        assert_eq!(parse_max_age(None), None);
    }

    #[test]
    fn new_cache_is_stale() {
        let cache = JwksCache::new(300);
        assert!(cache.is_stale());
        assert!(cache.can_force_refresh());
        assert!(cache.get("any").is_none());
    }

    #[test]
    fn parse_okp_key_rejects_wrong_kty() {
        let entry = JwkEntry {
            kty: "RSA".to_string(),
            crv: None,
            kid: "k".to_string(),
            x: URL_SAFE_NO_PAD.encode([0u8; 32]),
        };
        assert!(parse_okp_key(&entry).is_none());
    }
}
