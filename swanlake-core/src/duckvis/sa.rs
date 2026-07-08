//! Service-account (SA) token manager (contract C5).
//!
//! Mints an `aud=duckvis-api` access token via the client-credentials flow
//! (`POST {api}/v1/auth/oauth/token`, HTTP Basic auth) and caches it. Refreshes
//! proactively when fewer than 60s remain, and supports a single forced re-mint
//! after a downstream 401. Single-flight is provided by the caller holding the
//! `Mutex<Option<SaToken>>`.

use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine;
use serde::Deserialize;
use tracing::{debug, warn};

use super::DuckvisError;

/// Refresh the SA token when fewer than this many seconds remain.
const REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// A cached service-account access token with its computed expiry.
#[derive(Clone)]
pub struct SaToken {
    pub access_token: String,
    expires_at: Instant,
}

impl SaToken {
    fn is_fresh(&self) -> bool {
        // Fresh if it will remain valid beyond the refresh margin.
        self.expires_at
            .checked_duration_since(Instant::now())
            .is_some_and(|remaining| remaining > REFRESH_MARGIN)
    }
}

#[derive(Debug, Deserialize)]
struct OAuthTokenResponse {
    access_token: String,
    #[serde(default)]
    expires_in: Option<u64>,
}

/// Mint a fresh SA token via the client-credentials grant.
async fn mint(
    client: &reqwest::Client,
    api_url: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<SaToken, DuckvisError> {
    let url = format!("{}/v1/auth/oauth/token", api_url.trim_end_matches('/'));
    let basic = BASE64_STD.encode(format!("{client_id}:{client_secret}"));

    let params = [
        ("grant_type", "client_credentials"),
        ("resource", "duckvis-api"),
    ];

    let resp = client
        .post(&url)
        .header(
            reqwest::header::AUTHORIZATION,
            format!("Basic {basic}"),
        )
        .form(&params)
        .send()
        .await
        .map_err(|e| {
            warn!(error = %e, "SA token mint request failed");
            DuckvisError::Unavailable
        })?;

    if !resp.status().is_success() {
        warn!(status = %resp.status(), "SA token mint non-success status");
        return Err(DuckvisError::Unavailable);
    }

    let body: OAuthTokenResponse = resp.json().await.map_err(|e| {
        warn!(error = %e, "SA token response parse failed");
        DuckvisError::Unavailable
    })?;

    let ttl = body.expires_in.unwrap_or(600);
    let expires_at = Instant::now() + Duration::from_secs(ttl);
    debug!(ttl_secs = ttl, "minted SA token");

    Ok(SaToken {
        access_token: body.access_token,
        expires_at,
    })
}

/// Return a valid SA access token, minting/refreshing under the provided lock if
/// the cache is empty or near expiry. Single-flight via the held mutex guard.
pub async fn get_token(
    cache: &tokio::sync::Mutex<Option<SaToken>>,
    client: &reqwest::Client,
    api_url: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<String, DuckvisError> {
    let mut guard = cache.lock().await;
    if let Some(tok) = guard.as_ref() {
        if tok.is_fresh() {
            return Ok(tok.access_token.clone());
        }
    }
    let fresh = mint(client, api_url, client_id, client_secret).await?;
    let token = fresh.access_token.clone();
    *guard = Some(fresh);
    Ok(token)
}

/// Force a re-mint (used after a downstream 401). Invalidates the cache and mints
/// a new token, returning it.
pub async fn force_refresh(
    cache: &tokio::sync::Mutex<Option<SaToken>>,
    client: &reqwest::Client,
    api_url: &str,
    client_id: &str,
    client_secret: &str,
) -> Result<String, DuckvisError> {
    let mut guard = cache.lock().await;
    *guard = None;
    let fresh = mint(client, api_url, client_id, client_secret).await?;
    let token = fresh.access_token.clone();
    *guard = Some(fresh);
    Ok(token)
}
