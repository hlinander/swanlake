//! Service-account (SA) token manager (contract C5).
//!
//! Mints an `aud=duckvis-api` access token via the client-credentials flow
//! (`POST {api}/v1/auth/oauth/token`) authenticated by an Ed25519 signed-JWT
//! client assertion (RFC 7523), and caches it. Refreshes proactively when fewer
//! than 60s remain, and supports a single forced re-mint after a downstream
//! 401. Single-flight is provided by the caller holding the
//! `Mutex<Option<SaToken>>`.

use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer as _, SigningKey};
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, warn};

use super::DuckvisError;

/// Refresh the SA token when fewer than this many seconds remain.
const REFRESH_MARGIN: Duration = Duration::from_secs(60);

/// Frozen JWS protected header for the client assertion (RFC 7515). The server
/// validates these exact bytes; do not reorder or reformat.
const ASSERTION_HEADER: &str = r#"{"alg":"EdDSA","typ":"JWT"}"#;

/// Client-assertion lifetime in seconds.
const ASSERTION_TTL_SECS: i64 = 240;

/// RFC 7523 client-assertion type for the token request form.
const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

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

/// Current unix time in seconds.
fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Build the RFC 7523 signed-JWT client assertion: a compact EdDSA JWS
/// (base64url, no padding) with `iss` = `sub` = the SA client id (the SSA
/// name), `aud` = the configured duckvis issuer URL (verbatim), `iat` =
/// `now_secs`, and `exp` = `now_secs` + [`ASSERTION_TTL_SECS`].
fn build_client_assertion(
    signing_key: &SigningKey,
    client_id: &str,
    issuer: &str,
    now_secs: i64,
) -> String {
    let claims = json!({
        "iss": client_id,
        "sub": client_id,
        "aud": issuer,
        "iat": now_secs,
        "exp": now_secs + ASSERTION_TTL_SECS,
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(ASSERTION_HEADER.as_bytes()),
        URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes()),
    );
    let sig = signing_key.sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

/// Mint a fresh SA token via the client-credentials grant, authenticating with
/// a signed-JWT client assertion (no Authorization header).
async fn mint(
    client: &reqwest::Client,
    api_url: &str,
    client_id: &str,
    issuer: &str,
    signing_key: &SigningKey,
) -> Result<SaToken, DuckvisError> {
    let url = format!("{}/v1/auth/oauth/token", api_url.trim_end_matches('/'));
    let assertion = build_client_assertion(signing_key, client_id, issuer, now_secs());

    let params = [
        ("grant_type", "client_credentials"),
        ("client_assertion_type", ASSERTION_TYPE),
        ("client_assertion", assertion.as_str()),
        ("resource", "duckvis-api"),
    ];

    let resp = client.post(&url).form(&params).send().await.map_err(|e| {
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
    issuer: &str,
    signing_key: &SigningKey,
) -> Result<String, DuckvisError> {
    let mut guard = cache.lock().await;
    if let Some(tok) = guard.as_ref() {
        if tok.is_fresh() {
            return Ok(tok.access_token.clone());
        }
    }
    let fresh = mint(client, api_url, client_id, issuer, signing_key).await?;
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
    issuer: &str,
    signing_key: &SigningKey,
) -> Result<String, DuckvisError> {
    let mut guard = cache.lock().await;
    *guard = None;
    let fresh = mint(client, api_url, client_id, issuer, signing_key).await?;
    let token = fresh.access_token.clone();
    *guard = Some(fresh);
    Ok(token)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signature, VerifyingKey};
    use serde_json::Value;

    const SEED: [u8; 32] = [0x42; 32];
    const CLIENT_ID: &str = "swanlake-wrx80";
    const ISSUER: &str = "https://api.duckvis.test";
    const NOW: i64 = 1_767_225_600;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&SEED)
    }

    fn split3(jws: &str) -> (String, String, String) {
        let parts: Vec<&str> = jws.split('.').collect();
        assert_eq!(parts.len(), 3, "assertion must be a 3-segment compact JWS");
        (
            parts[0].to_string(),
            parts[1].to_string(),
            parts[2].to_string(),
        )
    }

    #[test]
    fn assertion_header_is_frozen() {
        let jws = build_client_assertion(&signing_key(), CLIENT_ID, ISSUER, NOW);
        let (h, _, _) = split3(&jws);
        // No padding allowed in any segment.
        assert!(!h.contains('='));
        let header = URL_SAFE_NO_PAD.decode(&h).expect("header decodes");
        assert_eq!(header, br#"{"alg":"EdDSA","typ":"JWT"}"#);
    }

    #[test]
    fn assertion_claims_match_contract() {
        let jws = build_client_assertion(&signing_key(), CLIENT_ID, ISSUER, NOW);
        let (_, p, _) = split3(&jws);
        assert!(!p.contains('='));
        let claims: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(&p).expect("claims decode"))
                .expect("claims are JSON");
        let obj = claims.as_object().expect("claims are an object");
        assert_eq!(obj.get("iss").and_then(Value::as_str), Some(CLIENT_ID));
        assert_eq!(obj.get("sub").and_then(Value::as_str), Some(CLIENT_ID));
        assert_eq!(obj.get("aud").and_then(Value::as_str), Some(ISSUER));
        assert_eq!(obj.get("iat").and_then(Value::as_i64), Some(NOW));
        assert_eq!(obj.get("exp").and_then(Value::as_i64), Some(NOW + 240));
        assert_eq!(obj.len(), 5, "no extra claims");
    }

    #[test]
    fn assertion_signature_verifies() {
        let jws = build_client_assertion(&signing_key(), CLIENT_ID, ISSUER, NOW);
        let (h, p, s) = split3(&jws);
        assert!(!s.contains('='));
        let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&s)
            .expect("signature decodes")
            .try_into()
            .expect("signature is 64 bytes");
        let vk: VerifyingKey = signing_key().verifying_key();
        let signing_input = format!("{h}.{p}");
        vk.verify_strict(signing_input.as_bytes(), &Signature::from_bytes(&sig_bytes))
            .expect("Ed25519 signature verifies over header.claims");
    }

    #[test]
    fn assertion_signature_binds_to_claims() {
        let jws = build_client_assertion(&signing_key(), CLIENT_ID, ISSUER, NOW);
        let (h, _, s) = split3(&jws);
        // Swap in claims for a different client id — signature must not verify.
        let forged = build_client_assertion(&signing_key(), "other-client", ISSUER, NOW);
        let (_, forged_p, _) = split3(&forged);
        let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
            .decode(&s)
            .unwrap()
            .try_into()
            .unwrap();
        let vk = signing_key().verifying_key();
        let tampered_input = format!("{h}.{forged_p}");
        assert!(vk
            .verify_strict(tampered_input.as_bytes(), &Signature::from_bytes(&sig_bytes))
            .is_err());
    }
}
