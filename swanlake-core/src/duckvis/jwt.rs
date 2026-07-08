//! Compact-JWS (EdDSA) access-token verification.
//!
//! Hand-rolled port of duckvis-api's `validate_access` + `verify_jws`
//! (`duckvis-api/server/src/{token,signing}.rs`) for exact parity with the
//! control plane's validation semantics. Every failure collapses to a single
//! `Unauthenticated` error (contract C4: no failure-mode split).

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_json::Value;

use super::DuckvisError;

/// Symmetric clock skew allowed on `exp`/`nbf` (seconds), matching duckvis-api
/// (`CLOCK_SKEW_SECS`, 03 §6).
pub const CLOCK_SKEW_SECS: i64 = 30;

/// The `actor_kind` discriminant carried by every access token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ActorKind {
    Human,
    Service,
}

/// The validated claim subset swanlake reads off an inbound user token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DuckvisClaims {
    pub sub: String,
    pub actor_kind: ActorKind,
}

/// Audience swanlake accepts (contract C5: checked last).
const AUD_SWANLAKE: &str = "swanlake";

/// Verify a compact JWS and validate its claims against `expected_iss` at `now_secs`.
///
/// `lookup_key` resolves a `kid` (from the JWS header) to its Ed25519 verifying
/// key. It returns `None` when the kid is unknown to the current key set; callers
/// (the JWKS cache) are responsible for a refresh-and-retry before treating an
/// unknown kid as a hard failure.
///
/// Order (matching duckvis-api): parse header (`alg==EdDSA`, `kid` present) →
/// resolve key → verify signature over `header.payload` → decode claims →
/// `exp`/`nbf` within ±30s skew → `iss` exact match → `actor_kind` ∈ {human,
/// service} → `sub` non-empty → `aud == "swanlake"` checked LAST.
pub fn verify_and_decode<F>(
    jwt: &str,
    expected_iss: &str,
    now_secs: i64,
    lookup_key: F,
) -> Result<DuckvisClaims, DuckvisError>
where
    F: FnOnce(&str) -> Option<VerifyingKey>,
{
    let mut parts = jwt.split('.');
    let (h, p, s) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some(h), Some(p), Some(s), None) => (h, p, s),
        _ => return Err(DuckvisError::Unauthenticated),
    };

    // Header: require alg == "EdDSA" and a present kid.
    let header: Value = decode_json(h)?;
    if header.get("alg").and_then(Value::as_str) != Some("EdDSA") {
        return Err(DuckvisError::Unauthenticated);
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or(DuckvisError::Unauthenticated)?;

    // Resolve the verifying key for this kid.
    let vk = lookup_key(kid).ok_or(DuckvisError::Unauthenticated)?;

    // Verify the signature over the ASCII `header.payload`.
    let sig_bytes: [u8; 64] = URL_SAFE_NO_PAD
        .decode(s)
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(DuckvisError::Unauthenticated)?;
    let signing_input = format!("{h}.{p}");
    vk.verify_strict(signing_input.as_bytes(), &Signature::from_bytes(&sig_bytes))
        .map_err(|_| DuckvisError::Unauthenticated)?;

    // Decode and validate the claim set.
    let payload: Value = decode_json(p)?;
    let obj = payload.as_object().ok_or(DuckvisError::Unauthenticated)?;

    let str_claim = |k: &str| obj.get(k).and_then(Value::as_str);
    let int_claim = |k: &str| obj.get(k).and_then(Value::as_i64);

    let exp = int_claim("exp").ok_or(DuckvisError::Unauthenticated)?;
    let nbf = int_claim("nbf").ok_or(DuckvisError::Unauthenticated)?;
    if now_secs >= exp + CLOCK_SKEW_SECS || now_secs < nbf - CLOCK_SKEW_SECS {
        return Err(DuckvisError::Unauthenticated);
    }

    if str_claim("iss") != Some(expected_iss) {
        return Err(DuckvisError::Unauthenticated);
    }

    let actor_kind = match str_claim("actor_kind") {
        Some("human") => ActorKind::Human,
        Some("service") => ActorKind::Service,
        _ => return Err(DuckvisError::Unauthenticated),
    };

    let sub = match str_claim("sub") {
        Some(s) if !s.is_empty() => s.to_string(),
        _ => return Err(DuckvisError::Unauthenticated),
    };

    // Audience is checked LAST (contract C5).
    if str_claim("aud") != Some(AUD_SWANLAKE) {
        return Err(DuckvisError::Unauthenticated);
    }

    Ok(DuckvisClaims { sub, actor_kind })
}

fn decode_json(segment: &str) -> Result<Value, DuckvisError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| DuckvisError::Unauthenticated)?;
    serde_json::from_slice(&bytes).map_err(|_| DuckvisError::Unauthenticated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    // Fixed seed oracle from duckvis-api e2e/src/keys.rs.
    const SEED_K1: [u8; 32] = [0x11; 32];
    const KID_K1: &str = "SniHfEoJJvxdXLKCu0XBHA";
    const X_K1: &str = "0EqyMnQrtKs6E2i9RhXk5tAiSrcaAWuvhSCjMsl3hzc";
    const ISS: &str = "https://api.duckvis.test";
    const NOW: i64 = 1_767_225_600;

    fn signing_key() -> SigningKey {
        SigningKey::from_bytes(&SEED_K1)
    }

    fn verifying_key() -> VerifyingKey {
        signing_key().verifying_key()
    }

    /// Mint a compact EdDSA JWS mirroring duckvis-api's signing.rs (header
    /// `{alg,typ,kid}`, signature over `b64(header).b64(payload)`).
    fn mint(kid: &str, claims: &Value) -> String {
        let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid });
        let signing_input = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
            URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes()),
        );
        let sig = signing_key().sign(signing_input.as_bytes());
        format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
    }

    fn base_claims() -> Value {
        json!({
            "sub": "user-123",
            "aud": "swanlake",
            "iss": ISS,
            "exp": NOW + 600,
            "iat": NOW,
            "nbf": NOW,
            "jti": "jti-1",
            "actor_kind": "human",
        })
    }

    fn lookup(kid: &str) -> Option<VerifyingKey> {
        if kid == KID_K1 {
            Some(verifying_key())
        } else {
            None
        }
    }

    #[test]
    fn oracle_x_matches_public_key() {
        // Independent cross-check that our key bytes match the e2e oracle.
        assert_eq!(
            URL_SAFE_NO_PAD.encode(verifying_key().to_bytes()),
            X_K1
        );
    }

    #[test]
    fn valid_token_decodes() {
        let tok = mint(KID_K1, &base_claims());
        let claims = verify_and_decode(&tok, ISS, NOW, lookup).unwrap();
        assert_eq!(claims.sub, "user-123");
        assert_eq!(claims.actor_kind, ActorKind::Human);
    }

    #[test]
    fn service_actor_kind_decodes() {
        let mut c = base_claims();
        c["actor_kind"] = json!("service");
        let tok = mint(KID_K1, &c);
        let claims = verify_and_decode(&tok, ISS, NOW, lookup).unwrap();
        assert_eq!(claims.actor_kind, ActorKind::Service);
    }

    #[test]
    fn expired_beyond_skew_rejected() {
        let mut c = base_claims();
        c["exp"] = json!(NOW - 31);
        let tok = mint(KID_K1, &c);
        assert!(matches!(
            verify_and_decode(&tok, ISS, NOW, lookup),
            Err(DuckvisError::Unauthenticated)
        ));
    }

    #[test]
    fn expired_within_skew_ok() {
        // `now >= exp + skew` fails, so exp == NOW-30 is the first rejected value;
        // exp == NOW-29 is still within the grace window.
        let mut c = base_claims();
        c["exp"] = json!(NOW - 29);
        let tok = mint(KID_K1, &c);
        assert!(verify_and_decode(&tok, ISS, NOW, lookup).is_ok());
    }

    #[test]
    fn nbf_future_rejected() {
        let mut c = base_claims();
        c["nbf"] = json!(NOW + 31);
        let tok = mint(KID_K1, &c);
        assert!(matches!(
            verify_and_decode(&tok, ISS, NOW, lookup),
            Err(DuckvisError::Unauthenticated)
        ));
    }

    #[test]
    fn nbf_within_skew_ok() {
        let mut c = base_claims();
        c["nbf"] = json!(NOW + 30);
        let tok = mint(KID_K1, &c);
        assert!(verify_and_decode(&tok, ISS, NOW, lookup).is_ok());
    }

    #[test]
    fn wrong_iss_rejected() {
        let tok = mint(KID_K1, &base_claims());
        assert!(matches!(
            verify_and_decode(&tok, "https://other.example", NOW, lookup),
            Err(DuckvisError::Unauthenticated)
        ));
    }

    #[test]
    fn wrong_aud_rejected() {
        let mut c = base_claims();
        c["aud"] = json!("duckvis-api");
        let tok = mint(KID_K1, &c);
        assert!(matches!(
            verify_and_decode(&tok, ISS, NOW, lookup),
            Err(DuckvisError::Unauthenticated)
        ));
    }

    #[test]
    fn unknown_kid_rejected() {
        let tok = mint("some-other-kid", &base_claims());
        assert!(matches!(
            verify_and_decode(&tok, ISS, NOW, lookup),
            Err(DuckvisError::Unauthenticated)
        ));
    }

    #[test]
    fn tampered_signature_rejected() {
        let tok = mint(KID_K1, &base_claims());
        let mut parts: Vec<&str> = tok.split('.').collect();
        let forged = URL_SAFE_NO_PAD.encode(
            json!({
                "sub": "attacker",
                "aud": "swanlake",
                "iss": ISS,
                "exp": NOW + 600,
                "nbf": NOW,
                "actor_kind": "human",
            })
            .to_string()
            .as_bytes(),
        );
        parts[1] = &forged;
        let tampered = parts.join(".");
        assert!(matches!(
            verify_and_decode(&tampered, ISS, NOW, lookup),
            Err(DuckvisError::Unauthenticated)
        ));
    }

    #[test]
    fn missing_actor_kind_rejected() {
        let mut c = base_claims();
        c.as_object_mut().unwrap().remove("actor_kind");
        let tok = mint(KID_K1, &c);
        assert!(matches!(
            verify_and_decode(&tok, ISS, NOW, lookup),
            Err(DuckvisError::Unauthenticated)
        ));
    }

    #[test]
    fn empty_sub_rejected() {
        let mut c = base_claims();
        c["sub"] = json!("");
        let tok = mint(KID_K1, &c);
        assert!(matches!(
            verify_and_decode(&tok, ISS, NOW, lookup),
            Err(DuckvisError::Unauthenticated)
        ));
    }

    #[test]
    fn malformed_token_rejected() {
        assert!(matches!(
            verify_and_decode("only.two", ISS, NOW, lookup),
            Err(DuckvisError::Unauthenticated)
        ));
        assert!(matches!(
            verify_and_decode("a.b.c.d", ISS, NOW, lookup),
            Err(DuckvisError::Unauthenticated)
        ));
    }
}
