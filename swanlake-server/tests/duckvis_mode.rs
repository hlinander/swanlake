//! Integration tests for duckvis mode.
//!
//! Each test spins up:
//!  - an in-process axum mock of duckvis-api (jwks.json, oauth/token,
//!    authz/check, authz/resolve-attachment) on an ephemeral port, and
//!  - the swanlake Flight service (with duckvis config pointing at the mock) on
//!    an ephemeral port,
//! then drives the server with the raw arrow-flight tonic client, setting gRPC
//! metadata directly.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arrow_flight::flight_service_client::FlightServiceClient;
use arrow_flight::{Action, FlightDescriptor, Ticket};
use base64::engine::general_purpose::{STANDARD as BASE64_STD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use ed25519_dalek::{Signature, Signer as _, SigningKey};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tonic::transport::Channel;
use tonic::Request;

use swanlake_core::config::{ServerConfig, SessionIdMode};
use swanlake_core::engine::EngineFactory;
use swanlake_core::metrics::Metrics;
use swanlake_core::service::SwanFlightService;
use swanlake_core::session::registry::SessionRegistry;

const SEED_K1: [u8; 32] = [0x11; 32];
const KID_K1: &str = "SniHfEoJJvxdXLKCu0XBHA";
const ISS: &str = "https://api.duckvis.test";

/// Seed of the swanlake service-account signing key (distinct from the
/// duckvis-api token-signing key above) and the SA client id (SSA name).
const SA_SEED: [u8; 32] = [0x33; 32];
const SA_CLIENT_ID: &str = "swanlake-rs";

// ---------------------------------------------------------------------------
// Token minting (mirrors duckvis-api signing.rs)
// ---------------------------------------------------------------------------

fn signing_key() -> SigningKey {
    SigningKey::from_bytes(&SEED_K1)
}

fn now_secs() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn mint_with(kid: &str, claims: &Value) -> String {
    let header = json!({ "alg": "EdDSA", "typ": "JWT", "kid": kid });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string().as_bytes()),
        URL_SAFE_NO_PAD.encode(claims.to_string().as_bytes()),
    );
    let sig = signing_key().sign(signing_input.as_bytes());
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(sig.to_bytes()))
}

fn user_claims(sub: &str) -> Value {
    let now = now_secs();
    json!({
        "sub": sub,
        "aud": "swanlake",
        "iss": ISS,
        "exp": now + 600,
        "iat": now,
        "nbf": now,
        "jti": "jti-user",
        "actor_kind": "human",
    })
}

fn valid_token(sub: &str) -> String {
    mint_with(KID_K1, &user_claims(sub))
}

fn jwk_x() -> String {
    URL_SAFE_NO_PAD.encode(signing_key().verifying_key().to_bytes())
}

fn jwks_body() -> Value {
    json!({
        "keys": [{
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "use": "sig",
            "kid": KID_K1,
            "x": jwk_x(),
        }]
    })
}

// ---------------------------------------------------------------------------
// Mock duckvis-api (axum)
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    /// Number of times jwks.json was fetched.
    jwks_hits: AtomicU64,
    /// authz/check returns this allow value.
    check_allow: AtomicBool,
    /// resolve-attachment returns this allow value.
    resolve_allow: AtomicBool,
    /// The secret_config to serve from resolve-attachment.
    secret_config: Mutex<String>,
    /// The attachment name/id served.
    attachment_name: Mutex<String>,
    attachment_id: Mutex<String>,
    /// When true, authz endpoints return HTTP 500.
    fail_500: AtomicBool,
    /// Provided ETag for jwks.
    etag: Mutex<String>,
}

impl MockState {
    fn new() -> Self {
        let s = MockState::default();
        s.check_allow.store(true, Ordering::SeqCst);
        s.resolve_allow.store(true, Ordering::SeqCst);
        *s.secret_config.lock().unwrap_or_else(|p| p.into_inner()) = String::new();
        *s.attachment_name.lock().unwrap_or_else(|p| p.into_inner()) = "attname".to_string();
        *s.attachment_id.lock().unwrap_or_else(|p| p.into_inner()) =
            "11111111-1111-1111-1111-111111111111".to_string();
        *s.etag.lock().unwrap_or_else(|p| p.into_inner()) = "\"etag-v1\"".to_string();
        s
    }
}

async fn spawn_mock_api(state: Arc<MockState>) -> String {
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{get, post};
    use axum::Json;

    async fn jwks(
        State(state): State<Arc<MockState>>,
        headers: HeaderMap,
    ) -> impl IntoResponse {
        state.jwks_hits.fetch_add(1, Ordering::SeqCst);
        let etag = state
            .etag
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        if let Some(inm) = headers.get(axum::http::header::IF_NONE_MATCH) {
            if inm.to_str().ok() == Some(etag.as_str()) {
                return (StatusCode::NOT_MODIFIED, HeaderMap::new(), String::new())
                    .into_response();
            }
        }
        let mut resp_headers = HeaderMap::new();
        resp_headers.insert(
            axum::http::header::ETAG,
            etag.parse().unwrap_or_else(|_| "\"e\"".parse().unwrap()),
        );
        resp_headers.insert(
            axum::http::header::CACHE_CONTROL,
            "max-age=300".parse().unwrap(),
        );
        (
            StatusCode::OK,
            resp_headers,
            jwks_body().to_string(),
        )
            .into_response()
    }

    /// Validate the RFC 7523 signed-JWT client assertion swanlake must send
    /// (contract C5): frozen header, iss/sub = SA client id, aud = issuer,
    /// exp = iat + 240, Ed25519 signature over `b64(header).b64(claims)`.
    fn verify_sa_assertion(jws: &str) -> bool {
        let parts: Vec<&str> = jws.split('.').collect();
        let [h, p, s] = parts.as_slice() else {
            return false;
        };
        let Ok(header) = URL_SAFE_NO_PAD.decode(h) else {
            return false;
        };
        if header != br#"{"alg":"EdDSA","typ":"JWT"}"# {
            return false;
        }
        let Ok(sig_bytes) = URL_SAFE_NO_PAD.decode(s) else {
            return false;
        };
        let Ok(sig_bytes) = <[u8; 64]>::try_from(sig_bytes) else {
            return false;
        };
        let vk = SigningKey::from_bytes(&SA_SEED).verifying_key();
        let signing_input = format!("{h}.{p}");
        if vk
            .verify_strict(signing_input.as_bytes(), &Signature::from_bytes(&sig_bytes))
            .is_err()
        {
            return false;
        }
        let Ok(claims) = URL_SAFE_NO_PAD
            .decode(p)
            .map_err(|_| ())
            .and_then(|b| serde_json::from_slice::<Value>(&b).map_err(|_| ()))
        else {
            return false;
        };
        let str_claim = |k: &str| claims.get(k).and_then(Value::as_str);
        let int_claim = |k: &str| claims.get(k).and_then(Value::as_i64);
        let (Some(iat), Some(exp)) = (int_claim("iat"), int_claim("exp")) else {
            return false;
        };
        str_claim("iss") == Some(SA_CLIENT_ID)
            && str_claim("sub") == Some(SA_CLIENT_ID)
            && str_claim("aud") == Some(ISS)
            && exp == iat + 240
            && (iat - now_secs()).abs() <= 300
    }

    async fn oauth_token(
        axum::extract::Form(params): axum::extract::Form<
            std::collections::HashMap<String, String>,
        >,
    ) -> impl IntoResponse {
        let ok = params.get("grant_type").map(String::as_str) == Some("client_credentials")
            && params.get("client_assertion_type").map(String::as_str)
                == Some("urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
            && params.get("resource").map(String::as_str) == Some("duckvis-api")
            && params
                .get("client_assertion")
                .is_some_and(|a| verify_sa_assertion(a));
        if !ok {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({ "error": "invalid_client" })),
            )
                .into_response();
        }
        Json(json!({
            "access_token": "sa-access-token",
            "token_type": "Bearer",
            "expires_in": 600,
        }))
        .into_response()
    }

    async fn authz_check(State(state): State<Arc<MockState>>) -> impl IntoResponse {
        if state.fail_500.load(Ordering::SeqCst) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({}))).into_response();
        }
        let allow = state.check_allow.load(Ordering::SeqCst);
        (StatusCode::OK, Json(json!({ "allow": allow }))).into_response()
    }

    async fn resolve_attachment(State(state): State<Arc<MockState>>) -> impl IntoResponse {
        if state.fail_500.load(Ordering::SeqCst) {
            return (StatusCode::INTERNAL_SERVER_ERROR, Json(json!({}))).into_response();
        }
        if !state.resolve_allow.load(Ordering::SeqCst) {
            return (StatusCode::OK, Json(json!({ "allow": false }))).into_response();
        }
        let secret = state
            .secret_config
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let name = state
            .attachment_name
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        let id = state
            .attachment_id
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        (
            StatusCode::OK,
            Json(json!({
                "allow": true,
                "attachment_id": id,
                "name": name,
                "kind": "connection",
                "secret_config": secret,
            })),
        )
            .into_response()
    }

    let app = axum::Router::new()
        .route("/.well-known/jwks.json", get(jwks))
        .route("/v1/auth/oauth/token", post(oauth_token))
        .route("/v1/authz/check", post(authz_check))
        .route("/v1/authz/resolve-attachment", post(resolve_attachment))
        .with_state(state);

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock api");
    let addr = listener.local_addr().expect("mock addr");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{addr}")
}

// ---------------------------------------------------------------------------
// Swanlake Flight server harness
// ---------------------------------------------------------------------------

struct Harness {
    endpoint: String,
    mock: Arc<MockState>,
}

async fn spawn_server(api_url: &str, mock: Arc<MockState>) -> Harness {
    let config = ServerConfig {
        duckvis_enabled: true,
        duckvis_api_url: Some(api_url.to_string()),
        duckvis_issuer: Some(ISS.to_string()),
        duckvis_client_id: Some(SA_CLIENT_ID.to_string()),
        duckvis_private_key: Some(swanlake_core::config::DuckvisPrivateKey::new(
            BASE64_STD.encode(SA_SEED),
        )),
        session_id_mode: SessionIdMode::PeerAddr,
        ..ServerConfig::default()
    };

    let factory = Arc::new(EngineFactory::new_without_extension_bootstrap(&config));
    let registry = Arc::new(SessionRegistry::new(&config, factory).expect("registry"));
    let metrics = Arc::new(Metrics::new(1_000, 64));
    let duckvis = swanlake_core::duckvis::DuckvisAuth::from_config(&config)
        .expect("duckvis config")
        .expect("duckvis enabled");

    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind server");
    let addr: SocketAddr = listener.local_addr().expect("server addr");
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);

    let service = SwanFlightService::with_duckvis(
        registry,
        metrics,
        SessionIdMode::PeerAddr,
        format!("grpc://{addr}"),
        Some(duckvis),
    );

    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(
                arrow_flight::flight_service_server::FlightServiceServer::new(service),
            )
            .serve_with_incoming(incoming)
            .await;
    });

    // Give the server a moment to start accepting connections.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    Harness {
        endpoint: format!("http://{addr}"),
        mock,
    }
}

async fn client(endpoint: &str) -> FlightServiceClient<Channel> {
    let channel = Channel::from_shared(endpoint.to_string())
        .expect("channel")
        .connect()
        .await
        .expect("connect");
    FlightServiceClient::new(channel)
}

/// Build a request with the given metadata headers set.
fn with_headers<T>(msg: T, headers: &[(&str, &str)]) -> Request<T> {
    use tonic::metadata::{MetadataKey, MetadataValue};
    let mut req = Request::new(msg);
    for (k, v) in headers {
        let key = MetadataKey::from_bytes(k.as_bytes()).expect("metadata key");
        let value: MetadataValue<_> = v.parse().expect("metadata value");
        req.metadata_mut().insert(key, value);
    }
    req
}

fn auth_headers<'a>(token: &'a str, session: &'a str) -> Vec<(&'a str, &'a str)> {
    vec![
        ("authorization", token),
        ("airport-client-session-id", session),
    ]
}

/// Run a `session_info` action and return the resulting tonic status (Ok on
/// success).
async fn session_info(
    cli: &mut FlightServiceClient<Channel>,
    headers: &[(&str, &str)],
) -> Result<(), tonic::Status> {
    let action = Action {
        r#type: "session_info".to_string(),
        body: Default::default(),
    };
    let mut stream = cli.do_action(with_headers(action, headers)).await?.into_inner();
    // Drain the stream.
    while let Some(item) = futures::StreamExt::next(&mut stream).await {
        item?;
    }
    Ok(())
}

/// Run a `duckvis_attach` action, returning the parsed JSON result on success.
async fn duckvis_attach(
    cli: &mut FlightServiceClient<Channel>,
    headers: &[(&str, &str)],
    bind_id: &str,
) -> Result<Value, tonic::Status> {
    let body = json!({ "bind_id": bind_id }).to_string();
    let action = Action {
        r#type: "duckvis_attach".to_string(),
        body: body.into_bytes().into(),
    };
    let mut stream = cli.do_action(with_headers(action, headers)).await?.into_inner();
    let first = futures::StreamExt::next(&mut stream)
        .await
        .ok_or_else(|| tonic::Status::internal("empty duckvis_attach stream"))??;
    serde_json::from_slice(&first.body)
        .map_err(|e| tonic::Status::internal(format!("bad json: {e}")))
}

/// Run a `duckvis_attach` action with a raw (possibly malformed) body.
async fn duckvis_attach_raw(
    cli: &mut FlightServiceClient<Channel>,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<Value, tonic::Status> {
    let action = Action {
        r#type: "duckvis_attach".to_string(),
        body: body.to_vec().into(),
    };
    let mut stream = cli.do_action(with_headers(action, headers)).await?.into_inner();
    let first = futures::StreamExt::next(&mut stream)
        .await
        .ok_or_else(|| tonic::Status::internal("empty stream"))??;
    serde_json::from_slice(&first.body)
        .map_err(|e| tonic::Status::internal(format!("bad json: {e}")))
}

/// Run arbitrary SQL via the "execute" action (msgpack `{sql}` body). Used to
/// exercise the C6 guard on the statement-execution path.
async fn execute_sql_action(
    cli: &mut FlightServiceClient<Channel>,
    headers: &[(&str, &str)],
    sql: &str,
) -> Result<(), tonic::Status> {
    #[derive(serde::Serialize)]
    struct Params<'a> {
        sql: &'a str,
    }
    let body = rmp_serde::to_vec_named(&Params { sql }).expect("encode");
    let action = Action {
        r#type: "execute".to_string(),
        body: body.into(),
    };
    let mut stream = cli.do_action(with_headers(action, headers)).await?.into_inner();
    while let Some(item) = futures::StreamExt::next(&mut stream).await {
        item?;
    }
    Ok(())
}

/// Run SQL passed directly as the action *type* (Airport DDL pattern).
async fn action_type_sql(
    cli: &mut FlightServiceClient<Channel>,
    headers: &[(&str, &str)],
    sql: &str,
) -> Result<(), tonic::Status> {
    let action = Action {
        r#type: sql.to_string(),
        body: Default::default(),
    };
    let mut stream = cli.do_action(with_headers(action, headers)).await?.into_inner();
    while let Some(item) = futures::StreamExt::next(&mut stream).await {
        item?;
    }
    Ok(())
}

/// Run a raw-SQL SELECT via the get_flight_info + do_get passthrough. Returns the
/// number of data batches received (proves the query executed end to end).
async fn run_select(
    cli: &mut FlightServiceClient<Channel>,
    headers: &[(&str, &str)],
    sql: &str,
) -> Result<usize, tonic::Status> {
    let descriptor = FlightDescriptor::new_cmd(sql.to_string());
    let info = cli
        .get_flight_info(with_headers(descriptor, headers))
        .await?
        .into_inner();
    let mut batches = 0usize;
    for ep in info.endpoint {
        if let Some(ticket) = ep.ticket {
            let ticket = Ticket {
                ticket: ticket.ticket,
            };
            let mut stream = cli.do_get(with_headers(ticket, headers)).await?.into_inner();
            while let Some(item) = futures::StreamExt::next(&mut stream).await {
                let data = item?;
                if !data.data_header.is_empty() {
                    batches += 1;
                }
            }
        }
    }
    Ok(batches)
}

const SESSION: &str = "test-session-1";
const WORKSPACE: &str = "22222222-2222-2222-2222-222222222222";
const BIND_ID: &str = "33333333-3333-3333-3333-333333333333";

fn ws_headers<'a>(token: &'a str, session: &'a str, workspace: &'a str) -> Vec<(&'a str, &'a str)> {
    let mut h = auth_headers(token, session);
    h.push(("x-duckvis-workspace-id", workspace));
    h
}

async fn base_harness() -> Harness {
    let mock = Arc::new(MockState::new());
    let api_url = spawn_mock_api(mock.clone()).await;
    spawn_server(&api_url, mock).await
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn no_token_is_unauthenticated_on_actions() {
    let h = base_harness().await;
    let mut cli = client(&h.endpoint).await;
    let headers = vec![("airport-client-session-id", SESSION)];
    let err = session_info(&mut cli, &headers).await.expect_err("should fail");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn no_token_is_unauthenticated_on_get_flight_info() {
    let h = base_harness().await;
    let mut cli = client(&h.endpoint).await;
    let headers = vec![("airport-client-session-id", SESSION)];
    let err = run_select(&mut cli, &headers, "SELECT 1")
        .await
        .expect_err("should fail");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn wrong_aud_is_unauthenticated() {
    let h = base_harness().await;
    let mut cli = client(&h.endpoint).await;
    let mut claims = user_claims("user-1");
    claims["aud"] = json!("duckvis-api");
    let token = format!("Bearer {}", mint_with(KID_K1, &claims));
    let headers = ws_headers(&token, SESSION, WORKSPACE);
    let err = session_info(&mut cli, &headers).await.expect_err("fail");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn wrong_iss_is_unauthenticated() {
    let h = base_harness().await;
    let mut cli = client(&h.endpoint).await;
    let mut claims = user_claims("user-1");
    claims["iss"] = json!("https://evil.example");
    let token = format!("Bearer {}", mint_with(KID_K1, &claims));
    let headers = ws_headers(&token, SESSION, WORKSPACE);
    let err = session_info(&mut cli, &headers).await.expect_err("fail");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn expired_token_is_unauthenticated() {
    let h = base_harness().await;
    let mut cli = client(&h.endpoint).await;
    let mut claims = user_claims("user-1");
    let now = now_secs();
    claims["exp"] = json!(now - 3600);
    claims["nbf"] = json!(now - 3700);
    let token = format!("Bearer {}", mint_with(KID_K1, &claims));
    let headers = ws_headers(&token, SESSION, WORKSPACE);
    let err = session_info(&mut cli, &headers).await.expect_err("fail");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}

#[tokio::test]
async fn unknown_kid_triggers_jwks_refetch() {
    let h = base_harness().await;
    let mut cli = client(&h.endpoint).await;
    // A token signed under a kid the server has never seen forces a JWKS
    // refetch. It still fails (the kid is not in the served set), but the mock
    // must have been hit more than once.
    let token = format!("Bearer {}", mint_with("unknown-kid-xyz", &user_claims("user-1")));
    let headers = ws_headers(&token, SESSION, WORKSPACE);
    let err = session_info(&mut cli, &headers).await.expect_err("fail");
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
    // Initial stale-cache fetch + forced unknown-kid refetch ⇒ ≥ 2 hits.
    assert!(
        h.mock.jwks_hits.load(Ordering::SeqCst) >= 2,
        "expected a forced jwks refetch on unknown kid"
    );
}

#[tokio::test]
async fn missing_workspace_header_is_invalid_argument() {
    let h = base_harness().await;
    let mut cli = client(&h.endpoint).await;
    let token = format!("Bearer {}", valid_token("user-1"));
    // No x-duckvis-workspace-id on the session-creating request.
    let headers = auth_headers(&token, SESSION);
    let err = session_info(&mut cli, &headers).await.expect_err("fail");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn authz_check_deny_is_permission_denied() {
    let h = base_harness().await;
    h.mock.check_allow.store(false, Ordering::SeqCst);
    let mut cli = client(&h.endpoint).await;
    let token = format!("Bearer {}", valid_token("user-1"));
    let headers = ws_headers(&token, SESSION, WORKSPACE);
    let err = session_info(&mut cli, &headers).await.expect_err("fail");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn happy_path_attach_select_detach() {
    // Create a real temp duckdb file for the ATTACH to target.
    let dir = tempfile::tempdir().expect("tempdir");
    let db_path = dir.path().join("wh.duckdb");
    {
        let conn = duckdb::Connection::open(&db_path).expect("open temp db");
        conn.execute_batch("CREATE TABLE t(id INTEGER); INSERT INTO t VALUES (7);")
            .expect("seed temp db");
    }
    let db_path_str = db_path.to_string_lossy().replace('\\', "/");

    let mock = Arc::new(MockState::new());
    *mock.secret_config.lock().unwrap_or_else(|p| p.into_inner()) =
        format!("ATTACH '{db_path_str}' AS ignored_alias");
    *mock.attachment_name.lock().unwrap_or_else(|p| p.into_inner()) = "wh".to_string();
    let api_url = spawn_mock_api(mock.clone()).await;
    let h = spawn_server(&api_url, mock).await;

    let mut cli = client(&h.endpoint).await;
    let token = format!("Bearer {}", valid_token("user-1"));
    let headers = ws_headers(&token, SESSION, WORKSPACE);

    // Create the session first (session_info) so the workspace binding is set.
    session_info(&mut cli, &headers).await.expect("session_info");

    // duckvis_attach.
    let result = duckvis_attach(&mut cli, &headers, BIND_ID)
        .await
        .expect("attach ok");
    assert_eq!(result["name"], json!("wh"));
    assert_eq!(
        result["attachment_id"],
        json!("11111111-1111-1111-1111-111111111111")
    );

    // Cross-catalog SELECT works.
    let batches = run_select(&mut cli, &headers, "SELECT id FROM wh.t")
        .await
        .expect("select ok");
    assert!(batches >= 1, "expected data from cross-catalog select");

    // DETACH is allowed.
    execute_sql_action(&mut cli, &headers, "DETACH wh")
        .await
        .expect("detach ok");
}

#[tokio::test]
async fn raw_attach_rejected_via_execute_action() {
    let h = base_harness().await;
    let mut cli = client(&h.endpoint).await;
    let token = format!("Bearer {}", valid_token("user-1"));
    let headers = ws_headers(&token, SESSION, WORKSPACE);
    session_info(&mut cli, &headers).await.expect("session");

    let err = execute_sql_action(&mut cli, &headers, "ATTACH 'x.db' AS x")
        .await
        .expect_err("should be denied");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn raw_attach_rejected_via_action_type_sql() {
    let h = base_harness().await;
    let mut cli = client(&h.endpoint).await;
    let token = format!("Bearer {}", valid_token("user-1"));
    let headers = ws_headers(&token, SESSION, WORKSPACE);
    session_info(&mut cli, &headers).await.expect("session");

    let err = action_type_sql(&mut cli, &headers, "ATTACH 'x.db' AS x")
        .await
        .expect_err("should be denied");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn raw_attach_rejected_in_multi_statement_batch() {
    let h = base_harness().await;
    let mut cli = client(&h.endpoint).await;
    let token = format!("Bearer {}", valid_token("user-1"));
    let headers = ws_headers(&token, SESSION, WORKSPACE);
    session_info(&mut cli, &headers).await.expect("session");

    let err = execute_sql_action(&mut cli, &headers, "SELECT 1; ATTACH 'x.db' AS x")
        .await
        .expect_err("should be denied");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn malformed_attach_body_is_invalid_argument() {
    let h = base_harness().await;
    let mut cli = client(&h.endpoint).await;
    let token = format!("Bearer {}", valid_token("user-1"));
    let headers = ws_headers(&token, SESSION, WORKSPACE);
    session_info(&mut cli, &headers).await.expect("session");

    // Not JSON at all.
    let err = duckvis_attach_raw(&mut cli, &headers, b"not-json")
        .await
        .expect_err("should be invalid");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // JSON, but bind_id is not a uuid.
    let bad = json!({ "bind_id": "not-a-uuid" }).to_string();
    let err = duckvis_attach_raw(&mut cli, &headers, bad.as_bytes())
        .await
        .expect_err("should be invalid");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);
}

#[tokio::test]
async fn resolve_deny_is_permission_denied() {
    let mock = Arc::new(MockState::new());
    mock.resolve_allow.store(false, Ordering::SeqCst);
    let api_url = spawn_mock_api(mock.clone()).await;
    let h = spawn_server(&api_url, mock).await;

    let mut cli = client(&h.endpoint).await;
    let token = format!("Bearer {}", valid_token("user-1"));
    let headers = ws_headers(&token, SESSION, WORKSPACE);
    session_info(&mut cli, &headers).await.expect("session");

    let err = duckvis_attach(&mut cli, &headers, BIND_ID)
        .await
        .expect_err("should be denied");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn api_500_is_unavailable() {
    let mock = Arc::new(MockState::new());
    let api_url = spawn_mock_api(mock.clone()).await;
    let h = spawn_server(&api_url, mock.clone()).await;

    let mut cli = client(&h.endpoint).await;
    let token = format!("Bearer {}", valid_token("user-1"));
    let headers = ws_headers(&token, SESSION, WORKSPACE);

    // Make authz/check return 500 → the session-creating request is unavailable.
    h.mock.fail_500.store(true, Ordering::SeqCst);
    let err = session_info(&mut cli, &headers).await.expect_err("fail");
    assert_eq!(err.code(), tonic::Code::Unavailable);
}

#[tokio::test]
async fn second_client_different_subject_is_permission_denied() {
    let h = base_harness().await;
    let mut cli = client(&h.endpoint).await;

    // First client binds the session to user-1.
    let token1 = format!("Bearer {}", valid_token("user-1"));
    let headers1 = ws_headers(&token1, SESSION, WORKSPACE);
    session_info(&mut cli, &headers1).await.expect("session1");

    // Second client, different subject, reuses the same session id.
    let token2 = format!("Bearer {}", valid_token("user-2"));
    let headers2 = auth_headers(&token2, SESSION);
    let err = session_info(&mut cli, &headers2)
        .await
        .expect_err("should be denied");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn workspace_header_mismatch_is_permission_denied() {
    let h = base_harness().await;
    let mut cli = client(&h.endpoint).await;
    let token = format!("Bearer {}", valid_token("user-1"));
    let headers = ws_headers(&token, SESSION, WORKSPACE);
    session_info(&mut cli, &headers).await.expect("session");

    // Same subject/session but a different workspace header → denied.
    let other_ws = "44444444-4444-4444-4444-444444444444";
    let headers2 = ws_headers(&token, SESSION, other_ws);
    let err = session_info(&mut cli, &headers2)
        .await
        .expect_err("should be denied");
    assert_eq!(err.code(), tonic::Code::PermissionDenied);
}

#[tokio::test]
async fn duckvis_attach_unimplemented_when_mode_off() {
    // Server with duckvis mode OFF.
    let config = ServerConfig {
        session_id_mode: SessionIdMode::PeerAddr,
        ..ServerConfig::default()
    };
    let factory = Arc::new(EngineFactory::new_without_extension_bootstrap(&config));
    let registry = Arc::new(SessionRegistry::new(&config, factory).expect("registry"));
    let metrics = Arc::new(Metrics::new(1_000, 64));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr: SocketAddr = listener.local_addr().expect("addr");
    let incoming = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let service = SwanFlightService::new(
        registry,
        metrics,
        SessionIdMode::PeerAddr,
        format!("grpc://{addr}"),
    );
    tokio::spawn(async move {
        let _ = tonic::transport::Server::builder()
            .add_service(arrow_flight::flight_service_server::FlightServiceServer::new(service))
            .serve_with_incoming(incoming)
            .await;
    });
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let mut cli = client(&format!("http://{addr}")).await;
    // No auth headers needed when mode is off; the handler short-circuits to
    // unimplemented before touching the auth gate.
    let headers = vec![("airport-client-session-id", SESSION)];
    let err = duckvis_attach(&mut cli, &headers, BIND_ID)
        .await
        .expect_err("should be unimplemented");
    assert_eq!(err.code(), tonic::Code::Unimplemented);
}
