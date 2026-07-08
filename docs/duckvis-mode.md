# Duckvis mode — interface contracts

Swanlake can run in "duckvis mode": it holds a duckvis-api **service account**, authenticates every
Flight request against duckvis-api-issued user tokens, scopes sessions to a workspace, and resolves
admin-managed workspace attachments by bind id instead of accepting raw ATTACH SQL from users.

These contracts are frozen across three implementations: swanlake (server), duckvis-api (control
plane), and the duckvis app (client). Do not deviate without updating this document.

## C1 — `duckvis_attach` Flight action

The only way to attach a database in duckvis mode. Arrow Flight DoAction with:

- action **type**: `duckvis_attach`
- action **body**: JSON `{"bind_id": "<WorkspaceAttachment uuid>"}`
- success result: one JSON payload `{"name": "<attached alias>", "attachment_id": "<uuid>"}`

Server behavior: requires duckvis mode (`unimplemented` otherwise) and an authenticated,
workspace-bound session. Swanlake calls the C3 endpoint with the session's subject + workspace and
the given bind id; on allow it normalizes the returned statement to
`ATTACH OR REPLACE … AS "<attachment-name>" …` (alias = attachment name, options preserved) and
executes it on the session's DuckDB connection via a privileged path (bypassing the C6 guard).
The resolved statement must never appear in logs, traces, or error messages.

Client invocation (duckvis app, via the DuckDB Airport extension — same pattern as `session_info`):
`airport_action('<grpc endpoint>', 'duckvis_attach', '{"bind_id":"…"}', headers := MAP{…})`.

`DETACH <name>` stays native SQL and remains allowed.

## C2 — gRPC metadata headers (client → swanlake)

- `authorization: Bearer <jwt>` — required on **every** Flight RPC in duckvis mode.
- `x-duckvis-workspace-id: <uuid>` — required on the request that creates a session; if present on
  later requests it must equal the session's bound workspace.
- Existing headers (`airport-client-session-id`, `x-session-id`, `x-expected-session-nonce`)
  unchanged.

## C3 — duckvis-api endpoint `POST /v1/authz/resolve-attachment`

Caller class identical to `POST /v1/authz/check`: Bearer JWT with `aud=duckvis-api`,
`actor_kind=service` (operator-provisioned duckvis-api system service account, `resource-server create`). Rate-limited per caller.

Request: `{"subject":"<uuid>", "workspace_id":"<uuid>", "bind_id":"<uuid>"}`

- 200 allow: `{"allow":true, "attachment_id":"<uuid>", "name":"<str>", "kind":"connection",
  "secret_config":"<full ATTACH statement>"}`
- 200 deny (uniform fail-closed, no existence split): `{"allow":false}` — subject lacks
  `Workspace.view`; bind not live under `workspace_id`; attachment tombstoned; unresolvable subject.
- 401 `unauthenticated` / `invalid_audience`; 403 `authz_caller_forbidden` (human caller);
  400 `resolve_request_invalid` (malformed body / non-uuid workspace_id or bind_id); 429 rate-limited.

This is the **sole** surface that ever serializes `Attachment.secret_config`.

## C4 — swanlake error mapping (tonic Status)

- Missing/malformed/expired/bad-signature token, unknown kid after JWKS refresh, wrong iss/aud →
  `unauthenticated` (generic message — no failure-mode split).
- authz-check deny; token sub ≠ session subject; workspace header ≠ session workspace; resolve
  deny; raw ATTACH in user SQL (C6) → `permission_denied`.
- Missing `x-duckvis-workspace-id` at session creation; malformed `duckvis_attach` body →
  `invalid_argument`.
- `duckvis_attach` when duckvis mode is off → `unimplemented`.
- duckvis-api unreachable / 5xx → `unavailable` (client-retryable).
- Existing nonce mismatch stays `failed_precondition`.

## C5 — Token flows

- **Swanlake service account** (aud=duckvis-api): `POST /v1/auth/oauth/token`, form
  `grant_type=client_credentials` + `resource=duckvis-api`, credentials via HTTP Basic
  (`base64(client_id:client_secret)`) or body pair — never both. Response
  `{access_token, token_type, expires_in: 600}`. Refresh proactively (<60s remaining) and once on 401.
- **User tokens** (aud=swanlake): app calls `POST /v1/auth/token/refresh`
  `{refresh_token, resource:"swanlake"}` → 600s EdDSA JWT. **This rotates the refresh token
  unconditionally** — the app must persist the rotated token and serialize all refresh
  presentations (a double-spend revokes the token family → forced re-login).
- **Validation** (swanlake side): EdDSA (Ed25519) compact JWS; key by `kid` from
  `GET {api}/.well-known/jwks.json` (honor ETag + Cache-Control max-age, refetch on unknown kid);
  claims: `exp`/`nbf` with ±30s skew, `iss` exact match (configured issuer), `sub` present,
  `actor_kind` ∈ {human, service}, and `aud == "swanlake"` checked last.

## C6 — Raw ATTACH denial

In duckvis mode, user-supplied SQL must NOT contain ATTACH statements, on any entry path
(statements, updates, prepared statements, action-type SQL, execute actions, raw passthrough).
Enforced at the Session level with a quote/comment-aware top-level statement split: if any
statement's leading keyword is `ATTACH` (case-insensitive, after whitespace/comments) →
`permission_denied` with message directing to the `duckvis_attach` action. `ATTACH` inside string
literals or comments is not a match. `DETACH` remains allowed. Only the `duckvis_attach` handler's
privileged execute path may run an ATTACH.

## Swanlake configuration (env, `SWANLAKE_` prefix)

`duckvis_enabled` (bool), `duckvis_api_url`, `duckvis_issuer`, `duckvis_client_id`,
`duckvis_client_secret`, `duckvis_jwks_max_age_secs` (default 300). All required when enabled.
`duckvis_client_id` is the system service account's id (its OAuth `client_id`), and
`duckvis_client_secret` the secret minted by `resource-server key mint`.
Duckvis mode should run with in-memory per-session databases; file-based `database_path` shares the
attached catalog across sessions (DuckDB instance cache) and is rejected/warned at startup.
