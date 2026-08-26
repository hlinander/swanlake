# SwanLake Configuration

SwanLake reads all settings from environment variables using the `SWANLAKE_` prefix.
`ServerConfig::load()` merges sources in the following order:

1. Built-in defaults (see `src/config.rs`)
2. Environment variables (`SWANLAKE_*`) – values from a local `.env` file are also picked up
   because the server calls `dotenvy::dotenv()` before loading the configuration.

Unset options fall back to their defaults. All numeric values are expressed in base-10,
and boolean flags accept `true/false` (case-insensitive).

## Core Server Options

| Env Var | Description | Default |
| --- | --- | --- |
| `SWANLAKE_HOST` | gRPC bind address | `0.0.0.0` |
| `SWANLAKE_PORT` | gRPC listening port | `4214` |
| `SWANLAKE_ADVERTISE_HOST` | Host advertised in FlightEndpoint locations (the address clients use to connect back) | `localhost` |
| `SWANLAKE_MAX_SESSIONS` | Maximum concurrent sessions | `100` |
| `SWANLAKE_SESSION_TIMEOUT_SECONDS` | Idle timeout before cleanup | `900` (15 min) |
| `SWANLAKE_SESSION_ID_MODE` | Session identifier source: `peer_addr` (IP:port) or `peer_ip` (IP only) | `peer_addr` |

## Logging

| Env Var | Description | Default |
| --- | --- | --- |
| `SWANLAKE_LOG_FORMAT` | `compact` or `json` | `compact` |
| `NO_COLOR` | Disable log color if set to `true` | _(unset)_ |

## Status Page & Metrics

| Env Var | Description | Default |
| --- | --- | --- |
| `SWANLAKE_STATUS_ENABLED` | Enable the status HTTP server | `true` |
| `SWANLAKE_STATUS_HOST` | Status server bind address | `0.0.0.0` |
| `SWANLAKE_STATUS_PORT` | Status server port | `4215` |
| `SWANLAKE_STATUS_PATH_PREFIX` | Path prefix for status endpoints (e.g., `/admin` results in `/admin/` and `/admin/status.json`) | _(empty)_ |
| `SWANLAKE_METRICS_SLOW_QUERY_THRESHOLD_MS` | Slow query threshold (ms) used for tagging slow queries | `5000` |
| `SWANLAKE_METRICS_HISTORY_SIZE` | Number of latency/error/slow-query entries retained | `200` |

## Memory

| Env Var | Description | Default |
| --- | --- | --- |
| `SWANLAKE_MEMORY_LIMIT` | Override DuckDB `memory_limit` (e.g. `16GB`, `4096MB`). Bypasses auto-detection. | _(unset)_ |

When `SWANLAKE_MEMORY_LIMIT` is not set, the server auto-detects the limit using this priority:

1. **cgroup** — 70% of the cgroup memory limit (e.g. when running under `systemd-run`)
2. **`/proc/meminfo`** — `(MemTotal - 10 GB) + SwapTotal`
3. **DuckDB default** — if none of the above are available

## DuckLake / DuckDB Initialization

| Env Var | Description | Default |
| --- | --- | --- |
| `SWANLAKE_DUCKLAKE_INIT_SQL` | SQL executed after DuckDB boots (attach remote catalogs, create schemas, etc.) | _(unset)_ |
| `SWANLAKE_DUCKDB_THREADS` | Override DuckDB execution thread count | DuckDB default (`# CPU cores`) |

The server always installs/loads the DuckLake, HTTPFS, AWS, and Postgres extensions before running
any user provided SQL so long as the binaries are available.

## External Connections

| Env Var | Description | Default |
| --- | --- | --- |
| `PGPASSWORD` | Password for Postgres connection | _(unset)_ |
| `PGHOST` | Host for Postgres connection | `127.0.0.1` |
| `PGUSER` | User for Postgres connection | `postgres` |

To enable DuckLake Postgres connection, see [DuckDB Postgres extension configuration](https://duckdb.org/docs/stable/core_extensions/postgres#configuring-via-environment-variables).

| Env Var | Description | Default |
| --- | --- | --- |
| `AWS_ACCESS_KEY_ID` | Access key ID for S3 connection | _(unset)_ |
| `AWS_SECRET_ACCESS_KEY` | Secret access key for S3 connection | _(unset)_ |
| `AWS_SECRET_ACCOUNT_ID` | Account ID for S3 connection | _(unset)_ |

To enable DuckLake S3 connection, see [DuckDB HTTPFS S3 API configuration](https://duckdb.org/docs/stable/core_extensions/httpfs/s3api#platform-specific-secret-types).

## DuckLake Maintenance (Checkpointing)

SwanLake can run background DuckLake checkpoints across multiple instances. Coordination and metadata are stored in PostgreSQL (`ducklake_checkpoints` table + advisory locks).

| Env Var | Description | Default |
| --- | --- | --- |
| `SWANLAKE_CHECKPOINT_DATABASES` | Comma-separated DuckLake database names to checkpoint (e.g. `db1,db2`) | _(unset)_ (disabled) |
| `SWANLAKE_CHECKPOINT_INTERVAL_HOURS` | Interval between checkpoints per database | `24` |
| `SWANLAKE_CHECKPOINT_POLL_SECONDS` | Polling interval used to check whether each database reached its checkpoint interval | `300` |
| `PGHOST` | PostgreSQL host | `localhost` |
| `PGPORT` | PostgreSQL port | `5432` |
| `PGUSER` | PostgreSQL user | `postgres` |
| `PGDATABASE` | PostgreSQL database | `postgres` |
| `PGPASSWORD` | PostgreSQL password | _(unset)_ |
| `PGSSLMODE` | TLS mode. `disable` = plaintext, `prefer` = try TLS then fall back to plaintext, `require` = TLS without verification, `verify-ca` = TLS verifying CA only, `verify-full` = full TLS verification | `disable` |

Notes:
- If `SWANLAKE_CHECKPOINT_DATABASES` is empty/unset, the checkpoint task is not started.
- Each configured database is checkpointed at most once per interval across all running instances.
- On first startup (no existing checkpoint record), SwanLake initializes the schedule and waits until the next interval instead of running an immediate checkpoint.
- Increasing `SWANLAKE_CHECKPOINT_POLL_SECONDS` lowers background polling overhead at the cost of less precise checkpoint timing.

## Duckvis Mode

When enabled, SwanLake authenticates every Flight request against duckvis-api-issued user tokens
(EdDSA JWTs, `aud=swanlake`), scopes each session to a project, and manages database attachments
through the `duckvis_attach` Flight action instead of raw `ATTACH` SQL. Raw `ATTACH` statements are
rejected on every SQL path in this mode; `DETACH` remains available.

| Env Var | Description | Default |
| --- | --- | --- |
| `SWANLAKE_DUCKVIS_ENABLED` | Enable duckvis mode (authenticated, project-scoped sessions) | `false` |
| `SWANLAKE_DUCKVIS_API_URL` | Base URL of the duckvis-api control plane (e.g. `https://api.duckvis.example`) | _(unset)_ |
| `SWANLAKE_DUCKVIS_ISSUER` | Expected `iss` claim (exact match) on inbound user tokens | _(unset)_ |
| `SWANLAKE_DUCKVIS_CLIENT_ID` | Service-account client id for the client-credentials token flow: the resource-server service account (SSA) name (e.g. `swanlake-wrx80`) | _(unset)_ |
| `SWANLAKE_DUCKVIS_PRIVATE_KEY` | Service-account signing key: base64 (standard alphabet) of the raw 32-byte Ed25519 seed, used to sign the RFC 7523 client assertion presented to the token endpoint | _(unset)_ |
| `SWANLAKE_DUCKVIS_JWKS_MAX_AGE_SECS` | Fallback JWKS cache max-age (seconds) when the response omits `Cache-Control: max-age` | `300` |

Notes:
- When `SWANLAKE_DUCKVIS_ENABLED=true`, all four of `SWANLAKE_DUCKVIS_API_URL`,
  `SWANLAKE_DUCKVIS_ISSUER`, `SWANLAKE_DUCKVIS_CLIENT_ID`, and `SWANLAKE_DUCKVIS_PRIVATE_KEY` are
  required; startup fails otherwise. `SWANLAKE_DUCKVIS_PRIVATE_KEY` must decode to exactly 32 bytes;
  it is validated at startup and never echoed in error messages or config logging.
- Duckvis mode requires in-memory per-session databases. Setting `SWANLAKE_DATABASE_PATH` to a file
  path is rejected at startup because a file-based DuckDB database shares its attached catalog across
  all sessions via the DuckDB instance cache, which would leak project attachments between sessions.
  Leave `SWANLAKE_DATABASE_PATH` unset (or `:memory:`).

## Validation

`ServerConfig::validate()` currently performs only lightweight checks; the remaining options are
validated as they are consumed (e.g. parsing socket addresses or attaching schemas).
