use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::{bail, Context};
use base64::engine::general_purpose::STANDARD as BASE64_STD;
use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// The duckvis service-account signing key: base64 (standard alphabet) of the
/// raw 32-byte Ed25519 seed. The value is redacted from `Debug` output so it
/// never appears in config logging.
#[derive(Clone, Deserialize, Serialize)]
#[serde(transparent)]
pub struct DuckvisPrivateKey(String);

impl DuckvisPrivateKey {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// Decode the raw 32-byte Ed25519 seed. Errors never include the
    /// configured value.
    pub fn decode_seed(&self) -> anyhow::Result<[u8; 32]> {
        let bytes = BASE64_STD.decode(self.0.trim()).map_err(|_| {
            anyhow::anyhow!(
                "SWANLAKE_DUCKVIS_PRIVATE_KEY must be base64 (standard alphabet) of the raw \
                 32-byte Ed25519 seed"
            )
        })?;
        <[u8; 32]>::try_from(bytes).map_err(|b| {
            anyhow::anyhow!(
                "SWANLAKE_DUCKVIS_PRIVATE_KEY must decode to exactly 32 bytes (got {})",
                b.len()
            )
        })
    }
}

impl std::fmt::Debug for DuckvisPrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<redacted>")
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionIdMode {
    PeerAddr,
    PeerIp,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    pub port: u16,
    /// Host advertised in FlightEndpoint locations. Defaults to "localhost".
    /// Set to the externally reachable hostname or IP for remote clients.
    pub advertise_host: String,
    /// Path to DuckDB database file. Use ":memory:" for in-memory (default).
    pub database_path: Option<String>,
    /// Directory for cache_httpfs disk cache. Enables S3/HTTP caching when set.
    pub cache_directory: Option<String>,
    /// Optional SQL statement executed during startup for ducklake integration.
    pub ducklake_init_sql: Option<String>,
    /// Optional override for DuckDB worker thread count.
    pub duckdb_threads: Option<usize>,
    /// Optional comma-separated list of DuckLake databases to checkpoint periodically.
    pub checkpoint_databases: Option<String>,
    /// Interval in hours between checkpoints for each configured database.
    pub checkpoint_interval_hours: Option<u64>,
    /// Poll interval in seconds for checking whether a checkpoint is due.
    pub checkpoint_poll_seconds: Option<u64>,
    /// Maximum number of concurrent sessions.
    pub max_sessions: Option<usize>,
    /// Session idle timeout in seconds.
    pub session_timeout_seconds: Option<u64>,
    /// Session identifier mode.
    pub session_id_mode: SessionIdMode,
    /// Log format: "compact" or "json".
    pub log_format: String,
    /// Enable the status HTTP server.
    pub status_enabled: bool,
    /// Status server bind address.
    pub status_host: String,
    /// Status server port.
    pub status_port: u16,
    /// Path prefix for status endpoints (e.g., "/admin" results in /admin/ and /admin/status.json).
    pub status_path_prefix: String,
    /// Slow query threshold in milliseconds for metrics.
    pub metrics_slow_query_threshold_ms: Option<u64>,
    /// Max number of latency/error/slow-query entries to retain.
    pub metrics_history_size: Option<usize>,
    /// Override DuckDB memory_limit (e.g. "16GB", "4096MB").
    /// When set, bypasses cgroup and meminfo auto-detection.
    pub memory_limit: Option<String>,
    /// Enable duckvis mode: authenticate every Flight request against
    /// duckvis-api-issued tokens and resolve attachments by bind id.
    pub duckvis_enabled: bool,
    /// Base URL of the duckvis-api control plane (e.g. "https://api.duckvis.example").
    pub duckvis_api_url: Option<String>,
    /// Expected `iss` claim (exact match) on inbound user tokens.
    pub duckvis_issuer: Option<String>,
    /// Service-account client id used for the client-credentials token flow:
    /// the resource-server service account (SSA) name (e.g. "swanlake-wrx80"),
    /// not a uuid.
    pub duckvis_client_id: Option<String>,
    /// Service-account signing key used to sign the RFC 7523 client assertion:
    /// base64 (standard alphabet) of the raw 32-byte Ed25519 seed.
    pub duckvis_private_key: Option<DuckvisPrivateKey>,
    /// Fallback max-age (seconds) for the JWKS cache when the response omits
    /// `Cache-Control: max-age`. Defaults to 300 when unset.
    pub duckvis_jwks_max_age_secs: Option<u64>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: 4214,
            advertise_host: "localhost".to_string(),
            database_path: None,
            cache_directory: None,
            ducklake_init_sql: None,
            duckdb_threads: None,
            checkpoint_databases: None,
            checkpoint_interval_hours: Some(24),
            checkpoint_poll_seconds: Some(300),
            max_sessions: Some(100),
            session_timeout_seconds: Some(900),
            session_id_mode: SessionIdMode::PeerAddr,
            log_format: "compact".to_string(),
            status_enabled: true,
            status_host: "0.0.0.0".to_string(),
            status_port: 4215,
            status_path_prefix: String::new(),
            metrics_slow_query_threshold_ms: Some(5000),
            metrics_history_size: Some(200),
            memory_limit: None,
            duckvis_enabled: false,
            duckvis_api_url: None,
            duckvis_issuer: None,
            duckvis_client_id: None,
            duckvis_private_key: None,
            duckvis_jwks_max_age_secs: None,
        }
    }
}

impl ServerConfig {
    pub fn load() -> anyhow::Result<Self> {
        let defaults_json = serde_json::to_string(&Self::default())
            .with_context(|| "failed to serialize defaults")?;
        let settings = config::Config::builder()
            .add_source(
                config::File::from_str(&defaults_json, config::FileFormat::Json).required(false),
            )
            .add_source(config::Environment::with_prefix("SWANLAKE"))
            .build()
            .with_context(|| "failed to load configuration")?;
        let cfg: ServerConfig = settings
            .try_deserialize()
            .with_context(|| "failed to deserialize configuration")?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn bind_addr(&self) -> anyhow::Result<SocketAddr> {
        let addr = format!("{}:{}", self.host, self.port);
        addr.to_socket_addrs()?
            .next()
            .ok_or_else(|| anyhow::anyhow!("unable to resolve bind address for {addr}"))
    }

    fn validate(&self) -> anyhow::Result<()> {
        if let Some(hours) = self.checkpoint_interval_hours {
            if hours == 0 {
                bail!("SWANLAKE_CHECKPOINT_INTERVAL_HOURS must be greater than 0");
            }
        }
        if let Some(seconds) = self.checkpoint_poll_seconds {
            if seconds == 0 {
                bail!("SWANLAKE_CHECKPOINT_POLL_SECONDS must be greater than 0");
            }
        }
        if self.duckvis_enabled {
            let missing: Vec<&str> = [
                ("SWANLAKE_DUCKVIS_API_URL", self.duckvis_api_url.is_none()),
                ("SWANLAKE_DUCKVIS_ISSUER", self.duckvis_issuer.is_none()),
                (
                    "SWANLAKE_DUCKVIS_CLIENT_ID",
                    self.duckvis_client_id.is_none(),
                ),
                (
                    "SWANLAKE_DUCKVIS_PRIVATE_KEY",
                    self.duckvis_private_key.is_none(),
                ),
            ]
            .into_iter()
            .filter_map(|(name, is_missing)| if is_missing { Some(name) } else { None })
            .collect();
            if !missing.is_empty() {
                bail!(
                    "duckvis mode requires the following settings: {}",
                    missing.join(", ")
                );
            }
            if let Some(key) = &self.duckvis_private_key {
                // Must decode to exactly a raw 32-byte Ed25519 seed; the error
                // never includes the configured value.
                key.decode_seed()?;
            }
            let file_backed = self
                .database_path
                .as_deref()
                .is_some_and(|p| !p.trim().is_empty() && p.trim() != ":memory:");
            if file_backed {
                bail!(
                    "SWANLAKE_DATABASE_PATH must not be a file path in duckvis mode: a file-based \
                     DuckDB \
                     database shares its attached catalog across all sessions via the instance \
                     cache, which would leak workspace attachments between sessions. Duckvis mode \
                     requires in-memory per-session databases (leave SWANLAKE_DATABASE_PATH unset \
                     or use \":memory:\")."
                );
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod duckvis_config_tests {
    use super::*;

    /// base64 (standard) of a valid raw 32-byte Ed25519 seed.
    fn valid_key_b64() -> String {
        BASE64_STD.encode([0x11u8; 32])
    }

    fn enabled_config() -> ServerConfig {
        ServerConfig {
            duckvis_enabled: true,
            duckvis_api_url: Some("https://api.example".to_string()),
            duckvis_issuer: Some("https://api.example".to_string()),
            duckvis_client_id: Some("swanlake-test".to_string()),
            duckvis_private_key: Some(DuckvisPrivateKey::new(valid_key_b64())),
            ..ServerConfig::default()
        }
    }

    #[test]
    fn valid_duckvis_config_passes() {
        assert!(enabled_config().validate().is_ok());
    }

    #[test]
    fn duckvis_requires_all_fields() {
        let mut config = enabled_config();
        config.duckvis_private_key = None;
        let err = config.validate().expect_err("should require private key");
        assert!(err.to_string().contains("SWANLAKE_DUCKVIS_PRIVATE_KEY"));
    }

    #[test]
    fn duckvis_rejects_bad_length_private_key() {
        let mut config = enabled_config();
        // 31 bytes: valid base64, wrong seed length.
        config.duckvis_private_key = Some(DuckvisPrivateKey::new(BASE64_STD.encode([0x22u8; 31])));
        let err = config.validate().expect_err("should reject 31-byte seed");
        assert!(err.to_string().contains("32 bytes"));
    }

    #[test]
    fn duckvis_rejects_non_base64_private_key() {
        let mut config = enabled_config();
        config.duckvis_private_key = Some(DuckvisPrivateKey::new("not-valid-base64!!!"));
        let err = config.validate().expect_err("should reject bad base64");
        // The error must name the knob but never echo the configured value.
        let msg = err.to_string();
        assert!(msg.contains("SWANLAKE_DUCKVIS_PRIVATE_KEY"));
        assert!(!msg.contains("not-valid-base64"));
    }

    #[test]
    fn private_key_is_redacted_in_debug() {
        let config = enabled_config();
        let debug = format!("{config:?}");
        assert!(!debug.contains(&valid_key_b64()));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn duckvis_rejects_file_database_path() {
        let mut config = enabled_config();
        config.database_path = Some("/data/warehouse.duckdb".to_string());
        let err = config.validate().expect_err("should reject file path");
        assert!(err.to_string().contains("SWANLAKE_DATABASE_PATH"));
    }

    #[test]
    fn duckvis_allows_memory_database_path() {
        let mut config = enabled_config();
        config.database_path = Some(":memory:".to_string());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn disabled_duckvis_ignores_missing_fields() {
        let config = ServerConfig {
            duckvis_enabled: false,
            database_path: Some("/data/x.duckdb".to_string()),
            ..ServerConfig::default()
        };
        assert!(config.validate().is_ok());
    }
}
