//! Factory for creating initialized DuckDB connections.
//!
//! Each connection is created with the same configuration and initialization SQL
//! (extensions, ATTACH statements, etc.).

use duckdb::{Config, Connection};
use tracing::{info, instrument};

use crate::cgroup::{compute_memory_limit_from_meminfo, format_bytes_for_duckdb, get_cgroup_memory_limit};
use crate::config::ServerConfig;
use crate::engine::connection::DuckDbConnection;
use crate::error::ServerError;

/// Factory for creating initialized DuckDB connections
#[derive(Clone)]
pub struct EngineFactory {
    init_sql: String,
    database_path: Option<String>,
}

impl EngineFactory {
    /// Create a new factory from configuration
    #[instrument(skip(config))]
    pub fn new(config: &ServerConfig) -> Result<Self, ServerError> {
        let mut init_statements = Vec::new();

        // Memory limit priority: config override > cgroup > meminfo > DuckDB default
        if let Some(ref limit) = config.memory_limit {
            info!("setting DuckDB memory_limit to {} (config override)", limit);
            init_statements.push(format!("SET memory_limit = '{}';", limit));
        } else if let Some(memory_bytes) = get_cgroup_memory_limit() {
            let duckdb_memory = (memory_bytes as f64 * 0.70) as u64;
            let memory_limit = format_bytes_for_duckdb(duckdb_memory);
            info!(
                "setting DuckDB memory_limit to {} (70% of {} cgroup limit)",
                memory_limit,
                format_bytes_for_duckdb(memory_bytes)
            );
            init_statements.push(format!("SET memory_limit = '{}';", memory_limit));
        } else if let Some(memory_bytes) = compute_memory_limit_from_meminfo() {
            let memory_limit = format_bytes_for_duckdb(memory_bytes);
            info!(
                "setting DuckDB memory_limit to {} (from /proc/meminfo: RAM - 10GB + swap)",
                memory_limit
            );
            init_statements.push(format!("SET memory_limit = '{}';", memory_limit));
        }

        // Enable progress bar API (required for query_progress to work)
        // Disable printing to avoid polluting logs
        init_statements.push(
            "PRAGMA enable_progress_bar=true; PRAGMA enable_progress_bar_print=false;".to_string(),
        );

        init_statements.push(
            "INSTALL ducklake; INSTALL httpfs; INSTALL aws; INSTALL postgres; \
            LOAD ducklake; LOAD httpfs; LOAD aws; LOAD postgres;"
                .to_string(),
        );

        // Enable disk caching for S3/HTTP if cache directory is configured
        if let Some(ref cache_dir) = config.cache_directory {
            info!("enabling cache_httpfs with directory: {}", cache_dir);
            init_statements.push(format!(
                "INSTALL cache_httpfs FROM community; LOAD cache_httpfs; \
                SET cache_httpfs_type = 'on_disk'; \
                SET cache_httpfs_cache_directory = '{}';",
                cache_dir
            ));
        }

        if let Some(sql) = config.ducklake_init_sql.as_ref() {
            let trimmed = sql.trim();
            if !trimmed.is_empty() {
                info!("Adding ducklake init SQL");
                init_statements.push(trimmed.to_string());
            }
        }

        let init_sql = init_statements.join("\n");
        info!("base init sql {}", init_sql);

        let database_path = config.database_path.clone();
        if let Some(ref path) = database_path {
            info!("using file-based database: {}", path);
        } else {
            info!("using in-memory database");
        }

        Ok(Self { init_sql, database_path })
    }

    /// Create a minimal factory for unit tests (no extensions, in-memory only).
    #[cfg(test)]
    pub(crate) fn new_for_test() -> Self {
        Self {
            init_sql: String::new(),
            database_path: None,
        }
    }

    /// Create a new initialized DuckDB connection
    ///
    /// If database_path is set, opens a file-based database (shared across sessions).
    /// Otherwise, creates an in-memory database (isolated per session).
    #[instrument(skip(self))]
    pub fn create_connection(&self) -> Result<DuckDbConnection, ServerError> {
        let t0 = std::time::Instant::now();
        let config = Config::default()
            .enable_autoload_extension(true)?
            .allow_unsigned_extensions()?;

        let conn = if let Some(ref path) = self.database_path {
            Connection::open_with_flags(path, config)?
        } else {
            Connection::open_in_memory_with_flags(config)?
        };
        let open_elapsed = t0.elapsed();

        conn.execute_batch(&self.init_sql)?;
        info!(
            open_ms = open_elapsed.as_millis() as u64,
            total_ms = t0.elapsed().as_millis() as u64,
            "created new DuckDB connection"
        );
        Ok(DuckDbConnection::new(conn))
    }
}
