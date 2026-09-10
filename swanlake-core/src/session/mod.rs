//! Session management module.
//!
//! This module provides:
//! - `Session`: Client session with dedicated DuckDB connection and state
//! - `SessionRegistry`: Registry for managing all active sessions
//! - `SessionId`: Unique identifier for sessions
//! - Transaction and prepared statement management per session

pub mod id;
pub mod registry;

pub use id::SessionId;

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use arrow_schema::Schema;
use duckdb::types::Value;
use tracing::{debug, info, instrument, warn};

use crate::engine::{cancellation::RequestCancellation, DuckDbConnection, QueryResult};
use crate::error::ServerError;
use crate::session::id::{
    StatementHandle, StatementHandleGenerator, TransactionId, TransactionIdGenerator,
};

/// Metadata persisted alongside each prepared/ephemeral handle.
///
/// This reflects the authoritative view of a statement that can be
/// executed later (SQL text, schema if known, flags, etc.).
#[derive(Debug, Clone)]
pub struct PreparedStatementMeta {
    pub sql: String,
    pub is_query: bool,
    pub schema: Option<Schema>,
    pub ephemeral: bool,
}

/// Builder-style options passed in when *creating* a prepared statement.
///
/// These options capture contextual data available up front (e.g. a schema
/// computed in the handler) without polluting the long-lived metadata struct.
/// Once the statement is registered, the selected options are copied into
/// [`PreparedStatementMeta`].
#[derive(Debug, Default)]
pub struct PreparedStatementOptions {
    pub cached_schema: Option<Schema>,
    pub ephemeral: bool,
}

impl PreparedStatementOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_cached_schema(mut self, schema: Option<Schema>) -> Self {
        self.cached_schema = schema;
        self
    }

    pub fn ephemeral(mut self) -> Self {
        self.ephemeral = true;
        self
    }
}

/// State for a prepared statement including pending parameters
#[derive(Debug)]
struct PreparedStatementState {
    meta: PreparedStatementMeta,
    pending_parameters: Option<Vec<Value>>,
}

impl PreparedStatementState {
    fn new(meta: PreparedStatementMeta) -> Self {
        Self {
            meta,
            pending_parameters: None,
        }
    }
}

const SCHEMA_CACHE_CAPACITY: usize = 128;

#[derive(Debug)]
struct SchemaCache {
    entries: HashMap<String, Schema>,
    order: VecDeque<String>,
}

impl SchemaCache {
    fn new() -> Self {
        Self {
            entries: HashMap::new(),
            order: VecDeque::new(),
        }
    }

    fn get(&mut self, key: &str) -> Option<Schema> {
        let schema = self.entries.get(key)?.clone();
        self.touch_key(key);
        Some(schema)
    }

    fn insert(&mut self, key: String, schema: Schema) {
        self.entries.insert(key.clone(), schema);
        self.touch_key(&key);
        self.evict_if_needed();
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.order.clear();
    }

    fn touch_key(&mut self, key: &str) {
        self.order.retain(|k| k != key);
        self.order.push_back(key.to_string());
    }

    fn evict_if_needed(&mut self) {
        while self.entries.len() > SCHEMA_CACHE_CAPACITY {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
    }
}

/// Authentication binding for a duckvis-mode session: the token subject, the
/// project scope, and the `Project.mutate_data` capability fixed at session
/// creation. Non-writer sessions arm attachments read-only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionAuth {
    pub subject: String,
    pub project_id: String,
    pub writer: bool,
}

/// Write-hardening engine-lockdown template (swanlake_write_hardening.md §4):
/// the per-instance scratch configuration bound into each duckvis session at
/// creation. The session applies the block once, before its first user
/// statement reaches the engine.
#[derive(Debug, Clone)]
pub struct LockdownTemplate {
    pub scratch_directory: String,
    pub scratch_max_size: String,
}

/// Lockdown progress: the armed lake data roots collected while arming, and
/// whether the block ran. Once applied, the allowed set is frozen for the
/// session's life.
#[derive(Debug, Default)]
struct LockdownState {
    applied: bool,
    roots: std::collections::BTreeSet<String>,
}

/// The §4 lockdown block. The profiling mode is pre-set to the values the
/// streaming path re-asserts per query (errors ignored), so the frozen
/// configuration already carries them. `lock_configuration` is last; a
/// non-writer additionally loses external access, confined to the armed lake
/// roots plus the scratch directory. Secret policy is not in the block:
/// DuckDB rejects secret-manager setting changes once the manager has been
/// used (an armed attach uses it), and disabling `allow_persistent_secrets`
/// before arming breaks the attach ("Unknown secret storage found:
/// 'local_file'"). The registry pins `secret_directory` per session at
/// connection creation, the lock freezes it, and statement admission rejects
/// persistent `CREATE SECRET` forms.
fn lockdown_sql(
    template: &LockdownTemplate,
    writer: bool,
    roots: &std::collections::BTreeSet<String>,
) -> String {
    let mut block = vec![
        "SET enable_profiling = 'no_output'".to_string(),
        "SET custom_profiling_settings = \
         '{\"OPERATOR_CPU_TIME\": \"true\", \"CPU_TIME_ACTUAL\": \"true\"}'"
            .to_string(),
        "SET autoinstall_known_extensions = false".to_string(),
        "SET autoload_known_extensions = false".to_string(),
        "SET allow_community_extensions = false".to_string(),
    ];
    if !writer {
        block.push(format!(
            "SET temp_directory = '{}'",
            escape_sql_literal(&template.scratch_directory)
        ));
        block.push(format!(
            "SET max_temp_directory_size = '{}'",
            escape_sql_literal(&template.scratch_max_size)
        ));
        let list = roots
            .iter()
            .chain(std::iter::once(&template.scratch_directory))
            .map(|dir| format!("'{}'", escape_sql_literal(dir)))
            .collect::<Vec<_>>()
            .join(", ");
        block.push(format!("SET allowed_directories = [{list}]"));
        block.push("SET enable_external_access = false".to_string());
    }
    block.push("SET lock_configuration = true".to_string());
    block.join(";\n")
}

fn escape_sql_literal(value: &str) -> String {
    value.replace('\'', "''")
}

/// A client session with dedicated connection and state
pub struct Session {
    id: SessionId,
    /// Optional duckvis-mode auth binding. When `Some`, the raw-ATTACH guard
    /// (contract C6) and statement admission are active and the session is
    /// project-scoped.
    auth: Option<SessionAuth>,
    /// Write-hardening lockdown template; `None` outside duckvis mode.
    lockdown: Option<LockdownTemplate>,
    lockdown_state: Mutex<LockdownState>,
    /// Opaque token assigned at creation. Clients cache this and send it back
    /// via `x-expected-session-nonce` so the server can detect that a session
    /// was silently recreated (after restart or idle eviction).
    nonce: String,
    /// The shared DuckDB connection (pub(crate) for streaming access)
    pub(crate) connection: std::sync::Arc<DuckDbConnection>,
    transactions: Mutex<HashSet<TransactionId>>,
    aborted_transactions: Mutex<HashSet<TransactionId>>,
    prepared_statements: Mutex<HashMap<StatementHandle, PreparedStatementState>>,
    last_prepared_statement_handle: Mutex<Option<StatementHandle>>,
    transaction_id_gen: TransactionIdGenerator,
    statement_handle_gen: StatementHandleGenerator,
    last_activity: Mutex<Instant>,
    schema_cache: Mutex<SchemaCache>,
    executions: Mutex<HashMap<String, Weak<RequestCancellation>>>,
}

impl Session {
    /// Create a new session with a specific ID and shared connection
    #[instrument(skip(connection))]
    pub fn new_with_id(id: SessionId, connection: std::sync::Arc<DuckDbConnection>) -> Self {
        Self::new_with_id_and_auth(id, connection, None, None)
    }

    /// Create a new session with a specific ID, shared connection, optional
    /// duckvis auth binding, and the write-hardening lockdown template that
    /// binds an authed session's engine before its first user statement.
    #[instrument(skip(connection, auth, lockdown))]
    pub fn new_with_id_and_auth(
        id: SessionId,
        connection: std::sync::Arc<DuckDbConnection>,
        auth: Option<SessionAuth>,
        lockdown: Option<LockdownTemplate>,
    ) -> Self {
        debug!(session_id = %id, "created new session with shared connection");

        Self {
            id,
            auth,
            lockdown,
            lockdown_state: Mutex::new(LockdownState::default()),
            nonce: uuid::Uuid::new_v4().to_string(),
            connection,
            transactions: Mutex::new(HashSet::new()),
            aborted_transactions: Mutex::new(HashSet::new()),
            prepared_statements: Mutex::new(HashMap::new()),
            last_prepared_statement_handle: Mutex::new(None),
            transaction_id_gen: TransactionIdGenerator::new(),
            statement_handle_gen: StatementHandleGenerator::new(),
            last_activity: Mutex::new(Instant::now()),
            schema_cache: Mutex::new(SchemaCache::new()),
            executions: Mutex::new(HashMap::new()),
        }
    }

    /// Opaque nonce assigned at session creation.
    pub fn nonce(&self) -> &str {
        &self.nonce
    }

    /// The duckvis auth binding for this session, if any.
    pub fn auth(&self) -> Option<&SessionAuth> {
        self.auth.as_ref()
    }

    /// Validate user-supplied SQL against the raw-ATTACH guard (contract C6)
    /// and, for non-writer sessions, statement admission (write-hardening §3).
    ///
    /// Active only when the session carries duckvis auth. Splits the SQL into
    /// top-level statements (quote/comment-aware); any `ATTACH` statement is
    /// rejected toward the `duckvis_attach` action (`DETACH` is allowed). A
    /// non-writer additionally loses the file-write verbs the engine cannot
    /// distinguish inside its allowed roots: `COPY` with a file sink (`COPY …
    /// FROM` stays), `EXPORT DATABASE`, and `CALL ducklake_*` maintenance.
    pub fn validate_user_sql(&self, sql: &str) -> Result<(), ServerError> {
        let Some(auth) = self.auth.as_ref() else {
            return Ok(());
        };
        for statement in crate::duckvis::attach::split_top_level_statements(sql) {
            let Some(keyword) = crate::duckvis::attach::leading_keyword(&statement) else {
                continue;
            };
            if keyword == "ATTACH" {
                return Err(ServerError::AttachNotPermitted);
            }
            if keyword == "CREATE"
                && crate::duckvis::attach::creates_persistent_secret(&statement)
            {
                return Err(ServerError::PersistentSecretNotPermitted);
            }
            if !auth.writer {
                match keyword.as_str() {
                    "EXPORT" => return Err(ServerError::WriteNotPermitted("EXPORT DATABASE")),
                    "CALL" if crate::duckvis::attach::call_targets_ducklake(&statement) => {
                        return Err(ServerError::WriteNotPermitted("CALL ducklake_*"));
                    }
                    "COPY" if crate::duckvis::attach::copy_writes_file(&statement) => {
                        return Err(ServerError::WriteNotPermitted("COPY to a file"));
                    }
                    _ => {}
                }
            }
        }
        Ok(())
    }

    /// Apply the write-hardening engine lockdown (swanlake_write_hardening.md
    /// §4) once, before the first user statement reaches the engine. A
    /// non-writer gets the confining variant — external access off, the armed
    /// roots plus scratch as the allowed set, configuration locked; a writer
    /// keeps external access and locks the flag set. Sessions without duckvis
    /// auth are out of scope.
    pub(crate) fn ensure_lockdown(&self) -> Result<(), ServerError> {
        let (Some(template), Some(auth)) = (self.lockdown.as_ref(), self.auth.as_ref()) else {
            return Ok(());
        };
        let mut state = self
            .lockdown_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.applied {
            return Ok(());
        }
        std::fs::create_dir_all(&template.scratch_directory).map_err(|e| {
            ServerError::Internal(format!("failed to create session scratch directory: {e}"))
        })?;
        let sql = lockdown_sql(template, auth.writer, &state.roots);
        self.connection.execute_batch(&sql)?;
        state.applied = true;
        info!(session_id = %self.id, writer = auth.writer, "session write-hardening lockdown applied");
        Ok(())
    }

    /// Record an armed lake's data root into the lockdown's allowed set.
    /// After the lockdown ran the set is frozen; a late root is dropped and
    /// the engine refuses the out-of-set path — fail closed.
    pub fn register_armed_root(&self, root: &str) {
        let mut state = self
            .lockdown_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.applied {
            warn!(
                session_id = %self.id,
                "data root armed after lockdown; the allowed set is frozen"
            );
            return;
        }
        state.roots.insert(root.to_string());
    }

    /// The data-file roots a just-armed DuckLake catalog actually reads and
    /// writes, from its metadata (`ducklake_options`). Authoritative for the
    /// lockdown allowed set: the ATTACH `DATA_PATH` option is a creation-time
    /// override, so re-attaching an existing lake carries no root in the
    /// statement while the lake's files still live under the metadata path.
    /// Distinct values cover a table- or schema-scoped `data_path` override.
    /// Runs on the raw connection so it does not trip the lockdown before the
    /// caller registers the roots it returns.
    pub fn ducklake_data_roots(&self, catalog: &str) -> Result<Vec<String>, ServerError> {
        let sql = format!(
            "SELECT DISTINCT value FROM ducklake_options('{}') \
             WHERE option_name = 'data_path' AND value IS NOT NULL",
            escape_sql_literal(catalog)
        );
        let conn = self
            .connection
            .conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
        let mut roots = Vec::new();
        for row in rows {
            roots.push(row?);
        }
        Ok(roots)
    }

    /// Get time since last activity
    pub fn idle_duration(&self) -> Duration {
        let last = self
            .last_activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        last.elapsed()
    }

    /// Update last activity timestamp
    fn touch(&self) {
        let mut last = self
            .last_activity
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *last = Instant::now();
    }

    /// Run an operation and automatically roll back if DuckDB reports an aborted transaction.
    /// After rollback, retry the operation once.
    fn with_transaction_recovery<T, F>(
        &self,
        mut op: F,
        retry_on_abort: bool,
    ) -> Result<T, ServerError>
    where
        F: FnMut() -> Result<T, ServerError>,
    {
        match op() {
            Ok(value) => Ok(value),
            Err(err) => {
                if Self::is_transaction_abort_error(&err) {
                    self.recover_from_transaction_abort(&err);
                    if retry_on_abort {
                        // Retry once after rollback
                        op()
                    } else {
                        Err(err)
                    }
                } else {
                    Err(err)
                }
            }
        }
    }

    /// Detect the "transaction aborted" state and roll back so the session can be reused.
    fn recover_from_transaction_abort(&self, err: &ServerError) {
        if !Self::is_transaction_abort_error(err) {
            return;
        }

        warn!(error = %err, "transaction aborted; rolling back session state");

        match self.connection.execute_batch("ROLLBACK") {
            Ok(()) => {
                let (cleared, cleared_ids) = {
                    let mut txs = self
                        .transactions
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let cleared = txs.len();
                    let ids = txs.iter().copied().collect::<Vec<_>>();
                    txs.clear();
                    (cleared, ids)
                };
                if !cleared_ids.is_empty() {
                    let mut aborted = self
                        .aborted_transactions
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    for id in cleared_ids {
                        aborted.insert(id);
                    }
                }
                info!(
                    cleared_transactions = cleared,
                    "auto-rolled back aborted transaction"
                );
            }
            Err(rollback_err) => {
                warn!(error = %rollback_err, "failed to rollback aborted transaction");
            }
        }
    }

    fn is_transaction_abort_error(err: &ServerError) -> bool {
        match err {
            ServerError::DuckDb(duck_err) => {
                let msg = duck_err.to_string();
                msg.contains("Current transaction is aborted")
                    || msg.contains("TransactionContext Error")
            }
            _ => false,
        }
    }

    fn transaction_absent(&self, transaction_id: TransactionId) -> Result<(), ServerError> {
        let mut aborted = self
            .aborted_transactions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if aborted.remove(&transaction_id) {
            return Err(ServerError::TransactionAborted);
        }

        debug!(
            transaction_id = %transaction_id,
            "transaction not found; treating as no-op"
        );
        Ok(())
    }

    /// Execute a SELECT query
    #[instrument(skip(self), fields(session_id = %self.id, sql = %sql))]
    pub fn execute_query(&self, sql: &str) -> Result<QueryResult, ServerError> {
        self.validate_user_sql(sql)?;
        self.ensure_lockdown()?;
        self.touch();
        self.with_transaction_recovery(|| self.connection.execute_query(sql), true)
    }

    /// Execute a query with parameters
    #[instrument(skip(self, params), fields(session_id = %self.id, sql = %sql))]
    pub fn execute_query_with_params(
        &self,
        sql: &str,
        params: &[Value],
    ) -> Result<QueryResult, ServerError> {
        self.validate_user_sql(sql)?;
        self.ensure_lockdown()?;
        self.touch();
        self.with_transaction_recovery(
            || self.connection.execute_query_with_params(sql, params),
            true,
        )
    }

    /// Return the number of parameters expected by a statement.
    pub fn parameter_count(&self, sql: &str) -> Result<usize, ServerError> {
        // Binding a statement can open files (table functions), so the
        // lockdown precedes it.
        self.ensure_lockdown()?;
        self.touch();
        self.with_transaction_recovery(|| self.connection.parameter_count(sql), true)
    }

    /// Execute a statement (DDL/DML)
    #[instrument(skip(self), fields(session_id = %self.id, sql = %sql))]
    pub fn execute_statement(&self, sql: &str) -> Result<i64, ServerError> {
        self.validate_user_sql(sql)?;
        self.ensure_lockdown()?;
        self.execute_statement_inner(sql)
    }

    /// Execute a statement bypassing the raw-ATTACH guard (contract C6).
    ///
    /// This is used ONLY by the `duckvis_attach` action handler to run the
    /// server-resolved, normalized ATTACH statement on the session connection.
    /// Never call this with user-supplied SQL.
    #[instrument(skip(self, sql), fields(session_id = %self.id))]
    pub fn execute_statement_privileged(&self, sql: &str) -> Result<i64, ServerError> {
        self.execute_statement_inner(sql)
    }

    pub fn execute_statement_with_telemetry(
        &self,
        sql: &str,
        execution: Option<&str>,
        cancellation: &RequestCancellation,
    ) -> Result<i64, ServerError> {
        self.validate_user_sql(sql)?;
        self.ensure_lockdown()?;
        self.touch();
        let result = self.with_transaction_recovery(
            || {
                self.connection
                    .execute_statement_with_telemetry(sql, execution, Some(cancellation))
            },
            true,
        );
        if result.is_ok() && Self::should_invalidate_schema_cache(sql) {
            self.clear_schema_cache();
        }
        result
    }

    pub fn register_execution(
        &self,
        id: &str,
        cancellation: &Arc<RequestCancellation>,
    ) -> Result<(), ServerError> {
        let mut executions = self.executions.lock().unwrap_or_else(|p| p.into_inner());
        executions.retain(|_, request| request.strong_count() > 0);
        if executions.contains_key(id) {
            return Err(ServerError::Internal(
                "execution request ID is already active".into(),
            ));
        }
        executions.insert(id.into(), Arc::downgrade(cancellation));
        Ok(())
    }

    pub fn cancel_execution(&self, id: &str) -> bool {
        let request = self
            .executions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(id)
            .and_then(Weak::upgrade);
        if let Some(request) = request {
            request.cancel();
            true
        } else {
            false
        }
    }

    pub fn kernel_updates(&self, request: &str) -> Result<Vec<u8>, ServerError> {
        match &self.connection.kernel_telemetry {
            Some(telemetry) => telemetry.read(request),
            None => Ok(br#"{"version":1,"unsupported":true}"#.to_vec()),
        }
    }

    fn execute_statement_inner(&self, sql: &str) -> Result<i64, ServerError> {
        self.touch();
        let result =
            self.with_transaction_recovery(|| self.connection.execute_statement(sql), true);
        if result.is_ok() && Self::should_invalidate_schema_cache(sql) {
            self.clear_schema_cache();
        }
        result
    }

    /// Invalidate the session's cached query schemas. Used after a privileged
    /// ATTACH so subsequent catalog lookups see the new database.
    pub fn invalidate_schema_cache(&self) {
        self.clear_schema_cache();
    }

    /// Execute a statement with parameters
    #[instrument(skip(self, params), fields(session_id = %self.id, sql = %sql))]
    pub fn execute_statement_with_params(
        &self,
        sql: &str,
        params: &[Value],
    ) -> Result<usize, ServerError> {
        self.validate_user_sql(sql)?;
        self.ensure_lockdown()?;
        self.touch();
        let result = self.with_transaction_recovery(
            || self.connection.execute_statement_with_params(sql, params),
            true,
        );
        if result.is_ok() && Self::should_invalidate_schema_cache(sql) {
            self.clear_schema_cache();
        }
        result
    }

    /// Get schema for a query
    #[instrument(skip(self), fields(session_id = %self.id, sql = %sql))]
    pub fn schema_for_query(&self, sql: &str) -> Result<arrow_schema::Schema, ServerError> {
        self.validate_user_sql(sql)?;
        self.ensure_lockdown()?;
        self.touch();
        let cache_key = Self::schema_cache_key(sql);
        if !cache_key.is_empty() {
            if let Some(schema) = self
                .schema_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .get(&cache_key)
            {
                debug!(field_count = schema.fields().len(), "schema cache hit");
                return Ok(schema);
            }
        }

        let schema =
            self.with_transaction_recovery(|| self.connection.schema_for_query(sql), true)?;

        if !cache_key.is_empty() {
            self.schema_cache
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .insert(cache_key, schema.clone());
        }

        Ok(schema)
    }

    /// Insert data using appender API with RecordBatches.
    ///
    /// This is an optimized path for INSERT statements that avoids
    /// converting RecordBatches to individual parameter values.
    #[instrument(skip(self, batches), fields(session_id = %self.id, catalog_name = %catalog_name, table_name = %table_name, rows = batches.iter().map(|b| b.num_rows()).sum::<usize>()))]
    pub fn insert_with_appender(
        &self,
        catalog_name: &str,
        table_name: &str,
        batches: Vec<arrow_array::RecordBatch>,
    ) -> Result<usize, ServerError> {
        self.ensure_lockdown()?;
        self.touch();
        self.with_transaction_recovery(
            || {
                self.connection
                    .insert_with_appender(catalog_name, table_name, batches.clone())
            },
            false,
        )
    }

    /// Get the schema of a table
    pub fn table_schema(&self, table_name: &str) -> Result<arrow_schema::Schema, ServerError> {
        self.with_transaction_recovery(|| self.connection.table_schema(table_name), true)
    }

    /// Return the current catalog selected for this session.
    pub fn current_catalog(&self) -> Result<String, ServerError> {
        self.with_transaction_recovery(|| self.connection.current_catalog(), true)
    }

    fn schema_cache_key(sql: &str) -> String {
        sql.trim_end_matches(';').trim().to_string()
    }

    fn should_invalidate_schema_cache(sql: &str) -> bool {
        let upper = sql.trim_start().to_uppercase();
        upper.starts_with("CREATE")
            || upper.starts_with("ALTER")
            || upper.starts_with("DROP")
            || upper.starts_with("TRUNCATE")
            || upper.starts_with("RENAME")
            || upper.starts_with("USE")
            || upper.starts_with("ATTACH")
            || upper.starts_with("DETACH")
    }

    fn clear_schema_cache(&self) {
        let mut cache = self
            .schema_cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cache.clear();
    }

    /// Resolve catalog/table for a parsed table reference, respecting the session's current catalog.
    ///
    /// - If the reference is unqualified (single part), use the current catalog when it is set
    ///   to a real catalog (not DuckDB's default "memory"); otherwise fall back to `default_catalog`.
    /// - If the reference is qualified, return the provided catalog and table parts.
    pub fn resolve_catalog_and_table(
        &self,
        parts: &[String],
        default_catalog: &str,
    ) -> (String, String) {
        if parts.len() == 1 {
            let catalog = self
                .current_catalog()
                .ok()
                .filter(|c| !c.eq_ignore_ascii_case("memory"))
                .unwrap_or_else(|| default_catalog.to_string());
            (catalog, parts[0].clone())
        } else {
            (parts[0].clone(), parts[1].clone())
        }
    }

    // === Prepared Statements ===

    /// Create a prepared statement and return its handle
    #[instrument(skip(self), fields(session_id = %self.id, sql = %sql))]
    pub fn create_prepared_statement(
        &self,
        sql: String,
        is_query: bool,
        options: PreparedStatementOptions,
    ) -> Result<StatementHandle, ServerError> {
        self.validate_user_sql(&sql)?;
        self.touch();

        let handle = self.statement_handle_gen.next();
        let meta = PreparedStatementMeta {
            sql,
            is_query,
            schema: options.cached_schema,
            ephemeral: options.ephemeral,
        };

        let mut prepared = self
            .prepared_statements
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        prepared.insert(handle, PreparedStatementState::new(meta));

        let mut last_handle = self
            .last_prepared_statement_handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *last_handle = Some(handle);

        debug!(handle = %handle, "created prepared statement");
        Ok(handle)
    }

    /// Get prepared statement metadata
    pub fn get_prepared_statement_meta(
        &self,
        handle: StatementHandle,
    ) -> Result<PreparedStatementMeta, ServerError> {
        let prepared = self
            .prepared_statements
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        prepared
            .get(&handle)
            .map(|state| state.meta.clone())
            .ok_or(ServerError::PreparedStatementNotFound)
    }

    pub fn cache_prepared_statement_schema(
        &self,
        handle: StatementHandle,
        schema: Schema,
    ) -> Result<(), ServerError> {
        let mut prepared = self
            .prepared_statements
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = prepared
            .get_mut(&handle)
            .ok_or(ServerError::PreparedStatementNotFound)?;
        state.meta.schema = Some(schema);
        Ok(())
    }

    /// Set parameters for a prepared statement
    pub fn set_prepared_statement_parameters(
        &self,
        handle: StatementHandle,
        params: Vec<Value>,
    ) -> Result<(), ServerError> {
        let mut prepared = self
            .prepared_statements
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = prepared
            .get_mut(&handle)
            .ok_or(ServerError::PreparedStatementNotFound)?;
        state.pending_parameters = Some(params);
        Ok(())
    }

    /// Take (consume) parameters from a prepared statement
    pub fn take_prepared_statement_parameters(
        &self,
        handle: StatementHandle,
    ) -> Result<Option<Vec<Value>>, ServerError> {
        let mut prepared = self
            .prepared_statements
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let state = prepared
            .get_mut(&handle)
            .ok_or(ServerError::PreparedStatementNotFound)?;
        Ok(state.pending_parameters.take())
    }

    /// Close a prepared statement
    pub fn close_prepared_statement(&self, handle: StatementHandle) -> Result<(), ServerError> {
        let mut prepared = self
            .prepared_statements
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        prepared
            .remove(&handle)
            .ok_or(ServerError::PreparedStatementNotFound)?;
        let mut last_handle = self
            .last_prepared_statement_handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if last_handle.as_ref() == Some(&handle) {
            *last_handle = None;
        }
        debug!(handle = %handle, "closed prepared statement");
        Ok(())
    }

    pub fn last_prepared_statement_handle(&self) -> Option<StatementHandle> {
        let last = self
            .last_prepared_statement_handle
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *last
    }

    // === Transactions ===

    /// Begin a new transaction
    #[instrument(skip(self), fields(session_id = %self.id))]
    pub fn begin_transaction(&self) -> Result<TransactionId, ServerError> {
        self.touch();

        // Execute BEGIN TRANSACTION on the connection
        self.with_transaction_recovery(
            || self.connection.execute_batch("BEGIN TRANSACTION"),
            true,
        )?;

        let tx_id = self.transaction_id_gen.next();
        let mut transactions = self
            .transactions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        transactions.insert(tx_id);

        debug!(transaction_id = %tx_id, "began transaction");
        Ok(tx_id)
    }

    /// Commit a transaction
    #[instrument(skip(self), fields(session_id = %self.id, transaction_id = %transaction_id))]
    pub fn commit_transaction(&self, transaction_id: TransactionId) -> Result<(), ServerError> {
        self.end_transaction(transaction_id, "COMMIT", "committed")
    }

    /// Rollback a transaction
    #[instrument(skip(self), fields(session_id = %self.id, transaction_id = %transaction_id))]
    pub fn rollback_transaction(&self, transaction_id: TransactionId) -> Result<(), ServerError> {
        self.end_transaction(transaction_id, "ROLLBACK", "rolled back")
    }

    fn end_transaction(
        &self,
        transaction_id: TransactionId,
        sql: &str,
        op_name: &str,
    ) -> Result<(), ServerError> {
        self.touch();

        // Verify transaction exists (without holding the lock during the commit/rollback)
        {
            let transactions = self
                .transactions
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !transactions.contains(&transaction_id) {
                return self.transaction_absent(transaction_id);
            }
        }

        // Execute COMMIT/ROLLBACK on the connection
        self.with_transaction_recovery(|| self.connection.execute_batch(sql), true)?;

        let mut transactions = self
            .transactions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        transactions.remove(&transaction_id);
        let mut aborted = self
            .aborted_transactions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        aborted.remove(&transaction_id);
        debug!(
            transaction_id = %transaction_id,
            operation = op_name,
            "completed transaction"
        );
        Ok(())
    }
}

#[cfg(test)]
mod guard_tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::engine::EngineFactory;
    use anyhow::{anyhow, Result};
    use std::sync::Arc;

    fn session_with_auth(auth: Option<SessionAuth>) -> Result<Session> {
        let config = ServerConfig::default();
        let factory = EngineFactory::new_for_tests(&config);
        let conn = factory
            .create_connection()
            .map_err(|e| anyhow!("failed to create test connection: {e}"))?;
        Ok(Session::new_with_id_and_auth(
            SessionId::from_string("test-session".to_string()),
            Arc::new(conn),
            auth,
            None,
        ))
    }

    fn authed_session() -> Result<Session> {
        session_with_auth(Some(SessionAuth {
            subject: "sub-1".to_string(),
            project_id: "project-1".to_string(),
            writer: false,
        }))
    }

    #[test]
    fn guard_rejects_leading_attach() -> Result<()> {
        let s = authed_session()?;
        assert!(matches!(
            s.validate_user_sql("ATTACH 'a.db' AS a"),
            Err(ServerError::AttachNotPermitted)
        ));
        Ok(())
    }

    #[test]
    fn guard_rejects_mixed_case_attach() -> Result<()> {
        let s = authed_session()?;
        assert!(matches!(
            s.validate_user_sql("  aTtAcH 'a.db' AS a"),
            Err(ServerError::AttachNotPermitted)
        ));
        Ok(())
    }

    #[test]
    fn guard_rejects_attach_after_leading_comment() -> Result<()> {
        let s = authed_session()?;
        assert!(matches!(
            s.validate_user_sql("-- comment\n/* block */ ATTACH 'a.db' AS a"),
            Err(ServerError::AttachNotPermitted)
        ));
        Ok(())
    }

    #[test]
    fn guard_rejects_attach_as_second_statement() -> Result<()> {
        let s = authed_session()?;
        assert!(matches!(
            s.validate_user_sql("SELECT 1; ATTACH 'a.db' AS a"),
            Err(ServerError::AttachNotPermitted)
        ));
        Ok(())
    }

    #[test]
    fn guard_allows_attach_inside_string_literal() -> Result<()> {
        let s = authed_session()?;
        assert!(s
            .validate_user_sql("SELECT 'ATTACH is a keyword' AS note")
            .is_ok());
        Ok(())
    }

    #[test]
    fn guard_allows_attach_inside_comment() -> Result<()> {
        let s = authed_session()?;
        assert!(s.validate_user_sql("SELECT 1 -- ATTACH here").is_ok());
        assert!(s.validate_user_sql("/* ATTACH */ SELECT 1").is_ok());
        Ok(())
    }

    #[test]
    fn guard_allows_detach() -> Result<()> {
        let s = authed_session()?;
        assert!(s.validate_user_sql("DETACH mydb").is_ok());
        Ok(())
    }

    #[test]
    fn guard_inactive_without_auth() -> Result<()> {
        let s = session_with_auth(None)?;
        // No auth binding → guard is a no-op even for ATTACH.
        assert!(s.validate_user_sql("ATTACH 'a.db' AS a").is_ok());
        Ok(())
    }

    fn writer_session() -> Result<Session> {
        session_with_auth(Some(SessionAuth {
            subject: "sub-1".to_string(),
            project_id: "project-1".to_string(),
            writer: true,
        }))
    }

    #[test]
    fn admission_rejects_copy_to_file_for_non_writer() -> Result<()> {
        let s = authed_session()?;
        for sql in [
            "COPY t TO 'out.csv'",
            "COPY (SELECT 1) TO 'out.parquet' (FORMAT parquet)",
            "SELECT 1; COPY t TO 'out.csv'",
            "cOpY /* from */ t TO 'out.csv'",
            "COPY t",
        ] {
            assert!(
                matches!(
                    s.validate_user_sql(sql),
                    Err(ServerError::WriteNotPermitted(_))
                ),
                "expected rejection: {sql}"
            );
        }
        Ok(())
    }

    #[test]
    fn admission_allows_copy_from_for_non_writer() -> Result<()> {
        let s = authed_session()?;
        assert!(s.validate_user_sql("COPY t FROM 'in.csv'").is_ok());
        assert!(s.validate_user_sql("COPY t (a, b) FROM 'in.csv'").is_ok());
        assert!(s.validate_user_sql("COPY FROM DATABASE a TO b").is_ok());
        Ok(())
    }

    #[test]
    fn admission_rejects_export_database_for_non_writer() -> Result<()> {
        let s = authed_session()?;
        assert!(matches!(
            s.validate_user_sql("EXPORT DATABASE 'dir'"),
            Err(ServerError::WriteNotPermitted(_))
        ));
        Ok(())
    }

    #[test]
    fn admission_rejects_ducklake_calls_for_non_writer() -> Result<()> {
        let s = authed_session()?;
        for sql in [
            "CALL ducklake_expire_snapshots('lake')",
            "CALL lake.ducklake_merge_adjacent_files()",
            "SELECT 1; CALL \"ducklake_cleanup_old_files\"()",
        ] {
            assert!(
                matches!(
                    s.validate_user_sql(sql),
                    Err(ServerError::WriteNotPermitted(_))
                ),
                "expected rejection: {sql}"
            );
        }
        assert!(s.validate_user_sql("CALL pragma_version()").is_ok());
        Ok(())
    }

    #[test]
    fn admission_rejects_persistent_secrets_for_every_session() -> Result<()> {
        for session in [authed_session()?, writer_session()?] {
            for sql in [
                "CREATE PERSISTENT SECRET s (TYPE s3)",
                "CREATE OR REPLACE PERSISTENT SECRET s (TYPE s3)",
                "CREATE SECRET s IN LOCAL_FILE (TYPE s3)",
                "SELECT 1; CREATE /* c */ pErSiStEnT SECRET s (TYPE s3)",
            ] {
                assert!(
                    matches!(
                        session.validate_user_sql(sql),
                        Err(ServerError::PersistentSecretNotPermitted)
                    ),
                    "expected rejection: {sql}"
                );
            }
            assert!(session.validate_user_sql("CREATE SECRET s (TYPE s3)").is_ok());
            assert!(session
                .validate_user_sql("CREATE TEMPORARY SECRET s (TYPE s3)")
                .is_ok());
            assert!(session
                .validate_user_sql("CREATE VIEW v AS SELECT a IN (1, 2) FROM t")
                .is_ok());
        }
        Ok(())
    }

    #[test]
    fn admission_passes_writer() -> Result<()> {
        let s = writer_session()?;
        assert!(s.validate_user_sql("COPY t TO 'out.csv'").is_ok());
        assert!(s.validate_user_sql("EXPORT DATABASE 'dir'").is_ok());
        assert!(s
            .validate_user_sql("CALL ducklake_expire_snapshots('lake')")
            .is_ok());
        // ATTACH stays rejected regardless of the write permission.
        assert!(matches!(
            s.validate_user_sql("ATTACH 'a.db' AS a"),
            Err(ServerError::AttachNotPermitted)
        ));
        Ok(())
    }
}

#[cfg(test)]
mod lockdown_tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::engine::EngineFactory;
    use anyhow::{anyhow, Result};
    use std::collections::BTreeSet;
    use std::sync::Arc;

    fn template(scratch: &std::path::Path) -> LockdownTemplate {
        LockdownTemplate {
            scratch_directory: scratch.to_string_lossy().into_owned(),
            scratch_max_size: "1GB".to_string(),
        }
    }

    fn raw_batch(conn: &DuckDbConnection, sql: &str) -> std::result::Result<(), duckdb::Error> {
        let raw = conn.conn.lock().unwrap_or_else(|p| p.into_inner());
        raw.execute_batch(sql)
    }

    fn raw_setting(conn: &DuckDbConnection, name: &str) -> Result<String> {
        let raw = conn.conn.lock().unwrap_or_else(|p| p.into_inner());
        Ok(raw.query_row(
            &format!("SELECT current_setting('{name}')::VARCHAR"),
            [],
            |row| row.get::<_, String>(0),
        )?)
    }

    fn test_connection() -> Result<DuckDbConnection> {
        let config = ServerConfig::default();
        let factory = EngineFactory::new_for_tests(&config);
        factory
            .create_connection()
            .map_err(|e| anyhow!("failed to create test connection: {e}"))
    }

    #[test]
    fn non_writer_lockdown_confines_and_freezes() -> Result<()> {
        let lake = tempfile::tempdir()?;
        let outside = tempfile::tempdir()?;
        let scratch = tempfile::tempdir()?;
        std::fs::write(lake.path().join("t.csv"), "a,b\n1,2\n")?;

        let conn = test_connection()?;
        // The registry pins the secret directory at connection creation; the
        // lock freezes it.
        raw_batch(
            &conn,
            &format!(
                "SET secret_directory = '{}'",
                scratch.path().join("secrets").display()
            ),
        )?;
        let mut roots = BTreeSet::new();
        roots.insert(lake.path().to_string_lossy().into_owned());
        raw_batch(&conn, &lockdown_sql(&template(scratch.path()), false, &roots))
            .map_err(|e| anyhow!("lockdown block failed: {e}"))?;

        assert_eq!(raw_setting(&conn, "enable_external_access")?, "false");
        assert_eq!(raw_setting(&conn, "lock_configuration")?, "true");
        assert!(raw_setting(&conn, "secret_directory")?.ends_with("secrets"));

        let csv = lake.path().join("t.csv");
        raw_batch(
            &conn,
            &format!(
                "CREATE TABLE t AS SELECT * FROM read_csv_auto('{}')",
                csv.display()
            ),
        )
        .map_err(|e| anyhow!("in-root read failed: {e}"))?;

        // File writes outside the allowed set fail; the scratch directory
        // accepts them (§5 residual).
        let denied = outside.path().join("out.csv");
        assert!(raw_batch(&conn, &format!("COPY t TO '{}'", denied.display())).is_err());
        let permitted = scratch.path().join("out.csv");
        raw_batch(&conn, &format!("COPY t TO '{}'", permitted.display()))
            .map_err(|e| anyhow!("scratch write failed: {e}"))?;

        assert!(raw_batch(&conn, "SET enable_external_access = true").is_err());
        assert!(raw_batch(&conn, "SET allowed_directories = ['/']").is_err());
        assert!(raw_batch(&conn, "SET secret_directory = '/tmp'").is_err());
        assert!(raw_batch(&conn, "SET lock_configuration = false").is_err());
        Ok(())
    }

    #[test]
    fn writer_lockdown_keeps_external_access() -> Result<()> {
        let scratch = tempfile::tempdir()?;
        let out = tempfile::tempdir()?;
        let conn = test_connection()?;

        raw_batch(
            &conn,
            &lockdown_sql(&template(scratch.path()), true, &BTreeSet::new()),
        )
        .map_err(|e| anyhow!("lockdown block failed: {e}"))?;

        assert_eq!(raw_setting(&conn, "enable_external_access")?, "true");
        assert_eq!(raw_setting(&conn, "lock_configuration")?, "true");

        raw_batch(&conn, "CREATE TABLE t AS SELECT 1 AS a")?;
        let target = out.path().join("w.csv");
        raw_batch(&conn, &format!("COPY t TO '{}'", target.display()))
            .map_err(|e| anyhow!("writer file write failed: {e}"))?;

        assert!(raw_batch(&conn, "SET allow_community_extensions = true").is_err());
        Ok(())
    }

    #[test]
    fn lockdown_stays_per_connection() -> Result<()> {
        let scratch = tempfile::tempdir()?;
        let config = ServerConfig::default();
        let factory = EngineFactory::new_for_tests(&config);
        let locked = factory
            .create_connection()
            .map_err(|e| anyhow!("failed to create test connection: {e}"))?;
        raw_batch(
            &locked,
            &lockdown_sql(&template(scratch.path()), false, &BTreeSet::new()),
        )
        .map_err(|e| anyhow!("lockdown block failed: {e}"))?;

        let sibling = factory
            .create_connection()
            .map_err(|e| anyhow!("failed to create test connection: {e}"))?;
        assert_eq!(raw_setting(&sibling, "lock_configuration")?, "false");
        assert_eq!(raw_setting(&sibling, "enable_external_access")?, "true");
        Ok(())
    }

    #[test]
    fn session_applies_lockdown_before_first_statement() -> Result<()> {
        let lake = tempfile::tempdir()?;
        let scratch = tempfile::tempdir()?;
        std::fs::write(lake.path().join("t.csv"), "a,b\n1,2\n")?;

        let session = Session::new_with_id_and_auth(
            SessionId::from_string("lockdown-test".to_string()),
            Arc::new(test_connection()?),
            Some(SessionAuth {
                subject: "sub-1".to_string(),
                project_id: "project-1".to_string(),
                writer: false,
            }),
            Some(template(scratch.path())),
        );
        session.register_armed_root(&lake.path().to_string_lossy());

        let result = session
            .execute_query("SELECT current_setting('lock_configuration')::VARCHAR AS v")
            .map_err(|e| anyhow!("{e}"))?;
        let batch = result.batches.first().ok_or_else(|| anyhow!("no batch"))?;
        let column = batch
            .column(0)
            .as_any()
            .downcast_ref::<arrow_array::StringArray>()
            .ok_or_else(|| anyhow!("not a string column"))?;
        assert_eq!(column.value(0), "true");

        // The root armed before the first statement is readable.
        let csv = lake.path().join("t.csv");
        session
            .execute_query(&format!("SELECT * FROM read_csv_auto('{}')", csv.display()))
            .map_err(|e| anyhow!("in-root read failed: {e}"))?;

        // A root armed after lockdown does not widen the allowed set.
        let late = tempfile::tempdir()?;
        std::fs::write(late.path().join("t.csv"), "a\n1\n")?;
        session.register_armed_root(&late.path().to_string_lossy());
        let late_csv = late.path().join("t.csv");
        assert!(session
            .execute_query(&format!(
                "SELECT * FROM read_csv_auto('{}')",
                late_csv.display()
            ))
            .is_err());
        Ok(())
    }
}
