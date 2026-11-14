//! DuckDB connection wrapper with query execution methods.
//!
//! Each connection is owned by a Session and maintains persistent state
//! (ATTACH, temp tables, etc.).

use std::cell::{Cell, RefCell};
use std::sync::Mutex;

use arrow_array::RecordBatch;
use arrow_schema::{Field, Schema, SchemaRef};
use duckdb::types::Value;
use duckdb::{params_from_iter, Connection};
use duckdb::{ArrowStream, Statement};
use tokio::sync::mpsc;
use tracing::{debug, info, instrument};

use super::cancellation::{ActiveQuery, RequestCancellation};
use super::{breakdown, result_projection};
use crate::error::ServerError;
use crate::usage::{ExecutionLabel, RequestAccounting, ResourceTotals};
use libduckdb_sys as ffi;

use crate::types::duckdb_type_to_arrow;

/// Message sent through the streaming channel
pub enum StreamingBatch {
    /// Schema message (sent first)
    Schema(Schema),
    /// A record batch
    Batch(RecordBatch),
    /// Query completed with totals
    Done {
        total_rows: usize,
        total_bytes: usize,
    },
    /// Error occurred
    Error(ServerError),
}

/// Result of a query execution
pub struct QueryResult {
    pub schema: Schema,
    pub batches: Vec<RecordBatch>,
    pub total_rows: usize,
    pub total_bytes: usize,
}

/// Wrapper around duckdb::Connection with execution methods
///
/// The Connection is wrapped in a Mutex because duckdb::Connection contains
/// RefCell internally and is not Sync. This allows the connection to be
/// shared safely across async tasks.
///
/// `conn` is the connection guard. [`DuckDbConnection::guarded`] is the one
/// place that takes it to issue statements, and the one place that brackets
/// them.
pub struct DuckDbConnection {
    conn: Mutex<Connection>,
    pub kernel_telemetry: Option<super::kernel_telemetry::KernelTelemetry>,
}

impl DuckDbConnection {
    /// Create a new connection wrapper
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: Mutex::new(conn),
            kernel_telemetry: None,
        }
    }

    /// Runs `f` under the connection guard.
    ///
    /// Takes the guard, recovering a poisoned one, activates `cancellation`,
    /// and runs `f` with the connection and a [`Bracket`]. Each attempt `f`
    /// measures through the bracket becomes one entry of `accounting` as the
    /// attempt closes; with no accounting the entries are discarded.
    /// Cancellation is disarmed before the guard is released.
    pub(crate) fn guarded<R>(
        &self,
        cancellation: Option<&RequestCancellation>,
        accounting: Option<&RequestAccounting>,
        f: impl FnOnce(&Connection, &Bracket<'_>) -> Result<R, ServerError>,
    ) -> Result<R, ServerError> {
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let handle = conn.interrupt_handle();
        let active = cancellation
            .map(|c| c.activate(handle.clone()))
            .transpose()?;
        // This thread holds the guard, so nothing closes the connection while
        // the bracket uses the pointer outside the handle's mutex.
        let bracket = Bracket {
            conn: &conn,
            native: handle.with_connection(|native| native),
            accounting,
            active: RefCell::new(active),
            open: Cell::new(false),
        };
        // `bracket` is declared after `conn`, so every exit, an unwind
        // included, disarms cancellation before it releases the guard.
        f(&conn, &bracket)
    }

    /// Get an interrupt handle for cancelling long-running queries.
    ///
    /// The returned handle can be used from another thread to interrupt
    /// queries running on this connection.
    ///
    /// Recovers a poisoned lock rather than propagating the panic, as every
    /// other read of `conn` in this file does. The `.expect` this replaces made
    /// a single interrupted query permanently fatal to the connection: DuckDB's
    /// Arrow fetch panics on `INTERRUPT Error` instead of returning it, that
    /// panic poisons the mutex, and then the next caller to ask for a handle —
    /// every streaming query, which needs one to be cancellable at all —
    /// panicked here before reaching the engine. The Flight request died with
    /// it, so the client saw `RST_STREAM` and a cancelled call, and nothing
    /// short of restarting the process ever served that connection again.
    ///
    /// Recovery is sound because an interrupt handle does not depend on the
    /// state the panicking thread was partway through: it is derived from the
    /// connection itself, and DuckDB treats an interrupted query as a query
    /// that ended, leaving the connection able to take the next one.
    pub fn interrupt_handle(&self) -> std::sync::Arc<duckdb::InterruptHandle> {
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        conn.interrupt_handle()
    }

    /// Bind read queries once and export their types through an empty local
    /// result. Commands retain their existing Arrow execution path.
    pub fn schema_for_query(
        &self,
        sql: &str,
        accounting: Option<&RequestAccounting>,
    ) -> Result<Schema, ServerError> {
        self.schema_for_query_cancellable(sql, None, accounting)
    }

    pub(crate) fn schema_for_query_cancellable(
        &self,
        sql: &str,
        cancellation: Option<&RequestCancellation>,
        accounting: Option<&RequestAccounting>,
    ) -> Result<Schema, ServerError> {
        Self::validate_sql(sql)?;
        let body = sql.trim_end_matches(';').trim();
        let result = self.guarded(cancellation, accounting, |conn, bracket| {
            // A body DESCRIBE can wrap is discovered by statements SwanLake
            // composes: the DESCRIBE and the projection it prepares, whose
            // stream is dropped unread.
            let discovered = if result_projection::is_query_body(sql) {
                bracket.measure(ExecutionLabel::SwanLake, || {
                    let query = match result_projection::schema_query(conn, sql)? {
                        Some(query) => query,
                        None => match result_projection::for_query(conn, body, None)? {
                            Some(query) => query,
                            None => return Ok(None),
                        },
                    };
                    if let Some(cancellation) = cancellation {
                        cancellation.check()?;
                    }
                    let mut stmt = conn.prepare(&query)?;
                    let stream = Self::stream_arrow_with_params(&mut stmt, None)?;
                    Ok::<_, ServerError>(Some(stream.get_schema().as_ref().clone()))
                })?
            } else {
                None
            };
            if let Some(schema) = discovered {
                return Ok(schema);
            }
            if let Some(cancellation) = cancellation {
                cancellation.check()?;
            }
            // The client's own text: every statement of the block but the
            // last executes, and the last starts and is abandoned.
            bracket.measure_block(body, |stmt| {
                let stream = Self::stream_arrow_with_params(stmt, None)?;
                Ok(stream.get_schema().as_ref().clone())
            })
        });
        if let Some(cancellation) = cancellation {
            cancellation.check()?;
        }
        result
    }

    /// Streaming and buffered query discovery export the same bound schema.
    pub fn schema_for_streaming(
        &self,
        sql: &str,
        accounting: Option<&RequestAccounting>,
    ) -> Result<Schema, ServerError> {
        self.schema_for_query(sql, accounting)
    }

    /// Execute a SELECT query and return results
    #[instrument(skip(self, accounting), fields(sql = %sql))]
    pub fn execute_query(
        &self,
        sql: &str,
        accounting: Option<&RequestAccounting>,
    ) -> Result<QueryResult, ServerError> {
        self.with_arrow_prepared(sql, None, accounting, |stmt| {
            let arrow = Self::stream_arrow_with_params(stmt, None)?;
            let schema = arrow.get_schema();
            let result = Self::collect_query_result(schema, arrow);
            debug!(
                batch_count = result.batches.len(),
                total_rows = result.total_rows,
                total_bytes = result.total_bytes,
                "executed query"
            );
            Ok(result)
        })
    }

    /// Execute a SELECT query and stream results through a channel.
    ///
    /// This method uses DuckDB's true streaming execution with backpressure.
    /// Unlike the old implementation, DuckDB will pause execution when the
    /// consumer is not pulling batches, preventing memory blowup.
    ///
    /// The channel receives:
    /// 1. `Schema` - The result schema (first message)
    /// 2. `Batch` - Zero or more record batches
    /// 3. `Done` - Final message with totals, OR `Error` if something failed
    ///
    /// Stream a read query, optionally interrupting when the receiver closes.
    pub fn execute_query_streaming(
        &self,
        sql: &str,
        tx: mpsc::Sender<StreamingBatch>,
        interrupt_handle: Option<std::sync::Arc<duckdb::InterruptHandle>>,
        accounting: Option<&RequestAccounting>,
    ) -> Result<(), ServerError> {
        self.stream_query(sql, None, tx, interrupt_handle, None, accounting)
    }

    /// Parameterized form of execute_query_streaming.
    pub fn execute_query_with_params_streaming(
        &self,
        sql: &str,
        params: &[Value],
        tx: mpsc::Sender<StreamingBatch>,
        interrupt_handle: Option<std::sync::Arc<duckdb::InterruptHandle>>,
        accounting: Option<&RequestAccounting>,
    ) -> Result<(), ServerError> {
        self.stream_query(sql, Some(params), tx, interrupt_handle, None, accounting)
    }

    pub(crate) fn stream_query_cancellable(
        &self,
        sql: &str,
        params: Option<&[Value]>,
        tx: mpsc::Sender<StreamingBatch>,
        cancellation: &RequestCancellation,
        accounting: Option<&RequestAccounting>,
    ) -> Result<(), ServerError> {
        self.stream_query(sql, params, tx, None, Some(cancellation), accounting)
    }

    #[instrument(skip(self, tx, params, interrupt_handle, cancellation, accounting), fields(sql = %sql))]
    fn stream_query(
        &self,
        sql: &str,
        params: Option<&[Value]>,
        tx: mpsc::Sender<StreamingBatch>,
        interrupt_handle: Option<std::sync::Arc<duckdb::InterruptHandle>>,
        cancellation: Option<&RequestCancellation>,
        accounting: Option<&RequestAccounting>,
    ) -> Result<(), ServerError> {
        if let Some(cancellation) = cancellation {
            cancellation.check()?;
        }

        // Now execute the full query in true streaming mode
        let completed = self.with_arrow_prepared_cancellable(
            sql,
            params,
            cancellation,
            true,
            accounting,
            |stmt, schema| {
                if let Some(schema) = &schema {
                    if tx
                        .blocking_send(StreamingBatch::Schema(schema.clone()))
                        .is_err()
                    {
                        return Ok(None);
                    }
                }
                if let Some(cancellation) = cancellation {
                    cancellation.check()?;
                }
                if tx.is_closed() {
                    return Ok(None);
                }
                let arrow = Self::stream_arrow_with_params(stmt, params)?;
                let executed_schema = arrow.get_schema();
                match schema {
                    Some(schema) if &schema != executed_schema.as_ref() => {
                        return Err(ServerError::Internal(
                            "query result schema changed after planning".to_string(),
                        ));
                    }
                    // Commands that cannot be described retain execution-time schema delivery.
                    None => {
                        if tx
                            .blocking_send(StreamingBatch::Schema(executed_schema.as_ref().clone()))
                            .is_err()
                        {
                            return Ok(None);
                        }
                    }
                    Some(_) => {}
                }

                // Stream batches with backpressure
                let mut total_rows = 0usize;
                let mut total_bytes = 0usize;
                let mut batch_count = 0usize;
                for batch in arrow {
                    // Check if client cancelled before processing batch
                    if tx.is_closed() {
                        info!(
                            batch_count,
                            total_rows, "streaming receiver closed, interrupting query"
                        );
                        if let Some(ref handle) = interrupt_handle {
                            handle.interrupt();
                        }
                        return Ok(None);
                    }

                    batch_count += 1;
                    let batch_rows = batch.num_rows();
                    let batch_bytes = batch.get_array_memory_size();
                    total_rows += batch_rows;
                    total_bytes += batch_bytes;

                    debug!(
                        batch_count,
                        batch_rows, batch_bytes, total_rows, total_bytes, "streaming batch"
                    );

                    if tx.blocking_send(StreamingBatch::Batch(batch)).is_err() {
                        info!(
                            batch_count,
                            total_rows, "streaming receiver dropped, interrupting query"
                        );
                        if let Some(ref handle) = interrupt_handle {
                            handle.interrupt();
                        }
                        return Ok(None);
                    }
                }

                Ok(Some((batch_count, total_rows, total_bytes)))
            },
        )?;

        // The receiver closes as soon as it consumes Done. Finish statement
        // cleanup and the final cancellation check before publishing it, so
        // normal stream closure cannot turn a completed query into an error.
        if let Some((batch_count, total_rows, total_bytes)) = completed {
            let _ = tx.blocking_send(StreamingBatch::Done {
                total_rows,
                total_bytes,
            });
            info!(
                batch_count,
                total_rows, total_bytes, "streaming query completed"
            );
        }
        Ok(())
    }

    /// Execute a query with bound parameters.
    #[instrument(skip(self, params, accounting), fields(sql = %sql, param_count = params.len()))]
    pub fn execute_query_with_params(
        &self,
        sql: &str,
        params: &[Value],
        accounting: Option<&RequestAccounting>,
    ) -> Result<QueryResult, ServerError> {
        self.with_arrow_prepared(sql, Some(params), accounting, |stmt| {
            let arrow = Self::stream_arrow_with_params(stmt, Some(params))?;
            let schema = arrow.get_schema();
            let result = Self::collect_query_result(schema, arrow);
            debug!(
                batch_count = result.batches.len(),
                total_rows = result.total_rows,
                total_bytes = result.total_bytes,
                "executed query with parameters"
            );
            Ok(result)
        })
    }

    /// Return the number of parameters expected by a prepared statement.
    pub fn parameter_count(
        &self,
        sql: &str,
        accounting: Option<&RequestAccounting>,
    ) -> Result<usize, ServerError> {
        self.with_prepared(sql, accounting, |stmt| Ok(stmt.parameter_count()))
    }

    /// Execute a statement (DDL/DML) without returning results
    #[instrument(skip(self, accounting), fields(sql = %sql))]
    pub fn execute_statement(
        &self,
        sql: &str,
        accounting: Option<&RequestAccounting>,
    ) -> Result<i64, ServerError> {
        self.execute_statement_with_telemetry(sql, None, None, accounting)
    }

    /// Runs a client block whose every result is discarded, under label 1
    /// as one attempt for the whole block. A block that holds no statement
    /// succeeds.
    pub fn execute_statement_with_telemetry(
        &self,
        sql: &str,
        execution: Option<&str>,
        cancellation: Option<&RequestCancellation>,
        accounting: Option<&RequestAccounting>,
    ) -> Result<i64, ServerError> {
        self.run_block(sql, execution, cancellation, accounting, |_, bracket| {
            bracket.measure_batch(sql)
        })
    }

    /// Runs a block SwanLake composed to serve a request, under label 0: the
    /// statements that arm an attachment.
    pub(crate) fn execute_statement_privileged(
        &self,
        sql: &str,
        accounting: Option<&RequestAccounting>,
    ) -> Result<i64, ServerError> {
        self.run_block(sql, None, None, accounting, |conn, bracket| {
            bracket
                .measure(ExecutionLabel::SwanLake, || conn.execute_batch(sql))
                .map_err(ServerError::from)
        })
    }

    /// Runs `run` between the two kernel telemetry calls. Those calls issue
    /// no statement, and run under the guard and outside every bracket.
    fn run_block(
        &self,
        sql: &str,
        execution: Option<&str>,
        cancellation: Option<&RequestCancellation>,
        accounting: Option<&RequestAccounting>,
        run: impl FnOnce(&Connection, &Bracket<'_>) -> Result<(), ServerError>,
    ) -> Result<i64, ServerError> {
        Self::validate_sql(sql)?;
        self.guarded(cancellation, accounting, |conn, bracket| {
            if let Some(telemetry) = &self.kernel_telemetry {
                telemetry.set(conn, execution)?;
            }
            let result = cancellation
                .map_or(Ok(()), |c| c.check())
                .and_then(|()| run(conn, bracket));
            // Disarm while we still own the connection, including before resetting
            // telemetry; a late cancellation cannot reach another statement.
            bracket.disarm();
            if let Some(telemetry) = &self.kernel_telemetry {
                telemetry.set(conn, None)?;
            }
            result
        })?;
        if let Some(cancellation) = cancellation {
            cancellation.check()?;
        }
        debug!("executed statement");
        Ok(0)
    }

    /// Execute a statement with parameters
    #[instrument(skip(self, params, accounting), fields(sql = %sql, param_count = params.len()))]
    pub fn execute_statement_with_params(
        &self,
        sql: &str,
        params: &[Value],
        accounting: Option<&RequestAccounting>,
    ) -> Result<usize, ServerError> {
        self.with_prepared(sql, accounting, |stmt| {
            let affected = Self::execute_with_params(stmt, params)?;
            debug!(affected, "executed statement with parameters");
            Ok(affected)
        })
    }

    /// Execute a batch of SQL statements through `duckdb_query`, as one
    /// attempt under `label`. No client block reaches this: its callers are
    /// the lockdown, the transaction actions, and the maintenance checkpoint.
    #[instrument(skip(self, accounting), fields(sql = %sql))]
    pub fn execute_batch(
        &self,
        sql: &str,
        label: ExecutionLabel,
        accounting: Option<&RequestAccounting>,
    ) -> Result<(), ServerError> {
        Self::validate_sql(sql)?;
        self.guarded(None, accounting, |conn, bracket| {
            bracket
                .measure(label, || conn.execute_batch(sql))
                .map_err(ServerError::from)
        })?;
        debug!("executed batch");
        Ok(())
    }

    /// Insert data using DuckDB's appender API with RecordBatches.
    ///
    /// This method is optimized for bulk inserts as it avoids converting
    /// RecordBatch to individual parameter values, reducing memory copies.
    ///
    /// # Arguments
    ///
    /// * `catalog_name` - The name of the catalog
    /// * `table_name` - The name of the table to insert into
    /// * `batches` - The RecordBatches containing data to insert
    ///
    /// # Returns
    ///
    /// The number of rows inserted
    #[instrument(skip(self, batches, accounting), fields(catalog_name = %catalog_name, table_name = %table_name, rows = batches.iter().map(|b| b.num_rows()).sum::<usize>()))]
    pub fn insert_with_appender(
        &self,
        catalog_name: &str,
        table_name: &str,
        batches: Vec<RecordBatch>,
        accounting: Option<&RequestAccounting>,
    ) -> Result<usize, ServerError> {
        let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
        info!(
            "appender to {}.{} with total rows {} and column {}",
            catalog_name,
            table_name,
            total_rows,
            batches.first().map(|b| b.num_columns()).unwrap_or(0)
        );

        self.guarded(None, accounting, |conn, bracket| {
            bracket.measure(ExecutionLabel::SwanLake, || {
                conn.execute(&format!("USE {catalog_name};"), [])
            })?;
            // One attempt covers the appender through its drop: on an error
            // path the destructor's flush is the only flush that runs.
            bracket.measure(ExecutionLabel::Client, || {
                let mut appender = conn.appender(table_name)?;
                for batch in batches {
                    appender.append_record_batch(batch)?;
                }
                appender.flush()?;
                Ok::<_, ServerError>(())
            })
        })?;

        debug!(
            rows = total_rows,
            table = %table_name,
            "inserted data using appender"
        );

        Ok(total_rows)
    }

    /// Whether a database of this name is attached, compared without case.
    pub(crate) fn catalog_attached(
        &self,
        catalog: &str,
        accounting: Option<&RequestAccounting>,
    ) -> Result<bool, ServerError> {
        self.guarded(None, accounting, |conn, bracket| {
            bracket
                .measure(ExecutionLabel::SwanLake, || {
                    conn.query_row(
                        "SELECT EXISTS (SELECT 1 FROM duckdb_databases() WHERE lower(database_name) = lower(?))",
                        [catalog],
                        |row| row.get(0),
                    )
                })
                .map_err(ServerError::from)
        })
    }

    /// The first column of every row of `sql`, a query SwanLake composed.
    pub(crate) fn query_strings(
        &self,
        sql: &str,
        accounting: Option<&RequestAccounting>,
    ) -> Result<Vec<String>, ServerError> {
        self.guarded(None, accounting, |conn, bracket| {
            bracket.measure(ExecutionLabel::SwanLake, || {
                let mut stmt = conn.prepare(sql)?;
                let rows = stmt.query_map([], |row| row.get::<_, String>(0))?;
                let mut values = Vec::new();
                for row in rows {
                    values.push(row?);
                }
                Ok(values)
            })
        })
    }

    /// Get the schema of a table using DESC SELECT
    pub fn table_schema(
        &self,
        table_name: &str,
        accounting: Option<&RequestAccounting>,
    ) -> Result<arrow_schema::Schema, ServerError> {
        self.guarded(None, accounting, |conn, bracket| {
            bracket.measure(ExecutionLabel::SwanLake, || {
                Self::describe_table(conn, table_name)
            })
        })
    }

    fn describe_table(
        conn: &Connection,
        table_name: &str,
    ) -> Result<arrow_schema::Schema, ServerError> {
        // Use DESC to get table schema without preparing parameters
        let desc_query = format!("DESC SELECT * FROM {table_name}");
        let mut stmt = conn.prepare(&desc_query).map_err(ServerError::DuckDb)?;
        let rows = stmt
            .query_map([], |row| {
                Ok((
                    row.get::<_, String>(0)?, // column_name
                    row.get::<_, String>(1)?, // column_type
                    row.get::<_, String>(2)?, // null (YES or NO)
                ))
            })
            .map_err(ServerError::DuckDb)?
            .collect::<Result<Vec<_>, _>>()?;

        if rows
            .iter()
            .any(|(_, ty, _)| result_projection::contains_variant(ty))
        {
            let sql = format!("SELECT * FROM {table_name}");
            if let Some(projection) = result_projection::for_query(conn, &sql, None)? {
                let mut projected = conn.prepare(&format!("{projection} LIMIT 0"))?;
                let stream = Self::stream_arrow_with_params(&mut projected, None)?;
                let schema = stream.get_schema();
                let fields = schema
                    .fields()
                    .iter()
                    .zip(&rows)
                    .map(|(field, (_, _, nullable))| {
                        field.as_ref().clone().with_nullable(nullable == "YES")
                    })
                    .collect::<Vec<_>>();
                return Ok(Schema::new_with_metadata(fields, schema.metadata().clone()));
            }
        }

        let mut fields = Vec::new();
        for (name, duckdb_type, null_str) in rows {
            let data_type = duckdb_type_to_arrow(&duckdb_type)?;
            let nullable = null_str == "YES";
            fields.push(Field::new(&name, data_type, nullable));
        }

        Ok(Schema::new(fields))
    }

    /// Return the currently selected catalog (database) for this connection.
    pub fn current_catalog(
        &self,
        accounting: Option<&RequestAccounting>,
    ) -> Result<String, ServerError> {
        self.guarded(None, accounting, |conn, bracket| {
            bracket.measure(ExecutionLabel::SwanLake, || {
                let mut stmt = conn
                    .prepare("SELECT current_database()")
                    .map_err(ServerError::DuckDb)?;
                let catalog: String = stmt
                    .query_row([], |row| row.get(0))
                    .map_err(ServerError::DuckDb)?;
                Ok(catalog)
            })
        })
    }

    /// Ensure SQL does not contain null bytes.
    fn validate_sql(sql: &str) -> Result<(), ServerError> {
        if sql.contains('\0') {
            return Err(ServerError::UnsupportedParameter(
                "SQL contains null bytes".to_string(),
            ));
        }
        Ok(())
    }

    /// Apply output conversion before schema discovery or Arrow execution.
    fn with_arrow_prepared<T, F>(
        &self,
        sql: &str,
        params: Option<&[Value]>,
        accounting: Option<&RequestAccounting>,
        f: F,
    ) -> Result<T, ServerError>
    where
        F: FnOnce(&mut Statement) -> Result<T, ServerError>,
    {
        self.with_arrow_prepared_cancellable(sql, params, None, false, accounting, |stmt, _| {
            f(stmt)
        })
    }

    fn with_arrow_prepared_cancellable<T, F>(
        &self,
        sql: &str,
        params: Option<&[Value]>,
        cancellation: Option<&RequestCancellation>,
        early_schema: bool,
        accounting: Option<&RequestAccounting>,
        f: F,
    ) -> Result<T, ServerError>
    where
        F: FnOnce(&mut Statement, Option<Schema>) -> Result<T, ServerError>,
    {
        Self::validate_sql(sql)?;
        let result = self.guarded(cancellation, accounting, |conn, bracket| {
            // The schema probe is SwanLake's work. A text that is no single
            // read query has no probe, and runs as the client sent it.
            let (query, schema) = if result_projection::is_query_body(sql) {
                bracket.measure(ExecutionLabel::SwanLake, || {
                    Ok::<_, ServerError>(if early_schema {
                        match result_projection::for_streaming_query(conn, sql, params)? {
                            Some((query, schema_query)) => {
                                let mut schema_stmt = conn.prepare(&schema_query)?;
                                let schema =
                                    Self::stream_arrow_with_params(&mut schema_stmt, None)?
                                        .get_schema()
                                        .as_ref()
                                        .clone();
                                (query, Some(schema))
                            }
                            None => (sql.to_string(), None),
                        }
                    } else {
                        (
                            result_projection::for_query(conn, sql, params)?
                                .unwrap_or_else(|| sql.to_string()),
                            None,
                        )
                    })
                })?
            } else {
                (sql.to_string(), None)
            };
            if let Some(cancellation) = cancellation {
                cancellation.check()?;
            }
            bracket.measure_block(&query, |stmt| f(stmt, schema))
        });
        if let Some(cancellation) = cancellation {
            cancellation.check()?;
        }
        result
    }

    /// Prepare a statement under the connection lock and run the provided closure.
    fn with_prepared<T, F>(
        &self,
        sql: &str,
        accounting: Option<&RequestAccounting>,
        f: F,
    ) -> Result<T, ServerError>
    where
        F: FnOnce(&mut Statement) -> Result<T, ServerError>,
    {
        Self::validate_sql(sql)?;
        self.guarded(None, accounting, |_, bracket| {
            bracket.measure_block(sql, f)
        })
    }

    /// Execute a statement with parameters, handling the empty-params case.
    fn execute_with_params(stmt: &mut Statement, params: &[Value]) -> Result<usize, ServerError> {
        let affected = if params.is_empty() {
            stmt.execute([])?
        } else {
            stmt.execute(params_from_iter(params.iter()))?
        };
        Ok(affected)
    }

    /// Run a query, binding parameters if provided, or filling with NULLs otherwise.
    /// Run a query in true streaming mode with backpressure support.
    ///
    /// Unlike `query_arrow`, this uses `execute_streaming` internally which
    /// does NOT materialize all results upfront. DuckDB will pause execution
    /// when the consumer is not pulling batches.
    fn stream_arrow_with_params<'a>(
        stmt: &'a mut Statement,
        params: Option<&[Value]>,
    ) -> Result<ArrowStream<'a>, ServerError> {
        match params {
            Some(values) => Ok(stmt.stream_arrow(params_from_iter(values.iter()))?),
            None => {
                let param_count = stmt.parameter_count();
                if param_count == 0 {
                    Ok(stmt.stream_arrow([])?)
                } else {
                    let nulls: Vec<Value> = (0..param_count).map(|_| Value::Null).collect();
                    Ok(stmt.stream_arrow(params_from_iter(nulls))?)
                }
            }
        }
    }

    /// Collect Arrow batches into a QueryResult with row/byte totals.
    fn collect_query_result<I: Iterator<Item = RecordBatch>>(
        schema: SchemaRef,
        batches_iter: I,
    ) -> QueryResult {
        let mut total_rows = 0usize;
        let mut total_bytes = 0usize;
        let batches: Vec<RecordBatch> = batches_iter
            .inspect(|batch| {
                total_rows += batch.num_rows();
                total_bytes += batch.get_array_memory_size();
            })
            .collect();

        QueryResult {
            schema: schema.as_ref().clone(),
            batches,
            total_rows,
            total_bytes,
        }
    }
}

/// The bracket handle [`DuckDbConnection::guarded`] passes its closure.
///
/// Each of its three methods measures attempts: a `duckdb_begin_measured`
/// before a body of work and a `duckdb_end_measured` after it, whose two
/// reads give the attempt's figures. One bracket is open at a time, and the
/// closing call runs on every exit from the measured work.
pub(crate) struct Bracket<'a> {
    conn: &'a Connection,
    /// The native connection, which stays open while the guard is held.
    native: Option<ffi::duckdb_connection>,
    accounting: Option<&'a RequestAccounting>,
    active: RefCell<Option<ActiveQuery<'a>>>,
    open: Cell<bool>,
}

impl<'a> Bracket<'a> {
    /// Measures the whole of `f` as one attempt under `label`. The attempt
    /// carries no breakdown, because `f` can run several executions.
    pub(crate) fn measure<T>(&self, label: ExecutionLabel, f: impl FnOnce() -> T) -> T {
        let _attempt = self.open(label, false);
        f()
    }

    /// Runs the block `sql` under label 1, one attempt for each statement,
    /// each with its breakdown.
    ///
    /// Every statement but the last runs and its result is discarded. The
    /// last is prepared and passed to `f`. Extraction parses the whole block
    /// before any statement runs and belongs to the first attempt. A
    /// statement that fails ends the block with its error. A block that holds
    /// no statement makes one attempt, never calls `f`, and returns the error
    /// a prepare of that block returns.
    pub(crate) fn measure_block<T>(
        &self,
        sql: &str,
        f: impl FnOnce(&mut Statement<'_>) -> Result<T, ServerError>,
    ) -> Result<T, ServerError> {
        let mut attempt = self.open(ExecutionLabel::Client, true);
        let mut statements = self.conn.extract(sql)?;
        let Some(last) = statements.len().checked_sub(1) else {
            return Err(ServerError::DuckDb(empty_block_error()));
        };
        for index in 0..last {
            statements.execute_and_discard(index)?;
            attempt.next();
        }
        // Declared after `attempt`, so the statement and whatever `f` left
        // open on it are released before the closing read.
        let mut stmt = statements.prepare(last)?;
        f(&mut stmt)
    }

    /// Runs the block `sql` under label 1 and discards every result, as one
    /// attempt for the whole block.
    ///
    /// The block runs through one `duckdb_query` call. That call rolls back
    /// a transaction the block opened with the automatic-rollback property
    /// when a statement of the block fails, and it clears the interrupt flag
    /// once, so an interrupt between two statements stops the next one. The
    /// engine expands some single statements into such a block, and a split
    /// into statements would leave the session in the failed transaction.
    ///
    /// The statement count decides only the breakdown: the profiler holds
    /// the last statement's tree after the call, so the entry carries a
    /// breakdown where the block holds exactly one statement. A count that
    /// fails is ignored, and the `duckdb_query` call reports the block's
    /// error. A block that holds no statement succeeds.
    pub(crate) fn measure_batch(&self, sql: &str) -> Result<(), ServerError> {
        let mut attempt = self.open(ExecutionLabel::Client, false);
        // The extracted set is released before the block runs.
        let count = self.conn.extract(sql).map(|statements| statements.len());
        attempt.breakdown = matches!(count, Ok(1));
        self.conn.execute_batch(sql)?;
        Ok(())
    }

    /// Disarms the request's cancellation ahead of the guard's release.
    fn disarm(&self) {
        self.active.borrow_mut().take();
    }

    fn open(&self, label: ExecutionLabel, breakdown: bool) -> Attempt<'_, 'a> {
        debug_assert!(!self.open.get(), "a bracket is already open");
        self.open.set(true);
        Attempt {
            bracket: self,
            label,
            breakdown,
            opening: self.begin(label),
        }
    }

    /// Opens a bracket and returns its opening read, or `None` where the
    /// engine reports a failure.
    fn begin(&self, label: ExecutionLabel) -> Option<ResourceTotals> {
        let native = self.native?;
        let mut totals = zeroed_totals();
        // SAFETY: the guard's holder keeps `native` open, and `totals` is a
        // valid struct.
        let state = unsafe { ffi::duckdb_begin_measured(native, &mut totals) };
        if state != ffi::DuckDBSuccess {
            return None;
        }
        let opening = ResourceTotals::from(totals);
        if let Some(accounting) = self.accounting {
            accounting.attempt_opened(label, &opening);
        }
        Some(opening)
    }

    /// Closes the open bracket, which ends an execution the attempt left
    /// open, and records the attempt's entry.
    ///
    /// An attempt whose opening or closing call failed records an entry with
    /// no figures: it reports less than the attempt used and never more.
    fn end(&self, label: ExecutionLabel, opening: Option<ResourceTotals>, breakdown: bool) {
        let Some(native) = self.native else {
            return;
        };
        let mut totals = zeroed_totals();
        let mut abandoned = false;
        // SAFETY: as in `begin`; `abandoned` is a valid bool.
        let state = unsafe { ffi::duckdb_end_measured(native, &mut totals, &mut abandoned) };
        let Some(accounting) = self.accounting else {
            return;
        };
        let closing = (state == ffi::DuckDBSuccess).then(|| ResourceTotals::from(totals));
        let (opening, closing) = match (opening, closing) {
            (Some(opening), Some(closing)) => (opening, closing),
            (Some(opening), None) => (opening, opening),
            (None, _) => (ResourceTotals::default(), ResourceTotals::default()),
        };
        // SAFETY: the guard's holder keeps `native` open and runs no
        // statement on it during the walk.
        let breakdown = breakdown
            .then(|| unsafe { breakdown::read(native) })
            .flatten();
        accounting.push_entry(label, &opening, &closing, abandoned, breakdown);
    }
}

/// One open attempt. Dropping it closes the bracket, so a clean return, an
/// early return, and an unwind each take the closing read.
struct Attempt<'b, 'a> {
    bracket: &'b Bracket<'a>,
    label: ExecutionLabel,
    breakdown: bool,
    opening: Option<ResourceTotals>,
}

impl Attempt<'_, '_> {
    /// Closes this attempt and opens the next one of the same kind.
    fn next(&mut self) {
        self.bracket
            .end(self.label, self.opening.take(), self.breakdown);
        self.opening = self.bracket.begin(self.label);
    }
}

impl Drop for Attempt<'_, '_> {
    fn drop(&mut self) {
        self.bracket
            .end(self.label, self.opening.take(), self.breakdown);
        self.bracket.open.set(false);
    }
}

fn zeroed_totals() -> ffi::duckdb_resource_totals {
    let zero = ffi::duckdb_usage_totals {
        cpu_ns: 0,
        bytes_read: 0,
        bytes_written: 0,
    };
    ffi::duckdb_resource_totals {
        connection: zero,
        database: zero,
        memory_bytes: 0,
        memory_peak_bytes: 0,
        memory_byte_ms: 0,
    }
}

/// The error a prepare returns for a block that holds no statement: the
/// failure duckdb-rs builds for an extraction that yields no statement and no
/// error text.
fn empty_block_error() -> duckdb::Error {
    duckdb::Error::DuckDBFailure(ffi::Error::new(ffi::DuckDBError), None)
}

#[cfg(test)]
impl DuckDbConnection {
    /// Whether another thread holds the connection guard.
    pub(crate) fn guard_is_held(&self) -> bool {
        matches!(self.conn.try_lock(), Err(std::sync::TryLockError::WouldBlock))
    }

    /// Whether a holder of the connection guard panicked.
    pub(crate) fn guard_is_poisoned(&self) -> bool {
        self.conn.is_poisoned()
    }

    /// Runs `f` on the connection under the guard, in no bracket. A panic in
    /// `f` poisons the guard, as a panic in a statement does.
    pub(crate) fn with_raw<R>(&self, f: impl FnOnce(&Connection) -> R) -> R {
        let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
        f(&conn)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streaming_schema_precedes_execution_error() -> anyhow::Result<()> {
        let connection = test_connection();
        for params in [None, Some(vec![Value::Int(2)])] {
            let sql = if params.is_some() {
                "SELECT sum(CAST('invalid' || i::VARCHAR AS BIGINT)) AS total FROM range(?) t(i)"
            } else {
                "SELECT sum(CAST('invalid' || i::VARCHAR AS BIGINT)) AS total FROM range(2) t(i)"
            };
            let (tx, mut rx) = mpsc::channel(4);
            let result = connection.stream_query(sql, params.as_deref(), tx, None, None, None);
            assert!(result.unwrap_err().to_string().contains("Conversion Error"));
            assert!(
                matches!(rx.blocking_recv(), Some(StreamingBatch::Schema(_))),
                "execution fails only after the result schema is published"
            );
            assert!(rx.blocking_recv().is_none());
            assert_eq!(connection.execute_query("SELECT 42", None)?.total_rows, 1);
        }
        Ok(())
    }

    #[test]
    fn streaming_schema_matches_bound_parameters_and_exported_types() -> anyhow::Result<()> {
        let connection = test_connection();
        connection.execute_batch(
            "SET arrow_lossless_conversion=true; CREATE SEQUENCE early_schema_rows",
            crate::usage::ExecutionLabel::SwanLake, None,
        )?;
        for (sql, params) in [
            ("SELECT ? AS value, ? AS label", Some(vec![Value::Int(42), Value::Text("text".into())])),
            ("SELECT 1::DECIMAL(30,4) AS d, [1,2] AS a, {'x': 1} AS s, 'a'::ENUM('a','b') AS e", None),
            ("SELECT NULL AS n, 1::UBIGINT AS u, now() AS t, uuid() AS id, INTERVAL '1 day' AS i, 'a'::JSON AS j WHERE false", None),
            ("SELECT 1 AS dup, 'x' AS dup, 2 AS \"quoted\"\"name\"", None),
            ("SELECT nextval('early_schema_rows')::VARIANT AS v FROM range(3)", None),
            ("SELECT {'x': 1::VARIANT} AS nested, [2::VARIANT] AS items", None),
        ] {
            let (tx, mut rx) = mpsc::channel(4);
            connection.stream_query(sql, params.as_deref(), tx, None, None, None)?;
            let Some(StreamingBatch::Schema(schema)) = rx.blocking_recv() else {
                anyhow::bail!("missing schema for {sql}");
            };
            let mut rows = 0;
            while let Some(message) = rx.blocking_recv() {
                match message {
                    StreamingBatch::Batch(batch) => {
                        assert_eq!(batch.schema().as_ref(), &schema, "{sql}");
                        rows += batch.num_rows();
                        if sql.starts_with("SELECT ?") {
                            assert_eq!(batch.column(0).as_any().downcast_ref::<arrow_array::Int32Array>().unwrap().value(0), 42);
                        }
                    }
                    StreamingBatch::Done { total_rows, .. } => assert_eq!(rows, total_rows),
                    _ => anyhow::bail!("unexpected stream message for {sql}"),
                }
            }
        }
        let result = connection.execute_query("SELECT currval('early_schema_rows')", None)?;
        assert_eq!(
            result.batches[0]
                .column(0)
                .as_any()
                .downcast_ref::<arrow_array::Int64Array>()
                .unwrap()
                .value(0),
            3
        );
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn streaming_schema_precedes_blocking_aggregation_and_allows_cancellation(
    ) -> anyhow::Result<()> {
        use crate::engine::cancellation::RequestCancellation;
        use std::{sync::Arc, time::Duration};

        let connection = Arc::new(test_connection());
        for parameterized in [false, true] {
            let cancellation = Arc::new(RequestCancellation::default());
            let (tx, mut rx) = mpsc::channel(1);
            let worker_connection = connection.clone();
            let worker_cancellation = cancellation.clone();
            let worker = tokio::task::spawn_blocking(move || {
                let params = [Value::BigInt(1_000_000_000_000)];
                worker_connection.stream_query_cancellable(
                    if parameterized {
                        "SELECT sum(sin(i::DOUBLE)) AS total FROM range(?) t(i)"
                    } else {
                        "SELECT sum(sin(i::DOUBLE)) AS total FROM range(1000000000000) t(i)"
                    },
                    parameterized.then_some(params.as_slice()),
                    tx,
                    &worker_cancellation,
                    None,
                )
            });
            let first = tokio::time::timeout(Duration::from_secs(2), rx.recv()).await;
            let still_running = !worker.is_finished();
            rx.close();
            cancellation.cancel();
            // Always cancel and join, including when the schema regression fails.
            let result = tokio::time::timeout(Duration::from_secs(2), worker).await??;
            assert!(matches!(result, Err(ServerError::Cancelled)));
            assert!(matches!(first, Ok(Some(StreamingBatch::Schema(_)))));
            assert!(still_running, "aggregation finished before cancellation");
            assert_eq!(connection.execute_query("SELECT 42", None)?.total_rows, 1);
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn completed_stream_survives_immediate_receiver_close() -> anyhow::Result<()> {
        use crate::engine::cancellation::RequestCancellation;
        use std::sync::Arc;

        let connection = Arc::new(test_connection());
        for iteration in 0..200 {
            let cancellation = Arc::new(RequestCancellation::default());
            let (tx, mut rx) = mpsc::channel(1);
            let worker_connection = connection.clone();
            let worker_cancellation = cancellation.clone();
            let worker = tokio::task::spawn_blocking(move || {
                worker_connection.stream_query_cancellable(
                    "SELECT ?::INTEGER AS value",
                    Some(&[Value::Int(iteration)]),
                    tx,
                    &worker_cancellation,
                    None,
                )
            });
            let mut rows = 0;
            loop {
                match rx.recv().await {
                    Some(StreamingBatch::Batch(batch)) => rows += batch.num_rows(),
                    Some(StreamingBatch::Done { total_rows, .. }) => {
                        assert_eq!(rows, 1);
                        assert_eq!(total_rows, rows);
                        // Flight closes the response immediately upon Done.
                        // That closure must not change the worker's result.
                        rx.close();
                        cancellation.cancel();
                        break;
                    }
                    Some(StreamingBatch::Schema(_)) => {}
                    Some(StreamingBatch::Error(error)) => return Err(error.into()),
                    None => anyhow::bail!("stream ended without completion"),
                }
            }
            worker.await??;
        }
        assert_eq!(connection.execute_query("SELECT 42", None)?.total_rows, 1);
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn unfinished_stream_still_cancels_on_receiver_close() -> anyhow::Result<()> {
        use crate::engine::cancellation::RequestCancellation;
        use std::sync::Arc;

        let connection = Arc::new(test_connection());
        let cancellation = Arc::new(RequestCancellation::default());
        let (tx, mut rx) = mpsc::channel(1);
        let worker_connection = connection.clone();
        let worker_cancellation = cancellation.clone();
        let worker = tokio::task::spawn_blocking(move || {
            worker_connection.stream_query_cancellable(
                "SELECT i FROM range(100000) t(i)",
                None,
                tx,
                &worker_cancellation,
                None,
            )
        });
        assert!(matches!(rx.recv().await, Some(StreamingBatch::Schema(_))));
        rx.close();
        cancellation.cancel();
        assert!(matches!(worker.await?, Err(ServerError::Cancelled)));
        assert_eq!(connection.execute_query("SELECT 42", None)?.total_rows, 1);
        Ok(())
    }

    fn test_connection() -> DuckDbConnection {
        // As `EngineFactory` opens a connection: an extension set built
        // from this engine's source carries no signature.
        let config = duckdb::Config::default()
            .enable_autoload_extension(true)
            .and_then(|config| config.allow_unsigned_extensions())
            .expect("connection config");
        let conn =
            Connection::open_in_memory_with_flags(config).expect("failed to open in-memory db");
        DuckDbConnection::new(conn)
    }

    /// A poisoned connection mutex must not take the next query down with it.
    ///
    /// DuckDB's Arrow fetch panics on `INTERRUPT Error` rather than returning
    /// it, so cancelling a query poisons this mutex. `interrupt_handle` used to
    /// `.expect` on the lock, and since every streaming query asks for a handle
    /// before it runs, one cancelled query made the connection permanently
    /// unusable — each later query panicked here, the Flight request died, and
    /// the client saw a cancelled call until the server was restarted.
    #[test]
    fn an_interrupt_handle_outlives_a_poisoned_mutex() {
        let conn = test_connection();

        // Poison it exactly as the interrupted fetch does: panic while holding
        // the guard. `catch_unwind` keeps the harness alive; the poison stays.
        let poisoned = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            conn.with_raw(|_| {
                panic!("Failed to fetch Arrow record batch: INTERRUPT Error: Interrupted!")
            })
        }));
        assert!(poisoned.is_err(), "the panic must have happened");
        assert!(conn.guard_is_poisoned(), "and must have poisoned the mutex");

        // The line that used to panic. Obtaining a handle is what makes a query
        // cancellable, so this failing is what made the connection dead.
        let _handle = conn.interrupt_handle();

        // And the connection still serves queries, which is the whole point of
        // recovering rather than reporting.
        conn.execute_statement("CREATE TABLE after_poison (id INTEGER)", None)
            .unwrap();
        conn.execute_statement("INSERT INTO after_poison VALUES (1)", None)
            .unwrap();
        let result = conn.execute_query("SELECT * FROM after_poison", None).unwrap();
        assert_eq!(result.total_rows, 1);
    }

    #[test]
    fn schema_discovery_preserves_exported_types_and_duplicate_names() {
        let conn = test_connection();
        for sql in [
            "SELECT 1::DECIMAL(30, 4) AS d, [1, 2] AS a, {'x': 1, 'y': ['a']} AS s, 'a'::ENUM('a', 'b') AS e",
            "SELECT NULL AS n, 1::UBIGINT AS u, now() AS t, uuid() AS id, INTERVAL '1 day' AS i, 'a'::JSON AS j WHERE false",
            "SELECT 1 AS dup, 'x' AS dup, 2 AS \"quoted\"\"name\"",
            "VALUES (1, 'a'), (2, 'b')",
            "WITH data AS (SELECT [1, 2] AS items) SELECT * FROM data",
        ] {
            assert_eq!(conn.schema_for_query(sql, None).unwrap(), conn.execute_query(sql, None).unwrap().schema, "{sql}");
        }
    }

    #[test]
    fn schema_discovery_does_not_evaluate_aggregate_inputs() {
        let conn = test_connection();
        conn.execute_batch("CREATE SEQUENCE schema_probe", crate::usage::ExecutionLabel::SwanLake, None).unwrap();
        let sql = "SELECT sum(nextval('schema_probe')) AS total FROM range(10)";
        let schema = conn.schema_for_query(sql, None).unwrap();
        let result = conn.execute_query(sql, None).unwrap();
        assert_eq!(schema, result.schema);
        let total = conn
            .execute_query("SELECT currval('schema_probe')", None)
            .unwrap();
        let value = total.batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<arrow_array::Int64Array>()
            .unwrap();
        assert_eq!(value.value(0), 10);
    }

    #[test]
    #[ignore = "requires the DuckDB httpfs extension and a loopback listener"]
    fn schema_discovery_avoids_reexecuting_remote_glob() {
        use std::io::{Read, Write};
        use std::sync::{
            atomic::{AtomicBool, AtomicUsize, Ordering},
            Arc,
        };

        struct Source {
            stop: Arc<AtomicBool>,
            thread: Option<std::thread::JoinHandle<()>>,
        }
        impl Drop for Source {
            fn drop(&mut self) {
                self.stop.store(true, Ordering::Relaxed);
                if let Some(thread) = self.thread.take() {
                    thread.join().unwrap();
                }
            }
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let count = Arc::new(AtomicUsize::new(0));
        let requests = count.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let _source = Source {
            stop,
            thread: Some(std::thread::spawn(move || {
                while !stopping.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream
                                .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                                .unwrap();
                            let mut request = Vec::new();
                            let mut buffer = [0; 4096];
                            while !request.windows(4).any(|part| part == b"\r\n\r\n") {
                                let n = stream.read(&mut buffer).unwrap();
                                if n == 0 {
                                    break;
                                }
                                request.extend_from_slice(&buffer[..n]);
                            }
                            requests.fetch_add(1, Ordering::Relaxed);
                            let body = "<ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Name>test</Name><KeyCount>0</KeyCount><IsTruncated>false</IsTruncated></ListBucketResult>";
                            write!(stream, "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", body.len(), body).unwrap();
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(std::time::Duration::from_millis(1));
                        }
                        Err(error) => panic!("mock S3 listener: {error}"),
                    }
                }
            })),
        };
        let conn = test_connection();
        conn.execute_batch(&format!(
            "LOAD httpfs; CREATE SECRET (TYPE S3, KEY_ID 'test', SECRET 'test', REGION 'test', ENDPOINT '{address}', USE_SSL false, URL_STYLE 'path')"
        ), crate::usage::ExecutionLabel::SwanLake, None).unwrap();
        let sql = "SELECT file FROM glob('s3://test/parquet/*/*/*.parquet')";
        let schema = conn.schema_for_query(sql, None).unwrap();
        let result = conn.execute_query(sql, None).unwrap();
        assert_eq!(schema, result.schema);
        assert_eq!(result.total_rows, 0);
        assert_eq!(count.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn basic_statement_and_query() {
        let conn = test_connection();
        conn.execute_statement("CREATE TABLE t (id INTEGER)", None).unwrap();
        conn.execute_statement("INSERT INTO t VALUES (1)", None).unwrap();
        let result = conn.execute_query("SELECT * FROM t", None).unwrap();
        assert_eq!(result.total_rows, 1);
    }

    #[test]
    fn streaming_result_uses_the_executed_schema() {
        let conn = test_connection();
        conn.execute_statement("CREATE TABLE t (id INTEGER, label VARCHAR)", None)
            .unwrap();
        conn.execute_statement("INSERT INTO t VALUES (1, 'one'), (2, 'two')", None)
            .unwrap();

        let result = conn
            .execute_query_with_params(
                "SELECT id, label FROM t WHERE id > ? ORDER BY id",
                &[Value::Int(0)],
                None,
            )
            .unwrap();

        assert_eq!(result.total_rows, 2);
        assert_eq!(result.schema.field(0).name(), "id");
        assert_eq!(
            result.schema.field(0).data_type(),
            &arrow_schema::DataType::Int32
        );
        assert_eq!(result.schema.field(1).name(), "label");
        assert_eq!(
            result.schema.field(1).data_type(),
            &arrow_schema::DataType::Utf8
        );
    }

    fn json_cell(result: &QueryResult, column: usize, row: usize) -> serde_json::Value {
        let values = result.batches[0]
            .column(column)
            .as_any()
            .downcast_ref::<arrow_array::StringArray>()
            .unwrap();
        serde_json::from_str(values.value(row)).unwrap()
    }

    #[test]
    fn variant_results_convert_without_changing_storage_or_query_semantics() {
        let conn = test_connection();
        conn.execute_batch(
            "CREATE TABLE run(id INTEGER, config VARIANT); \
            INSERT INTO run VALUES (1, {'width': 64, 'tags': ['a', 'b']}::VARIANT), \
            (2, {'dataset': 'test'}::VARIANT), (3, NULL);",
            crate::usage::ExecutionLabel::SwanLake, None,
        )
        .unwrap();
        let sql = "SELECT * FROM run ORDER BY id";
        let schema = conn.schema_for_streaming(sql, None).unwrap();
        let result = conn.execute_query(sql, None).unwrap();
        assert_eq!(schema, result.schema);
        assert_eq!(conn.table_schema("run", None).unwrap(), result.schema);
        assert_eq!(
            result.schema.field(0).data_type(),
            &arrow_schema::DataType::Int32
        );
        assert_eq!(
            result.schema.field(1).data_type(),
            &arrow_schema::DataType::Utf8
        );
        assert_eq!(
            json_cell(&result, 1, 0),
            serde_json::json!({"width": 64, "tags": ["a", "b"]})
        );
        assert_eq!(
            json_cell(&result, 1, 1),
            serde_json::json!({"dataset": "test"})
        );
        assert!(result.batches[0].column(1).is_null(2));
        let filtered = conn
            .execute_query(
                "SELECT config.width AS width FROM run \
            WHERE typeof(config) = 'VARIANT' AND config.width::INTEGER = 64",
            None,
            )
            .unwrap();
        assert_eq!(filtered.total_rows, 1);
        assert_eq!(json_cell(&filtered, 0, 0), serde_json::json!(64));
    }

    #[test]
    fn variant_results_preserve_duplicate_names_and_sql_comments() {
        let conn = test_connection();
        let sql = "-- leading comment\nSELECT 42::VARIANT AS \"x\"\";雪\", \
            7 AS \"x\"\";雪\"; -- trailing comment";
        let result = conn.execute_query(sql, None).unwrap();
        assert_eq!(result.schema.field(0).name(), "x\";雪");
        assert_eq!(result.schema.field(1).name(), "x\";雪");
        assert_eq!(json_cell(&result, 0, 0), serde_json::json!(42));
        assert_eq!(
            result.schema.field(1).data_type(),
            &arrow_schema::DataType::Int32
        );
        assert_eq!(conn.schema_for_streaming(sql, None).unwrap(), result.schema);
    }

    #[test]
    fn variant_results_convert_nested_containers_only_when_needed() {
        let conn = test_connection();
        let result = conn
            .execute_query(
                "SELECT [42::VARIANT, NULL] AS list, \
            {'v': 3::VARIANT} AS object, map(['v'], [4::VARIANT]) AS map, \
            [5::VARIANT]::VARIANT[1] AS array, {'VARIANT': 6} AS ordinary, \
            union_value(v := 7::VARIANT) AS union_value",
            None,
            )
            .unwrap();
        assert_eq!(json_cell(&result, 0, 0), serde_json::json!([42, null]));
        assert_eq!(json_cell(&result, 1, 0), serde_json::json!({"v": 3}));
        assert_eq!(json_cell(&result, 2, 0), serde_json::json!({"v": 4}));
        assert_eq!(json_cell(&result, 3, 0), serde_json::json!([5]));
        assert!(matches!(
            result.schema.field(4).data_type(),
            arrow_schema::DataType::Struct(_)
        ));
        assert_eq!(json_cell(&result, 5, 0), serde_json::json!({"v": 7}));
    }

    #[test]
    fn variant_results_match_schema_for_parameterized_and_plain_streams() {
        let conn = test_connection();
        for parameterized in [false, true] {
            let sql = if parameterized {
                "SELECT ?::VARIANT AS config"
            } else {
                "SELECT 64::VARIANT AS config"
            };
            let schema = conn.schema_for_query(sql, None).unwrap();
            let (tx, mut rx) = mpsc::channel(4);
            if parameterized {
                let collected = conn
                    .execute_query_with_params(sql, &[Value::Int(64)], None)
                    .unwrap();
                assert_eq!(json_cell(&collected, 0, 0), serde_json::json!(64));
                conn.execute_query_with_params_streaming(sql, &[Value::Int(64)], tx, None, None)
                    .unwrap();
            } else {
                conn.execute_query_streaming(sql, tx, None, None).unwrap();
            }
            let Some(StreamingBatch::Schema(actual)) = rx.blocking_recv() else {
                panic!("missing schema")
            };
            assert_eq!(schema, actual);
            let Some(StreamingBatch::Batch(batch)) = rx.blocking_recv() else {
                panic!("missing batch")
            };
            assert_eq!(batch.schema().as_ref(), &schema);
            let value = batch
                .column(0)
                .as_any()
                .downcast_ref::<arrow_array::StringArray>()
                .unwrap();
            assert_eq!(value.value(0), "64");
            assert!(matches!(
                rx.blocking_recv(),
                Some(StreamingBatch::Done { total_rows: 1, .. })
            ));
        }
    }

    #[test]
    fn variant_results_evaluate_rows_once_and_keep_json_metadata() {
        let conn = test_connection();
        conn.execute_batch("CREATE SEQUENCE s; SET arrow_lossless_conversion = true;", crate::usage::ExecutionLabel::SwanLake, None)
            .unwrap();
        let sql = "SELECT nextval('s')::VARIANT AS v FROM range(3)";
        let schema = conn.schema_for_streaming(sql, None).unwrap();
        let result = conn.execute_query(sql, None).unwrap();
        assert_eq!(schema, result.schema);
        for i in 0..3 {
            assert_eq!(json_cell(&result, 0, i), serde_json::json!(i + 1));
        }
        assert_eq!(
            schema
                .field(0)
                .metadata()
                .get("ARROW:extension:name")
                .map(String::as_str),
            Some("arrow.json")
        );
        conn.execute_batch("CREATE TABLE run(config VARIANT NOT NULL)", crate::usage::ExecutionLabel::SwanLake, None)
            .unwrap();
        let table_schema = conn.table_schema("run", None).unwrap();
        assert_eq!(table_schema.field(0).metadata(), schema.field(0).metadata());
        assert!(!table_schema.field(0).is_nullable());
    }

    #[test]
    fn variant_results_leave_commands_and_batches_on_the_existing_path() {
        let conn = test_connection();
        conn.execute_batch("CREATE TABLE t (id INTEGER);", crate::usage::ExecutionLabel::SwanLake, None).unwrap();
        conn.execute_query("WITH source AS (SELECT 1 AS id) INSERT INTO t SELECT id FROM source", None)
            .unwrap();
        let result = conn
            .execute_query("INSERT INTO t VALUES (2); SELECT * FROM t ORDER BY id", None)
            .unwrap();
        assert_eq!(result.total_rows, 2);
        assert_eq!(
            conn.execute_query("EXPLAIN SELECT 42::VARIANT", None)
                .unwrap()
                .total_rows,
            1
        );
    }

    #[test]
    fn attached_catalog_schema_probe_can_be_followed_by_streaming_execution() {
        let dir = tempfile::tempdir().unwrap();
        let database_path = dir.path().join("attached.duckdb");
        {
            let attached = duckdb::Connection::open(&database_path).unwrap();
            attached
                .execute_batch("CREATE TABLE t (id INTEGER); INSERT INTO t VALUES (1);")
                .unwrap();
        }

        let conn = test_connection();
        conn.execute_statement(&format!(
            "ATTACH '{}' AS wh",
            database_path.to_string_lossy().replace('\'', "''")
        ), None)
        .unwrap();

        let schema = conn.schema_for_streaming("SELECT id FROM wh.t", None).unwrap();
        assert_eq!(schema.field(0).name(), "id");

        let (tx, mut rx) = mpsc::channel(4);
        conn.execute_query_streaming("SELECT id FROM wh.t", tx, None, None)
            .unwrap();

        let mut total_rows = None;
        while let Some(message) = rx.blocking_recv() {
            if let StreamingBatch::Done { total_rows: rows, .. } = message {
                total_rows = Some(rows);
            }
        }
        assert_eq!(total_rows, Some(1));

        conn.execute_statement("DETACH wh", None).unwrap();
    }

    /// Execution preserves profiling configured during session setup. The
    /// supported `no_output` mode also permits CTAS without JSON rendering.
    #[test]
    fn execution_preserves_preset_profiling() {
        let conn = test_connection();
        conn.execute_batch("SET enable_profiling = 'no_output'", crate::usage::ExecutionLabel::SwanLake, None)
            .unwrap();
        let assert_profiling = || {
            let profiling: Option<String> = conn
                .with_raw(|raw| {
                    raw.query_row("SELECT current_setting('enable_profiling')", [], |row| {
                        row.get(0)
                    })
                })
                .unwrap();
            assert_eq!(profiling.as_deref(), Some("no_output"));
        };

        conn.execute_statement("CREATE TABLE t AS SELECT 1 AS a", None)
            .unwrap();
        assert_profiling();
        conn.execute_statement_with_params("INSERT INTO t VALUES (?)", &[Value::Int(2)], None)
            .unwrap();
        assert_profiling();

        let (tx, mut rx) = mpsc::channel(4);
        conn.execute_query_streaming("SELECT * FROM t", tx, None, None)
            .unwrap();
        let mut total_rows = None;
        while let Some(message) = rx.blocking_recv() {
            if let StreamingBatch::Done {
                total_rows: rows, ..
            } = message
            {
                total_rows = Some(rows);
            }
        }
        assert_eq!(total_rows, Some(2));
        assert_profiling();
        assert_eq!(
            conn.execute_query("SELECT * FROM t", None).unwrap().total_rows,
            2
        );
    }

    // === Brackets, entries, and labels (duckvis#815, C7) ===

    use crate::usage::testing::{attempts, record_of};

    fn swanlake(abandoned: bool) -> (String, bool) {
        ("SWANLAKE".to_string(), abandoned)
    }

    fn client(abandoned: bool) -> (String, bool) {
        ("CLIENT".to_string(), abandoned)
    }

    fn row_count(conn: &DuckDbConnection, table: &str) -> usize {
        conn.with_raw(|raw| {
            raw.query_row(&format!("SELECT count(*) FROM {table}"), [], |row| {
                row.get::<_, i64>(0)
            })
        })
        .map(|count| count as usize)
        .unwrap_or(usize::MAX)
    }

    /// A read query makes a label-0 attempt for its schema probe, ahead of
    /// the label-1 attempt for the client's statement.
    #[test]
    fn a_read_query_records_its_probe_and_its_statement() {
        let conn = test_connection();
        let (result, record) = record_of(|accounting| {
            conn.execute_query("SELECT 42 AS answer", Some(accounting))
        });
        assert_eq!(result.unwrap().total_rows, 1);
        let record = record.expect("the request recorded entries");
        assert_eq!(attempts(&record), [swanlake(false), client(false)]);

        let (result, record) = record_of(|accounting| {
            conn.execute_query_with_params("SELECT ? AS answer", &[Value::Int(42)], Some(accounting))
        });
        assert_eq!(result.unwrap().total_rows, 1);
        assert_eq!(
            attempts(&record.unwrap()),
            [swanlake(false), client(false)]
        );
    }

    /// The streaming probe reads a schema and drops its stream unread, so
    /// its attempt is abandoned on every request. The client's stream is
    /// read to its end and is not.
    #[test]
    fn a_streamed_query_records_an_abandoned_probe() {
        let conn = test_connection();
        let (tx, mut rx) = mpsc::channel(16);
        let (result, record) = record_of(|accounting| {
            conn.execute_query_streaming("SELECT 42 AS answer", tx, None, Some(accounting))
        });
        result.unwrap();
        let mut done = false;
        while let Some(message) = rx.blocking_recv() {
            done |= matches!(message, StreamingBatch::Done { total_rows: 1, .. });
        }
        assert!(done);
        assert_eq!(
            attempts(&record.unwrap()),
            [swanlake(true), client(false)]
        );
    }

    /// A text that is no single read query has no probe: it runs as the
    /// client sent it, under label 1 alone.
    #[test]
    fn a_command_records_its_statement_alone() {
        let conn = test_connection();
        let (result, record) = record_of(|accounting| {
            conn.execute_statement_with_params(
                "CREATE TABLE commands (i INTEGER)",
                &[],
                Some(accounting),
            )
        });
        result.unwrap();
        assert_eq!(attempts(&record.unwrap()), [client(false)]);

        let (result, record) = record_of(|accounting| {
            conn.execute_statement_with_params(
                "INSERT INTO commands VALUES (?)",
                &[Value::Int(1)],
                Some(accounting),
            )
        });
        assert_eq!(result.unwrap(), 1);
        assert_eq!(attempts(&record.unwrap()), [client(false)]);

        let (result, record) = record_of(|accounting| {
            conn.parameter_count("INSERT INTO commands VALUES (?)", Some(accounting))
        });
        assert_eq!(result.unwrap(), 1);
        assert_eq!(attempts(&record.unwrap()), [client(false)]);
        assert_eq!(row_count(&conn, "commands"), 1);
    }

    /// A block yields one entry for each statement, in order, and its
    /// outcome is the one a prepare of the block had.
    #[test]
    fn a_block_records_one_entry_for_each_statement() {
        let conn = test_connection();
        let (result, record) = record_of(|accounting| {
            conn.execute_statement_with_params(
                "CREATE TABLE block (i INTEGER); INSERT INTO block VALUES (1), (2); \
                 INSERT INTO block VALUES (3)",
                &[],
                Some(accounting),
            )
        });
        assert_eq!(result.unwrap(), 1, "the last statement's affected rows");
        assert_eq!(
            attempts(&record.unwrap()),
            [client(false), client(false), client(false)]
        );
        assert_eq!(row_count(&conn, "block"), 3, "each statement ran once");
    }

    /// A statement that fails ends the block: its attempt is the last entry,
    /// no later statement runs, and the failure carries the engine's type.
    #[test]
    fn a_failing_statement_records_its_entry_and_ends_the_block() {
        let conn = test_connection();
        let (result, record) = record_of(|accounting| {
            conn.execute_statement_with_params(
                "CREATE TABLE failing (i INTEGER PRIMARY KEY); INSERT INTO failing VALUES (1); \
                 INSERT INTO failing VALUES (1); INSERT INTO failing VALUES (2)",
                &[],
                Some(accounting),
            )
        });
        let Err(ServerError::DuckDb(duckdb::Error::DuckDBFailure(failure, _))) = result else {
            panic!("expected the constraint failure, got {result:?}");
        };
        assert_eq!(
            failure.error_type,
            ffi::duckdb_error_type_DUCKDB_ERROR_CONSTRAINT
        );
        assert_eq!(
            attempts(&record.unwrap()),
            [client(false), client(false), client(false)]
        );
        assert_eq!(row_count(&conn, "failing"), 1);
    }

    /// Extraction parses the whole block before any statement runs, so a
    /// parse error in a later statement keeps the first from running. The
    /// one attempt covers the parse.
    #[test]
    fn a_parse_error_runs_no_statement() {
        let conn = test_connection();
        let (result, record) = record_of(|accounting| {
            conn.execute_statement_with_params(
                "CREATE TABLE unparsed (i INTEGER); SELEC 1",
                &[],
                Some(accounting),
            )
        });
        let Err(ServerError::DuckDb(duckdb::Error::DuckDBFailure(failure, _))) = result else {
            panic!("expected the parse failure, got {result:?}");
        };
        assert_eq!(failure.error_type, ffi::duckdb_error_type_DUCKDB_ERROR_PARSER);
        assert_eq!(attempts(&record.unwrap()), [client(false)]);
        assert_eq!(
            row_count(&conn, "unparsed"),
            usize::MAX,
            "the first statement did not run"
        );
    }

    /// A block that holds no statement returns, on a route that prepares,
    /// the error a prepare of that block returns, and makes one attempt.
    #[test]
    fn an_empty_block_returns_the_prepare_error() {
        let conn = test_connection();
        for sql in ["", "   ", ";", "-- a comment"] {
            let expected = conn
                .with_raw(|raw| raw.prepare(sql).map(|_| ()))
                .expect_err("a prepare of an empty block fails");
            let (result, record) = record_of(|accounting| {
                conn.execute_statement_with_params(sql, &[], Some(accounting))
            });
            let Err(ServerError::DuckDb(error)) = result else {
                panic!("expected a failure for {sql:?}, got {result:?}");
            };
            assert_eq!(format!("{error:?}"), format!("{expected:?}"), "{sql:?}");
            assert_eq!(error.to_string(), expected.to_string(), "{sql:?}");
            assert_eq!(attempts(&record.unwrap()), [client(false)], "{sql:?}");
        }
    }

    // The route that discards every result (`measure_batch`).

    fn run_batch(
        conn: &DuckDbConnection,
        sql: &str,
        accounting: &RequestAccounting,
    ) -> Result<i64, ServerError> {
        conn.execute_statement_with_telemetry(sql, None, None, Some(accounting))
    }

    fn profiled_connection() -> DuckDbConnection {
        let conn = test_connection();
        conn.execute_batch(
            "SET enable_profiling = 'no_output'",
            ExecutionLabel::SwanLake,
            None,
        )
        .unwrap();
        conn
    }

    /// A block of several statements on the discarding route is one label-1
    /// attempt with no breakdown and no probe, and every statement runs once.
    #[test]
    fn a_batch_of_several_statements_records_one_entry_without_a_breakdown() {
        let conn = profiled_connection();
        let (result, record) = record_of(|accounting| {
            run_batch(
                &conn,
                "CREATE TABLE batch (i INTEGER); INSERT INTO batch VALUES (1), (2); \
                 INSERT INTO batch SELECT i FROM range(10) t(i)",
                accounting,
            )
        });
        result.unwrap();
        let record = record.unwrap();
        assert_eq!(attempts(&record), [client(false)]);
        assert_eq!(row_count(&conn, "batch"), 12, "each statement ran once");
        let entry = &record["entries"][0];
        assert!(
            entry.get("breakdown").is_none(),
            "a block of several statements carries no tree: {entry}"
        );
        assert_eq!(record["breakdown_omitted"], false);
    }

    /// A block of exactly one statement on the discarding route is one
    /// label-1 attempt that carries the statement's breakdown.
    #[test]
    fn a_batch_of_one_statement_records_one_entry_with_its_breakdown() {
        let conn = profiled_connection();
        conn.execute_statement("CREATE TABLE single (i INTEGER)", None)
            .unwrap();
        let (result, record) = record_of(|accounting| {
            run_batch(
                &conn,
                "INSERT INTO single SELECT i FROM range(10) t(i)",
                accounting,
            )
        });
        result.unwrap();
        let record = record.unwrap();
        assert_eq!(attempts(&record), [client(false)]);
        assert_eq!(row_count(&conn, "single"), 10);
        let breakdown = &record["entries"][0]["breakdown"];
        assert!(breakdown.is_object(), "the statement's tree: {breakdown}");
        assert!(
            !breakdown["children"].as_array().unwrap().is_empty(),
            "the tree holds the statement's operators: {breakdown}"
        );
    }

    /// The engine expands an `ADD COLUMN` with a default that is not a
    /// constant into `BEGIN`, a body, and `COMMIT`. When the body fails on
    /// the discarding route, the one `duckdb_query` call rolls the
    /// transaction back: the session stays in autocommit and takes the next
    /// statement.
    #[test]
    fn a_failing_expanded_statement_leaves_the_session_in_autocommit() {
        let conn = test_connection();
        conn.execute_statement("CREATE TABLE expanded (i INTEGER, c INTEGER)", None)
            .unwrap();
        conn.execute_statement("INSERT INTO expanded VALUES (1, 1)", None)
            .unwrap();
        let (result, record) = record_of(|accounting| {
            run_batch(
                &conn,
                "ALTER TABLE expanded ADD COLUMN c INTEGER DEFAULT (random()*10)::INTEGER",
                accounting,
            )
        });
        let Err(ServerError::DuckDb(duckdb::Error::DuckDBFailure(failure, _))) = result else {
            panic!("expected the catalog failure, got {result:?}");
        };
        assert_eq!(
            failure.error_type,
            ffi::duckdb_error_type_DUCKDB_ERROR_CATALOG
        );
        assert_eq!(attempts(&record.unwrap()), [client(false)]);

        // A plain statement runs and commits by itself.
        conn.execute_statement("INSERT INTO expanded VALUES (2, 2)", None)
            .expect("the session takes the next statement");
        // No transaction is open: a ROLLBACK has nothing to end, and the
        // insert above is kept.
        let rollback = conn.execute_statement("ROLLBACK", None);
        assert!(
            rollback.is_err(),
            "the session is in autocommit, so ROLLBACK fails: {rollback:?}"
        );
        assert_eq!(row_count(&conn, "expanded"), 2);
    }

    /// The discarding route prepares no statement, so a statement with a
    /// VARIANT result column succeeds there, last in the block or not.
    #[test]
    fn a_batch_runs_a_variant_result_statement() {
        let conn = test_connection();
        for sql in [
            "SELECT 42::VARIANT AS v",
            "SELECT 42::VARIANT AS v; SELECT 'x'::VARIANT AS w",
        ] {
            let (result, record) = record_of(|accounting| run_batch(&conn, sql, accounting));
            result.unwrap_or_else(|error| panic!("{sql:?} failed: {error}"));
            assert_eq!(attempts(&record.unwrap()), [client(false)], "{sql:?}");
        }
    }

    /// A parse error in a later statement of a batch keeps the first from
    /// running. The count's failure is ignored, the `duckdb_query` call
    /// reports the error with its type, and the one attempt covers both.
    #[test]
    fn a_batch_parse_error_runs_no_statement() {
        let conn = test_connection();
        let (result, record) = record_of(|accounting| {
            run_batch(&conn, "CREATE TABLE unparsed_batch (i INTEGER); SELEC 1", accounting)
        });
        let Err(ServerError::DuckDb(duckdb::Error::DuckDBFailure(failure, _))) = result else {
            panic!("expected the parse failure, got {result:?}");
        };
        assert_eq!(failure.error_type, ffi::duckdb_error_type_DUCKDB_ERROR_PARSER);
        assert_eq!(attempts(&record.unwrap()), [client(false)]);
        assert_eq!(
            row_count(&conn, "unparsed_batch"),
            usize::MAX,
            "the first statement did not run"
        );
    }

    /// A block that holds no statement succeeds on the discarding route and
    /// makes one attempt with no breakdown.
    #[test]
    fn an_empty_batch_succeeds() {
        let conn = profiled_connection();
        for sql in ["", "   ", ";", "-- a comment"] {
            let (result, record) = record_of(|accounting| run_batch(&conn, sql, accounting));
            assert_eq!(result.unwrap(), 0, "{sql:?}");
            let record = record.unwrap();
            assert_eq!(attempts(&record), [client(false)], "{sql:?}");
            assert!(record["entries"][0].get("breakdown").is_none(), "{sql:?}");
        }
    }

    /// A statement that fails ends a batch: the block is one entry, no later
    /// statement runs, and the failure carries the engine's type.
    #[test]
    fn a_failing_batch_statement_records_one_entry_and_ends_the_block() {
        let conn = test_connection();
        let (result, record) = record_of(|accounting| {
            run_batch(
                &conn,
                "CREATE TABLE failing_batch (i INTEGER PRIMARY KEY); \
                 INSERT INTO failing_batch VALUES (1); INSERT INTO failing_batch VALUES (1); \
                 INSERT INTO failing_batch VALUES (2)",
                accounting,
            )
        });
        let Err(ServerError::DuckDb(duckdb::Error::DuckDBFailure(failure, _))) = result else {
            panic!("expected the constraint failure, got {result:?}");
        };
        assert_eq!(
            failure.error_type,
            ffi::duckdb_error_type_DUCKDB_ERROR_CONSTRAINT
        );
        assert_eq!(attempts(&record.unwrap()), [client(false)]);
        assert_eq!(row_count(&conn, "failing_batch"), 1);
    }

    /// A stream the consumer leaves unread leaves its execution open, and
    /// the bracket that started it ends it: the attempt is abandoned.
    #[test]
    fn an_abandoned_stream_marks_its_attempt() {
        let conn = test_connection();
        let (tx, mut rx) = mpsc::channel(1);
        let (result, record) = record_of(|accounting| {
            std::thread::scope(|scope| {
                let worker = scope.spawn(|| {
                    conn.execute_query_streaming(
                        "SELECT i FROM range(10000000) t(i)",
                        tx,
                        None,
                        Some(accounting),
                    )
                });
                assert!(matches!(rx.blocking_recv(), Some(StreamingBatch::Schema(_))));
                assert!(matches!(rx.blocking_recv(), Some(StreamingBatch::Batch(_))));
                drop(rx);
                worker.join().expect("the stream task returns")
            })
        });
        result.unwrap();
        assert_eq!(attempts(&record.unwrap()), [swanlake(true), client(true)]);
        // The connection takes the next statement.
        assert_eq!(conn.execute_query("SELECT 42", None).unwrap().total_rows, 1);
    }

    /// Ending an abandoned read leaves the client's explicit transaction
    /// open and usable.
    #[test]
    fn an_abandoned_read_keeps_an_explicit_transaction() {
        let conn = test_connection();
        conn.execute_statement("CREATE TABLE kept (i INTEGER)", None)
            .unwrap();
        conn.execute_batch("BEGIN TRANSACTION", ExecutionLabel::Client, None)
            .unwrap();
        conn.execute_statement_with_params("INSERT INTO kept VALUES (1)", &[], None)
            .unwrap();
        let (schema, record) =
            record_of(|accounting| conn.schema_for_query("SELECT i FROM kept", Some(accounting)));
        assert_eq!(schema.unwrap().fields().len(), 1);
        assert_eq!(attempts(&record.unwrap()), [swanlake(true)]);
        conn.execute_statement_with_params("INSERT INTO kept VALUES (2)", &[], None)
            .unwrap();
        conn.execute_batch("COMMIT", ExecutionLabel::Client, None)
            .unwrap();
        assert_eq!(row_count(&conn, "kept"), 2);
    }

    /// Schema discovery for a body DESCRIBE can wrap is SwanLake's work.
    /// For a body it cannot wrap, the client's text runs under label 1:
    /// every statement but the last executes, and the last is abandoned.
    #[test]
    fn schema_discovery_records_by_what_it_runs() {
        let conn = test_connection();
        let (schema, record) =
            record_of(|accounting| conn.schema_for_query("SELECT 1 AS a, 'x' AS b", Some(accounting)));
        assert_eq!(schema.unwrap().fields().len(), 2);
        assert_eq!(attempts(&record.unwrap()), [swanlake(true)]);

        let (schema, record) = record_of(|accounting| {
            conn.schema_for_query(
                "CREATE TABLE discovered (i INTEGER); SELECT i FROM range(100000) t(i)",
                Some(accounting),
            )
        });
        assert_eq!(schema.unwrap().fields().len(), 1);
        assert_eq!(attempts(&record.unwrap()), [client(false), client(true)]);
        assert_eq!(row_count(&conn, "discovered"), 0, "the first statement ran once");
    }

    /// `execute_batch` is one attempt under the label its caller passes.
    #[test]
    fn a_batch_is_one_attempt_under_its_label() {
        let conn = test_connection();
        for (label, expected) in [
            (ExecutionLabel::SwanLake, swanlake(false)),
            (ExecutionLabel::Client, client(false)),
        ] {
            let (result, record) = record_of(|accounting| {
                conn.execute_batch("SELECT 1; SELECT 2", label, Some(accounting))
            });
            result.unwrap();
            assert_eq!(attempts(&record.unwrap()), [expected]);
        }
    }

    /// An appender insert is the `USE` under label 0 and one label-1 attempt
    /// that covers every flush, the appender's own drop included.
    #[test]
    fn an_appender_insert_records_its_use_and_one_insert() {
        use arrow_array::Int32Array;
        let conn = test_connection();
        conn.execute_statement("CREATE TABLE appended (i INTEGER)", None)
            .unwrap();
        let batch = RecordBatch::try_new(
            std::sync::Arc::new(Schema::new(vec![Field::new(
                "i",
                arrow_schema::DataType::Int32,
                true,
            )])),
            vec![std::sync::Arc::new(Int32Array::from(vec![1, 2, 3]))],
        )
        .unwrap();
        let (result, record) = record_of(|accounting| {
            conn.insert_with_appender("memory", "appended", vec![batch.clone()], Some(accounting))
        });
        assert_eq!(result.unwrap(), 3);
        assert_eq!(attempts(&record.unwrap()), [swanlake(false), client(false)]);
        assert_eq!(row_count(&conn, "appended"), 3);

        // A failed insert still records both attempts.
        let (result, record) = record_of(|accounting| {
            conn.insert_with_appender("memory", "no_such_table", vec![batch], Some(accounting))
        });
        assert!(result.is_err());
        assert_eq!(attempts(&record.unwrap()), [swanlake(false), client(false)]);
    }

    /// The statements SwanLake composes to serve a request run under label 0.
    #[test]
    fn swanlake_statements_record_under_label_0() {
        let conn = test_connection();
        conn.execute_statement("CREATE TABLE described (i INTEGER, v VARCHAR)", None)
            .unwrap();
        let (schema, record) =
            record_of(|accounting| conn.table_schema("described", Some(accounting)));
        assert_eq!(schema.unwrap().fields().len(), 2);
        assert_eq!(attempts(&record.unwrap()), [swanlake(false)]);

        let (catalog, record) = record_of(|accounting| conn.current_catalog(Some(accounting)));
        assert_eq!(catalog.unwrap(), "memory");
        assert_eq!(attempts(&record.unwrap()), [swanlake(false)]);

        let (attached, record) =
            record_of(|accounting| conn.catalog_attached("MEMORY", Some(accounting)));
        assert!(attached.unwrap());
        assert_eq!(attempts(&record.unwrap()), [swanlake(false)]);

        let (values, record) = record_of(|accounting| {
            conn.query_strings("SELECT v FROM (VALUES ('a'), ('b')) t(v)", Some(accounting))
        });
        assert_eq!(values.unwrap(), ["a", "b"]);
        assert_eq!(attempts(&record.unwrap()), [swanlake(false)]);

        let (result, record) = record_of(|accounting| {
            conn.execute_statement_privileged("ATTACH ':memory:' AS armed", Some(accounting))
        });
        result.unwrap();
        assert_eq!(attempts(&record.unwrap()), [swanlake(false)]);
    }

    /// With no accounting the brackets still run and the entries are
    /// discarded; a request with no entry queues no record.
    #[test]
    fn a_request_without_statements_queues_no_record() {
        let conn = test_connection();
        let ((), record) = record_of(|_| {
            conn.execute_query("SELECT 1", None).unwrap();
        });
        assert!(record.is_none());
    }

    /// Each attempt of a block carries its statement's profiling tree, and
    /// an attempt of `measure` carries none.
    #[test]
    fn block_attempts_carry_a_breakdown() {
        let conn = test_connection();
        conn.execute_batch(
            "SET enable_profiling = 'no_output'",
            ExecutionLabel::SwanLake,
            None,
        )
        .unwrap();
        let (result, record) = record_of(|accounting| {
            conn.execute_query(
                "SELECT sum(sin(i::DOUBLE)) AS total FROM range(200000) t(i)",
                Some(accounting),
            )
        });
        assert_eq!(result.unwrap().total_rows, 1);
        let record = record.unwrap();
        assert_eq!(attempts(&record), [swanlake(false), client(false)]);
        let entries = record["entries"].as_array().unwrap();
        assert!(entries[0].get("breakdown").is_none());
        let breakdown = &entries[1]["breakdown"];
        assert!(breakdown.is_object(), "the statement's tree: {breakdown}");
        assert!(
            !breakdown["children"].as_array().unwrap().is_empty(),
            "the tree holds the statement's operators: {breakdown}"
        );
        assert!(entries[1]["cpu_seconds"].as_f64().unwrap() > 0.0);
        assert_eq!(record["breakdown_omitted"], false);
    }

    /// A panic inside a measured statement unwinds through the bracket: the
    /// closing read runs, the entry is recorded, and the guard is released.
    #[test]
    fn an_unwind_records_the_attempt() {
        let conn = test_connection();
        let (outcome, record) = record_of(|accounting| {
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                conn.guarded(None, Some(accounting), |raw, bracket| {
                    bracket.measure_block("SELECT 1; SELECT 2", |_| -> Result<(), ServerError> {
                        raw.execute_batch("SELECT 3").unwrap();
                        panic!("Failed to fetch Arrow record batch: INTERRUPT Error: Interrupted!")
                    })
                })
            }))
        });
        assert!(outcome.is_err(), "the panic propagates");
        assert_eq!(attempts(&record.unwrap()), [client(false), client(false)]);
        assert!(conn.guard_is_poisoned());
        assert!(!conn.guard_is_held());
        assert_eq!(conn.execute_query("SELECT 42", None).unwrap().total_rows, 1);
    }
}
