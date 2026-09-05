//! DuckDB connection wrapper with query execution methods.
//!
//! Each connection is owned by a Session and maintains persistent state
//! (ATTACH, temp tables, etc.).

use std::sync::Mutex;

use arrow_array::RecordBatch;
use arrow_schema::{Field, Schema, SchemaRef};
use duckdb::types::Value;
use duckdb::{params_from_iter, Connection};
use duckdb::{ArrowStream, Statement};
use tokio::sync::mpsc;
use tracing::{debug, info, instrument};

use super::result_projection;
use crate::error::ServerError;

use crate::types::duckdb_type_to_arrow;

/// Message sent through the streaming channel
pub enum StreamingBatch {
    /// Schema message (sent first)
    Schema(Schema),
    /// A record batch
    Batch(RecordBatch),
    /// Query completed with totals
    Done { total_rows: usize, total_bytes: usize },
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
pub struct DuckDbConnection {
    pub conn: Mutex<Connection>,
}

impl DuckDbConnection {
    /// Create a new connection wrapper
    pub fn new(conn: Connection) -> Self {
        Self {
            conn: Mutex::new(conn),
        }
    }

    /// Get an interrupt handle for cancelling long-running queries.
    ///
    /// The returned handle can be used from another thread to interrupt
    /// queries running on this connection.
    pub fn interrupt_handle(&self) -> std::sync::Arc<duckdb::InterruptHandle> {
        let conn = self.conn.lock().expect("connection mutex poisoned");
        conn.interrupt_handle()
    }

    /// Get the schema for a query without executing the full query.
    ///
    /// **Implementation Note:**
    /// DuckDB-rs doesn't provide a `Statement::schema()` method to get schema
    /// without execution. We execute the query as-is and rely on DuckDB's lazy
    /// evaluation to avoid pulling all data unnecessarily.
    ///
    /// This approach:
    /// 1. Is simple and always correct
    /// 2. Works with all SQL syntax (SHOW, DESCRIBE, PRAGMA, etc.)
    /// 3. Relies on DuckDB's streaming to avoid memory issues
    pub fn schema_for_query(&self, sql: &str) -> Result<Schema, ServerError> {
        let trimmed_sql = sql.trim_end_matches(';').trim();

        self.with_arrow_prepared(trimmed_sql, None, false, |stmt| {
            let stream = Self::stream_arrow_with_params(stmt, None)?;
            let schema = stream.get_schema();
            debug!(field_count = schema.fields().len(), "retrieved schema");
            Ok(schema.as_ref().clone())
        })
    }

    /// Schema planning for streaming: wraps in `SELECT * FROM () LIMIT 0` to
    /// avoid materializing data, except for statements like EXPLAIN that can't
    /// be used as subqueries.
    pub fn schema_for_streaming(&self, sql: &str) -> Result<Schema, ServerError> {
        self.with_arrow_prepared(sql, None, true, |stmt| {
            let stream = Self::stream_arrow_with_params(stmt, None)?;
            Ok(stream.get_schema().as_ref().clone())
        })
    }

    /// Execute a SELECT query and return results
    #[instrument(skip(self), fields(sql = %sql))]
    pub fn execute_query(&self, sql: &str) -> Result<QueryResult, ServerError> {
        self.with_arrow_prepared(sql, None, false, |stmt| {
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
    /// Pass an optional interrupt handle to enable cancellation when the
    /// receiver is closed.
    #[instrument(skip(self, tx, interrupt_handle), fields(sql = %sql))]
    pub fn execute_query_streaming(
        &self,
        sql: &str,
        tx: mpsc::Sender<StreamingBatch>,
        interrupt_handle: Option<std::sync::Arc<duckdb::InterruptHandle>>,
    ) -> Result<(), ServerError> {
        // `no_output` collects CPU metrics without taking DuckDB 1.5.5's JSON
        // rendering path, which aborts after an attached-catalog stream ends.
        {
            let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
            let _ = conn.execute_batch(
                "SET enable_profiling = 'no_output'; \
                 SET custom_profiling_settings = '{\"OPERATOR_CPU_TIME\": \"true\", \"CPU_TIME_ACTUAL\": \"true\"}';"
            );
        }

        // Now execute the full query in true streaming mode
        self.with_arrow_prepared(sql, None, false, |stmt| {
            let arrow = Self::stream_arrow_with_params(stmt, None)?;
            let schema = arrow.get_schema();

            if tx
                .blocking_send(StreamingBatch::Schema(schema.as_ref().clone()))
                .is_err()
            {
                debug!("streaming receiver dropped before schema sent");
                return Ok(());
            }

            // Stream batches with backpressure
            let mut total_rows = 0usize;
            let mut total_bytes = 0usize;
            let mut batch_count = 0usize;
            for batch in arrow {
                // Check if client cancelled before processing batch
                if tx.is_closed() {
                    info!(batch_count, total_rows, "streaming receiver closed, interrupting query");
                    if let Some(ref handle) = interrupt_handle {
                        handle.interrupt();
                    }
                    return Ok(());
                }

                batch_count += 1;
                let batch_rows = batch.num_rows();
                let batch_bytes = batch.get_array_memory_size();
                total_rows += batch_rows;
                total_bytes += batch_bytes;

                debug!(
                    batch_count,
                    batch_rows,
                    batch_bytes,
                    total_rows,
                    total_bytes,
                    "streaming batch"
                );

                if tx.blocking_send(StreamingBatch::Batch(batch)).is_err() {
                    info!(batch_count, total_rows, "streaming receiver dropped, interrupting query");
                    if let Some(ref handle) = interrupt_handle {
                        handle.interrupt();
                    }
                    return Ok(());
                }
            }

            // Send completion message
            let _ = tx.blocking_send(StreamingBatch::Done { total_rows, total_bytes });
            info!(batch_count, total_rows, total_bytes, "streaming query completed");
            Ok(())
        })
    }

    /// Execute a query with parameters and stream results through a channel.
    ///
    /// This method uses DuckDB's true streaming execution with backpressure.
    ///
    /// Pass an optional interrupt handle to enable cancellation when the
    /// receiver is closed.
    #[instrument(skip(self, tx, params, interrupt_handle), fields(sql = %sql, param_count = params.len()))]
    pub fn execute_query_with_params_streaming(
        &self,
        sql: &str,
        params: &[Value],
        tx: mpsc::Sender<StreamingBatch>,
        interrupt_handle: Option<std::sync::Arc<duckdb::InterruptHandle>>,
    ) -> Result<(), ServerError> {
        // `no_output` collects CPU metrics without taking DuckDB 1.5.5's JSON
        // rendering path, which aborts after an attached-catalog stream ends.
        {
            let conn = self.conn.lock().unwrap_or_else(|p| p.into_inner());
            let _ = conn.execute_batch(
                "SET enable_profiling = 'no_output'; \
                 SET custom_profiling_settings = '{\"OPERATOR_CPU_TIME\": \"true\", \"CPU_TIME_ACTUAL\": \"true\"}';"
            );
        }

        // Now execute the full query in true streaming mode
        self.with_arrow_prepared(sql, Some(params), false, |stmt| {
            let arrow = Self::stream_arrow_with_params(stmt, Some(params))?;
            let schema = arrow.get_schema();

            if tx
                .blocking_send(StreamingBatch::Schema(schema.as_ref().clone()))
                .is_err()
            {
                debug!("streaming receiver dropped before schema sent");
                return Ok(());
            }

            // Stream batches with backpressure
            let mut total_rows = 0usize;
            let mut total_bytes = 0usize;
            let mut batch_count = 0usize;
            for batch in arrow {
                // Check if client cancelled before processing batch
                if tx.is_closed() {
                    info!(batch_count, total_rows, "streaming receiver closed, interrupting query");
                    if let Some(ref handle) = interrupt_handle {
                        handle.interrupt();
                    }
                    return Ok(());
                }

                batch_count += 1;
                let batch_rows = batch.num_rows();
                let batch_bytes = batch.get_array_memory_size();
                total_rows += batch_rows;
                total_bytes += batch_bytes;

                debug!(
                    batch_count,
                    batch_rows,
                    batch_bytes,
                    total_rows,
                    total_bytes,
                    "streaming batch (with params)"
                );

                if tx.blocking_send(StreamingBatch::Batch(batch)).is_err() {
                    info!(batch_count, total_rows, "streaming receiver dropped, interrupting query");
                    if let Some(ref handle) = interrupt_handle {
                        handle.interrupt();
                    }
                    return Ok(());
                }
            }

            // Send completion message
            let _ = tx.blocking_send(StreamingBatch::Done { total_rows, total_bytes });
            info!(batch_count, total_rows, total_bytes, "streaming query with params completed");
            Ok(())
        })
    }

    /// Execute a query with parameters
    #[instrument(skip(self, params), fields(sql = %sql, param_count = params.len()))]
    pub fn execute_query_with_params(
        &self,
        sql: &str,
        params: &[Value],
    ) -> Result<QueryResult, ServerError> {
        self.with_arrow_prepared(sql, Some(params), false, |stmt| {
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
    pub fn parameter_count(&self, sql: &str) -> Result<usize, ServerError> {
        self.with_prepared(sql, |stmt| Ok(stmt.parameter_count()))
    }

    /// Execute a statement (DDL/DML) without returning results
    #[instrument(skip(self), fields(sql = %sql))]
    pub fn execute_statement(&self, sql: &str) -> Result<i64, ServerError> {
        Self::validate_sql(sql)?;
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // The streaming path enables profiling on this shared session connection
        // for CPU sampling and never resets it. With profiling on, a
        // `CREATE TABLE AS SELECT` run through the arrow C-API returns a null
        // result ("out is null"). Clear it first so DDL/DML (including CTAS)
        // from the execute action run cleanly. Ignored result: RESET is a no-op
        // when profiling is already at its default.
        let _ = conn.execute_batch("RESET enable_profiling");
        conn.execute_batch(sql)?;
        debug!("executed statement");
        Ok(0)
    }

    /// Execute a statement with parameters
    #[instrument(skip(self, params), fields(sql = %sql, param_count = params.len()))]
    pub fn execute_statement_with_params(
        &self,
        sql: &str,
        params: &[Value],
    ) -> Result<usize, ServerError> {
        // Clear any leaked profiling state before running a (possibly
        // query-materializing) statement; see `execute_statement`.
        {
            let conn = self
                .conn
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let _ = conn.execute_batch("RESET enable_profiling");
        }
        self.with_prepared(sql, |stmt| {
            let affected = Self::execute_with_params(stmt, params)?;
            debug!(affected, "executed statement with parameters");
            Ok(affected)
        })
    }

    /// Execute a batch of SQL statements
    #[instrument(skip(self), fields(sql = %sql))]
    pub fn execute_batch(&self, sql: &str) -> Result<(), ServerError> {
        Self::validate_sql(sql)?;
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        conn.execute_batch(sql)?;
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
    #[instrument(skip(self, batches), fields(catalog_name = %catalog_name, table_name = %table_name, rows = batches.iter().map(|b| b.num_rows()).sum::<usize>()))]
    pub fn insert_with_appender(
        &self,
        catalog_name: &str,
        table_name: &str,
        batches: Vec<RecordBatch>,
    ) -> Result<usize, ServerError> {
        let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
        info!(
            "appender to {}.{} with total rows {} and column {}",
            catalog_name,
            table_name,
            total_rows,
            batches.first().map(|b| b.num_columns()).unwrap_or(0)
        );

        let conn = self
            .conn
            .lock()
            .map_err(|_| ServerError::Internal("connection mutex poisoned".to_string()))?;
        conn.execute(&format!("USE {catalog_name};"), [])?;
        let mut appender = conn.appender(table_name)?;
        for batch in batches {
            appender.append_record_batch(batch)?;
        }
        appender.flush()?;

        debug!(
            rows = total_rows,
            table = %table_name,
            "inserted data using appender"
        );

        Ok(total_rows)
    }

    /// Get the schema of a table using DESC SELECT
    pub fn table_schema(&self, table_name: &str) -> Result<arrow_schema::Schema, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| ServerError::Internal("connection mutex poisoned".to_string()))?;

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
            if let Some(projection) = result_projection::for_query(&conn, &sql, None)? {
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
    pub fn current_catalog(&self) -> Result<String, ServerError> {
        let conn = self
            .conn
            .lock()
            .map_err(|_| ServerError::Internal("connection mutex poisoned".to_string()))?;
        let mut stmt = conn
            .prepare("SELECT current_database()")
            .map_err(ServerError::DuckDb)?;
        let catalog: String = stmt
            .query_row([], |row| row.get(0))
            .map_err(ServerError::DuckDb)?;
        Ok(catalog)
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
        schema_only: bool,
        f: F,
    ) -> Result<T, ServerError>
    where
        F: FnOnce(&mut Statement) -> Result<T, ServerError>,
    {
        Self::validate_sql(sql)?;
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let projection = result_projection::for_query(&conn, sql, params)?;
        let query = match projection {
            Some(query) if schema_only => format!("{query} LIMIT 0"),
            Some(query) => query,
            None if schema_only
                && !sql.trim_start().to_ascii_uppercase().starts_with("EXPLAIN") =>
            {
                format!(
                    "SELECT * FROM ({}) LIMIT 0",
                    sql.trim_end_matches(';').trim()
                )
            }
            None => sql.to_string(),
        };
        let mut stmt = conn.prepare(&query)?;
        f(&mut stmt)
    }

    /// Prepare a statement under the connection lock and run the provided closure.
    fn with_prepared<T, F>(&self, sql: &str, f: F) -> Result<T, ServerError>
    where
        F: FnOnce(&mut Statement) -> Result<T, ServerError>,
    {
        Self::validate_sql(sql)?;
        let conn = self
            .conn
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let mut stmt = conn.prepare(sql)?;
        f(&mut stmt)
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

#[cfg(test)]
mod tests {
    use super::*;

    fn test_connection() -> DuckDbConnection {
        let conn = Connection::open_in_memory().expect("failed to open in-memory db");
        DuckDbConnection::new(conn)
    }

    #[test]
    fn basic_statement_and_query() {
        let conn = test_connection();
        conn.execute_statement("CREATE TABLE t (id INTEGER)").unwrap();
        conn.execute_statement("INSERT INTO t VALUES (1)").unwrap();
        let result = conn.execute_query("SELECT * FROM t").unwrap();
        assert_eq!(result.total_rows, 1);
    }

    #[test]
    fn streaming_result_uses_the_executed_schema() {
        let conn = test_connection();
        conn.execute_statement("CREATE TABLE t (id INTEGER, label VARCHAR)")
            .unwrap();
        conn.execute_statement("INSERT INTO t VALUES (1, 'one'), (2, 'two')")
            .unwrap();

        let result = conn
            .execute_query_with_params(
                "SELECT id, label FROM t WHERE id > ? ORDER BY id",
                &[Value::Int(0)],
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
        )
        .unwrap();
        let sql = "SELECT * FROM run ORDER BY id";
        let schema = conn.schema_for_streaming(sql).unwrap();
        let result = conn.execute_query(sql).unwrap();
        assert_eq!(schema, result.schema);
        assert_eq!(conn.table_schema("run").unwrap(), result.schema);
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
        let result = conn.execute_query(sql).unwrap();
        assert_eq!(result.schema.field(0).name(), "x\";雪");
        assert_eq!(result.schema.field(1).name(), "x\";雪");
        assert_eq!(json_cell(&result, 0, 0), serde_json::json!(42));
        assert_eq!(
            result.schema.field(1).data_type(),
            &arrow_schema::DataType::Int32
        );
        assert_eq!(conn.schema_for_streaming(sql).unwrap(), result.schema);
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
            let schema = conn.schema_for_query(sql).unwrap();
            let (tx, mut rx) = mpsc::channel(4);
            if parameterized {
                let collected = conn
                    .execute_query_with_params(sql, &[Value::Int(64)])
                    .unwrap();
                assert_eq!(json_cell(&collected, 0, 0), serde_json::json!(64));
                conn.execute_query_with_params_streaming(sql, &[Value::Int(64)], tx, None)
                    .unwrap();
            } else {
                conn.execute_query_streaming(sql, tx, None).unwrap();
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
        conn.execute_batch("CREATE SEQUENCE s; SET arrow_lossless_conversion = true;")
            .unwrap();
        let sql = "SELECT nextval('s')::VARIANT AS v FROM range(3)";
        let schema = conn.schema_for_streaming(sql).unwrap();
        let result = conn.execute_query(sql).unwrap();
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
        conn.execute_batch("CREATE TABLE run(config VARIANT NOT NULL)")
            .unwrap();
        let table_schema = conn.table_schema("run").unwrap();
        assert_eq!(table_schema.field(0).metadata(), schema.field(0).metadata());
        assert!(!table_schema.field(0).is_nullable());
    }

    #[test]
    fn variant_results_leave_commands_and_batches_on_the_existing_path() {
        let conn = test_connection();
        conn.execute_batch("CREATE TABLE t (id INTEGER);").unwrap();
        conn.execute_query("WITH source AS (SELECT 1 AS id) INSERT INTO t SELECT id FROM source")
            .unwrap();
        let result = conn
            .execute_query("INSERT INTO t VALUES (2); SELECT * FROM t ORDER BY id")
            .unwrap();
        assert_eq!(result.total_rows, 2);
        assert_eq!(
            conn.execute_query("EXPLAIN SELECT 42::VARIANT")
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
        ))
        .unwrap();

        let schema = conn.schema_for_streaming("SELECT id FROM wh.t").unwrap();
        assert_eq!(schema.field(0).name(), "id");

        let (tx, mut rx) = mpsc::channel(4);
        conn.execute_query_streaming("SELECT id FROM wh.t", tx, None)
            .unwrap();

        let mut total_rows = None;
        while let Some(message) = rx.blocking_recv() {
            if let StreamingBatch::Done { total_rows: rows, .. } = message {
                total_rows = Some(rows);
            }
        }
        assert_eq!(total_rows, Some(1));

        conn.execute_statement("DETACH wh").unwrap();
    }

    /// The streaming path enables profiling on the shared session connection and
    /// never resets it. With profiling on, a `CREATE TABLE AS SELECT` executed
    /// through the arrow C-API returns a null result, surfaced by duckdb-rs as the
    /// opaque "out is null". Execute-statement paths must clear profiling first
    /// so DDL/DML (including CTAS) run cleanly.
    #[test]
    fn execute_statement_succeeds_after_profiling_enabled() {
        let conn = test_connection();
        // Simulate the streaming path leaving profiling enabled on the session.
        conn.execute_batch("SET enable_profiling = 'json'").unwrap();
        // Pre-fix: this returns Err("out is null").
        conn.execute_statement("CREATE TABLE t AS SELECT 1 AS a").unwrap();
        assert_eq!(
            conn.execute_query("SELECT count(*) FROM t").unwrap().total_rows,
            1
        );
    }
}
