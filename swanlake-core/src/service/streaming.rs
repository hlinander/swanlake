//! Streaming query execution and FlightData encoding.
//!
//! This module provides progressive streaming of query results, encoding
//! each RecordBatch to FlightData as it becomes available rather than
//! collecting all results first.
//!
//! Progress reporting: Each batch includes app_metadata with msgpack-encoded
//! progress (0.0 to 1.0) compatible with the Airport extension.
//!
//! Cancellation support: When the client cancels the request (e.g., Ctrl+C),
//! the stream is dropped, which triggers DuckDB query interruption via the
//! interrupt handle.

use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use arrow_array::RecordBatch;
use arrow_flight::flight_service_server::FlightService;
use arrow_flight::FlightData;
use arrow_ipc::writer::{IpcDataGenerator, IpcWriteOptions};
use arrow_schema::Schema;
use duckdb::InterruptHandle;
use futures::Stream;
use serde::Serialize;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Response, Status};
use tracing::{debug, error, info, trace, warn};

use crate::engine::{query_progress, ResourceSnapshot, ResourceTracker, StreamingBatch};
use crate::session::Session;

use super::SwanFlightSqlService;

/// Progress information encoded in FlightData app_metadata.
/// Compatible with Airport extension's AirportScannerProgress struct.
#[derive(Serialize)]
struct ScannerProgress {
    /// Progress from 0.0 to 1.0
    progress: f64,
    /// Peak memory usage in bytes since query start.
    #[serde(skip_serializing_if = "Option::is_none")]
    peak_memory_bytes: Option<u64>,
    /// Current memory usage in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    current_memory_bytes: Option<u64>,
    /// Accumulated CPU time in microseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    cpu_time_us: Option<u64>,
}

/// Encode progress and optional resource stats as msgpack for app_metadata.
fn encode_progress(progress: f64, snapshot: Option<ResourceSnapshot>) -> bytes::Bytes {
    let scanner_progress = ScannerProgress {
        progress: progress.clamp(0.0, 1.0),
        peak_memory_bytes: snapshot.map(|s| s.peak_memory_bytes),
        current_memory_bytes: snapshot.map(|s| s.current_memory_bytes),
        cpu_time_us: snapshot.and_then(|s| if s.cpu_time_us > 0 { Some(s.cpu_time_us) } else { None }),
    };
    match rmp_serde::to_vec_named(&scanner_progress) {
        Ok(bytes) => bytes.into(),
        Err(_) => bytes::Bytes::new(),
    }
}

/// Encode a schema to FlightData (schema message only).
fn encode_schema(schema: &Schema) -> Result<FlightData, Status> {
    let options = IpcWriteOptions::default();
    let data_gen = IpcDataGenerator::default();

    let mut dict_tracker = arrow_ipc::writer::DictionaryTracker::new(false);
    let schema_flight = data_gen.schema_to_bytes_with_dictionary_tracker(
        schema,
        &mut dict_tracker,
        &options,
    );

    Ok(FlightData {
        flight_descriptor: None,
        data_header: schema_flight.ipc_message.into(),
        data_body: bytes::Bytes::new(),
        app_metadata: bytes::Bytes::new(),
    })
}

/// Encode a RecordBatch to FlightData with optional progress in app_metadata.
#[allow(deprecated)]
fn encode_batch(
    batch: &RecordBatch,
    progress: Option<f64>,
    snapshot: Option<ResourceSnapshot>,
) -> Result<FlightData, Status> {
    let options = IpcWriteOptions::default();
    let data_gen = IpcDataGenerator::default();

    let mut dict_tracker = arrow_ipc::writer::DictionaryTracker::new(false);

    let (_, encoded) = data_gen
        .encoded_batch(batch, &mut dict_tracker, &options)
        .map_err(|e| Status::internal(format!("failed to encode batch: {e}")))?;

    let has_resource_data = snapshot
        .map_or(false, |s| s.peak_memory_bytes > 0 || s.cpu_time_us > 0);
    let app_metadata = if progress.is_some() || has_resource_data {
        encode_progress(progress.unwrap_or(0.0), snapshot)
    } else {
        bytes::Bytes::new()
    };

    Ok(FlightData {
        flight_descriptor: None,
        data_header: encoded.ipc_message.into(),
        data_body: encoded.arrow_data.into(),
        app_metadata,
    })
}

impl SwanFlightSqlService {
    /// Execute a query with streaming results.
    ///
    /// This method streams results as they become available from DuckDB,
    /// encoding each batch to FlightData lazily. This reduces:
    /// - Time to first byte (client sees data sooner)
    /// - Peak memory usage (no need to buffer all results)
    ///
    /// Cancellation support:
    /// - A monitor task watches for receiver closure (client disconnect)
    /// - When detected, it immediately interrupts DuckDB
    /// - The stream's Drop impl also calls interrupt as a fallback
    pub(crate) async fn execute_query_streaming(
        session: Arc<Session>,
        sql: String,
        params: Option<Vec<duckdb::types::Value>>,
    ) -> Result<Response<<Self as FlightService>::DoGetStream>, Status> {
        // Create channel for streaming batches (buffer of 4 for pipelining)
        let (tx, rx) = mpsc::channel::<StreamingBatch>(4);

        // Get interrupt handle for cancellation support
        let interrupt_handle = session.connection.interrupt_handle();

        // Spawn a cancellation monitor task that proactively interrupts DuckDB
        // as soon as the receiver is closed (client disconnects).
        // This is more responsive than waiting for the next batch iteration.
        let tx_monitor = tx.clone();
        let interrupt_handle_monitor = interrupt_handle.clone();
        let sql_for_monitor = sql.clone();
        tokio::spawn(async move {
            // Wait for the receiver to close (client disconnect or stream drop)
            tx_monitor.closed().await;
            // Interrupt DuckDB immediately - don't wait for next batch iteration
            info!(sql = %sql_for_monitor, "client disconnected, interrupting DuckDB query");
            interrupt_handle_monitor.interrupt();
        });

        // Create monitoring connection BEFORE spawning the blocking task,
        // while the session's connection mutex is still available.
        // try_clone() creates a sibling connection to the same database via duckdb_connect().
        // duckdb_memory() is database-wide, so any connection to the same DB works.
        let resource_tracker = {
            let conn_guard = session.connection.conn.lock()
                .map_err(|_| Status::internal("connection mutex poisoned"))?;
            match conn_guard.try_clone() {
                Ok(mon_conn) => {
                    drop(conn_guard);
                    Arc::new(ResourceTracker::start(mon_conn, interrupt_handle.clone()))
                }
                Err(e) => {
                    drop(conn_guard);
                    warn!(%e, "failed to clone monitoring connection, resource tracking disabled");
                    Arc::new(ResourceTracker::disabled())
                }
            }
        };

        // Spawn blocking task to execute query and stream batches
        let interrupt_handle_clone = interrupt_handle.clone();
        let sql_clone = sql.clone();

        tokio::task::spawn_blocking(move || {
            let result = match params {
                Some(ref p) => session.connection.execute_query_with_params_streaming(
                    &sql_clone,
                    p,
                    tx.clone(),
                    Some(interrupt_handle_clone.clone()),
                ),
                None => session.connection.execute_query_streaming(
                    &sql_clone,
                    tx.clone(),
                    Some(interrupt_handle_clone.clone()),
                ),
            };

            if let Err(e) = result {
                error!(%e, "streaming query execution failed");
                let _ = tx.blocking_send(StreamingBatch::Error(e));
            }
        });

        info!(sql = %sql, "started streaming query execution");

        // Convert channel to stream, mapping StreamingBatch to FlightData
        let rx_stream = ReceiverStream::new(rx);

        // State for tracking schema (needed for batch encoding context)
        // Pass interrupt handle for cancellation on drop (fallback mechanism)
        let stream =
            StreamingBatchToFlightData::new(rx_stream, interrupt_handle, resource_tracker);

        Ok(Response::new(Box::pin(stream)))
    }
}

/// Stream adapter that converts StreamingBatch messages to FlightData.
///
/// When dropped (e.g., client cancels), it interrupts the running DuckDB query.
/// Includes progress information in app_metadata for each batch.
///
/// Sends periodic heartbeat messages (0-row batches with app_metadata) so that
/// resource stats (memory, CPU) reach the client even when no data batches are
/// being produced.
struct StreamingBatchToFlightData<S> {
    inner: S,
    schema: Option<Arc<Schema>>,
    done: bool,
    /// Interrupt handle for cancellation and progress polling.
    interrupt_handle: Arc<InterruptHandle>,
    /// Resource tracker for memory usage sampling.
    resource_tracker: Arc<ResourceTracker>,
    /// Rows sent so far (for fallback progress calculation)
    rows_sent: u64,
    /// Periodic timer for sending progress heartbeats between data batches.
    heartbeat: tokio::time::Interval,
}

impl<S> StreamingBatchToFlightData<S> {
    fn new(
        inner: S,
        interrupt_handle: Arc<InterruptHandle>,
        resource_tracker: Arc<ResourceTracker>,
    ) -> Self {
        // First tick after 250ms (not immediately), then every 250ms.
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_millis(250),
            Duration::from_millis(250),
        );
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        Self {
            inner,
            schema: None,
            done: false,
            interrupt_handle,
            resource_tracker,
            rows_sent: 0,
            heartbeat,
        }
    }

    /// Get current progress (0.0 to 1.0) from DuckDB's query progress API.
    fn get_progress(&self) -> Option<f64> {
        query_progress(&self.interrupt_handle).map(|p| {
            // Convert percentage (0-100) to fraction (0-1)
            (p.percentage / 100.0).clamp(0.0, 1.0)
        })
    }
}

impl<S> Drop for StreamingBatchToFlightData<S> {
    fn drop(&mut self) {
        // If the stream wasn't fully consumed (done=false), the client cancelled
        if !self.done {
            warn!("streaming query cancelled by client, interrupting DuckDB");
            self.interrupt_handle.interrupt();
        }
    }
}

impl<S> Stream for StreamingBatchToFlightData<S>
where
    S: Stream<Item = StreamingBatch> + Unpin,
{
    type Item = Result<FlightData, Status>;

    fn poll_next(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use std::task::Poll;

        if self.done {
            return Poll::Ready(None);
        }

        match Pin::new(&mut self.inner).poll_next(cx) {
            Poll::Ready(Some(batch)) => match batch {
                StreamingBatch::Schema(schema) => {
                    debug!(fields = schema.fields().len(), "streaming: received schema");
                    self.schema = Some(Arc::new(schema.clone()));
                    match encode_schema(&schema) {
                        Ok(fd) => Poll::Ready(Some(Ok(fd))),
                        Err(e) => {
                            self.done = true;
                            Poll::Ready(Some(Err(e)))
                        }
                    }
                }
                StreamingBatch::Batch(batch) => {
                    let batch_rows = batch.num_rows() as u64;
                    self.rows_sent += batch_rows;
                    // Reset heartbeat so we don't send one right after real data.
                    self.heartbeat.reset();

                    // Get progress and resource stats
                    let progress = self.get_progress();
                    let snapshot = self.resource_tracker.snapshot();
                    info!(
                        rows = batch_rows,
                        total_rows_sent = self.rows_sent,
                        progress = ?progress,
                        peak_memory_bytes = snapshot.peak_memory_bytes,
                        current_memory_bytes = snapshot.current_memory_bytes,
                        cpu_time_us = snapshot.cpu_time_us,
                        "streaming: encoding batch with progress"
                    );

                    match encode_batch(&batch, progress, Some(snapshot)) {
                        Ok(fd) => Poll::Ready(Some(Ok(fd))),
                        Err(e) => {
                            self.done = true;
                            Poll::Ready(Some(Err(e)))
                        }
                    }
                }
                StreamingBatch::Done { total_rows, total_bytes } => {
                    info!(total_rows, total_bytes, "streaming query completed");
                    self.done = true;
                    Poll::Ready(None)
                }
                StreamingBatch::Error(e) => {
                    error!(%e, "streaming query error");
                    self.done = true;
                    Poll::Ready(Some(Err(Status::internal(format!("query error: {e}")))))
                }
            },
            Poll::Ready(None) => {
                self.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => {
                // No data batch available — send a heartbeat with resource stats
                // if the timer has fired. Uses a 0-row RecordBatch so the airport
                // extension sees a valid (but empty) batch and processes app_metadata.
                if let Some(schema) = self.schema.clone() {
                    if self.heartbeat.poll_tick(cx).is_ready() {
                        let progress = self.get_progress();
                        let snapshot = self.resource_tracker.snapshot();
                        let has_data = progress.is_some()
                            || snapshot.peak_memory_bytes > 0
                            || snapshot.cpu_time_us > 0;
                        if has_data {
                            let empty_batch = RecordBatch::new_empty(schema);
                            match encode_batch(&empty_batch, progress, Some(snapshot)) {
                                Ok(fd) => {
                                    trace!(
                                        progress = ?progress,
                                        peak_memory_bytes = snapshot.peak_memory_bytes,
                                        cpu_time_us = snapshot.cpu_time_us,
                                        "heartbeat: sending progress update"
                                    );
                                    return Poll::Ready(Some(Ok(fd)));
                                }
                                Err(_) => {}
                            }
                        }
                    }
                }
                Poll::Pending
            }
        }
    }
}
