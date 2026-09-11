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

use crate::engine::cancellation::{CancelOnDrop, RequestCancellation};
use crate::engine::{ResourceSnapshot, ResourceTracker, StreamingBatch, query_progress};
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
    /// - Disconnects cancel this request while it owns the connection
    /// - Dropping a completed stream cannot interrupt a subsequent query
    pub(crate) async fn execute_query_streaming(
        session: Arc<Session>,
        sql: String,
        params: Option<Vec<duckdb::types::Value>>,
    ) -> Result<Response<<Self as FlightService>::DoGetStream>, Status> {
        // Create channel for streaming batches (buffer of 4 for pipelining)
        let (tx, rx) = mpsc::channel::<StreamingBatch>(4);

        let cancellation = Arc::new(RequestCancellation::default());
        let cancel_on_disconnect = CancelOnDrop(cancellation.clone());

        // Connection acquisition can wait behind another query. Keep that wait
        // off the async runtime and reject cancelled requests after acquisition.
        let setup_session = session.clone();
        let setup_cancellation = cancellation.clone();
        let (interrupt_handle, monitoring_connection) = tokio::task::spawn_blocking(move || {
            let conn = setup_session
                .connection
                .conn
                .lock()
                .map_err(|_| Status::internal("connection mutex poisoned"))?;
            setup_cancellation
                .check()
                .map_err(Self::status_from_error)?;
            let interrupt = conn.interrupt_handle();
            let monitor = conn.try_clone();
            Ok::<_, Status>((interrupt, monitor))
        })
        .await
        .map_err(Self::status_from_join)??;
        let resource_tracker = match monitoring_connection {
            Ok(conn) => Arc::new(ResourceTracker::start(conn)),
            Err(e) => {
                warn!(%e, "failed to clone monitoring connection, resource tracking disabled");
                Arc::new(ResourceTracker::disabled())
            }
        };

        let tx_monitor = tx.clone();
        let monitor_cancellation = cancellation.clone();
        tokio::spawn(async move {
            tx_monitor.closed().await;
            monitor_cancellation.cancel();
        });

        let query_connection = session.connection.clone();
        let sql_clone = sql.clone();
        tokio::task::spawn_blocking(move || {
            let result = cancellation
                .check()
                .and_then(|()| session.ensure_lockdown())
                .and_then(|()| {
                    session.connection.stream_query_cancellable(
                        &sql_clone,
                        params.as_deref(),
                        tx.clone(),
                        &cancellation,
                    )
                });
            if let Err(e) = result {
                error!(%e, "streaming query execution failed");
                let _ = tx.blocking_send(StreamingBatch::Error(e));
            }
        });

        info!(sql = %sql, "started streaming query execution");

        // Convert channel to stream, mapping StreamingBatch to FlightData
        let rx_stream = ReceiverStream::new(rx);

        // State for tracking schema (needed for batch encoding context)
        // Transfer the disconnect guard to the response stream.
        let stream = StreamingBatchToFlightData::new(
            rx_stream,
            interrupt_handle,
            resource_tracker,
            cancel_on_disconnect,
            query_connection,
        );

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
    // InterruptHandle does not own its native connection. Progress polling must
    // retain the connection even after query completion or session eviction.
    _query_connection: Arc<crate::engine::DuckDbConnection>,
    schema: Option<Arc<Schema>>,
    done: bool,
    /// Interrupt handle used only for progress polling.
    interrupt_handle: Arc<InterruptHandle>,
    /// Cancels only the query belonging to this response, even after completion.
    _cancel_on_disconnect: CancelOnDrop,
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
        cancel_on_disconnect: CancelOnDrop,
        query_connection: Arc<crate::engine::DuckDbConnection>,
    ) -> Self {
        // First tick after 250ms (not immediately), then every 250ms.
        let mut heartbeat = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_millis(250),
            Duration::from_millis(250),
        );
        heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        Self {
            inner,
            _query_connection: query_connection,
            schema: None,
            done: false,
            interrupt_handle,
            _cancel_on_disconnect: cancel_on_disconnect,
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

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use crate::config::ServerConfig;
    use crate::engine::EngineFactory;
    use crate::session::{SessionId, registry::SessionRegistry};

    #[test]
    fn unavailable_cpu_metric_is_omitted_without_hiding_memory() {
        let bytes = encode_progress(
            0.5,
            Some(ResourceSnapshot {
                peak_memory_bytes: 100,
                current_memory_bytes: 80,
                cpu_time_us: 0,
            }),
        );
        let metadata: serde_json::Value = rmp_serde::from_slice(&bytes).unwrap();
        assert_eq!(metadata["peak_memory_bytes"], 100);
        assert_eq!(metadata["current_memory_bytes"], 80);
        assert!(metadata.get("cpu_time_us").is_none());
    }

    async fn session() -> anyhow::Result<Arc<Session>> {
        let config = ServerConfig::default();
        let registry = SessionRegistry::new(
            &config,
            Arc::new(EngineFactory::new_without_extension_bootstrap(&config)),
        )?;
        Ok(registry
            .get_or_create_by_id(&SessionId::from_string("stream-cancel".into()))
            .await?)
    }

    #[tokio::test]
    async fn response_keeps_query_connection_alive_after_execution() -> anyhow::Result<()> {
        let session = session().await?;
        let connection = Arc::downgrade(&session.connection);
        let mut response =
            SwanFlightSqlService::execute_query_streaming(session.clone(), "SELECT 1".into(), None)
                .await?
                .into_inner();
        drop(session);
        // Consume execution output but keep the response (and telemetry) alive.
        use futures::StreamExt;
        while response.next().await.is_some() {}
        tokio::time::sleep(Duration::from_millis(200)).await;
        assert!(
            connection.upgrade().is_some(),
            "telemetry outlived its query connection"
        );
        drop(response);
        assert!(connection.upgrade().is_none());
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn disconnected_stream_releases_active_query() -> anyhow::Result<()> {
        let session = session().await?;
        let cleanup = session.connection.interrupt_handle();
        let response = SwanFlightSqlService::execute_query_streaming(
            session.clone(),
            "SELECT sum(i) FROM range(1000000000) t(i)".into(),
            None,
        )
        .await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            while session.connection.conn.try_lock().is_ok() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        drop(response);
        let released = tokio::time::timeout(Duration::from_secs(2), async {
            while session.connection.conn.try_lock().is_err() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .is_ok();
        if !released {
            for _ in 0..100 {
                if session.connection.conn.try_lock().is_ok() {
                    break;
                }
                cleanup.interrupt();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        let next = tokio::task::spawn_blocking(move || {
            session.execute_statement("CREATE TABLE after_stream_cancel AS SELECT 42 AS value")
        });
        tokio::time::timeout(Duration::from_secs(5), next).await???;
        assert!(released, "disconnected stream left its query running");
        Ok(())
    }

    #[tokio::test]
    async fn queued_stream_setup_allows_deadline_to_fire() -> anyhow::Result<()> {
        let session = session().await?;
        let connection = session.connection.clone();
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            let _lock = connection.conn.lock().unwrap();
            let _ = ready_tx.send(());
            // Bound the pre-fix failure: a synchronous setup lock stalls the
            // sole runtime thread, preventing its request deadline from firing.
            let _ = release_rx.recv_timeout(Duration::from_secs(1));
        });
        ready_rx.await?;
        let result = tokio::time::timeout(
            Duration::from_millis(50),
            SwanFlightSqlService::execute_query_streaming(session.clone(), "SELECT 1".into(), None),
        )
        .await;
        let _ = release_tx.send(());
        blocker.await?;
        assert!(
            result.is_err(),
            "waiting for a connection blocked the request deadline"
        );
        let next = tokio::task::spawn_blocking(move || {
            session.execute_statement("CREATE TABLE after_queued_cancel AS SELECT 42 AS value")
        });
        tokio::time::timeout(Duration::from_secs(2), next).await???;
        Ok(())
    }

    #[tokio::test]
    async fn dropping_completed_response_cannot_interrupt_next_query() -> anyhow::Result<()> {
        let session = session().await?;
        let completed =
            SwanFlightSqlService::execute_query_streaming(session.clone(), "SELECT 1".into(), None)
                .await?;
        // Let the producer finish, but leave its small result unconsumed.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let connection = session.connection.clone();
        let next = tokio::task::spawn_blocking(move || -> anyhow::Result<i64> {
            let conn = connection.conn.lock().unwrap();
            // A late interrupt must not hit the next owner of this connection.
            let _ = ready_tx.send(());
            Ok(
                conn.query_row("SELECT sum(i) FROM range(100000000) t(i)", [], |row| {
                    row.get(0)
                })?,
            )
        });
        ready_rx.await?;
        tokio::time::sleep(Duration::from_millis(10)).await;
        drop(completed);
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), next).await???,
            4999999950000000
        );
        Ok(())
    }
}
