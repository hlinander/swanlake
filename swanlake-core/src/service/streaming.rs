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
use tracing::{debug, error, info, trace};

use crate::engine::cancellation::{CancelOnDrop, RequestCancellation};
use crate::engine::{ResourceSnapshot, StreamingBatch, progress_snapshot, query_progress};
use crate::session::Session;
use crate::usage::{Progress, RequestAccounting};

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
    ///
    /// The stream task holds `accounting` until the query ends, so the
    /// request's record is queued after its last attempt closes and not when
    /// the handler returns. The response stream holds the progress figures
    /// alone.
    pub(crate) async fn execute_query_streaming(
        session: Arc<Session>,
        sql: String,
        params: Option<Vec<duckdb::types::Value>>,
        accounting: Arc<RequestAccounting>,
    ) -> Result<Response<<Self as FlightService>::DoGetStream>, Status> {
        // Create channel for streaming batches (buffer of 4 for pipelining)
        let (tx, rx) = mpsc::channel::<StreamingBatch>(4);

        let cancellation = Arc::new(RequestCancellation::default());
        let cancel_on_disconnect = CancelOnDrop(cancellation.clone());

        // Connection acquisition can wait behind another query. Keep that wait
        // off the async runtime and reject cancelled requests after acquisition.
        let setup_session = session.clone();
        let setup_cancellation = cancellation.clone();
        let interrupt_handle = tokio::task::spawn_blocking(move || {
            let interrupt = setup_session.connection.interrupt_handle();
            setup_cancellation
                .check()
                .map_err(Self::status_from_error)?;
            Ok::<_, Status>(interrupt)
        })
        .await
        .map_err(Self::status_from_join)??;

        let tx_monitor = tx.clone();
        let monitor_cancellation = cancellation.clone();
        tokio::spawn(async move {
            tx_monitor.closed().await;
            monitor_cancellation.cancel();
        });

        let query_connection = session.connection.clone();
        let sql_clone = sql.clone();
        let progress = accounting.progress();
        tokio::task::spawn_blocking(move || {
            let result = cancellation
                .check()
                .and_then(|()| session.ensure_lockdown(Some(&accounting)))
                .and_then(|()| {
                    session.connection.stream_query_cancellable(
                        &sql_clone,
                        params.as_deref(),
                        tx.clone(),
                        &cancellation,
                        Some(&accounting),
                    )
                });
            if let Err(e) = result {
                error!(%e, "streaming query execution failed");
                Self::record_failure(&accounting, &e);
                // The record is queued before the client can observe the
                // stream's end.
                drop(accounting);
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
            progress,
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
    /// The request's progress figures, which outlive its accounting.
    progress: Progress,
    /// Rows sent so far (for fallback progress calculation)
    rows_sent: u64,
    /// Periodic timer for sending progress heartbeats between data batches.
    heartbeat: tokio::time::Interval,
}

impl<S> StreamingBatchToFlightData<S> {
    fn new(
        inner: S,
        interrupt_handle: Arc<InterruptHandle>,
        progress: Progress,
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
            progress,
            rows_sent: 0,
            heartbeat,
        }
    }

    /// The request's CPU and memory figures as of this call.
    fn snapshot(&self) -> ResourceSnapshot {
        progress_snapshot(&self.interrupt_handle, &self.progress)
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
                    let snapshot = self.snapshot();
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
                        let snapshot = self.snapshot();
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
    use crate::session::{SessionAuth, SessionId, registry::SessionRegistry};

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

    /// The accounting of a request whose record nothing reads.
    fn accounting() -> Arc<RequestAccounting> {
        Arc::new(RequestAccounting::new("DoGet", None, None))
    }

    async fn session() -> anyhow::Result<Arc<Session>> {
        let config = ServerConfig::default();
        let registry = SessionRegistry::new(
            &config,
            Arc::new(EngineFactory::new_without_extension_bootstrap(&config)),
        )?;
        Ok(registry
            .get_or_create_by_id_with_auth(
                &SessionId::from_string("stream-cancel".into()),
                Some(SessionAuth {
                    subject: "stream-test".into(),
                    project_id: "project-test".into(),
                    writer: false,
                }),
            )
            .await?)
    }

    /// The progress messages of a running statement carry the CPU the
    /// database has used since the attempt opened: the figure is positive and
    /// rises while the statement still holds the connection guard, and it
    /// never falls.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn executing_query_reports_rising_cpu_before_completion() -> anyhow::Result<()> {
        use futures::StreamExt;
        let session = session().await?;
        let mut response = SwanFlightSqlService::execute_query_streaming(
            session.clone(),
            // The aggregate uses CPU before the first row, and the
            // cross-product keeps the statement running while the client
            // reads.
            "SELECT sin(i::DOUBLE) + s FROM range(1000000) t(i) CROSS JOIN \
             (SELECT sum(sin(j::DOUBLE)) AS s FROM range(1000000) t(j))"
                .into(),
            None,
            accounting(),
        )
        .await?
        .into_inner();
        let observed = tokio::time::timeout(Duration::from_secs(10), async {
            let mut live = Vec::new();
            let mut last = 0;
            while let Some(batch) = response.next().await {
                let batch = batch?;
                if batch.app_metadata.is_empty() {
                    continue;
                }
                let metadata: serde_json::Value = rmp_serde::from_slice(&batch.app_metadata)?;
                let cpu = metadata["cpu_time_us"].as_u64().unwrap_or(0);
                anyhow::ensure!(cpu >= last, "CPU figure fell from {last} to {cpu}");
                last = cpu;
                if cpu > 0 && session.connection.guard_is_held() {
                    live.push(cpu);
                }
            }
            anyhow::ensure!(
                live.first() < live.last(),
                "CPU figure did not rise while the query was executing: {live:?}"
            );
            Ok::<_, anyhow::Error>(())
        })
        .await;
        drop(response);
        observed??;
        Ok(())
    }

    #[tokio::test]
    async fn response_keeps_query_connection_alive_after_execution() -> anyhow::Result<()> {
        let session = session().await?;
        let connection = Arc::downgrade(&session.connection);
        let mut response =
            SwanFlightSqlService::execute_query_streaming(session.clone(), "SELECT 1".into(), None, accounting())
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

    /// An interrupted Arrow fetch panics while holding the connection guard;
    /// the next streaming query on that session still runs.
    #[tokio::test]
    async fn streaming_query_runs_after_a_poisoned_connection() -> anyhow::Result<()> {
        use futures::StreamExt;
        let session = session().await?;
        let connection = session.connection.clone();
        let poisoned = std::thread::spawn(move || {
            connection.with_raw(|_| {
                panic!("Failed to fetch Arrow record batch: INTERRUPT Error: Interrupted!")
            })
        })
        .join();
        assert!(poisoned.is_err());
        assert!(session.connection.guard_is_poisoned());

        let mut response =
            SwanFlightSqlService::execute_query_streaming(session, "SELECT 42".into(), None, accounting())
                .await?
                .into_inner();
        let mut messages = 0;
        while let Some(message) = response.next().await {
            message?;
            messages += 1;
        }
        assert!(messages > 0, "the stream carried no data");
        Ok(())
    }

    /// The record a stream's request queues once the stream task ends.
    async fn queued_record(queue: &crate::usage::UsageQueue) -> anyhow::Result<serde_json::Value> {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if let Some(record) = crate::usage::testing::records(queue).pop() {
                    return record;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("the request queued no record"))
    }

    /// A stream the client reads to its end queues one record once the
    /// stream task ends: the label-0 attempt of the session's lockdown, the
    /// probe's abandoned label-0 attempt, then the statement's label-1
    /// attempt, which is not abandoned.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_drained_stream_records_its_probe_and_its_statement() -> anyhow::Result<()> {
        use crate::usage::testing;
        use futures::StreamExt;
        let session = session().await?;
        let queue = testing::queue();
        let mut response = SwanFlightSqlService::execute_query_streaming(
            session,
            "SELECT i FROM range(1000) t(i)".into(),
            None,
            testing::accounting("DoGet", &queue),
        )
        .await?
        .into_inner();
        while let Some(message) = response.next().await {
            message?;
        }
        let record = queued_record(&queue).await?;
        assert_eq!(record["endpoint"], "DoGet");
        assert_eq!(
            testing::attempts(&record),
            [
                ("SWANLAKE".to_string(), false),
                ("SWANLAKE".to_string(), true),
                ("CLIENT".to_string(), false)
            ],
            "the session's lockdown, the probe, the statement"
        );
        assert_eq!(testing::records(&queue).len(), 1);
        Ok(())
    }

    /// A client that stops reading abandons the statement: its label-1
    /// attempt carries `abandoned`.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_abandoned_stream_marks_its_statement() -> anyhow::Result<()> {
        use crate::usage::testing;
        use futures::StreamExt;
        let session = session().await?;
        let queue = testing::queue();
        let mut response = SwanFlightSqlService::execute_query_streaming(
            session,
            "SELECT i FROM range(100000000) t(i)".into(),
            None,
            testing::accounting("DoGet", &queue),
        )
        .await?
        .into_inner();
        // The schema, then one message of the running statement.
        for _ in 0..2 {
            response.next().await.transpose()?;
        }
        drop(response);
        let record = queued_record(&queue).await?;
        assert_eq!(
            testing::attempts(&record).last(),
            Some(&("CLIENT".to_string(), true))
        );
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
            accounting(),
        )
        .await?;
        tokio::time::timeout(Duration::from_secs(5), async {
            while !session.connection.guard_is_held() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await?;
        drop(response);
        let released = tokio::time::timeout(Duration::from_secs(2), async {
            while session.connection.guard_is_held() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .is_ok();
        if !released {
            for _ in 0..100 {
                if !session.connection.guard_is_held() {
                    break;
                }
                cleanup.interrupt();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
        let next = tokio::task::spawn_blocking(move || {
            session.execute_statement("CREATE TABLE after_stream_cancel AS SELECT 42 AS value", None)
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
            connection.with_raw(|_| {
                let _ = ready_tx.send(());
                // Bound the pre-fix failure: a synchronous setup lock stalls the
                // sole runtime thread, preventing its request deadline from firing.
                let _ = release_rx.recv_timeout(Duration::from_secs(1));
            });
        });
        ready_rx.await?;
        let result = tokio::time::timeout(
            Duration::from_millis(50),
            SwanFlightSqlService::execute_query_streaming(session.clone(), "SELECT 1".into(), None, accounting()),
        )
        .await;
        let _ = release_tx.send(());
        blocker.await?;
        assert!(
            result.is_err(),
            "waiting for a connection blocked the request deadline"
        );
        let next = tokio::task::spawn_blocking(move || {
            session.execute_statement("CREATE TABLE after_queued_cancel AS SELECT 42 AS value", None)
        });
        tokio::time::timeout(Duration::from_secs(2), next).await???;
        Ok(())
    }

    #[tokio::test]
    async fn dropping_completed_response_cannot_interrupt_next_query() -> anyhow::Result<()> {
        let session = session().await?;
        let completed =
            SwanFlightSqlService::execute_query_streaming(session.clone(), "SELECT 1".into(), None, accounting())
                .await?;
        // Let the producer finish, but leave its small result unconsumed.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let (ready_tx, ready_rx) = tokio::sync::oneshot::channel();
        let connection = session.connection.clone();
        let next = tokio::task::spawn_blocking(move || -> anyhow::Result<i64> {
            connection.with_raw(|conn| {
                // A late interrupt must not hit the next owner of this connection.
                let _ = ready_tx.send(());
                Ok(
                    conn.query_row("SELECT sum(i) FROM range(100000000) t(i)", [], |row| {
                        row.get(0)
                    })?,
                )
            })
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
