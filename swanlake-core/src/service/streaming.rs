//! Streaming query execution and FlightData encoding.
//!
//! This module provides progressive streaming of query results, encoding
//! each RecordBatch to FlightData as it becomes available rather than
//! collecting all results first.

use std::pin::Pin;
use std::sync::Arc;

use arrow_array::RecordBatch;
use arrow_flight::flight_service_server::FlightService;
use arrow_flight::FlightData;
use arrow_ipc::writer::{IpcDataGenerator, IpcWriteOptions};
use arrow_schema::Schema;
use futures::Stream;
use tokio::sync::mpsc;
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Response, Status};
use tracing::{debug, error, info};

use crate::engine::StreamingBatch;
use crate::session::Session;

use super::SwanFlightSqlService;

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

/// Encode a RecordBatch to FlightData.
#[allow(deprecated)]
fn encode_batch(batch: &RecordBatch) -> Result<FlightData, Status> {
    let options = IpcWriteOptions::default();
    let data_gen = IpcDataGenerator::default();

    let mut dict_tracker = arrow_ipc::writer::DictionaryTracker::new(false);

    let (_, encoded) = data_gen
        .encoded_batch(batch, &mut dict_tracker, &options)
        .map_err(|e| Status::internal(format!("failed to encode batch: {e}")))?;

    Ok(FlightData {
        flight_descriptor: None,
        data_header: encoded.ipc_message.into(),
        data_body: encoded.arrow_data.into(),
        app_metadata: bytes::Bytes::new(),
    })
}

impl SwanFlightSqlService {
    /// Execute a query with streaming results.
    ///
    /// This method streams results as they become available from DuckDB,
    /// encoding each batch to FlightData lazily. This reduces:
    /// - Time to first byte (client sees data sooner)
    /// - Peak memory usage (no need to buffer all results)
    pub(crate) async fn execute_query_streaming(
        session: Arc<Session>,
        sql: String,
        params: Option<Vec<duckdb::types::Value>>,
    ) -> Result<Response<<Self as FlightService>::DoGetStream>, Status> {
        // Create channel for streaming batches (buffer of 4 for pipelining)
        let (tx, rx) = mpsc::channel::<StreamingBatch>(4);

        // Spawn blocking task to execute query and stream batches
        let sql_clone = sql.clone();
        tokio::task::spawn_blocking(move || {
            let result = match params {
                Some(ref p) => session
                    .connection
                    .execute_query_with_params_streaming(&sql_clone, p, tx.clone()),
                None => session
                    .connection
                    .execute_query_streaming(&sql_clone, tx.clone()),
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
        let stream = StreamingBatchToFlightData::new(rx_stream);

        Ok(Response::new(Box::pin(stream)))
    }
}

/// Stream adapter that converts StreamingBatch messages to FlightData.
struct StreamingBatchToFlightData<S> {
    inner: S,
    schema: Option<Arc<Schema>>,
    done: bool,
}

impl<S> StreamingBatchToFlightData<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            schema: None,
            done: false,
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
                    debug!(rows = batch.num_rows(), "streaming: encoding batch");
                    match encode_batch(&batch) {
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
            Poll::Pending => Poll::Pending,
        }
    }
}
