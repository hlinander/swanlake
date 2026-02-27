//! DoExchange handler for Airport insert operations.
//!
//! Airport uses DoExchange for bidirectional data streaming during inserts.
//! Headers:
//! - `airport-operation`: operation type (e.g., "insert")
//! - `airport-flight-path`: table path for the operation

use std::pin::Pin;
use std::sync::Arc;

use arrow_array::{Int64Array, RecordBatch};
use arrow_flight::flight_service_server::FlightService;
use arrow_flight::FlightData;
use arrow_schema::{DataType, Field, Schema};
use futures::{Stream, StreamExt};
use tonic::{Request, Response, Status, Streaming};
use tracing::{info, warn};

use crate::service::SwanFlightSqlService;

/// Handle DoExchange for Airport insert operations
pub(crate) async fn do_exchange(
    service: &SwanFlightSqlService,
    request: Request<Streaming<FlightData>>,
) -> Result<Response<<SwanFlightSqlService as FlightService>::DoExchangeStream>, Status> {
    // Extract headers before moving request
    let operation = request
        .metadata()
        .get("airport-operation")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    let flight_path = request
        .metadata()
        .get("airport-flight-path")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();

    info!(
        operation = %operation,
        flight_path = %flight_path,
        "handling DoExchange"
    );

    match operation.as_str() {
        "insert" => do_exchange_insert(service, request, &flight_path).await,
        "delete" => do_exchange_delete(service, request, &flight_path).await,
        "update" => do_exchange_update(service, request, &flight_path).await,
        _ => Err(Status::unimplemented(format!(
            "DoExchange operation not supported: {}",
            operation
        ))),
    }
}

/// Handle insert operation via DoExchange
async fn do_exchange_insert(
    service: &SwanFlightSqlService,
    request: Request<Streaming<FlightData>>,
    flight_path: &str,
) -> Result<Response<<SwanFlightSqlService as FlightService>::DoExchangeStream>, Status> {
    // Parse table path (schema.table format)
    let (schema_name, table_name) = parse_table_path(flight_path)?;

    info!(
        schema = %schema_name,
        table = %table_name,
        "inserting data via DoExchange"
    );

    let session = service.prepare_request(&request).await?;
    let mut stream = request.into_inner();

    // Collect all flight data and decode batches
    let mut flight_data_vec = Vec::new();
    while let Some(data) = stream.next().await {
        let data = data.map_err(|e| Status::internal(format!("Failed to receive data: {}", e)))?;
        flight_data_vec.push(data);
    }

    if flight_data_vec.is_empty() {
        return Err(Status::invalid_argument("No data received for insert"));
    }

    // Decode flight data to record batches
    let batches = decode_flight_data(flight_data_vec)?;

    if batches.is_empty() {
        info!("No batches to insert");
        return Ok(create_rows_affected_response(0));
    }

    let total_rows: usize = batches.iter().map(|b| b.num_rows()).sum();
    info!(batch_count = batches.len(), total_rows, "decoded batches for insert");

    // Insert using appender API
    let session_clone = session.clone();
    let schema_name_owned = schema_name.to_string();
    let table_name_owned = table_name.to_string();

    let rows_inserted = tokio::task::spawn_blocking(move || {
        // Use the catalog name (empty for default) and qualified table name
        let qualified_table = if schema_name_owned.is_empty() {
            table_name_owned
        } else {
            format!("{}.{}", schema_name_owned, table_name_owned)
        };

        session_clone.insert_with_appender("", &qualified_table, batches)
    })
    .await
    .map_err(SwanFlightSqlService::status_from_join)?
    .map_err(SwanFlightSqlService::status_from_error)?;

    info!(rows_inserted, "insert completed via DoExchange");

    Ok(create_rows_affected_response(rows_inserted as i64))
}

/// Handle delete operation via DoExchange
async fn do_exchange_delete(
    _service: &SwanFlightSqlService,
    _request: Request<Streaming<FlightData>>,
    _flight_path: &str,
) -> Result<Response<<SwanFlightSqlService as FlightService>::DoExchangeStream>, Status> {
    // TODO: Implement delete
    Err(Status::unimplemented("DELETE via DoExchange not yet implemented"))
}

/// Handle update operation via DoExchange
async fn do_exchange_update(
    _service: &SwanFlightSqlService,
    _request: Request<Streaming<FlightData>>,
    _flight_path: &str,
) -> Result<Response<<SwanFlightSqlService as FlightService>::DoExchangeStream>, Status> {
    // TODO: Implement update
    Err(Status::unimplemented("UPDATE via DoExchange not yet implemented"))
}

/// Parse table path in format "schema/table" or just "table"
fn parse_table_path(path: &str) -> Result<(&str, &str), Status> {
    // Path format: "schema/table" or just "table"
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();

    match parts.len() {
        1 => Ok(("", parts[0])),
        2 => Ok((parts[0], parts[1])),
        _ => Err(Status::invalid_argument(format!(
            "Invalid table path format: {}",
            path
        ))),
    }
}

/// Decode FlightData messages to RecordBatches
fn decode_flight_data(flight_data: Vec<FlightData>) -> Result<Vec<RecordBatch>, Status> {
    use arrow_flight::decode::FlightRecordBatchStream;
    use futures::executor::block_on;

    // Create a stream from the owned flight data
    let stream = futures::stream::iter(flight_data.into_iter().map(Ok));
    let decoder = FlightRecordBatchStream::new_from_flight_data(stream);

    // Collect batches
    let batches: Vec<RecordBatch> = block_on(async {
        decoder
            .filter_map(|result| async {
                match result {
                    Ok(batch) => Some(batch),
                    Err(e) => {
                        warn!("Error decoding batch: {}", e);
                        None
                    }
                }
            })
            .collect()
            .await
    });

    Ok(batches)
}

/// Create response stream with rows_affected count
fn create_rows_affected_response(
    rows: i64,
) -> Response<<SwanFlightSqlService as FlightService>::DoExchangeStream> {
    // Create schema with rows_inserted field
    let schema = Arc::new(Schema::new(vec![Field::new(
        "rows_inserted",
        DataType::Int64,
        false,
    )]));

    // Create batch with the count
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![Arc::new(Int64Array::from(vec![rows]))],
    )
    .expect("Failed to create response batch");

    // Encode to FlightData
    let flight_data =
        arrow_flight::utils::batches_to_flight_data(&schema, vec![batch]).unwrap_or_default();

    let stream: Pin<Box<dyn Stream<Item = Result<FlightData, Status>> + Send>> =
        Box::pin(futures::stream::iter(flight_data.into_iter().map(Ok)));

    Response::new(stream)
}
