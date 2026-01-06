use arrow_array::{Array, RecordBatch, StringArray};
use arrow_flight::flight_service_server::FlightService;
use arrow_flight::Action;
use arrow_schema::{DataType, Field, Schema};
use futures::stream;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::info;

use crate::service::SwanFlightSqlService;

/// Handle the "list_schemas" custom action from DuckDB Airport extension
pub(crate) async fn do_action_list_schemas(
    service: &SwanFlightSqlService,
    request: Request<Action>,
) -> Result<Response<<SwanFlightSqlService as FlightService>::DoActionStream>, Status> {
    let session = service.prepare_request(&request).await?;

    info!("handling list_schemas action");

    // Query DuckDB for available schemas
    let sql = "SELECT schema_name FROM information_schema.schemata ORDER BY schema_name";

    let session_clone = session.clone();
    let query_result = tokio::task::spawn_blocking(move || {
        session_clone.execute_query(sql)
    })
    .await
    .map_err(SwanFlightSqlService::status_from_join)?
    .map_err(SwanFlightSqlService::status_from_error)?;

    // Convert the Arrow batches to a list of schema names
    let mut schema_names = Vec::new();
    for batch in &query_result.batches {
        let schema_col = batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or_else(|| Status::internal("Failed to downcast schema_name column"))?;

        for i in 0..schema_col.len() {
            if let Some(name) = schema_col.value(i).to_string().into() {
                schema_names.push(name);
            }
        }
    }

    info!(count = schema_names.len(), "found schemas");

    // Build a response with schema names encoded as Arrow Flight Result messages
    // Each schema name is returned as a separate Result message
    let mut results: Vec<Result<arrow_flight::Result, Status>> = Vec::new();

    for name in schema_names {
        // Create a simple RecordBatch with the schema name
        let schema = Arc::new(Schema::new(vec![Field::new(
            "schema_name",
            DataType::Utf8,
            false,
        )]));

        let schema_array = StringArray::from(vec![name.as_str()]);
        let batch = RecordBatch::try_new(schema, vec![Arc::new(schema_array)])
            .map_err(|e| Status::internal(format!("Failed to create batch: {}", e)))?;

        // Serialize the batch as IPC
        let mut writer = arrow_ipc::writer::StreamWriter::try_new(
            Vec::new(),
            batch.schema_ref(),
        )
        .map_err(|e| Status::internal(format!("Failed to create IPC writer: {}", e)))?;

        writer
            .write(&batch)
            .map_err(|e| Status::internal(format!("Failed to write batch: {}", e)))?;

        writer
            .finish()
            .map_err(|e| Status::internal(format!("Failed to finish IPC stream: {}", e)))?;

        let body = writer.into_inner()
            .map_err(|e| Status::internal(format!("Failed to get IPC bytes: {}", e)))?;

        results.push(Ok(arrow_flight::Result { body: body.into() }));
    }

    let output_stream = Box::pin(stream::iter(results));
    Ok(Response::new(output_stream))
}
