use arrow_array::{Array, StringArray};
use arrow_flight::flight_service_server::FlightService;
use arrow_flight::Action;
use futures::stream;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tonic::{Request, Response, Status};
use tracing::info;

use crate::service::SwanFlightSqlService;

/// Airport extension's expected format for compressed content
/// Note: This uses tuple serialization (MSGPACK_DEFINE), not map (MSGPACK_DEFINE_MAP)
#[derive(Debug, Serialize, Deserialize)]
struct AirportSerializedCompressedContent(
    /// The uncompressed length of the data
    u32,
    /// The compressed data using ZStandard
    Vec<u8>,
);

/// Airport extension's expected format for content with SHA256 hash
#[derive(Debug, Serialize, Deserialize)]
struct AirportSerializedContentsWithSHA256Hash {
    /// The SHA256 of the serialized contents or external URL
    sha256: String,
    /// The external URL where contents should be obtained
    #[serde(skip_serializing_if = "Option::is_none")]
    url: Option<String>,
    /// The inline serialized contents
    #[serde(skip_serializing_if = "Option::is_none")]
    serialized: Option<String>,
}

/// Airport extension's expected format for a schema
/// Uses MSGPACK_DEFINE_MAP(schema, description, tags, contents) - note: "schema" not "name"
#[derive(Debug, Serialize, Deserialize)]
struct AirportSerializedSchema {
    /// The name of the schema (field is "schema" in msgpack, not "name")
    #[serde(rename = "schema")]
    name: String,
    /// The description of the schema
    description: String,
    /// Any tags to apply to the schema
    tags: HashMap<String, String>,
    /// The contents of the schema itself
    contents: AirportSerializedContentsWithSHA256Hash,
    // Note: is_default is NOT included in MSGPACK_DEFINE_MAP, so we don't serialize it
}

/// Airport extension's expected format for catalog root
/// Uses MSGPACK_DEFINE_MAP(contents, schemas) - only these 2 fields
#[derive(Debug, Serialize, Deserialize)]
struct AirportSerializedCatalogRoot {
    /// The contents of the catalog itself
    contents: AirportSerializedContentsWithSHA256Hash,
    /// A list of schemas
    schemas: Vec<AirportSerializedSchema>,
    // Note: version_info is NOT included in MSGPACK_DEFINE_MAP
}

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
    let query_result = tokio::task::spawn_blocking(move || session_clone.execute_query(sql))
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

    info!(count = schema_names.len(), schemas = ?schema_names, "found schemas");

    // Build the Airport-compatible response
    let schemas: Vec<AirportSerializedSchema> = schema_names
        .into_iter()
        .map(|name| {
            AirportSerializedSchema {
                name: name.clone(),
                description: format!("Schema: {}", name),
                tags: HashMap::new(),
                contents: AirportSerializedContentsWithSHA256Hash {
                    sha256: String::new(), // Empty for now
                    url: None,
                    serialized: Some(String::new()), // Empty serialized content
                },
            }
        })
        .collect();

    let catalog_root = AirportSerializedCatalogRoot {
        contents: AirportSerializedContentsWithSHA256Hash {
            sha256: String::new(),
            url: None,
            serialized: Some(String::new()),
        },
        schemas,
    };

    // Serialize to msgpack
    let serialized = rmp_serde::to_vec(&catalog_root)
        .map_err(|e| Status::internal(format!("Failed to msgpack encode catalog root: {}", e)))?;

    info!(serialized_size = serialized.len(), "serialized catalog root");

    // Compress with zstd
    let compressed = zstd::encode_all(serialized.as_slice(), 3)
        .map_err(|e| Status::internal(format!("Failed to zstd compress: {}", e)))?;

    info!(
        compressed_size = compressed.len(),
        uncompressed_size = serialized.len(),
        "compressed catalog data"
    );

    // Wrap in compressed content structure (tuple format)
    let compressed_content = AirportSerializedCompressedContent(
        serialized.len() as u32,
        compressed,
    );

    // Serialize the wrapper to msgpack
    let final_body = rmp_serde::to_vec(&compressed_content).map_err(|e| {
        Status::internal(format!("Failed to msgpack encode compressed content: {}", e))
    })?;

    info!(final_size = final_body.len(), "final encoded response size");

    // Return as a single Result message
    let result = arrow_flight::Result {
        body: final_body.into(),
    };

    let output_stream = Box::pin(stream::iter(vec![Ok(result)]));
    Ok(Response::new(output_stream))
}
