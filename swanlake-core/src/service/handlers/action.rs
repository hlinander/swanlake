use arrow_array::{Array, StringArray};
use arrow_flight::flight_service_server::FlightService;
use arrow_flight::{Action, FlightDescriptor, FlightEndpoint, FlightInfo, Ticket};
use arrow_schema::{DataType, Field, Schema};
use futures::stream;
use prost::Message;
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tonic::{Request, Response, Status};
use tracing::info;

use crate::service::SwanFlightSqlService;

/// Airport extension's expected format for compressed content
/// Note: This uses tuple serialization (MSGPACK_DEFINE), not map (MSGPACK_DEFINE_MAP)
/// C++ uses: MSGPACK_DEFINE(length, data) where data is std::string
#[derive(Debug, Serialize, Deserialize)]
struct AirportSerializedCompressedContent(
    /// The uncompressed length of the data
    u32,
    /// The compressed data using ZStandard (serialized as msgpack bin/str, not array)
    ByteBuf,
);

/// Airport extension's expected format for content with SHA256 hash
/// Uses MSGPACK_DEFINE_MAP(sha256, url, serialized)
/// Note: 'serialized' is raw bytes (zstd compressed msgpack), stored as std::string in C++
#[derive(Debug, Serialize, Deserialize)]
struct AirportSerializedContentsWithSHA256Hash {
    /// The SHA256 of the serialized contents or external URL
    sha256: String,
    /// The external URL where contents should be obtained
    url: Option<String>,
    /// The inline serialized contents (raw bytes, not UTF-8)
    #[serde(with = "serde_bytes")]
    serialized: Option<Vec<u8>>,
}

/// Airport extension's expected format for a schema
/// Uses MSGPACK_DEFINE_MAP(name, description, tags, contents, is_default)
#[derive(Debug, Serialize, Deserialize)]
struct AirportSerializedSchema {
    /// The name of the schema
    name: String,
    /// The description of the schema
    description: String,
    /// Any tags to apply to the schema
    tags: HashMap<String, String>,
    /// The contents of the schema itself
    contents: AirportSerializedContentsWithSHA256Hash,
    /// Should this schema be considered the default schema
    is_default: Option<bool>,
}

/// Airport extension's expected format for catalog version result
/// Uses MSGPACK_DEFINE_MAP(catalog_version, is_fixed)
#[derive(Debug, Serialize, Deserialize)]
struct AirportGetCatalogVersionResult {
    catalog_version: u64,
    is_fixed: bool,
}

/// Airport extension's expected format for catalog root
/// Uses MSGPACK_DEFINE_MAP(contents, schemas, version_info)
#[derive(Debug, Serialize, Deserialize)]
struct AirportSerializedCatalogRoot {
    /// The contents of the catalog itself
    contents: AirportSerializedContentsWithSHA256Hash,
    /// A list of schemas
    schemas: Vec<AirportSerializedSchema>,
    /// The version of the catalog returned
    version_info: AirportGetCatalogVersionResult,
}

/// Airport extension's metadata format for FlightInfo app_metadata
/// Uses MSGPACK_DEFINE_MAP(type, schema, catalog, name, comment, input_schema, action_name, description, extra_data)
#[derive(Debug, Serialize, Deserialize)]
struct AirportSerializedFlightAppMetadata {
    /// The type of object: "table", "scalar_function", or "table_function"
    r#type: String,
    /// The schema name
    schema: String,
    /// The catalog name
    catalog: String,
    /// The object name
    name: String,
    /// Optional comment
    comment: Option<String>,
    /// Optional input schema (for functions)
    input_schema: Option<String>,
    /// Optional action name (for functions)
    action_name: Option<String>,
    /// Optional description
    description: Option<String>,
    /// Optional extra data
    extra_data: Option<String>,
}

/// Serialize schema contents (tables) as compressed msgpack array of FlightInfo
fn serialize_schema_contents(
    flight_infos: Vec<FlightInfo>,
) -> Result<AirportSerializedContentsWithSHA256Hash, Status> {
    // Serialize each FlightInfo to bytes and collect as byte arrays
    // Even if empty, we serialize an empty array so Airport doesn't fall back to ListFlights
    let serialized_infos: Vec<ByteBuf> = flight_infos
        .into_iter()
        .map(|info| ByteBuf::from(info.encode_to_vec()))
        .collect();

    // Serialize as msgpack array of byte strings
    let msgpack_data = rmp_serde::to_vec(&serialized_infos)
        .map_err(|e| Status::internal(format!("Failed to msgpack encode flight infos: {}", e)))?;

    // Compress with zstd
    let compressed = zstd::encode_all(msgpack_data.as_slice(), 3)
        .map_err(|e| Status::internal(format!("Failed to zstd compress schema contents: {}", e)))?;

    // Wrap in AirportSerializedCompressedContent (tuple format: length, data)
    let compressed_content = AirportSerializedCompressedContent(
        msgpack_data.len() as u32,
        ByteBuf::from(compressed),
    );

    // Serialize the compressed content wrapper to msgpack
    let serialized_wrapper = rmp_serde::to_vec(&compressed_content)
        .map_err(|e| Status::internal(format!("Failed to msgpack encode compressed content: {}", e)))?;

    // Compute SHA256 of the final serialized data
    let mut hasher = Sha256::new();
    hasher.update(&serialized_wrapper);
    let hash = hasher.finalize();
    let sha256_hex = hex::encode(hash);

    Ok(AirportSerializedContentsWithSHA256Hash {
        sha256: sha256_hex,
        url: None,
        serialized: Some(serialized_wrapper),
    })
}

/// Build a FlightInfo for a table
fn build_table_flight_info(
    catalog_name: &str,
    schema_name: &str,
    table_name: &str,
    columns: Vec<(String, DataType)>,
) -> Result<FlightInfo, Status> {
    // Build Arrow schema for the table
    let fields: Vec<Field> = columns
        .into_iter()
        .map(|(name, dtype)| Field::new(name, dtype, true))
        .collect();
    let arrow_schema = Schema::new(fields);

    // Build the app_metadata with table info
    let metadata = AirportSerializedFlightAppMetadata {
        r#type: "table".to_string(),
        schema: schema_name.to_string(),
        catalog: catalog_name.to_string(),
        name: table_name.to_string(),
        comment: None,
        input_schema: None,
        action_name: None,
        description: None,
        extra_data: None,
    };

    let app_metadata = rmp_serde::to_vec_named(&metadata)
        .map_err(|e| Status::internal(format!("Failed to serialize table metadata: {}", e)))?;

    // Create FlightDescriptor for this table
    let descriptor = FlightDescriptor::new_path(vec![
        catalog_name.to_string(),
        schema_name.to_string(),
        table_name.to_string(),
    ]);

    // Create a ticket for fetching the table data
    let ticket = Ticket::new(format!("{}.{}.{}", catalog_name, schema_name, table_name));
    let endpoint = FlightEndpoint::new().with_ticket(ticket);

    let flight_info = FlightInfo::new()
        .with_descriptor(descriptor)
        .with_endpoint(endpoint)
        .with_app_metadata(app_metadata)
        .try_with_schema(&arrow_schema)
        .map_err(|e| Status::internal(format!("Failed to build FlightInfo: {}", e)))?;

    Ok(flight_info)
}

/// Map DuckDB type name to Arrow DataType
fn duckdb_type_to_arrow(type_name: &str) -> DataType {
    match type_name.to_uppercase().as_str() {
        "BIGINT" | "INT8" | "LONG" => DataType::Int64,
        "INTEGER" | "INT4" | "INT" | "SIGNED" => DataType::Int32,
        "SMALLINT" | "INT2" | "SHORT" => DataType::Int16,
        "TINYINT" | "INT1" => DataType::Int8,
        "UBIGINT" => DataType::UInt64,
        "UINTEGER" => DataType::UInt32,
        "USMALLINT" => DataType::UInt16,
        "UTINYINT" => DataType::UInt8,
        "DOUBLE" | "FLOAT8" | "NUMERIC" | "REAL" => DataType::Float64,
        "FLOAT" | "FLOAT4" => DataType::Float32,
        "BOOLEAN" | "BOOL" | "LOGICAL" => DataType::Boolean,
        "VARCHAR" | "CHAR" | "BPCHAR" | "TEXT" | "STRING" => DataType::Utf8,
        "BLOB" | "BYTEA" | "BINARY" | "VARBINARY" => DataType::Binary,
        "DATE" => DataType::Date32,
        "TIME" => DataType::Time64(arrow_schema::TimeUnit::Microsecond),
        "TIMESTAMP" | "DATETIME" => DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, None),
        "TIMESTAMP WITH TIME ZONE" | "TIMESTAMPTZ" => {
            DataType::Timestamp(arrow_schema::TimeUnit::Microsecond, Some("UTC".into()))
        }
        "INTERVAL" => DataType::Interval(arrow_schema::IntervalUnit::MonthDayNano),
        "UUID" => DataType::Utf8, // Store UUID as string
        "JSON" => DataType::Utf8, // Store JSON as string
        _ => {
            // Handle parameterized types like DECIMAL(18,3), VARCHAR(255), etc.
            if type_name.starts_with("DECIMAL") || type_name.starts_with("NUMERIC") {
                DataType::Float64 // Simplified - could parse precision/scale
            } else if type_name.starts_with("VARCHAR") || type_name.starts_with("CHAR") {
                DataType::Utf8
            } else if type_name.contains("[]") || type_name.starts_with("LIST") {
                DataType::Utf8 // Simplified - could handle arrays properly
            } else {
                DataType::Utf8 // Default to string for unknown types
            }
        }
    }
}

/// Handle the "list_schemas" custom action from DuckDB Airport extension
pub(crate) async fn do_action_list_schemas(
    service: &SwanFlightSqlService,
    request: Request<Action>,
) -> Result<Response<<SwanFlightSqlService as FlightService>::DoActionStream>, Status> {
    let session = service.prepare_request(&request).await?;

    info!("handling list_schemas action");

    // Query DuckDB for available schemas
    let sql = "SELECT DISTINCT schema_name FROM information_schema.schemata ORDER BY schema_name";

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

    // Get the catalog name from the request body (msgpack encoded)
    let catalog_name = if !request.get_ref().body.is_empty() {
        #[derive(Deserialize)]
        struct CatalogRequest {
            catalog_name: String,
        }
        rmp_serde::from_slice::<CatalogRequest>(&request.get_ref().body)
            .map(|r| r.catalog_name)
            .unwrap_or_else(|_| "hello".to_string())
    } else {
        "hello".to_string()
    };

    // Build schemas with their tables
    let mut schemas = Vec::new();
    for schema_name in schema_names {
        let is_default = schema_name == "main";

        // Query tables in this schema
        let tables_sql = format!(
            "SELECT table_name, column_name, data_type \
             FROM information_schema.columns \
             WHERE table_schema = '{}' \
             ORDER BY table_name, ordinal_position",
            schema_name
        );

        let session_clone = session.clone();
        let tables_result =
            tokio::task::spawn_blocking(move || session_clone.execute_query(&tables_sql))
                .await
                .map_err(SwanFlightSqlService::status_from_join)?
                .map_err(SwanFlightSqlService::status_from_error)?;

        // Group columns by table
        let mut tables: HashMap<String, Vec<(String, DataType)>> = HashMap::new();
        for batch in &tables_result.batches {
            let table_col = batch.column(0).as_any().downcast_ref::<StringArray>().unwrap();
            let column_col = batch.column(1).as_any().downcast_ref::<StringArray>().unwrap();
            let type_col = batch.column(2).as_any().downcast_ref::<StringArray>().unwrap();

            for i in 0..batch.num_rows() {
                let table_name = table_col.value(i).to_string();
                let column_name = column_col.value(i).to_string();
                let data_type = type_col.value(i).to_string();

                tables
                    .entry(table_name)
                    .or_default()
                    .push((column_name, duckdb_type_to_arrow(&data_type)));
            }
        }

        info!(schema = %schema_name, table_count = tables.len(), "found tables in schema");

        // Build FlightInfo for each table
        let mut flight_infos = Vec::new();
        for (table_name, columns) in tables {
            let flight_info =
                build_table_flight_info(&catalog_name, &schema_name, &table_name, columns)?;
            flight_infos.push(flight_info);
        }

        // Serialize schema contents
        let contents = serialize_schema_contents(flight_infos)?;

        schemas.push(AirportSerializedSchema {
            name: schema_name,
            description: String::new(),
            tags: HashMap::new(),
            contents,
            is_default: if is_default { Some(true) } else { None },
        });
    }

    let catalog_root = AirportSerializedCatalogRoot {
        contents: AirportSerializedContentsWithSHA256Hash {
            sha256: String::new(),
            url: None,
            serialized: None,
        },
        schemas,
        version_info: AirportGetCatalogVersionResult {
            catalog_version: 1,
            is_fixed: false,
        },
    };

    // Serialize to msgpack as a map with named fields (matching C++ MSGPACK_DEFINE_MAP)
    let serialized = rmp_serde::to_vec_named(&catalog_root)
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
        ByteBuf::from(compressed),
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
