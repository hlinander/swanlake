use arrow_array::{Array, StringArray};
use arrow_flight::flight_service_server::FlightService;
use arrow_flight::sql::{ProstMessageExt, TicketStatementQuery};
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
use super::ticket::{StatementTicketKind, TicketStatementPayload};

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
    // Serialize each FlightInfo to bytes
    // C++ uses std::vector<std::string> which in msgpack is an array of "str" type (not "bin")
    // Even though FlightInfo is binary data, C++ std::string is used as binary container
    // We need to use msgpack str format for compatibility
    let serialized_infos: Vec<Vec<u8>> = flight_infos
        .into_iter()
        .map(|info| info.encode_to_vec())
        .collect();

    // Manually build msgpack array of str type (not bin type) using rmp directly
    // This matches C++ msgpack's serialization of std::vector<std::string>
    let mut msgpack_data = Vec::new();

    // Write array header
    rmp::encode::write_array_len(&mut msgpack_data, serialized_infos.len() as u32)
        .map_err(|e| Status::internal(format!("Failed to write msgpack array len: {}", e)))?;

    // Write each FlightInfo as a str (not bin) - C++ expects str format
    for info_bytes in &serialized_infos {
        rmp::encode::write_str_len(&mut msgpack_data, info_bytes.len() as u32)
            .map_err(|e| Status::internal(format!("Failed to write msgpack str len: {}", e)))?;
        msgpack_data.extend_from_slice(info_bytes);
    }

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
    // The 'catalog' field must match the attached catalog name that the client uses
    let metadata = AirportSerializedFlightAppMetadata {
        r#type: "table".to_string(),
        schema: schema_name.to_string(),
        catalog: catalog_name.to_string(), // Must match the attached catalog name
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
    // Use schema.table path (without catalog prefix, since catalog is the attached server itself)
    let descriptor = FlightDescriptor::new_path(vec![
        schema_name.to_string(),
        table_name.to_string(),
    ]);

    // Create a ticket for fetching the table data
    let ticket = Ticket::new(format!("{}.{}", schema_name, table_name));
    // Add location - empty string means "same server"
    let endpoint = FlightEndpoint::new()
        .with_ticket(ticket)
        .with_location("grpc://localhost:4214");

    let flight_info = FlightInfo::new()
        .with_descriptor(descriptor)
        .with_endpoint(endpoint)
        .with_app_metadata(app_metadata)
        .with_total_records(-1) // Unknown
        .with_total_bytes(-1) // Unknown
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
            .unwrap_or_else(|e| {
                info!("Failed to parse catalog request: {}, using default", e);
                "hello".to_string()
            })
    } else {
        "hello".to_string()
    };

    info!(catalog_name = %catalog_name, "using catalog name for list_schemas");

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

        info!(schema = %schema_name, table_count = tables.len(), tables = ?tables.keys().collect::<Vec<_>>(), "found tables in schema");

        // Build FlightInfo for each table
        let mut flight_infos = Vec::new();
        for (table_name, columns) in tables {
            info!(
                catalog = %catalog_name,
                schema = %schema_name,
                table = %table_name,
                column_count = columns.len(),
                "building FlightInfo for table"
            );
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
            is_default: Some(is_default),
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

/// Airport's transaction identifier result
#[derive(Debug, Serialize, Deserialize)]
struct GetTransactionIdentifierResult {
    identifier: Option<String>,
}

/// Airport's endpoint parameters
#[derive(Debug, Deserialize, Default)]
struct AirportEndpointParameters {
    /// JSON filters for predicate pushdown
    #[serde(default)]
    json_filters: String,
    /// Column IDs to project
    #[serde(default)]
    column_ids: Vec<i64>,
    /// Table function parameters
    #[serde(default)]
    table_function_parameters: String,
    /// Table function input schema
    #[serde(default)]
    table_function_input_schema: String,
    /// Point-in-time unit
    #[serde(default)]
    at_unit: String,
    /// Point-in-time value
    #[serde(default)]
    at_value: String,
}

/// DuckDB filter JSON structure for predicate pushdown
#[derive(Debug, Deserialize)]
struct DuckDBFilters {
    filters: Vec<DuckDBExpression>,
    column_binding_names_by_index: Vec<String>,
}

/// DuckDB expression (all types supported by Airport)
#[derive(Debug, Deserialize)]
#[serde(tag = "expression_class")]
enum DuckDBExpression {
    #[serde(rename = "BOUND_COMPARISON")]
    Comparison {
        #[serde(rename = "type")]
        comparison_type: String,
        left: Box<DuckDBExpression>,
        right: Box<DuckDBExpression>,
    },
    #[serde(rename = "BOUND_COLUMN_REF")]
    ColumnRef {
        alias: String,
    },
    #[serde(rename = "BOUND_CONSTANT")]
    Constant {
        value: DuckDBValue,
    },
    #[serde(rename = "BOUND_CONJUNCTION")]
    Conjunction {
        #[serde(rename = "type")]
        conjunction_type: String,
        children: Vec<DuckDBExpression>,
    },
    #[serde(rename = "BOUND_OPERATOR")]
    Operator {
        #[serde(rename = "type")]
        operator_type: String,
        children: Vec<DuckDBExpression>,
    },
    #[serde(rename = "BOUND_BETWEEN")]
    Between {
        input: Box<DuckDBExpression>,
        lower: Box<DuckDBExpression>,
        upper: Box<DuckDBExpression>,
    },
    #[serde(rename = "BOUND_FUNCTION")]
    Function {
        name: String,
        children: Vec<DuckDBExpression>,
    },
    #[serde(rename = "BOUND_CAST")]
    Cast {
        child: Box<DuckDBExpression>,
    },
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Deserialize)]
struct DuckDBValue {
    #[serde(rename = "type")]
    value_type: DuckDBType,
    is_null: bool,
    #[serde(default)]
    value: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct DuckDBType {
    id: String,
}

/// Convert a DuckDB expression to SQL
fn expression_to_sql(expr: &DuckDBExpression) -> Option<String> {
    match expr {
        DuckDBExpression::Comparison { comparison_type, left, right } => {
            let left_sql = expression_to_sql(left)?;
            let right_sql = expression_to_sql(right)?;
            let op = match comparison_type.as_str() {
                "COMPARE_EQUAL" => "=",
                "COMPARE_NOTEQUAL" => "!=",
                "COMPARE_LESSTHAN" => "<",
                "COMPARE_GREATERTHAN" => ">",
                "COMPARE_LESSTHANOREQUALTO" => "<=",
                "COMPARE_GREATERTHANOREQUALTO" => ">=",
                _ => return None,
            };
            Some(format!("{} {} {}", left_sql, op, right_sql))
        }
        DuckDBExpression::ColumnRef { alias } => {
            // Quote column name to handle special characters
            Some(format!("\"{}\"", alias))
        }
        DuckDBExpression::Constant { value } => {
            if value.is_null {
                return Some("NULL".to_string());
            }
            match value.value_type.id.as_str() {
                "INTEGER" | "BIGINT" | "SMALLINT" | "TINYINT" | "DOUBLE" | "FLOAT" => {
                    Some(value.value.to_string())
                }
                "VARCHAR" | "TEXT" => {
                    if let Some(s) = value.value.as_str() {
                        // Escape single quotes
                        Some(format!("'{}'", s.replace('\'', "''")))
                    } else {
                        Some(format!("'{}'", value.value))
                    }
                }
                "BOOLEAN" => {
                    Some(value.value.to_string().to_uppercase())
                }
                _ => Some(value.value.to_string()),
            }
        }
        DuckDBExpression::Conjunction { conjunction_type, children } => {
            let parts: Vec<String> = children.iter()
                .filter_map(expression_to_sql)
                .collect();
            if parts.is_empty() {
                return None;
            }
            let op = match conjunction_type.as_str() {
                "CONJUNCTION_AND" => " AND ",
                "CONJUNCTION_OR" => " OR ",
                _ => return None,
            };
            Some(format!("({})", parts.join(op)))
        }
        DuckDBExpression::Operator { operator_type, children } => {
            match operator_type.as_str() {
                "OPERATOR_IS_NULL" => {
                    let child = children.first()?;
                    let child_sql = expression_to_sql(child)?;
                    Some(format!("{} IS NULL", child_sql))
                }
                "OPERATOR_IS_NOT_NULL" => {
                    let child = children.first()?;
                    let child_sql = expression_to_sql(child)?;
                    Some(format!("{} IS NOT NULL", child_sql))
                }
                "COMPARE_IN" => {
                    if children.is_empty() {
                        return None;
                    }
                    let column = expression_to_sql(children.first()?)?;
                    let values: Vec<String> = children.iter()
                        .skip(1)
                        .filter_map(expression_to_sql)
                        .collect();
                    if values.is_empty() {
                        return None;
                    }
                    Some(format!("{} IN ({})", column, values.join(", ")))
                }
                "COMPARE_NOT_IN" => {
                    if children.is_empty() {
                        return None;
                    }
                    let column = expression_to_sql(children.first()?)?;
                    let values: Vec<String> = children.iter()
                        .skip(1)
                        .filter_map(expression_to_sql)
                        .collect();
                    if values.is_empty() {
                        return None;
                    }
                    Some(format!("{} NOT IN ({})", column, values.join(", ")))
                }
                "OPERATOR_NOT" => {
                    let child = children.first()?;
                    let child_sql = expression_to_sql(child)?;
                    Some(format!("NOT ({})", child_sql))
                }
                _ => {
                    info!(operator = %operator_type, "unsupported operator type");
                    None
                }
            }
        }
        DuckDBExpression::Between { input, lower, upper } => {
            let input_sql = expression_to_sql(input)?;
            let lower_sql = expression_to_sql(lower)?;
            let upper_sql = expression_to_sql(upper)?;
            Some(format!("{} BETWEEN {} AND {}", input_sql, lower_sql, upper_sql))
        }
        DuckDBExpression::Function { name, children } => {
            // Handle common functions that can be pushed down
            match name.to_lowercase().as_str() {
                "~~" | "like" => {
                    // LIKE operator: first child is column, second is pattern
                    if children.len() < 2 {
                        return None;
                    }
                    let column = expression_to_sql(&children[0])?;
                    let pattern = expression_to_sql(&children[1])?;
                    Some(format!("{} LIKE {}", column, pattern))
                }
                "!~~" | "not_like" => {
                    if children.len() < 2 {
                        return None;
                    }
                    let column = expression_to_sql(&children[0])?;
                    let pattern = expression_to_sql(&children[1])?;
                    Some(format!("{} NOT LIKE {}", column, pattern))
                }
                "~~~" | "ilike" => {
                    if children.len() < 2 {
                        return None;
                    }
                    let column = expression_to_sql(&children[0])?;
                    let pattern = expression_to_sql(&children[1])?;
                    Some(format!("{} ILIKE {}", column, pattern))
                }
                _ => {
                    // For other functions, try to generate standard function call syntax
                    let args: Vec<String> = children.iter()
                        .filter_map(expression_to_sql)
                        .collect();
                    if args.is_empty() && !children.is_empty() {
                        return None;
                    }
                    Some(format!("{}({})", name, args.join(", ")))
                }
            }
        }
        DuckDBExpression::Cast { child } => {
            // For casts, just evaluate the child expression
            // The type conversion will be handled by the database
            expression_to_sql(child)
        }
        DuckDBExpression::Unknown => {
            info!("encountered unknown expression type, skipping");
            None
        }
    }
}

/// Parse filters JSON and convert to SQL WHERE clause
fn parse_filters_to_where_clause(json_filters: &str) -> Option<String> {
    if json_filters.is_empty() {
        return None;
    }

    let filters: DuckDBFilters = serde_json::from_str(json_filters).ok()?;

    if filters.filters.is_empty() {
        return None;
    }

    let conditions: Vec<String> = filters.filters.iter()
        .filter_map(expression_to_sql)
        .collect();

    if conditions.is_empty() {
        return None;
    }

    Some(conditions.join(" AND "))
}

/// Airport's endpoints request
#[derive(Debug, Deserialize)]
struct AirportGetFlightEndpointsRequest {
    /// The flight descriptor (serialized)
    #[serde(with = "serde_bytes")]
    descriptor: Vec<u8>,
    /// Endpoint parameters
    #[serde(default)]
    parameters: AirportEndpointParameters,
}

/// Handle the "create_transaction" custom action from DuckDB Airport extension
pub(crate) async fn do_action_create_transaction(
    service: &SwanFlightSqlService,
    request: Request<Action>,
) -> Result<Response<<SwanFlightSqlService as FlightService>::DoActionStream>, Status> {
    let session = service.prepare_request(&request).await?;

    info!("handling create_transaction action");

    // Start a transaction in the session
    let session_clone = session.clone();
    let transaction_id = tokio::task::spawn_blocking(move || session_clone.begin_transaction())
        .await
        .map_err(SwanFlightSqlService::status_from_join)?
        .map_err(SwanFlightSqlService::status_from_error)?;

    info!(transaction_id = %transaction_id, "transaction started for Airport");

    // Return the transaction identifier
    let result_struct = GetTransactionIdentifierResult {
        identifier: Some(transaction_id.to_string()),
    };

    let result_body = rmp_serde::to_vec_named(&result_struct)
        .map_err(|e| Status::internal(format!("Failed to serialize transaction result: {}", e)))?;

    let result = arrow_flight::Result {
        body: result_body.into(),
    };

    let output_stream = Box::pin(stream::iter(vec![Ok(result)]));
    Ok(Response::new(output_stream))
}

/// Handle the "catalog_version" action from DuckDB Airport extension
/// Returns the current catalog version for cache invalidation
pub(crate) async fn do_action_catalog_version(
    service: &SwanFlightSqlService,
    request: Request<Action>,
) -> Result<Response<<SwanFlightSqlService as FlightService>::DoActionStream>, Status> {
    let _session = service.prepare_request(&request).await?;

    info!("handling catalog_version action");

    // Return a fixed catalog version (could be made dynamic based on schema changes)
    let result_struct = AirportGetCatalogVersionResult {
        catalog_version: 1,
        is_fixed: false,
    };

    let result_body = rmp_serde::to_vec_named(&result_struct)
        .map_err(|e| Status::internal(format!("Failed to serialize catalog version: {}", e)))?;

    let result = arrow_flight::Result {
        body: result_body.into(),
    };

    let output_stream = Box::pin(stream::iter(vec![Ok(result)]));
    Ok(Response::new(output_stream))
}

/// Handle the "endpoints" action from DuckDB Airport extension
/// Returns FlightEndpoints for data retrieval
pub(crate) async fn do_action_endpoints(
    service: &SwanFlightSqlService,
    request: Request<Action>,
) -> Result<Response<<SwanFlightSqlService as FlightService>::DoActionStream>, Status> {
    let _session = service.prepare_request(&request).await?;

    // Parse the request
    let request_data: AirportGetFlightEndpointsRequest =
        rmp_serde::from_slice(&request.get_ref().body)
            .map_err(|e| Status::invalid_argument(format!("Failed to parse endpoints request: {}", e)))?;

    // The descriptor is a serialized FlightDescriptor (protobuf)
    let descriptor = FlightDescriptor::decode(request_data.descriptor.as_slice())
        .map_err(|e| Status::invalid_argument(format!("Failed to decode flight descriptor: {}", e)))?;

    info!(
        descriptor = ?descriptor,
        filters = %request_data.parameters.json_filters,
        columns = ?request_data.parameters.column_ids,
        "handling endpoints action"
    );

    // Build SQL query - either from cmd (for SQL passthrough) or from path (for table scans)
    let sql = if !descriptor.cmd.is_empty() {
        // CMD type descriptor - contains raw SQL (from airport_take_flight)
        let raw_sql = std::str::from_utf8(&descriptor.cmd)
            .map_err(|e| Status::invalid_argument(format!("Invalid UTF-8 in SQL: {e}")))?;
        info!(sql = %raw_sql, "using raw SQL from descriptor cmd (SQL passthrough)");
        raw_sql.to_string()
    } else {
        // PATH type descriptor - build SQL from path (for table scans)
        let table_path = descriptor.path.join(".");

        // Parse filters for predicate pushdown
        let where_clause = parse_filters_to_where_clause(&request_data.parameters.json_filters);

        if let Some(ref conditions) = where_clause {
            format!("SELECT * FROM {} WHERE {}", table_path, conditions)
        } else {
            format!("SELECT * FROM {}", table_path)
        }
    };

    // Parse filters for predicate pushdown (for logging)
    let where_clause = parse_filters_to_where_clause(&request_data.parameters.json_filters);

    info!(sql = %sql, predicate_pushdown = where_clause.is_some(), "creating ticket for Airport query");

    // Create a ticket using SwanLake's internal format (wrapped in Flight SQL's TicketStatementQuery)
    // This will be executed when Airport calls DoGet
    let ticket_payload = TicketStatementPayload::new(StatementTicketKind::Ephemeral)
        .with_fallback_sql(&sql)
        .with_returns_rows(true);

    let ticket_query = TicketStatementQuery {
        statement_handle: ticket_payload.encode_to_vec().into(),
    };

    // Encode as Any-wrapped protobuf (required by Flight SQL)
    let ticket = Ticket::new(ticket_query.as_any().encode_to_vec());

    // Create a single endpoint pointing back to this server
    // The client will call DoGet with this ticket
    let endpoint = FlightEndpoint::new()
        .with_ticket(ticket)
        .with_location("grpc://localhost:4214");

    // Serialize the endpoint
    let endpoint_bytes = endpoint.encode_to_vec();

    // Return as msgpack array of serialized endpoints (as strings, not bin)
    // Using manual msgpack encoding to match C++ std::vector<std::string>
    let mut result_body = Vec::new();
    rmp::encode::write_array_len(&mut result_body, 1)
        .map_err(|e| Status::internal(format!("Failed to write array len: {}", e)))?;
    rmp::encode::write_str_len(&mut result_body, endpoint_bytes.len() as u32)
        .map_err(|e| Status::internal(format!("Failed to write str len: {}", e)))?;
    result_body.extend_from_slice(&endpoint_bytes);

    let result = arrow_flight::Result {
        body: result_body.into(),
    };

    let output_stream = Box::pin(stream::iter(vec![Ok(result)]));
    Ok(Response::new(output_stream))
}
