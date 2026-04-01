use std::pin::Pin;
use std::sync::Arc;

use arrow_flight::error::FlightError;
use arrow_flight::flight_service_server::FlightService;
use arrow_flight::sql::{ProstMessageExt, TicketStatementQuery};
use arrow_flight::{
    Action, Criteria, Empty, FlightData, FlightDescriptor, FlightEndpoint, FlightInfo,
    HandshakeRequest, SchemaResult, Ticket,
};
use futures::{stream, Stream};
use prost::Message;
use tonic::{Request, Response, Status, Streaming};
use tracing::{error, info, Span};

use crate::error::ServerError;
use crate::session::{registry::SessionRegistry, Session, SessionId};

mod convert;
mod execute;
mod handlers;
pub(crate) mod streaming;

use handlers::ticket::{StatementTicketKind, TicketStatementPayload};

// Phase 2 Complete: All state (prepared statements, transactions) is session-scoped
// - Each gRPC connection gets a dedicated session (based on remote_addr)
// - Sessions persist across requests from the same connection
// - Prepared statements and transactions are isolated per session
// - Automatic cleanup via idle timeout (30min default)

#[derive(Clone)]
pub struct SwanFlightSqlService {
    registry: Arc<SessionRegistry>,
    instance_id: Arc<str>,
}

impl SwanFlightSqlService {
    pub fn new(registry: Arc<SessionRegistry>) -> Self {
        let instance_id: Arc<str> = uuid::Uuid::new_v4().to_string().into();
        info!(%instance_id, "server instance initialized");
        Self { registry, instance_id }
    }

    pub(crate) fn instance_id(&self) -> &str {
        &self.instance_id
    }

    /// Validate that the client's expected instance ID matches this server's.
    /// If no header is sent, allow the request (backwards compatible).
    fn validate_instance_id<T>(&self, request: &Request<T>) -> Result<(), Status> {
        if let Some(expected) = request.metadata().get("x-expected-instance-id") {
            if let Ok(expected_str) = expected.to_str() {
                if expected_str != self.instance_id.as_ref() {
                    return Err(Status::failed_precondition(format!(
                        "server instance changed: expected {}, got {}",
                        expected_str, self.instance_id
                    )));
                }
            }
        }
        Ok(())
    }

    /// Extract session ID from tonic Request metadata
    ///
    /// Checks for session ID in order:
    /// 1. `airport-client-session-id` (Airport extension's header)
    /// 2. `x-session-id` (custom header)
    pub(crate) fn extract_session_id<T>(request: &Request<T>) -> Result<SessionId, Status> {
        let metadata = request.metadata();

        // Airport extension sends this header
        if let Some(session_id) = metadata.get("airport-client-session-id") {
            if let Ok(id_str) = session_id.to_str() {
                if !id_str.is_empty() {
                    return Ok(SessionId::from_string(id_str.to_string()));
                }
            }
        }

        // Fallback to x-session-id
        if let Some(session_id) = metadata.get("x-session-id") {
            if let Ok(id_str) = session_id.to_str() {
                if !id_str.is_empty() {
                    return Ok(SessionId::from_string(id_str.to_string()));
                }
            }
        }

        Err(Status::invalid_argument("session ID header is required (airport-client-session-id or x-session-id)"))
    }

    /// Prepare request: extract session_id from header, record to tracing span, and get/create session.
    pub(crate) async fn prepare_request<T>(
        &self,
        request: &Request<T>,
    ) -> Result<Arc<Session>, Status> {
        self.validate_instance_id(request)?;
        let session_id = Self::extract_session_id(request)?;
        Span::current().record("session_id", session_id.as_ref());
        self.registry
            .get_or_create_by_id(&session_id)
            .await
            .map_err(Self::status_from_error)
    }

    pub(crate) fn status_from_error(err: ServerError) -> Status {
        match err {
            ServerError::DuckDb(e) => {
                error!(error = %e, "duckdb engine error");
                Status::internal(format!("duckdb error: {e}"))
            }
            ServerError::Arrow(e) => {
                error!(error = %e, "arrow conversion error");
                Status::internal(format!("arrow error: {e}"))
            }
            ServerError::TransactionAborted => {
                error!("transaction aborted and rolled back");
                Status::failed_precondition(
                    "transaction aborted and rolled back; start a new transaction",
                )
            }
            ServerError::TransactionNotFound => {
                error!("unknown transaction");
                Status::invalid_argument("unknown transaction")
            }
            ServerError::PreparedStatementNotFound => {
                error!("unknown prepared statement");
                Status::invalid_argument("unknown prepared statement")
            }
            ServerError::MaxSessionsReached => {
                error!("maximum number of sessions reached");
                Status::resource_exhausted("maximum number of sessions reached")
            }
            ServerError::UnsupportedParameter(param) => {
                error!(param = %param, "unsupported parameter type");
                Status::invalid_argument(format!("unsupported parameter type: {param}"))
            }
            ServerError::Internal(msg) => {
                error!(msg = %msg, "internal error");
                Status::internal(format!("internal error: {msg}"))
            }
        }
    }

    pub(crate) fn status_from_join(err: tokio::task::JoinError) -> Status {
        if err.is_panic() {
            error!(%err, "blocking task panicked");
            Status::internal("blocking task panicked")
        } else {
            error!(%err, "blocking task cancelled");
            Status::internal(format!("blocking task cancelled: {err}"))
        }
    }

    pub(crate) fn status_from_flight_error(err: FlightError) -> Status {
        match err {
            FlightError::Tonic(status) => {
                error!(status = ?status, "tonic flight error");
                *status
            }
            other => {
                error!(error = %other, "flight decode error");
                Status::internal(format!("flight decode error: {other}"))
            }
        }
    }

    pub(crate) fn into_stream(
        batches: Vec<FlightData>,
    ) -> Pin<Box<dyn Stream<Item = Result<FlightData, Status>> + Send + 'static>> {
        Box::pin(stream::iter(batches.into_iter().map(Ok)))
    }
}

/// Run a blocking operation with interrupt support.
///
/// Exported for use by handlers.
///
/// This spawns a monitor task that watches for the parent async task being dropped
/// (e.g., client disconnect) and immediately interrupts the DuckDB query.
///
/// Unlike a simple InterruptOnDrop guard, this uses a channel-based approach that
/// works correctly with spawn_blocking: the monitor task calls interrupt() as soon
/// as the cancellation signal is dropped, regardless of whether spawn_blocking
/// has finished.
pub(crate) async fn run_interruptible<T, F>(
    interrupt_handle: Arc<duckdb::InterruptHandle>,
    f: F,
) -> Result<T, Status>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, ServerError> + Send + 'static,
{
    // Create a oneshot channel for signaling completion
    let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();

    // Spawn monitor task that will interrupt DuckDB if we're cancelled
    let interrupt_handle_monitor = interrupt_handle.clone();
    let monitor = tokio::spawn(async move {
        // Wait for either:
        // 1. done_tx is dropped (blocking task finished or parent cancelled)
        // 2. The channel receives a value (normal completion)
        if done_rx.await.is_err() {
            // Sender was dropped without sending - this means cancellation
            info!("request cancelled, interrupting DuckDB query via monitor");
            interrupt_handle_monitor.interrupt();
        }
    });

    // Run the blocking operation
    let result = tokio::task::spawn_blocking(f)
        .await
        .map_err(SwanFlightSqlService::status_from_join)?
        .map_err(SwanFlightSqlService::status_from_error);

    // Signal completion to the monitor (so it doesn't interrupt)
    let _ = done_tx.send(());

    // Clean up the monitor task
    let _ = monitor.await;

    result
}

/// Wrapper service that handles both raw Flight and Flight SQL requests.
///
/// This enables `airport_take_flight` SQL passthrough by intercepting raw Flight
/// requests (where cmd contains SQL as raw bytes) before the Flight SQL layer
/// tries to decode them as protobuf.
#[derive(Clone)]
pub struct SwanFlightService {
    inner: SwanFlightSqlService,
}

impl SwanFlightService {
    pub fn new(registry: Arc<SessionRegistry>) -> Self {
        Self {
            inner: SwanFlightSqlService::new(registry),
        }
    }

    /// Check if the FlightDescriptor cmd field contains raw SQL (not protobuf).
    /// Airport's `airport_take_flight` sends SQL as raw UTF-8 bytes in the cmd field.
    fn is_raw_sql_command(descriptor: &FlightDescriptor) -> bool {
        if descriptor.cmd.is_empty() {
            return false;
        }
        // Try to parse as UTF-8 string - if it looks like SQL, it's raw
        if let Ok(text) = std::str::from_utf8(&descriptor.cmd) {
            // Simple heuristic: if it starts with common SQL keywords, treat as raw SQL
            let trimmed = text.trim().to_uppercase();
            trimmed.starts_with("SELECT")
                || trimmed.starts_with("INSERT")
                || trimmed.starts_with("UPDATE")
                || trimmed.starts_with("DELETE")
                || trimmed.starts_with("CREATE")
                || trimmed.starts_with("DROP")
                || trimmed.starts_with("ALTER")
                || trimmed.starts_with("WITH")
                || trimmed.starts_with("EXPLAIN")
                || trimmed.starts_with("DESCRIBE")
                || trimmed.starts_with("SHOW")
        } else {
            false
        }
    }

    /// Check if SQL is a DDL statement (doesn't return rows)
    fn is_ddl_statement(sql: &str) -> bool {
        let trimmed = sql.trim().to_uppercase();
        trimmed.starts_with("CREATE")
            || trimmed.starts_with("DROP")
            || trimmed.starts_with("ALTER")
    }

    /// Handle raw Flight SQL passthrough (for airport_take_flight).
    async fn handle_raw_sql_flight_info(
        &self,
        request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        let descriptor = request.get_ref();
        let sql = std::str::from_utf8(&descriptor.cmd)
            .map_err(|e| Status::invalid_argument(format!("Invalid UTF-8 in SQL: {e}")))?
            .to_string();

        info!(sql = %sql, "handling raw Flight SQL passthrough (airport_take_flight)");

        let session = self.inner.prepare_request(&request).await?;

        // Check if this is a DDL statement - execute directly without expecting results
        if Self::is_ddl_statement(&sql) {
            info!(sql = %sql, "executing DDL statement via passthrough");

            let sql_clone = sql.clone();
            let session_clone = Arc::clone(&session);

            // Use interruptible execution so client cancellation (Ctrl+C) stops the query
            let interrupt_handle = session.connection.interrupt_handle();
            run_interruptible(interrupt_handle, move || {
                session_clone.execute_statement(&sql_clone)
            })
            .await?;

            // Return empty FlightInfo for DDL (no result rows)
            let info = FlightInfo::new()
                .try_with_schema(&arrow_schema::Schema::empty())
                .map_err(|e| Status::internal(format!("Failed to encode schema: {e}")))?
                .with_descriptor(request.into_inner());

            return Ok(Response::new(info));
        }

        // For queries, get schema using LIMIT 0 to avoid materializing data
        let schema_sql = format!("SELECT * FROM ({}) LIMIT 0", sql.trim_end_matches(';').trim());
        let session_clone = Arc::clone(&session);

        // Use interruptible execution so client cancellation (Ctrl+C) stops the query
        let interrupt_handle = session.connection.interrupt_handle();
        let schema = run_interruptible(interrupt_handle, move || {
            session_clone.schema_for_query(&schema_sql)
        })
        .await?;

        // Create a ticket with the SQL
        let ticket_payload = TicketStatementPayload::new(StatementTicketKind::Ephemeral)
            .with_fallback_sql(&sql)
            .with_returns_rows(true);

        let ticket_query = TicketStatementQuery {
            statement_handle: ticket_payload.encode_to_vec().into(),
        };

        let ticket = Ticket::new(ticket_query.as_any().encode_to_vec());
        let endpoint = FlightEndpoint::new().with_ticket(ticket);

        let info = FlightInfo::new()
            .try_with_schema(&schema)
            .map_err(|e| Status::internal(format!("Failed to encode schema: {e}")))?
            .with_descriptor(request.into_inner())
            .with_endpoint(endpoint);

        Ok(Response::new(info))
    }
}

#[tonic::async_trait]
impl FlightService for SwanFlightService {
    type HandshakeStream = <SwanFlightSqlService as FlightService>::HandshakeStream;
    type ListFlightsStream = <SwanFlightSqlService as FlightService>::ListFlightsStream;
    type DoGetStream = <SwanFlightSqlService as FlightService>::DoGetStream;
    type DoPutStream = <SwanFlightSqlService as FlightService>::DoPutStream;
    type DoActionStream = <SwanFlightSqlService as FlightService>::DoActionStream;
    type ListActionsStream = <SwanFlightSqlService as FlightService>::ListActionsStream;
    type DoExchangeStream = <SwanFlightSqlService as FlightService>::DoExchangeStream;

    async fn handshake(
        &self,
        request: Request<Streaming<HandshakeRequest>>,
    ) -> Result<Response<Self::HandshakeStream>, Status> {
        self.inner.handshake(request).await
    }

    async fn list_flights(
        &self,
        request: Request<Criteria>,
    ) -> Result<Response<Self::ListFlightsStream>, Status> {
        self.inner.list_flights(request).await
    }

    /// Override get_flight_info to handle raw Flight SQL passthrough.
    async fn get_flight_info(
        &self,
        request: Request<FlightDescriptor>,
    ) -> Result<Response<FlightInfo>, Status> {
        // Check if this is a raw SQL command from airport_take_flight
        if Self::is_raw_sql_command(request.get_ref()) {
            return self.handle_raw_sql_flight_info(request).await;
        }

        // Otherwise delegate to Flight SQL handler
        self.inner.get_flight_info(request).await
    }

    async fn get_schema(
        &self,
        request: Request<FlightDescriptor>,
    ) -> Result<Response<SchemaResult>, Status> {
        self.inner.get_schema(request).await
    }

    async fn do_get(&self, request: Request<Ticket>) -> Result<Response<Self::DoGetStream>, Status> {
        self.inner.do_get(request).await
    }

    async fn do_put(
        &self,
        request: Request<Streaming<FlightData>>,
    ) -> Result<Response<Self::DoPutStream>, Status> {
        self.inner.do_put(request).await
    }

    async fn do_action(
        &self,
        request: Request<Action>,
    ) -> Result<Response<Self::DoActionStream>, Status> {
        self.inner.do_action(request).await
    }

    async fn list_actions(
        &self,
        request: Request<Empty>,
    ) -> Result<Response<Self::ListActionsStream>, Status> {
        self.inner.list_actions(request).await
    }

    async fn do_exchange(
        &self,
        request: Request<Streaming<FlightData>>,
    ) -> Result<Response<Self::DoExchangeStream>, Status> {
        // Handle Airport's DoExchange for insert/update/delete operations
        handlers::exchange::do_exchange(&self.inner, request).await
    }

    async fn poll_flight_info(
        &self,
        request: Request<FlightDescriptor>,
    ) -> Result<Response<arrow_flight::PollInfo>, Status> {
        self.inner.poll_flight_info(request).await
    }
}
