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

use crate::config::SessionIdMode;
use crate::error::ServerError;
use crate::metrics::Metrics;
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
    metrics: Arc<Metrics>,
    session_id_mode: SessionIdMode,
}

impl SwanFlightSqlService {
    pub fn new(
        registry: Arc<SessionRegistry>,
        metrics: Arc<Metrics>,
        session_id_mode: SessionIdMode,
    ) -> Self {
        Self {
            registry,
            metrics,
            session_id_mode,
        }
    }

    /// Extract session ID from tonic Request metadata.
    ///
    /// Checks for session ID in order:
    /// 1. `airport-client-session-id` (Airport extension's header)
    /// 2. `x-session-id` (custom header)
    /// 3. Falls back to peer address or IP based on session_id_mode
    pub(crate) fn extract_session_id<T>(&self, request: &Request<T>) -> SessionId {
        let metadata = request.metadata();

        // Airport extension sends this header
        if let Some(session_id) = metadata.get("airport-client-session-id") {
            if let Ok(id_str) = session_id.to_str() {
                if !id_str.is_empty() {
                    return SessionId::from_string(id_str.to_string());
                }
            }
        }

        // Custom header
        if let Some(session_id) = metadata.get("x-session-id") {
            if let Ok(id_str) = session_id.to_str() {
                if !id_str.is_empty() {
                    return SessionId::from_string(id_str.to_string());
                }
            }
        }

        // Fallback to peer address
        match self.session_id_mode {
            SessionIdMode::PeerAddr => {
                if let Some(addr) = request.remote_addr() {
                    SessionId::from_string(addr.to_string())
                } else {
                    SessionId::from_string(uuid::Uuid::new_v4().to_string())
                }
            }
            SessionIdMode::PeerIp => {
                if let Some(addr) = request.remote_addr() {
                    SessionId::from_string(addr.ip().to_string())
                } else {
                    SessionId::from_string(uuid::Uuid::new_v4().to_string())
                }
            }
        }
    }

    /// Prepare request: extract session_id from header, record to tracing span, and get/create session.
    pub(crate) async fn prepare_request<T>(
        &self,
        request: &Request<T>,
    ) -> Result<Arc<Session>, Status> {
        let session_id = self.extract_session_id(request);
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
/// This spawns a monitor task that watches for the parent async task being dropped
/// (e.g., client disconnect) and immediately interrupts the DuckDB query.
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
    pub fn new(
        registry: Arc<SessionRegistry>,
        metrics: Arc<Metrics>,
        session_id_mode: SessionIdMode,
    ) -> Self {
        Self {
            inner: SwanFlightSqlService::new(registry, metrics, session_id_mode),
        }
    }

    /// Check if the FlightDescriptor cmd field contains raw SQL (not protobuf).
    fn is_raw_sql_command(descriptor: &FlightDescriptor) -> bool {
        if descriptor.cmd.is_empty() {
            return false;
        }
        if let Ok(text) = std::str::from_utf8(&descriptor.cmd) {
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

            let interrupt_handle = session.connection.interrupt_handle();
            run_interruptible(interrupt_handle, move || {
                session_clone.execute_statement(&sql_clone)
            })
            .await?;

            let info = FlightInfo::new()
                .try_with_schema(&arrow_schema::Schema::empty())
                .map_err(|e| Status::internal(format!("Failed to encode schema: {e}")))?
                .with_descriptor(request.into_inner());

            return Ok(Response::new(info));
        }

        // For queries, get schema using LIMIT 0 to avoid materializing data
        let schema_sql = format!("SELECT * FROM ({}) LIMIT 0", sql.trim_end_matches(';').trim());
        let session_clone = Arc::clone(&session);

        let interrupt_handle = session.connection.interrupt_handle();
        let schema = run_interruptible(interrupt_handle, move || {
            session_clone.schema_for_query(&schema_sql)
        })
        .await?;

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
        if Self::is_raw_sql_command(request.get_ref()) {
            return self.handle_raw_sql_flight_info(request).await;
        }
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
        handlers::exchange::do_exchange(&self.inner, request).await
    }

    async fn poll_flight_info(
        &self,
        request: Request<FlightDescriptor>,
    ) -> Result<Response<arrow_flight::PollInfo>, Status> {
        self.inner.poll_flight_info(request).await
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{anyhow, Result};
    use arrow_flight::error::FlightError;
    use arrow_flight::FlightData;
    use futures::StreamExt;
    use tonic::transport::server::TcpConnectInfo;
    use tonic::{Code, Request, Status};
    use uuid::Uuid;

    use super::*;
    use crate::config::{ServerConfig, SessionIdMode};
    use crate::engine::EngineFactory;

    fn test_service(mode: SessionIdMode) -> Result<SwanFlightSqlService> {
        let config = ServerConfig {
            session_id_mode: mode.clone(),
            ..ServerConfig::default()
        };
        let factory = Arc::new(EngineFactory::new_for_tests(&config));
        let registry =
            Arc::new(SessionRegistry::new(&config, factory).map_err(|e| anyhow!(e.to_string()))?);
        let metrics = Arc::new(Metrics::new(1_000, 64));
        Ok(SwanFlightSqlService::new(registry, metrics, mode))
    }

    #[test]
    fn extract_session_id_uses_peer_addr_and_peer_ip_modes() -> Result<()> {
        let addr = "127.10.20.30:4321"
            .parse()
            .map_err(|e| anyhow!("failed to parse socket addr: {e}"))?;
        let mut request = Request::new(());
        request.extensions_mut().insert(TcpConnectInfo {
            local_addr: None,
            remote_addr: Some(addr),
        });

        let peer_addr_service = test_service(SessionIdMode::PeerAddr)?;
        let peer_addr_id = peer_addr_service.extract_session_id(&request);
        assert_eq!(peer_addr_id.as_ref(), "127.10.20.30:4321");

        let peer_ip_service = test_service(SessionIdMode::PeerIp)?;
        let peer_ip_id = peer_ip_service.extract_session_id(&request);
        assert_eq!(peer_ip_id.as_ref(), "127.10.20.30");

        let fallback_request = Request::new(());
        let fallback_id = peer_ip_service.extract_session_id(&fallback_request);
        assert!(Uuid::parse_str(fallback_id.as_ref()).is_ok());
        Ok(())
    }

    #[test]
    fn status_from_error_maps_expected_codes() -> Result<()> {
        let conn = duckdb::Connection::open_in_memory()?;
        let duck_error = match conn.execute_batch("SELECT * FROM __missing_table__") {
            Ok(()) => return Err(anyhow!("expected missing-table query to fail")),
            Err(err) => err,
        };
        let duck_status = SwanFlightSqlService::status_from_error(ServerError::DuckDb(duck_error));
        assert_eq!(duck_status.code(), Code::Internal);

        let arrow_status = SwanFlightSqlService::status_from_error(ServerError::Arrow(
            arrow_schema::ArrowError::ParseError("bad".to_string()),
        ));
        assert_eq!(arrow_status.code(), Code::Internal);

        assert_eq!(
            SwanFlightSqlService::status_from_error(ServerError::TransactionAborted).code(),
            Code::FailedPrecondition
        );
        assert_eq!(
            SwanFlightSqlService::status_from_error(ServerError::TransactionNotFound).code(),
            Code::InvalidArgument
        );
        assert_eq!(
            SwanFlightSqlService::status_from_error(ServerError::PreparedStatementNotFound).code(),
            Code::InvalidArgument
        );
        assert_eq!(
            SwanFlightSqlService::status_from_error(ServerError::MaxSessionsReached).code(),
            Code::ResourceExhausted
        );
        assert_eq!(
            SwanFlightSqlService::status_from_error(ServerError::UnsupportedParameter(
                "x".to_string()
            ))
            .code(),
            Code::InvalidArgument
        );
        assert_eq!(
            SwanFlightSqlService::status_from_error(ServerError::Internal("x".to_string())).code(),
            Code::Internal
        );
        Ok(())
    }

    #[test]
    fn status_from_join_handles_panic_and_cancellation() -> Result<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;

        let panic_join = runtime.block_on(async {
            tokio::task::spawn_blocking(|| {
                let values = [1_u8];
                let idx = values.len();
                let _ = values[idx];
            })
            .await
        });
        let panic_error = match panic_join {
            Ok(()) => return Err(anyhow!("expected panicking task to return JoinError")),
            Err(err) => err,
        };
        let panic_status = SwanFlightSqlService::status_from_join(panic_error);
        assert_eq!(panic_status.code(), Code::Internal);
        assert!(panic_status.message().contains("panicked"));

        let cancelled_join = runtime.block_on(async {
            let handle = tokio::spawn(async {
                tokio::time::sleep(Duration::from_secs(30)).await;
            });
            handle.abort();
            handle.await
        });
        let cancelled_error = match cancelled_join {
            Ok(()) => return Err(anyhow!("expected cancelled task to return JoinError")),
            Err(err) => err,
        };
        let cancelled_status = SwanFlightSqlService::status_from_join(cancelled_error);
        assert_eq!(cancelled_status.code(), Code::Internal);
        assert!(cancelled_status.message().contains("cancelled"));
        Ok(())
    }

    #[test]
    fn status_from_flight_error_preserves_tonic_status() {
        let tonic_status = Status::permission_denied("denied");
        let mapped =
            SwanFlightSqlService::status_from_flight_error(FlightError::from(tonic_status.clone()));
        assert_eq!(mapped.code(), Code::PermissionDenied);
        assert_eq!(mapped.message(), tonic_status.message());

        let decode_status = SwanFlightSqlService::status_from_flight_error(
            FlightError::DecodeError("bad payload".to_string()),
        );
        assert_eq!(decode_status.code(), Code::Internal);
        assert!(decode_status.message().contains("decode"));
    }

    #[test]
    fn into_stream_yields_all_batches() {
        let mut stream = SwanFlightSqlService::into_stream(vec![
            FlightData::default(),
            FlightData::default(),
            FlightData::default(),
        ]);

        let emitted = futures::executor::block_on(async {
            let mut count = 0usize;
            while let Some(item) = stream.next().await {
                assert!(item.is_ok());
                count += 1;
            }
            count
        });

        assert_eq!(emitted, 3);
    }
}
