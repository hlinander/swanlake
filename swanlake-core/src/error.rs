use thiserror::Error;

#[derive(Debug, Error)]
pub enum ServerError {
    #[error("duckdb error: {0}")]
    DuckDb(#[from] duckdb::Error),
    #[error("arrow error: {0}")]
    Arrow(#[from] arrow_schema::ArrowError),
    #[error("transaction was aborted and rolled back")]
    TransactionAborted,
    #[error("transaction not found")]
    TransactionNotFound,
    #[error("prepared statement not found")]
    PreparedStatementNotFound,
    #[error("maximum number of sessions reached")]
    MaxSessionsReached,
    #[error("unsupported parameter type: {0}")]
    UnsupportedParameter(String),
    #[error("internal error: {0}")]
    Internal(String),
    /// Raw ATTACH is not permitted in duckvis mode (contract C6). Maps to
    /// `permission_denied`.
    #[error("ATTACH is managed by duckvis; use the duckvis_attach action")]
    AttachNotPermitted,
}
