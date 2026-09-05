//! DuckDB engine module - connection management and query execution.
//!
//! This module provides:
//! - `DuckDbConnection`: Wrapper around duckdb::Connection with execution methods
//! - `EngineFactory`: Factory for creating initialized connections
//! - `QueryResult`: Query execution results
//! - `progress`: Query progress tracking via FFI

pub(crate) mod batch;
pub mod connection;
mod factory;
pub mod progress;
pub mod resource_tracker;
mod result_projection;

pub use connection::{DuckDbConnection, QueryResult, StreamingBatch};
pub use factory::EngineFactory;
pub use progress::{query_progress, QueryProgress};
pub use resource_tracker::{ResourceSnapshot, ResourceTracker};
