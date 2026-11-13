//! Query progress, read through the interrupt handle's connection accessor.

use duckdb::InterruptHandle;
use libduckdb_sys as ffi;

/// Query progress information from DuckDB.
#[derive(Debug, Clone, Copy)]
pub struct QueryProgress {
    /// Percentage complete (0.0 - 100.0)
    pub percentage: f64,
    /// Number of rows processed so far
    pub rows_processed: u64,
    /// Total rows to process (estimate)
    pub total_rows: u64,
}

/// Get query progress from an InterruptHandle.
///
/// Returns `None` if:
/// - No query is currently running
/// - Progress information is unavailable
/// - The connection has been closed
///
/// The caller holds no connection guard, so the engine call runs inside the
/// accessor, which keeps the connection open for its duration.
pub fn query_progress(handle: &InterruptHandle) -> Option<QueryProgress> {
    // SAFETY: the accessor passes a live connection and holds it open for
    // the call, which takes no client-context lock.
    let progress = handle.with_connection(|conn| unsafe { ffi::duckdb_query_progress(conn) })?;

    if progress.percentage < 0.0 {
        None
    } else {
        Some(QueryProgress {
            percentage: progress.percentage,
            rows_processed: progress.rows_processed,
            total_rows: progress.total_rows_to_process,
        })
    }
}
