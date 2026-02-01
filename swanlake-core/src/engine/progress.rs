//! Query progress tracking via libduckdb-sys.
//!
//! This module provides a way to get query progress by accessing the raw
//! duckdb_connection pointer through InterruptHandle's internal structure.
//!
//! WARNING: This relies on the memory layout of InterruptHandle not changing.
//! If duckdb-rs updates and changes the struct layout, this will break.

use duckdb::InterruptHandle;
use libduckdb_sys as ffi;
use std::sync::Mutex;

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

/// Mirror of InterruptHandle's internal layout.
/// This is fragile and depends on duckdb-rs internals not changing.
#[repr(C)]
struct InterruptHandleHack {
    conn: Mutex<ffi::duckdb_connection>,
}

/// Get query progress from an InterruptHandle.
///
/// Returns `None` if:
/// - No query is currently running
/// - Progress information is unavailable
/// - The connection has been closed
///
/// # Safety
/// This function uses transmute to access private fields of InterruptHandle.
/// It assumes InterruptHandle's layout is `Mutex<duckdb_connection>`.
pub fn query_progress(handle: &InterruptHandle) -> Option<QueryProgress> {
    // SAFETY: We're assuming InterruptHandle has the same layout as InterruptHandleHack.
    // This is fragile but works for the current duckdb-rs version.
    let hack: &InterruptHandleHack = unsafe { std::mem::transmute(handle) };

    let conn = match hack.conn.lock() {
        Ok(c) => *c,
        Err(_) => return None,
    };

    if conn.is_null() {
        return None;
    }

    let progress = unsafe { ffi::duckdb_query_progress(conn) };

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
