//! Resource figures of a running request.
//!
//! A snapshot takes its CPU and memory figures from the request's progress
//! figures and one `duckdb_resource_totals_read` of the request's connection.
//! Flight clients receive it alongside query progress.

use duckdb::InterruptHandle;
use libduckdb_sys as ffi;

use crate::usage::{Progress, ResourceTotals, UsageTotals};

/// Snapshot of resource usage at a point in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResourceSnapshot {
    pub peak_memory_bytes: u64,
    pub current_memory_bytes: u64,
    pub cpu_time_us: u64,
}

impl From<ffi::duckdb_usage_totals> for UsageTotals {
    fn from(totals: ffi::duckdb_usage_totals) -> Self {
        Self {
            cpu_ns: totals.cpu_ns,
            bytes_read: totals.bytes_read,
            bytes_written: totals.bytes_written,
        }
    }
}

impl From<ffi::duckdb_resource_totals> for ResourceTotals {
    fn from(totals: ffi::duckdb_resource_totals) -> Self {
        Self {
            connection: totals.connection.into(),
            database: totals.database.into(),
            memory_bytes: totals.memory_bytes,
            memory_peak_bytes: totals.memory_peak_bytes,
            memory_byte_ms: totals.memory_byte_ms,
        }
    }
}

/// Reads the totals of the connection behind `handle`, and of its database.
///
/// The call takes no lock a running statement holds, so it returns while the
/// statement thread executes. It runs inside the handle's mutex, which keeps
/// the native connection open for the read. Returns `None` once the
/// connection is closed, and when the engine reports a failure.
pub fn read_totals(handle: &InterruptHandle) -> Option<ResourceTotals> {
    handle
        .with_connection(|native| {
            let mut totals = ffi::duckdb_resource_totals {
                connection: ffi::duckdb_usage_totals {
                    cpu_ns: 0,
                    bytes_read: 0,
                    bytes_written: 0,
                },
                database: ffi::duckdb_usage_totals {
                    cpu_ns: 0,
                    bytes_read: 0,
                    bytes_written: 0,
                },
                memory_bytes: 0,
                memory_peak_bytes: 0,
                memory_byte_ms: 0,
            };
            // SAFETY: `with_connection` passes a live connection and holds the
            // mutex that closing it takes, and `totals` is a valid struct.
            let state = unsafe { ffi::duckdb_resource_totals_read(native, &mut totals) };
            (state == ffi::DuckDBSuccess).then(|| ResourceTotals::from(totals))
        })
        .flatten()
}

/// The resource figures of a request's label-1 attempts as of this call.
///
/// While an attempt is open, the snapshot adds the database's CPU since that
/// attempt's opening read to the CPU of the attempts that have closed, and
/// its memory level and peak are those of one read of the connection behind
/// `handle`. With no attempt open it reads nothing: the snapshot carries the
/// closed attempts' CPU and their largest peak, and no memory level. Once the
/// request's last label-1 attempt has closed, the snapshot equals the
/// request's total.
pub fn progress_snapshot(handle: &InterruptHandle, progress: &Progress) -> ResourceSnapshot {
    let figures = progress.figures();
    let current = figures.open.and_then(|_| read_totals(handle));
    ResourceSnapshot {
        peak_memory_bytes: current.map_or(figures.closed_peak_bytes, |read| read.memory_peak_bytes),
        current_memory_bytes: current.map_or(0, |read| read.memory_bytes),
        cpu_time_us: figures.cpu_ns(current.as_ref()) / 1_000,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use super::*;
    use crate::engine::DuckDbConnection;
    use crate::usage::{ExecutionLabel, RequestAccounting};

    const BUSY_SQL: &str = "SELECT sum(sin(i::DOUBLE)) FROM range(200000) t(i)";

    fn connection() -> Arc<DuckDbConnection> {
        let native = duckdb::Connection::open_in_memory().unwrap();
        native.execute_batch("SET threads=2").unwrap();
        Arc::new(DuckDbConnection::new(native))
    }

    /// A read never waits for the statement thread: it returns while another
    /// thread holds the connection guard inside a statement.
    #[test]
    fn a_read_returns_while_a_statement_holds_the_guard() {
        let connection = connection();
        let handle = connection.interrupt_handle();
        let (started_tx, started_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let worker = {
            let connection = connection.clone();
            thread::spawn(move || {
                connection.with_raw(|native| {
                    native.execute_batch(BUSY_SQL).unwrap();
                    started_tx.send(()).unwrap();
                    let _ = release_rx.recv_timeout(Duration::from_secs(5));
                });
            })
        };
        started_rx.recv().unwrap();
        assert!(connection.guard_is_held());
        let start = Instant::now();
        let totals = read_totals(&handle).expect("the connection is open");
        let elapsed = start.elapsed();
        release_tx.send(()).unwrap();
        worker.join().unwrap();
        assert!(totals.database.cpu_ns > 0, "the statement's CPU is in the totals");
        assert!(
            elapsed < Duration::from_millis(100),
            "a read took {elapsed:?} while a statement held the guard"
        );
    }

    /// The totals survive what emptied the profiling tree: an execution error
    /// in autocommit, and an explicit rollback. They never decrease.
    #[test]
    fn totals_survive_autocommit_errors_and_explicit_rollbacks() {
        let connection = connection();
        let handle = connection.interrupt_handle();
        let mut last = read_totals(&handle).unwrap();
        for _ in 0..20 {
            connection.with_raw(|native| {
                let error = native.query_row::<i64, _, _>(
                    "SELECT sum(CAST(CASE WHEN i=199999 THEN 'invalid' ELSE '1' END AS BIGINT)) \
                     FROM range(200000) t(i)",
                    [],
                    |row| row.get(0),
                );
                assert!(error.is_err());
            });
            let after_error = read_totals(&handle).unwrap();
            assert!(after_error.database.cpu_ns > last.database.cpu_ns);
            connection.with_raw(|native| {
                native.execute_batch("BEGIN TRANSACTION").unwrap();
                let _: f64 = native.query_row(BUSY_SQL, [], |row| row.get(0)).unwrap();
                native.execute_batch("ROLLBACK").unwrap();
            });
            let after_rollback = read_totals(&handle).unwrap();
            assert!(after_rollback.database.cpu_ns > after_error.database.cpu_ns);
            assert!(after_rollback.connection.cpu_ns >= after_error.connection.cpu_ns);
            last = after_rollback;
        }
    }

    /// A handle does not keep its connection open, and a read through it
    /// after the connection closed reports nothing.
    #[test]
    fn a_read_after_the_connection_closed_reports_nothing() {
        let connection = connection();
        let handle = connection.interrupt_handle();
        let weak = Arc::downgrade(&connection);
        for _ in 0..20 {
            connection
                .execute_query(BUSY_SQL, None)
                .expect("the query runs");
        }
        assert!(read_totals(&handle).is_some());
        drop(connection);
        assert!(weak.upgrade().is_none(), "a handle retained its connection");
        assert!(read_totals(&handle).is_none());
        let progress = RequestAccounting::new("DoGet", None, None).progress();
        assert_eq!(
            progress_snapshot(&handle, &progress),
            ResourceSnapshot {
                peak_memory_bytes: 0,
                current_memory_bytes: 0,
                cpu_time_us: 0,
            }
        );
    }

    /// The snapshot follows the request's label-1 attempts: it reads the
    /// connection while one is open, and equals the request's total once the
    /// last has closed.
    #[test]
    fn a_snapshot_reads_the_open_attempt_and_settles_on_the_total() {
        let connection = connection();
        let handle = connection.interrupt_handle();
        let accounting = RequestAccounting::new("DoGet", None, None);
        let progress = accounting.progress();

        // A label-0 attempt is no part of the request's total.
        connection
            .execute_batch("SELECT 1", ExecutionLabel::SwanLake, Some(&accounting))
            .unwrap();
        assert_eq!(progress_snapshot(&handle, &progress).cpu_time_us, 0);

        let during = connection
            .guarded(None, Some(&accounting), |native, bracket| {
                Ok(bracket.measure(ExecutionLabel::Client, || {
                    native.execute_batch(BUSY_SQL).unwrap();
                    let first = progress_snapshot(&handle, &progress);
                    native.execute_batch(BUSY_SQL).unwrap();
                    (first, progress_snapshot(&handle, &progress))
                }))
            })
            .unwrap();
        let (first, second) = during;
        assert!(first.cpu_time_us > 0, "an open attempt reports its CPU so far");
        assert!(second.cpu_time_us > first.cpu_time_us);
        assert!(second.peak_memory_bytes >= second.current_memory_bytes);

        let figures = progress.figures();
        assert!(figures.open.is_none());
        let settled = progress_snapshot(&handle, &progress);
        assert_eq!(settled.cpu_time_us, figures.closed_cpu_ns / 1_000);
        assert_eq!(settled.peak_memory_bytes, figures.closed_peak_bytes);
        assert!(settled.cpu_time_us >= second.cpu_time_us);
        // Later work on the connection is no part of the request.
        connection.execute_query(BUSY_SQL, None).unwrap();
        assert_eq!(progress_snapshot(&handle, &progress), settled);
    }
}
