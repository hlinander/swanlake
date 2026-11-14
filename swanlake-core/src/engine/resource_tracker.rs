//! Resource figures of a running request.
//!
//! A snapshot takes its CPU and memory figures from the request's progress
//! figures and one `duckdb_resource_totals_read` of the request's connection.
//! Flight clients receive it alongside query progress.

use duckdb::InterruptHandle;
use libduckdb_sys as ffi;

use crate::usage::{Progress, ProgressFigures, ResourceTotals, UsageTotals};

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
/// attempt's opening read to the CPU of the attempts that have closed, its
/// memory level is that of one read of the connection behind `handle`, and
/// its peak is the larger of that read's peak and the largest peak among the
/// closed attempts. With no attempt open it reads nothing: the snapshot
/// carries the closed attempts' CPU and their largest peak, and no memory
/// level. Once the request's last label-1 attempt has closed, the snapshot
/// equals the request's total.
pub fn progress_snapshot(handle: &InterruptHandle, progress: &Progress) -> ResourceSnapshot {
    let figures = progress.figures();
    let current = figures.open.and_then(|_| read_totals(handle));
    snapshot_of(&figures, current.as_ref())
}

/// The snapshot of `figures`, with `current` a read taken while an attempt
/// is open.
///
/// A read's peak covers only the attempt that is open, so the peak is the
/// larger of it and the closed attempts' largest peak, and never falls
/// during a request.
fn snapshot_of(figures: &ProgressFigures, current: Option<&ResourceTotals>) -> ResourceSnapshot {
    ResourceSnapshot {
        peak_memory_bytes: current.map_or(figures.closed_peak_bytes, |read| {
            read.memory_peak_bytes.max(figures.closed_peak_bytes)
        }),
        current_memory_bytes: current.map_or(0, |read| read.memory_bytes),
        cpu_time_us: figures.cpu_ns(current) / 1_000,
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

    /// A statement that runs until it is interrupted.
    const ENDLESS_SQL: &str = "SELECT sum(sin(i::DOUBLE)) FROM range(100000000000) t(i)";

    /// A read never waits for the statement thread: it returns while another
    /// thread executes a statement under the connection guard, and it
    /// reports that statement's CPU as it accrues.
    #[test]
    fn a_read_returns_while_a_statement_runs() {
        let connection = connection();
        let handle = connection.interrupt_handle();
        let finished = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let worker = {
            let connection = connection.clone();
            let finished = finished.clone();
            thread::spawn(move || {
                let result = connection.with_raw(|native| native.execute_batch(ENDLESS_SQL));
                finished.store(true, std::sync::atomic::Ordering::SeqCst);
                result
            })
        };

        // The statement is executing once the database's CPU rises between
        // two reads.
        let deadline = Instant::now() + Duration::from_secs(30);
        let first = read_totals(&handle).expect("the connection is open");
        let mut slowest = Duration::ZERO;
        let mut latest = first;
        while latest.database.cpu_ns <= first.database.cpu_ns || !connection.guard_is_held() {
            assert!(Instant::now() < deadline, "the statement's CPU never reached a read");
            thread::sleep(Duration::from_millis(10));
            let start = Instant::now();
            latest = read_totals(&handle).expect("the connection is open");
            slowest = slowest.max(start.elapsed());
        }
        // Reads taken while the statement executes.
        for _ in 0..20 {
            let start = Instant::now();
            let read = read_totals(&handle).expect("the connection is open");
            slowest = slowest.max(start.elapsed());
            assert!(read.database.cpu_ns >= latest.database.cpu_ns);
            latest = read;
        }
        let still_running = !finished.load(std::sync::atomic::Ordering::SeqCst);
        handle.interrupt();
        let result = worker.join().unwrap();

        assert!(still_running, "the statement ended before the reads did");
        assert!(result.is_err(), "the statement ran until the interrupt: {result:?}");
        assert!(
            slowest < Duration::from_millis(100),
            "a read took {slowest:?} while a statement executed"
        );
    }

    /// The peak of a snapshot never falls during a request: a read taken
    /// while an attempt is open reports that attempt's peak alone, and the
    /// snapshot reports the larger of it and the closed attempts' peak.
    #[test]
    fn a_snapshot_peak_is_never_below_the_closed_attempts_peak() {
        let read = |peak: u64| ResourceTotals {
            memory_bytes: peak / 2,
            memory_peak_bytes: peak,
            ..ResourceTotals::default()
        };
        let closed = ProgressFigures {
            closed_cpu_ns: 5_000,
            closed_peak_bytes: 800,
            open: None,
        };
        let open = ProgressFigures {
            open: Some(read(0)),
            ..closed
        };

        // With no attempt open, the closed attempts' peak and no level.
        let settled = snapshot_of(&closed, None);
        assert_eq!((settled.peak_memory_bytes, settled.current_memory_bytes), (800, 0));
        // An open attempt whose own peak is below the closed attempts' peak.
        let below = snapshot_of(&open, Some(&read(300)));
        assert_eq!((below.peak_memory_bytes, below.current_memory_bytes), (800, 150));
        // An open attempt whose peak passes it.
        let above = snapshot_of(&open, Some(&read(900)));
        assert_eq!((above.peak_memory_bytes, above.current_memory_bytes), (900, 450));
    }

    /// Through the engine: the second attempt of a request uses less memory
    /// than the first, and a snapshot taken while it is open still reports
    /// the first attempt's peak.
    #[test]
    fn a_later_smaller_attempt_keeps_the_request_peak() {
        let connection = connection();
        let handle = connection.interrupt_handle();
        let accounting = RequestAccounting::new("DoGet", None, None);
        let progress = accounting.progress();

        connection
            .guarded(None, Some(&accounting), |native, bracket| {
                bracket.measure(ExecutionLabel::Client, || {
                    native.execute_batch(
                        "SELECT count(*) FROM (SELECT i % 1000000 AS g, count(*) AS n \
                         FROM range(3000000) t(i) GROUP BY g)",
                    )
                })?;
                Ok(())
            })
            .unwrap();
        let first_peak = progress.figures().closed_peak_bytes;
        assert!(first_peak > 0, "the first attempt used memory");

        let during = connection
            .guarded(None, Some(&accounting), |native, bracket| {
                Ok(bracket.measure(ExecutionLabel::Client, || {
                    native.execute_batch("SELECT 1").unwrap();
                    let own = read_totals(&handle).expect("the connection is open");
                    (own, progress_snapshot(&handle, &progress))
                }))
            })
            .unwrap();
        let (own, snapshot) = during;
        assert!(
            own.memory_peak_bytes < first_peak,
            "the second attempt's own peak, {}, is below the first's, {first_peak}",
            own.memory_peak_bytes
        );
        assert_eq!(snapshot.peak_memory_bytes, first_peak);
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
