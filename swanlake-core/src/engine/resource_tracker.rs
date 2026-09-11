//! Resource tracking for running queries.
//!
//! Samples DuckDB memory usage and CPU time on a background thread,
//! providing metrics that can be streamed to Flight clients alongside
//! query progress.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

use super::DuckDbConnection;
use libduckdb_sys as ffi;
use tracing::{trace, warn};

/// Snapshot of resource usage at a point in time.
#[derive(Debug, Clone, Copy)]
pub struct ResourceSnapshot {
    pub peak_memory_bytes: u64,
    pub current_memory_bytes: u64,
    pub cpu_time_us: u64,
}

/// The sampler thread retains the owning connection for every raw-pointer read.
struct SendConn(ffi::duckdb_connection);
unsafe impl Send for SendConn {}

/// Mirror of InterruptHandle's internal layout (same as in progress.rs).
#[repr(C)]
struct InterruptHandleHack {
    conn: std::sync::Mutex<ffi::duckdb_connection>,
}

/// Tracks resource usage of a running DuckDB query by polling on a background thread.
///
/// Memory: uses a separate monitoring connection (via `try_clone()`) to query
/// `duckdb_memory()` every ~100ms.
///
/// CPU time: calls `duckdb_get_accumulated_cpu_time()` on the query connection,
/// which acquires the profiler lock internally for thread safety.
pub struct ResourceTracker {
    peak_memory_bytes: Arc<AtomicU64>,
    current_memory_bytes: Arc<AtomicU64>,
    cpu_time_us: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    sampler_handle: Option<thread::JoinHandle<()>>,
}

impl ResourceTracker {
    /// Start sampling resource usage on a background thread.
    ///
    /// - `monitoring_conn`: separate connection to the same database (for memory queries)
    /// - `query_connection`: actual owner of the connection being sampled
    ///
    /// Call during blocking setup: obtaining its interrupt handle takes the
    /// connection mutex. The sampler then reads the profiler without that mutex.
    pub fn start(
        monitoring_conn: duckdb::Connection,
        query_connection: Arc<DuckDbConnection>,
    ) -> Self {
        let peak_memory_bytes = Arc::new(AtomicU64::new(0));
        let current_memory_bytes = Arc::new(AtomicU64::new(0));
        let cpu_time_us = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let peak = Arc::clone(&peak_memory_bytes);
        let current = Arc::clone(&current_memory_bytes);
        let cpu = Arc::clone(&cpu_time_us);
        let stop_flag = Arc::clone(&stop);

        // Derive the pointer from the same connection the thread will retain.
        // InterruptHandle alone does not keep a native connection alive.
        let query_interrupt = query_connection.interrupt_handle();
        let query_conn = SendConn({
            let hack: &InterruptHandleHack =
                unsafe { std::mem::transmute(query_interrupt.as_ref()) };
            *hack.conn.lock().expect("interrupt handle mutex poisoned")
        });

        let sampler_handle = thread::Builder::new()
            .name("resource-sampler".into())
            .spawn(move || {
                // Keep the actual owner alive until the sampler exits. Retaining
                // only InterruptHandle leaves a dangling pointer after session
                // closure or a completed query whose response is still alive.
                let _query_owner = query_connection;
                // Force capture of entire SendConn (not just .0) for Send impl.
                let query_conn = query_conn;
                let mut warned = false;

                while !stop_flag.load(Ordering::Relaxed) {
                    // Sample memory via monitoring connection
                    match monitoring_conn.query_row(
                        "SELECT sum(memory_usage_bytes) FROM duckdb_memory()",
                        [],
                        |row| row.get::<_, i64>(0),
                    ) {
                        Ok(memory) if memory >= 0 => {
                            let mem = memory as u64;
                            current.store(mem, Ordering::Relaxed);
                            peak.fetch_max(mem, Ordering::Relaxed);
                            trace!(memory_bytes = mem, "sampled duckdb memory");
                            warned = false;
                        }
                        Ok(_) => {
                            warned = false;
                        }
                        Err(e) => {
                            if !warned {
                                warn!(%e, "failed to query duckdb_memory()");
                                warned = true;
                            }
                        }
                    }

                    // Sample CPU time from query connection's profiler
                    if !query_conn.0.is_null() {
                        let cpu_seconds =
                            unsafe { ffi::duckdb_get_accumulated_cpu_time(query_conn.0) };
                        if cpu_seconds > 0.0 {
                            let us = (cpu_seconds * 1_000_000.0) as u64;
                            cpu.store(us, Ordering::Relaxed);
                            trace!(cpu_time_us = us, "sampled cpu time");
                        }
                    }

                    thread::sleep(Duration::from_millis(100));
                }
            })
            .expect("failed to spawn resource sampler thread");

        Self {
            peak_memory_bytes,
            current_memory_bytes,
            cpu_time_us,
            stop,
            sampler_handle: Some(sampler_handle),
        }
    }

    /// Create a disabled resource tracker (no sampling).
    pub fn disabled() -> Self {
        Self {
            peak_memory_bytes: Arc::new(AtomicU64::new(0)),
            current_memory_bytes: Arc::new(AtomicU64::new(0)),
            cpu_time_us: Arc::new(AtomicU64::new(0)),
            stop: Arc::new(AtomicBool::new(true)),
            sampler_handle: None,
        }
    }

    /// Get a snapshot of current resource usage.
    pub fn snapshot(&self) -> ResourceSnapshot {
        ResourceSnapshot {
            peak_memory_bytes: self.peak_memory_bytes.load(Ordering::Relaxed),
            current_memory_bytes: self.current_memory_bytes.load(Ordering::Relaxed),
            cpu_time_us: self.cpu_time_us.load(Ordering::Relaxed),
        }
    }
}

impl Drop for ResourceTracker {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.sampler_handle.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sampler_retains_connection_through_query_turnover_and_owner_drop() {
        let native = duckdb::Connection::open_in_memory().unwrap();
        native.execute_batch("SET threads=2; SET enable_profiling='no_output'; \
            SET custom_profiling_settings='{\"OPERATOR_CPU_TIME\":\"true\",\"CPU_TIME_ACTUAL\":\"true\"}'").unwrap();
        let monitoring = native.try_clone().unwrap();
        let connection = Arc::new(DuckDbConnection::new(native));
        let weak = Arc::downgrade(&connection);
        let tracker = ResourceTracker::start(monitoring, connection.clone());
        let worker = thread::spawn(move || {
            let native = connection.conn.lock().unwrap();
            // Repeated start/finalize/reset while the profiler is sampled.
            for _ in 0..150 {
                let _: f64 = native
                    .query_row(
                        "SELECT sum(sin(i::DOUBLE)) FROM range(200000) t(i)",
                        [],
                        |row| row.get(0),
                    )
                    .unwrap();
            }
        });
        worker.join().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while tracker.snapshot().cpu_time_us == 0 && std::time::Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert!(tracker.snapshot().cpu_time_us > 0);
        assert!(
            weak.upgrade().is_some(),
            "sampler lost its native connection owner"
        );
        drop(tracker);
        assert!(
            weak.upgrade().is_none(),
            "sampler leaked its connection after shutdown"
        );
    }
}
