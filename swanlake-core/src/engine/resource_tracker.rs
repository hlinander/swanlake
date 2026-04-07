//! Resource tracking for running queries.
//!
//! Samples DuckDB memory usage and CPU time on a background thread,
//! providing metrics that can be streamed to Flight clients alongside
//! query progress.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use duckdb::InterruptHandle;
use libduckdb_sys as ffi;
use tracing::{trace, warn};

extern "C" {
    /// Thread-safe C API that traverses the profiling tree under lock,
    /// summing OPERATOR_CPU_TIME across all nodes. Returns seconds.
    fn duckdb_get_accumulated_cpu_time(connection: ffi::duckdb_connection) -> f64;
}

/// Snapshot of resource usage at a point in time.
#[derive(Debug, Clone, Copy)]
pub struct ResourceSnapshot {
    pub peak_memory_bytes: u64,
    pub current_memory_bytes: u64,
    pub cpu_time_us: u64,
}

/// Wrapper to send raw DuckDB connection pointer across threads.
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
    /// - `query_interrupt`: interrupt handle of the connection running the query (for CPU time)
    pub fn start(
        monitoring_conn: duckdb::Connection,
        query_interrupt: Arc<InterruptHandle>,
    ) -> Self {
        let peak_memory_bytes = Arc::new(AtomicU64::new(0));
        let current_memory_bytes = Arc::new(AtomicU64::new(0));
        let cpu_time_us = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let peak = Arc::clone(&peak_memory_bytes);
        let current = Arc::clone(&current_memory_bytes);
        let cpu = Arc::clone(&cpu_time_us);
        let stop_flag = Arc::clone(&stop);

        // Extract raw query connection pointer for CPU time FFI.
        let query_conn = SendConn({
            let hack: &InterruptHandleHack =
                unsafe { std::mem::transmute(query_interrupt.as_ref()) };
            *hack.conn.lock().expect("interrupt handle mutex poisoned")
        });

        let sampler_handle = thread::Builder::new()
            .name("resource-sampler".into())
            .spawn(move || {
                // Keep interrupt handle alive so the connection pointer remains valid.
                let _interrupt_owner = query_interrupt;
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
                            unsafe { duckdb_get_accumulated_cpu_time(query_conn.0) };
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
