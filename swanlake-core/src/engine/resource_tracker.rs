//! Resource tracking for running queries.
//!
//! Samples DuckDB memory usage via FFI on a background thread,
//! providing peak and current memory metrics that can be streamed
//! to Flight clients alongside query progress.

use std::ffi::CString;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use duckdb::InterruptHandle;
use libduckdb_sys as ffi;
use tracing::{trace, warn};

extern "C" {
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
///
/// # Safety
/// DuckDB's C API supports concurrent query execution on the same connection,
/// so it is safe to use the connection pointer from a different thread while
/// a streaming query is running.
struct SendConn(ffi::duckdb_connection);
unsafe impl Send for SendConn {}

/// Tracks memory usage of a running DuckDB query by polling on a background thread.
///
/// Uses the same `InterruptHandle` transmute pattern as `progress.rs` to obtain
/// the raw `duckdb_connection` pointer, then executes `SELECT duckdb_memory()`
/// via FFI every ~100ms.
pub struct ResourceTracker {
    peak_memory_bytes: Arc<AtomicU64>,
    current_memory_bytes: Arc<AtomicU64>,
    cpu_time_us: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    sampler_handle: Option<thread::JoinHandle<()>>,
}

/// Mirror of InterruptHandle's internal layout (same as in progress.rs).
#[repr(C)]
struct InterruptHandleHack {
    conn: std::sync::Mutex<ffi::duckdb_connection>,
}

impl ResourceTracker {
    /// Start sampling memory usage on a background thread.
    ///
    /// The sampler runs until the tracker is dropped.
    pub fn start(interrupt_handle: &InterruptHandle) -> Self {
        let peak_memory_bytes = Arc::new(AtomicU64::new(0));
        let current_memory_bytes = Arc::new(AtomicU64::new(0));
        let cpu_time_us = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        // SAFETY: We assume InterruptHandle has the same layout as InterruptHandleHack.
        // This is the same pattern used in progress.rs.
        let hack: &InterruptHandleHack = unsafe { std::mem::transmute(interrupt_handle) };
        let conn = SendConn(*hack.conn.lock().expect("interrupt handle mutex poisoned"));

        let peak = Arc::clone(&peak_memory_bytes);
        let current = Arc::clone(&current_memory_bytes);
        let cpu = Arc::clone(&cpu_time_us);
        let stop_flag = Arc::clone(&stop);

        let sampler_handle = thread::Builder::new()
            .name("resource-sampler".into())
            .spawn(move || {
                let query =
                    CString::new("SELECT duckdb_memory()").expect("CString::new failed");
                let mut warned = false;

                while !stop_flag.load(Ordering::Relaxed) {
                    if !conn.0.is_null() {
                        let mut result: ffi::duckdb_result = unsafe { std::mem::zeroed() };
                        let state = unsafe {
                            ffi::duckdb_query(conn.0, query.as_ptr(), &mut result)
                        };

                        if state == ffi::duckdb_state_DuckDBSuccess {
                            let memory =
                                unsafe { ffi::duckdb_value_int64(&mut result, 0, 0) };
                            if memory >= 0 {
                                let mem = memory as u64;
                                current.store(mem, Ordering::Relaxed);
                                peak.fetch_max(mem, Ordering::Relaxed);
                                trace!(memory_bytes = mem, "sampled duckdb memory");
                            }
                            warned = false;
                        } else if !warned {
                            warn!("failed to query duckdb_memory()");
                            warned = true;
                        }

                        unsafe { ffi::duckdb_destroy_result(&mut result) };

                        // Sample CPU time from profiler (thread-safe via lock)
                        let cpu_seconds = unsafe {
                            duckdb_get_accumulated_cpu_time(conn.0)
                        };
                        if cpu_seconds > 0.0 {
                            cpu.store((cpu_seconds * 1_000_000.0) as u64, Ordering::Relaxed);
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
