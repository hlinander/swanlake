//! Resource tracking for running queries.
//!
//! Samples DuckDB memory usage on a background thread,
//! providing peak and current memory metrics that can be streamed
//! to Flight clients alongside query progress.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use tracing::{trace, warn};

/// Snapshot of resource usage at a point in time.
#[derive(Debug, Clone, Copy)]
pub struct ResourceSnapshot {
    pub peak_memory_bytes: u64,
    pub current_memory_bytes: u64,
    pub cpu_time_us: u64,
}

/// Tracks memory usage of a running DuckDB query by polling on a background thread.
///
/// Uses a **separate** connection to the same database (created via `try_clone()`)
/// to run `SELECT duckdb_memory()` every ~100ms. Memory usage is database-wide
/// so any connection to the same database reports the same value.
pub struct ResourceTracker {
    peak_memory_bytes: Arc<AtomicU64>,
    current_memory_bytes: Arc<AtomicU64>,
    cpu_time_us: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    sampler_handle: Option<thread::JoinHandle<()>>,
}

impl ResourceTracker {
    /// Start sampling memory usage on a background thread.
    ///
    /// `monitoring_conn` must be a **separate** connection to the same database
    /// (created via `Connection::try_clone()`). The sampler runs until the
    /// tracker is dropped.
    pub fn start(monitoring_conn: duckdb::Connection) -> Self {
        let peak_memory_bytes = Arc::new(AtomicU64::new(0));
        let current_memory_bytes = Arc::new(AtomicU64::new(0));
        let cpu_time_us = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));

        let peak = Arc::clone(&peak_memory_bytes);
        let current = Arc::clone(&current_memory_bytes);
        let stop_flag = Arc::clone(&stop);

        let sampler_handle = thread::Builder::new()
            .name("resource-sampler".into())
            .spawn(move || {
                let mut warned = false;

                while !stop_flag.load(Ordering::Relaxed) {
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
