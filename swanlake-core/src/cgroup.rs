//! Utilities for reading cgroup resource limits.
//!
//! This module provides functions to read resource limits from Linux cgroups,
//! particularly useful when running under systemd-run with resource constraints.

use std::fs;
use std::path::PathBuf;

use tracing::{debug, warn};

/// Get the memory limit from the current process's cgroup.
///
/// For cgroup v2 (unified hierarchy), reads from `memory.max`.
/// Returns `None` if:
/// - Not running on Linux
/// - Unable to determine cgroup path
/// - Memory limit is "max" (unlimited)
/// - Any I/O error occurs
pub fn get_cgroup_memory_limit() -> Option<u64> {
    // Read the cgroup path from /proc/self/cgroup
    let cgroup_content = match fs::read_to_string("/proc/self/cgroup") {
        Ok(content) => content,
        Err(e) => {
            debug!("failed to read /proc/self/cgroup: {}", e);
            return None;
        }
    };

    // For cgroup v2, the format is "0::<path>"
    let cgroup_path = cgroup_content
        .lines()
        .find(|line| line.starts_with("0::"))
        .map(|line| line.trim_start_matches("0::"))?;

    debug!("cgroup path: {}", cgroup_path);

    // Build the full path to memory.max
    let memory_max_path: PathBuf = ["/sys/fs/cgroup", cgroup_path.trim_start_matches('/'), "memory.max"]
        .iter()
        .collect();

    debug!("reading memory limit from: {:?}", memory_max_path);

    // Read the memory limit
    let memory_max = match fs::read_to_string(&memory_max_path) {
        Ok(content) => content.trim().to_string(),
        Err(e) => {
            debug!("failed to read {:?}: {}", memory_max_path, e);
            return None;
        }
    };

    // "max" means unlimited
    if memory_max == "max" {
        debug!("cgroup memory limit is unlimited");
        return None;
    }

    // Parse the value (in bytes)
    match memory_max.parse::<u64>() {
        Ok(bytes) => {
            debug!("cgroup memory limit: {} bytes", bytes);
            Some(bytes)
        }
        Err(e) => {
            warn!("failed to parse memory limit '{}': {}", memory_max, e);
            None
        }
    }
}

/// Format bytes as a human-readable string suitable for DuckDB's memory_limit setting.
///
/// Returns values like "1GB", "512MB", etc.
pub fn format_bytes_for_duckdb(bytes: u64) -> String {
    const GB: u64 = 1024 * 1024 * 1024;
    const MB: u64 = 1024 * 1024;

    if bytes >= GB && bytes % GB == 0 {
        format!("{}GB", bytes / GB)
    } else if bytes >= MB {
        // Use MB for anything >= 1MB, rounding down
        format!("{}MB", bytes / MB)
    } else {
        // For smaller values, just use bytes
        format!("{}B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_bytes_for_duckdb() {
        assert_eq!(format_bytes_for_duckdb(1024 * 1024 * 1024), "1GB");
        assert_eq!(format_bytes_for_duckdb(2 * 1024 * 1024 * 1024), "2GB");
        assert_eq!(format_bytes_for_duckdb(512 * 1024 * 1024), "512MB");
        assert_eq!(format_bytes_for_duckdb(1536 * 1024 * 1024), "1536MB"); // 1.5GB
        assert_eq!(format_bytes_for_duckdb(100 * 1024 * 1024), "100MB");
    }
}
