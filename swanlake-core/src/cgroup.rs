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

/// Parse `/proc/meminfo` content and compute a memory limit as
/// `(MemTotal - 10 GB) + SwapTotal`. Returns `None` when either field is
/// missing or the result would be non-positive.
fn compute_memory_limit_from_meminfo_content(content: &str) -> Option<u64> {
    const KB: u64 = 1024;
    const TEN_GB: u64 = 10 * 1024 * 1024 * 1024;

    let mut mem_total: Option<u64> = None;
    let mut swap_total: Option<u64> = None;

    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            mem_total = parse_meminfo_kb(rest);
        } else if let Some(rest) = line.strip_prefix("SwapTotal:") {
            swap_total = parse_meminfo_kb(rest);
        }
        if mem_total.is_some() && swap_total.is_some() {
            break;
        }
    }

    let mem_bytes = mem_total? * KB;
    let swap_bytes = swap_total? * KB;

    if mem_bytes <= TEN_GB {
        debug!("meminfo: MemTotal ({} bytes) <= 10 GB, skipping", mem_bytes);
        return None;
    }

    let limit = (mem_bytes - TEN_GB) + swap_bytes;
    Some(limit)
}

/// Parse a value like `" 16384000 kB"` → `Some(16384000)`.
fn parse_meminfo_kb(value: &str) -> Option<u64> {
    value.split_whitespace().next()?.parse::<u64>().ok()
}

/// Read `/proc/meminfo` and compute a DuckDB memory limit from system RAM and
/// swap using the formula `(MemTotal - 10 GB) + SwapTotal`.
///
/// Returns `None` on non-Linux, parse failure, or when MemTotal ≤ 10 GB.
pub fn compute_memory_limit_from_meminfo() -> Option<u64> {
    let content = match fs::read_to_string("/proc/meminfo") {
        Ok(c) => c,
        Err(e) => {
            debug!("failed to read /proc/meminfo: {}", e);
            return None;
        }
    };
    let limit = compute_memory_limit_from_meminfo_content(&content)?;
    debug!("meminfo memory limit: {} bytes", limit);
    Some(limit)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_memory_limit_from_meminfo_content() {
        // 64 GB RAM, 32 GB swap → (64 - 10) + 32 = 86 GB
        let content = "\
MemTotal:       67108864 kB
MemFree:        10000000 kB
SwapTotal:      33554432 kB
SwapFree:       33554432 kB
";
        let limit = compute_memory_limit_from_meminfo_content(content).unwrap();
        let expected = (64 - 10 + 32) * 1024 * 1024 * 1024_u64;
        assert_eq!(limit, expected);
    }

    #[test]
    fn test_meminfo_too_little_ram() {
        // 8 GB RAM (≤ 10 GB) → None
        let content = "\
MemTotal:        8388608 kB
SwapTotal:       4194304 kB
";
        assert!(compute_memory_limit_from_meminfo_content(content).is_none());
    }

    #[test]
    fn test_meminfo_missing_fields() {
        let content = "MemTotal:       67108864 kB\n";
        assert!(compute_memory_limit_from_meminfo_content(content).is_none());
    }

    #[test]
    fn test_format_bytes_for_duckdb() {
        assert_eq!(format_bytes_for_duckdb(1024 * 1024 * 1024), "1GB");
        assert_eq!(format_bytes_for_duckdb(2 * 1024 * 1024 * 1024), "2GB");
        assert_eq!(format_bytes_for_duckdb(512 * 1024 * 1024), "512MB");
        assert_eq!(format_bytes_for_duckdb(1536 * 1024 * 1024), "1536MB"); // 1.5GB
        assert_eq!(format_bytes_for_duckdb(100 * 1024 * 1024), "100MB");
    }
}
