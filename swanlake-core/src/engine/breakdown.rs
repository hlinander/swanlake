//! Reads a statement's profiling tree as a usage-record breakdown.

use std::ffi::CStr;

use libduckdb_sys as ffi;

use crate::usage::BreakdownNode;

/// The profiling tree of the connection's latest statement, or `None` where
/// the engine holds no tree: after a statement that failed in parsing or
/// binding, when no statement started, and while profiling is off.
///
/// # Safety
///
/// `native` must be a live connection that no other thread runs a statement
/// on for the duration of the call. The holder of the connection guard
/// satisfies both.
pub(super) unsafe fn read(native: ffi::duckdb_connection) -> Option<BreakdownNode> {
    // SAFETY: the caller passes a live connection.
    let root = unsafe { ffi::duckdb_get_profiling_info(native) };
    if root.is_null() {
        return None;
    }
    // SAFETY: `root` is a node of the tree the connection owns, and the
    // caller keeps that tree unchanged.
    Some(unsafe { node(root) })
}

/// # Safety
///
/// `info` must be a non-null node of a profiling tree that stays unchanged
/// for the duration of the call.
unsafe fn node(info: ffi::duckdb_profiling_info) -> BreakdownNode {
    let mut out = BreakdownNode {
        operator_type: String::new(),
        operator_name: String::new(),
        operator_cpu_time: 0.0,
        operator_timing: 0.0,
        operator_cardinality: 0,
        operator_bytes_read: 0,
        operator_bytes_written: 0,
        children: Vec::new(),
    };
    // SAFETY: `info` is a live node. The map and each key and value taken
    // from it are destroyed below.
    unsafe {
        let mut metrics = ffi::duckdb_profiling_info_get_metrics(info);
        if !metrics.is_null() {
            for index in 0..ffi::duckdb_get_map_size(metrics) {
                let mut key = ffi::duckdb_get_map_key(metrics, index);
                let mut value = ffi::duckdb_get_map_value(metrics, index);
                if let (Some(key), Some(value)) = (varchar(key), varchar(value)) {
                    match key.as_str() {
                        "OPERATOR_TYPE" => out.operator_type = value,
                        "OPERATOR_NAME" => out.operator_name = value,
                        "OPERATOR_CPU_TIME" => out.operator_cpu_time = number(&value),
                        "OPERATOR_TIMING" => out.operator_timing = number(&value),
                        "OPERATOR_CARDINALITY" => out.operator_cardinality = number(&value),
                        "OPERATOR_BYTES_READ" => out.operator_bytes_read = number(&value),
                        "OPERATOR_BYTES_WRITTEN" => out.operator_bytes_written = number(&value),
                        _ => {}
                    }
                }
                ffi::duckdb_destroy_value(&mut key);
                ffi::duckdb_destroy_value(&mut value);
            }
            ffi::duckdb_destroy_value(&mut metrics);
        }
        for index in 0..ffi::duckdb_profiling_info_get_child_count(info) {
            let child = ffi::duckdb_profiling_info_get_child(info, index);
            if !child.is_null() {
                out.children.push(node(child));
            }
        }
    }
    out
}

/// The text of a value, or `None` for a null value.
///
/// # Safety
///
/// `value` must be null or a live value.
unsafe fn varchar(value: ffi::duckdb_value) -> Option<String> {
    if value.is_null() {
        return None;
    }
    // SAFETY: `value` is live, and the returned text is freed below.
    unsafe {
        let text = ffi::duckdb_get_varchar(value);
        if text.is_null() {
            return None;
        }
        let owned = CStr::from_ptr(text).to_string_lossy().into_owned();
        ffi::duckdb_free(text.cast());
        Some(owned)
    }
}

/// A metric's number, or the type's zero for a text that is not one.
fn number<T: std::str::FromStr + Default>(text: &str) -> T {
    text.trim().parse().unwrap_or_default()
}
