//! Test support: runs a request against a queue and reads its record back.

use std::sync::Arc;

use serde_json::Value;

use super::{RequestAccounting, UsageQueue};
use crate::metrics::Metrics;
use crate::session::SessionAuth;

/// A queue no task drains, so a test reads what requests pushed.
pub(crate) fn queue() -> UsageQueue {
    UsageQueue::new(Metrics::new(100, 8))
}

/// The accounting of one request of an authenticated session, which queues
/// its record on `queue`.
pub(crate) fn accounting(endpoint: &str, queue: &UsageQueue) -> Arc<RequestAccounting> {
    let auth = SessionAuth {
        subject: "subject-1".to_owned(),
        project_id: "project-1".to_owned(),
        writer: true,
    };
    Arc::new(RequestAccounting::new(
        endpoint,
        Some(&auth),
        Some(queue.clone()),
    ))
}

/// The records on `queue`, in the order their requests ended.
pub(crate) fn records(queue: &UsageQueue) -> Vec<Value> {
    queue
        .snapshot()
        .iter()
        .map(|bytes| serde_json::from_slice(bytes).expect("a record is JSON"))
        .collect()
}

/// Runs `request` under one accounting and returns the record it queued, or
/// `None` for a request that recorded no entry.
pub(crate) fn record_of<T>(request: impl FnOnce(&RequestAccounting) -> T) -> (T, Option<Value>) {
    let queue = queue();
    let accounting = accounting("DoGet", &queue);
    let outcome = request(&accounting);
    drop(accounting);
    let mut records = records(&queue);
    assert!(records.len() <= 1, "one request queues at most one record");
    (outcome, records.pop())
}

/// Each entry's provenance and `abandoned` flag, in `attempt_id` order.
pub(crate) fn attempts(record: &Value) -> Vec<(String, bool)> {
    record["entries"]
        .as_array()
        .expect("a record carries entries")
        .iter()
        .enumerate()
        .map(|(index, entry)| {
            assert_eq!(entry["attempt_id"], index as u64, "attempt ids count from 0");
            (
                entry["provenance"].as_str().expect("provenance").to_owned(),
                entry["abandoned"].as_bool().expect("abandoned"),
            )
        })
        .collect()
}
