//! Per-request usage records: the figures of each measured attempt of a
//! request, the record that carries them, and its delivery to the duckvis API.
//!
//! [`RequestAccounting`] collects one request's entries. When its last owner
//! drops it, it serializes one record and pushes it onto the process's
//! [`UsageQueue`], which one background task drains with
//! `POST {api}/v1/usage/requests`.
//!
//! Nothing here blocks a request or writes to disk. A record the queue cannot
//! hold or the API refuses is dropped and counted in
//! [`crate::metrics::Metrics`], so a failure reports less than a statement
//! used and never more.

mod accounting;
mod queue;
mod record;

pub use accounting::{
    BreakdownNode, Entry, ExecutionLabel, Progress, ProgressFigures, RequestAccounting,
    ResourceTotals, UsageTotals,
};
pub use queue::{spawn_delivery, UsageQueue, MAX_QUEUE_BYTES};
pub use record::{MAX_RECORD_BYTES, MAX_SQL_BYTES};
