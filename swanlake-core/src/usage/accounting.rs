//! Request accounting: one request's identity, its entries, and its progress
//! figures, from admission until its record is queued.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use serde::Serialize;
use uuid::Uuid;

use super::queue::UsageQueue;
use super::record::{self, RecordParts, SqlText};
use crate::session::SessionAuth;

/// The cumulative CPU and IO figures of one connection or one database.
/// Mirrors `duckdb_usage_totals`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct UsageTotals {
    pub cpu_ns: u64,
    pub bytes_read: u64,
    pub bytes_written: u64,
    /// The part of `bytes_read` the engine read from local files.
    pub file_bytes_read: u64,
    /// The part of `bytes_read` the engine's HTTP client read.
    pub http_bytes_read: u64,
}

/// One read of a connection's totals, its database's totals, and that
/// database's memory marks. Mirrors `duckdb_resource_totals`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ResourceTotals {
    pub connection: UsageTotals,
    pub database: UsageTotals,
    /// The floor of the buffer pool's level.
    pub memory_bytes: u64,
    /// The largest floor since the bracket opened.
    pub memory_peak_bytes: u64,
    /// The integral of the floor over time, truncated to 64 bits.
    pub memory_byte_ms: u64,
}

/// The execution label of an attempt, which an entry reports as its
/// `provenance`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum ExecutionLabel {
    /// Label 0: a statement SwanLake adds to serve a request.
    #[serde(rename = "SWANLAKE")]
    SwanLake,
    /// Label 1: the work a request exists to perform.
    #[serde(rename = "CLIENT")]
    Client,
}

/// One node of a statement's profiling tree.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct BreakdownNode {
    pub operator_type: String,
    pub operator_name: String,
    /// `OPERATOR_CPU_TIME`, in seconds. A time that is not finite
    /// serializes as 0.
    #[serde(serialize_with = "finite_or_zero")]
    pub operator_cpu_time: f64,
    /// `OPERATOR_TIMING`, in seconds. A time that is not finite serializes
    /// as 0.
    #[serde(serialize_with = "finite_or_zero")]
    pub operator_timing: f64,
    pub operator_cardinality: u64,
    pub operator_bytes_read: u64,
    pub operator_bytes_written: u64,
    pub children: Vec<BreakdownNode>,
}

impl BreakdownNode {
    /// Whether the tree has more than `levels` levels, its root being the
    /// first.
    fn is_deeper_than(&self, levels: usize) -> bool {
        let mut unvisited = vec![(self, 1_usize)];
        while let Some((node, level)) = unvisited.pop() {
            if level > levels {
                return true;
            }
            unvisited.extend(node.children.iter().map(|child| (child, level + 1)));
        }
        false
    }
}

/// Serializes a breakdown time, with 0 in place of a NaN or an infinity,
/// which JSON cannot carry as a number.
fn finite_or_zero<S: serde::Serializer>(seconds: &f64, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_f64(if seconds.is_finite() { *seconds } else { 0.0 })
}

/// The figures of one attempt.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Entry {
    pub attempt_id: u64,
    pub provenance: ExecutionLabel,
    /// The database's CPU between the attempt's two reads.
    pub cpu_seconds: f64,
    pub bytes_read: u64,
    /// The part of `bytes_read` read from local files.
    pub file_bytes_read: u64,
    /// The part of `bytes_read` read through the engine's HTTP client. The
    /// remainder of `bytes_read` after both parts is Postgres traffic.
    pub http_bytes_read: u64,
    pub bytes_written: u64,
    /// The connection's part of `cpu_seconds`.
    pub connection_cpu_seconds: f64,
    pub connection_bytes_read: u64,
    pub connection_file_bytes_read: u64,
    pub connection_http_bytes_read: u64,
    pub connection_bytes_written: u64,
    pub memory_peak_bytes: u64,
    pub memory_byte_seconds: f64,
    pub memory_open_bytes: u64,
    pub abandoned: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub breakdown: Option<BreakdownNode>,
}

impl Entry {
    /// Derives an attempt's figures from its bracket's two reads.
    ///
    /// The totals never decrease, so each CPU and IO difference saturates at
    /// zero: a closing value below its opening value reports nothing. The
    /// memory integral is truncated to 64 bits by the engine, so its
    /// difference wraps.
    fn from_reads(
        attempt_id: u64,
        label: ExecutionLabel,
        opening: &ResourceTotals,
        closing: &ResourceTotals,
        abandoned: bool,
        breakdown: Option<BreakdownNode>,
    ) -> Self {
        let database = difference(&opening.database, &closing.database);
        let connection = difference(&opening.connection, &closing.connection);
        let memory_byte_ms = closing.memory_byte_ms.wrapping_sub(opening.memory_byte_ms);
        Self {
            attempt_id,
            provenance: label,
            cpu_seconds: seconds_from_ns(database.cpu_ns),
            bytes_read: database.bytes_read,
            file_bytes_read: database.file_bytes_read,
            http_bytes_read: database.http_bytes_read,
            bytes_written: database.bytes_written,
            connection_cpu_seconds: seconds_from_ns(connection.cpu_ns),
            connection_bytes_read: connection.bytes_read,
            connection_file_bytes_read: connection.file_bytes_read,
            connection_http_bytes_read: connection.http_bytes_read,
            connection_bytes_written: connection.bytes_written,
            memory_peak_bytes: closing.memory_peak_bytes,
            memory_byte_seconds: memory_byte_ms as f64 / 1_000.0,
            memory_open_bytes: opening.memory_bytes,
            abandoned,
            breakdown,
        }
    }
}

fn difference(opening: &UsageTotals, closing: &UsageTotals) -> UsageTotals {
    UsageTotals {
        cpu_ns: closing.cpu_ns.saturating_sub(opening.cpu_ns),
        bytes_read: closing.bytes_read.saturating_sub(opening.bytes_read),
        bytes_written: closing.bytes_written.saturating_sub(opening.bytes_written),
        file_bytes_read: closing
            .file_bytes_read
            .saturating_sub(opening.file_bytes_read),
        http_bytes_read: closing
            .http_bytes_read
            .saturating_sub(opening.http_bytes_read),
    }
}

fn seconds_from_ns(ns: u64) -> f64 {
    ns as f64 / 1_000_000_000.0
}

/// The progress figures of a request's label-1 attempts.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProgressFigures {
    /// The database's CPU, summed over the attempts that have closed.
    pub closed_cpu_ns: u64,
    /// The largest `memory_peak_bytes` among the attempts that have closed.
    pub closed_peak_bytes: u64,
    /// The opening read of the attempt that is open.
    pub open: Option<ResourceTotals>,
}

impl ProgressFigures {
    /// The request's CPU so far: the closed attempts' sum, plus the
    /// database's CPU since the open attempt's opening read when `current` is
    /// a read taken while that attempt is open.
    pub fn cpu_ns(&self, current: Option<&ResourceTotals>) -> u64 {
        let open_cpu_ns = match (self.open.as_ref(), current) {
            (Some(open), Some(current)) => {
                current.database.cpu_ns.saturating_sub(open.database.cpu_ns)
            }
            _ => 0,
        };
        self.closed_cpu_ns.saturating_add(open_cpu_ns)
    }
}

/// A request's progress figures, shared between the request's accounting,
/// which writes them, and readers that outlive it. Clones share one value.
#[derive(Debug, Clone, Default)]
pub struct Progress(Arc<Mutex<ProgressFigures>>);

impl Progress {
    /// The figures as of this call.
    pub fn figures(&self) -> ProgressFigures {
        *self.lock()
    }

    fn lock(&self) -> MutexGuard<'_, ProgressFigures> {
        self.0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Where a request's record goes, and the attribution it carries.
struct Destination {
    project_id: String,
    subject: String,
    queue: UsageQueue,
}

/// The bounds on what a request's accounting stores while the request runs.
#[derive(Debug, Clone, Copy)]
struct Limits {
    /// Most levels a stored breakdown has.
    breakdown_levels: usize,
    /// Largest size of the stored entries at which an entry keeps its
    /// breakdown.
    entries_bytes_with_breakdown: usize,
    /// Largest size of the stored entries.
    entries_bytes: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            breakdown_levels: record::MAX_BREAKDOWN_LEVELS,
            entries_bytes_with_breakdown: record::MAX_ENTRIES_BYTES_WITH_BREAKDOWN,
            entries_bytes: record::MAX_ENTRIES_BYTES,
        }
    }
}

#[derive(Default)]
struct State {
    next_attempt_id: u64,
    entries: Vec<Entry>,
    /// The serialized size of `entries`, as an estimate: each entry's JSON
    /// and one separator.
    entries_bytes: usize,
    /// Set when an entry was stored without the breakdown its attempt had.
    breakdown_omitted: bool,
    /// Set when an entry would have taken `entries` past its bound. No entry
    /// is stored from then on, and the request produces no record.
    overflowed: bool,
    sql: Option<SqlText>,
    error_type: Option<&'static str>,
}

/// One request's identity, entries, and progress figures.
///
/// The request's owners share it in an `Arc`. When the last owner drops it,
/// it serializes the request's record and pushes it onto the queue. A request
/// with no entry, a session without duckvis authentication, and a process
/// without a queue produce no record.
///
/// A request can run any number of statements, so the accounting bounds what
/// it stores: an entry loses its breakdown when the breakdown is deeper than
/// [`record::MAX_BREAKDOWN_LEVELS`] or would take the entries past
/// [`record::MAX_ENTRIES_BYTES_WITH_BREAKDOWN`], and no entry is stored once
/// one would take them past [`record::MAX_ENTRIES_BYTES`]. Such a request's
/// record is discarded when the request ends and counted as oversized.
pub struct RequestAccounting {
    request_id: Uuid,
    endpoint: String,
    destination: Option<Destination>,
    limits: Limits,
    state: Mutex<State>,
    progress: Progress,
    /// The bytes of the Flight data messages sent to the client so far.
    response_bytes: AtomicU64,
}

impl RequestAccounting {
    /// Creates the accounting of one request and assigns its `request_id`, a
    /// UUIDv7 of the current time.
    ///
    /// `endpoint` names the Flight RPC that carries the request. `auth` is
    /// the session's duckvis binding and `queue` the process's delivery
    /// queue; the request produces a record only when both are present.
    pub fn new(
        endpoint: impl Into<String>,
        auth: Option<&SessionAuth>,
        queue: Option<UsageQueue>,
    ) -> Self {
        let destination = match (auth, queue) {
            (Some(auth), Some(queue)) => Some(Destination {
                project_id: auth.project_id.clone(),
                subject: auth.subject.clone(),
                queue,
            }),
            _ => None,
        };
        Self {
            request_id: Uuid::now_v7(),
            endpoint: endpoint.into(),
            destination,
            limits: Limits::default(),
            state: Mutex::new(State::default()),
            progress: Progress::default(),
            response_bytes: AtomicU64::new(0),
        }
    }

    #[cfg(test)]
    fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    pub fn request_id(&self) -> Uuid {
        self.request_id
    }

    /// Records the SQL text the client sent. The first text set is the
    /// request's; later calls change nothing. An empty text sets nothing,
    /// so a later text is still the first.
    pub fn set_sql(&self, sql: &str) {
        if self.destination.is_none() || sql.is_empty() {
            return;
        }
        // The redaction scan runs outside the lock.
        if self.state().sql.is_some() {
            return;
        }
        let captured = SqlText::capture(sql);
        self.state().sql.get_or_insert(captured);
    }

    /// Records the DuckDB error type of the failure that failed the request
    /// in the engine. The record carries the type's name. The first type set
    /// is the request's; later calls change nothing. A value that is no
    /// constant of `duckdb_error_type` sets nothing.
    pub fn set_error_type(&self, error_type: libduckdb_sys::duckdb_error_type) {
        if let Some(name) = record::error_type_name(error_type) {
            self.state().error_type.get_or_insert(name);
        }
    }

    /// Adds the bytes of one Flight data message sent to the client: its
    /// header, body, and application metadata. The record reports the sum as
    /// `response_bytes`.
    pub fn add_response_bytes(&self, bytes: u64) {
        self.response_bytes.fetch_add(bytes, Ordering::Relaxed);
    }

    /// Records the opening read of an attempt. A label-1 attempt becomes the
    /// open attempt of the progress figures.
    pub fn attempt_opened(&self, label: ExecutionLabel, opening: &ResourceTotals) {
        if label == ExecutionLabel::Client {
            self.progress.lock().open = Some(*opening);
        }
    }

    /// Records the entry of an attempt that has closed, from its bracket's
    /// two reads, and returns the `attempt_id` it assigns. Attempt ids count
    /// from 0 in the order of the calls. A label-1 attempt enters the
    /// progress figures and is no longer the open attempt.
    ///
    /// The entry is stored within the bounds the type describes. An attempt
    /// whose entry is not stored still receives its `attempt_id` and still
    /// enters the progress figures.
    pub fn push_entry(
        &self,
        label: ExecutionLabel,
        opening: &ResourceTotals,
        closing: &ResourceTotals,
        abandoned: bool,
        breakdown: Option<BreakdownNode>,
    ) -> u64 {
        let mut breakdown = breakdown.filter(|_| self.destination.is_some());
        let mut breakdown_omitted = false;
        let mut breakdown_bytes = 0;
        // No breakdown is stored once the record has overflowed, or once the
        // stored entries have reached the bound for entries with breakdowns:
        // the stored size never falls, and a breakdown adds to it. Such a
        // breakdown is dropped without being measured.
        let storable = breakdown.is_some() && {
            let state = self.state();
            !state.overflowed && state.entries_bytes < self.limits.entries_bytes_with_breakdown
        };
        if breakdown.is_some() && !storable {
            breakdown = None;
            breakdown_omitted = true;
        }
        // A breakdown that can be stored is measured outside the lock.
        if let Some(root) = &breakdown {
            if root.is_deeper_than(self.limits.breakdown_levels) {
                breakdown = None;
                breakdown_omitted = true;
            } else {
                breakdown_bytes = record::BREAKDOWN_MEMBER_BYTES + record::serialized_len(root);
            }
        }

        let mut state = self.state();
        let attempt_id = state.next_attempt_id;
        state.next_attempt_id += 1;
        if label == ExecutionLabel::Client {
            let cpu_ns = closing
                .database
                .cpu_ns
                .saturating_sub(opening.database.cpu_ns);
            let mut progress = self.progress.lock();
            progress.closed_cpu_ns = progress.closed_cpu_ns.saturating_add(cpu_ns);
            progress.closed_peak_bytes = progress.closed_peak_bytes.max(closing.memory_peak_bytes);
            progress.open = None;
        }
        if self.destination.is_some() && !state.overflowed {
            let mut entry = Entry::from_reads(attempt_id, label, opening, closing, abandoned, None);
            // The entry and the separator ahead of the next one.
            let bare_bytes = record::serialized_len(&entry) + 1;
            let with_breakdown = state
                .entries_bytes
                .saturating_add(bare_bytes)
                .saturating_add(breakdown_bytes);
            if breakdown.is_some() && with_breakdown > self.limits.entries_bytes_with_breakdown {
                breakdown = None;
                breakdown_omitted = true;
                breakdown_bytes = 0;
            }
            let entries_bytes = state
                .entries_bytes
                .saturating_add(bare_bytes)
                .saturating_add(breakdown_bytes);
            if entries_bytes > self.limits.entries_bytes {
                // The record is discarded when the request ends, so the
                // entries stored so far are released here.
                state.overflowed = true;
                state.entries = Vec::new();
                state.entries_bytes = 0;
            } else {
                entry.breakdown = breakdown;
                state.entries.push(entry);
                state.entries_bytes = entries_bytes;
                state.breakdown_omitted |= breakdown_omitted;
            }
        }
        attempt_id
    }

    /// The progress figures of the request's label-1 attempts. The handle
    /// stays readable after the accounting is dropped.
    pub fn progress(&self) -> Progress {
        self.progress.clone()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Drop for RequestAccounting {
    fn drop(&mut self) {
        let Some(destination) = self.destination.take() else {
            return;
        };
        let state = std::mem::take(
            self.state
                .get_mut()
                .unwrap_or_else(|poisoned| poisoned.into_inner()),
        );
        if state.overflowed {
            destination.queue.accept(record::Serialized::Oversized);
            return;
        }
        if state.entries.is_empty() {
            return;
        }
        let sql = state.sql.unwrap_or_default();
        destination.queue.accept(record::serialize(RecordParts {
            request_id: self.request_id,
            project_id: &destination.project_id,
            subject: &destination.subject,
            endpoint: &self.endpoint,
            sql: &sql,
            ended_at: chrono::Utc::now(),
            error_type: state.error_type,
            breakdown_omitted: state.breakdown_omitted,
            response_bytes: *self.response_bytes.get_mut(),
            entries: state.entries,
        }));
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use serde_json::{json, Value};

    use super::*;
    use crate::metrics::Metrics;

    fn auth() -> SessionAuth {
        SessionAuth {
            subject: "subject-1".to_owned(),
            project_id: "project-1".to_owned(),
            writer: true,
        }
    }

    fn queue() -> (UsageQueue, Metrics) {
        let metrics = Metrics::new(100, 8);
        (UsageQueue::new(metrics.clone()), metrics)
    }

    fn totals(database_cpu_ns: u64, peak: u64) -> ResourceTotals {
        ResourceTotals {
            database: UsageTotals {
                cpu_ns: database_cpu_ns,
                ..UsageTotals::default()
            },
            memory_peak_bytes: peak,
            ..ResourceTotals::default()
        }
    }

    fn queued(queue: &UsageQueue) -> Vec<Value> {
        queue
            .snapshot()
            .iter()
            .map(|bytes| serde_json::from_slice(bytes).expect("record is JSON"))
            .collect()
    }

    #[test]
    fn differences_follow_the_derivation_table() {
        let opening = ResourceTotals {
            connection: UsageTotals {
                cpu_ns: 1_000_000_000,
                bytes_read: 100,
                bytes_written: 10,
                file_bytes_read: 40,
                http_bytes_read: 20,
            },
            database: UsageTotals {
                cpu_ns: 5_000_000_000,
                bytes_read: 1_000,
                bytes_written: 500,
                file_bytes_read: 400,
                http_bytes_read: 200,
            },
            memory_bytes: 4_096,
            memory_peak_bytes: 4_096,
            memory_byte_ms: 7_000,
        };
        let closing = ResourceTotals {
            connection: UsageTotals {
                cpu_ns: 1_750_000_000,
                bytes_read: 164,
                bytes_written: 42,
                file_bytes_read: 70,
                http_bytes_read: 45,
            },
            database: UsageTotals {
                cpu_ns: 7_500_000_000,
                bytes_read: 3_000,
                bytes_written: 800,
                file_bytes_read: 1_600,
                http_bytes_read: 900,
            },
            memory_bytes: 8_192,
            memory_peak_bytes: 65_536,
            memory_byte_ms: 9_500,
        };

        let entry = Entry::from_reads(3, ExecutionLabel::Client, &opening, &closing, true, None);

        assert_eq!(
            entry,
            Entry {
                attempt_id: 3,
                provenance: ExecutionLabel::Client,
                cpu_seconds: 2.5,
                bytes_read: 2_000,
                file_bytes_read: 1_200,
                http_bytes_read: 700,
                bytes_written: 300,
                connection_cpu_seconds: 0.75,
                connection_bytes_read: 64,
                connection_file_bytes_read: 30,
                connection_http_bytes_read: 25,
                connection_bytes_written: 32,
                memory_peak_bytes: 65_536,
                memory_byte_seconds: 2.5,
                memory_open_bytes: 4_096,
                abandoned: true,
                breakdown: None,
            }
        );
    }

    #[test]
    fn memory_integral_difference_wraps() {
        let opening = ResourceTotals {
            memory_byte_ms: u64::MAX - 499,
            ..ResourceTotals::default()
        };
        let closing = ResourceTotals {
            memory_byte_ms: 1_500,
            ..ResourceTotals::default()
        };

        let entry = Entry::from_reads(0, ExecutionLabel::Client, &opening, &closing, false, None);

        assert_eq!(entry.memory_byte_seconds, 2.0);
    }

    #[test]
    fn a_total_that_decreases_reports_nothing() {
        let opening = ResourceTotals {
            connection: UsageTotals {
                cpu_ns: 9,
                bytes_read: 9,
                bytes_written: 9,
                file_bytes_read: 9,
                http_bytes_read: 9,
            },
            database: UsageTotals {
                cpu_ns: 9,
                bytes_read: 9,
                bytes_written: 9,
                file_bytes_read: 9,
                http_bytes_read: 9,
            },
            ..ResourceTotals::default()
        };

        let entry = Entry::from_reads(
            0,
            ExecutionLabel::Client,
            &opening,
            &ResourceTotals::default(),
            false,
            None,
        );

        assert_eq!(entry.cpu_seconds, 0.0);
        assert_eq!(entry.connection_cpu_seconds, 0.0);
        assert_eq!(entry.bytes_read, 0);
        assert_eq!(entry.bytes_written, 0);
        assert_eq!(entry.connection_bytes_read, 0);
        assert_eq!(entry.connection_bytes_written, 0);
        assert_eq!(entry.file_bytes_read, 0);
        assert_eq!(entry.http_bytes_read, 0);
        assert_eq!(entry.connection_file_bytes_read, 0);
        assert_eq!(entry.connection_http_bytes_read, 0);
    }

    #[test]
    fn request_ids_are_distinct_version_7() {
        let first = RequestAccounting::new("DoGet", None, None);
        let second = RequestAccounting::new("DoGet", None, None);

        assert_eq!(first.request_id().get_version_num(), 7);
        assert_ne!(first.request_id(), second.request_id());
    }

    #[test]
    fn entries_carry_attempt_ids_in_push_order() {
        let (queue, _metrics) = queue();
        let accounting = RequestAccounting::new("DoPut", Some(&auth()), Some(queue.clone()));
        let request_id = accounting.request_id();
        accounting.set_sql("SELECT 1; SELECT 2");

        let ids = [
            accounting.push_entry(
                ExecutionLabel::SwanLake,
                &totals(0, 0),
                &totals(1_000_000_000, 10),
                false,
                None,
            ),
            accounting.push_entry(
                ExecutionLabel::Client,
                &totals(1_000_000_000, 0),
                &totals(3_000_000_000, 20),
                false,
                None,
            ),
            accounting.push_entry(
                ExecutionLabel::Client,
                &totals(3_000_000_000, 0),
                &totals(6_000_000_000, 30),
                true,
                None,
            ),
        ];
        assert_eq!(ids, [0, 1, 2]);
        assert!(queued(&queue).is_empty());

        drop(accounting);

        let records = queued(&queue);
        assert_eq!(records.len(), 1);
        let record = &records[0];
        assert_eq!(record["request_id"], json!(request_id.to_string()));
        assert_eq!(record["project_id"], json!("project-1"));
        assert_eq!(record["subject"], json!("subject-1"));
        assert_eq!(record["endpoint"], json!("DoPut"));
        assert_eq!(record["sql"], json!("SELECT 1; SELECT 2"));
        let entries = record["entries"].as_array().expect("entries");
        let seen = entries
            .iter()
            .map(|entry| {
                (
                    entry["attempt_id"].as_u64(),
                    entry["provenance"].as_str(),
                    entry["cpu_seconds"].as_f64(),
                )
            })
            .collect::<Vec<_>>();
        assert_eq!(
            seen,
            vec![
                (Some(0), Some("SWANLAKE"), Some(1.0)),
                (Some(1), Some("CLIENT"), Some(2.0)),
                (Some(2), Some("CLIENT"), Some(3.0)),
            ]
        );
    }

    #[test]
    fn the_record_is_queued_when_the_last_owner_drops() {
        let (queue, _metrics) = queue();
        let handler = Arc::new(RequestAccounting::new(
            "DoGet",
            Some(&auth()),
            Some(queue.clone()),
        ));
        let stream = Arc::clone(&handler);
        handler.push_entry(
            ExecutionLabel::Client,
            &totals(0, 0),
            &totals(1, 1),
            false,
            None,
        );

        drop(handler);
        assert!(queued(&queue).is_empty());
        drop(stream);
        assert_eq!(queued(&queue).len(), 1);
    }

    #[test]
    fn a_request_with_no_entry_produces_no_record() {
        let (queue, metrics) = queue();
        let accounting = RequestAccounting::new("DoGet", Some(&auth()), Some(queue.clone()));
        accounting.set_sql("SELECT 1");
        accounting.attempt_opened(ExecutionLabel::Client, &totals(0, 0));

        drop(accounting);

        assert!(queued(&queue).is_empty());
        let drops = metrics.snapshot().usage_records_dropped;
        assert_eq!(
            (drops.queue_full, drops.oversized, drops.refused),
            (0, 0, 0)
        );
    }

    #[test]
    fn a_session_without_duckvis_authentication_produces_no_record() {
        let (queue, _metrics) = queue();
        let accounting = RequestAccounting::new("DoGet", None, Some(queue.clone()));
        accounting.set_sql("SELECT 1");
        let attempt_id = accounting.push_entry(
            ExecutionLabel::Client,
            &totals(0, 0),
            &totals(5, 7),
            false,
            None,
        );

        // Attempt ids and progress figures do not depend on a destination.
        assert_eq!(attempt_id, 0);
        assert_eq!(accounting.progress().figures().closed_cpu_ns, 5);
        drop(accounting);
        assert!(queued(&queue).is_empty());
    }

    #[test]
    fn the_first_sql_text_is_kept() {
        let (queue, _metrics) = queue();
        let accounting = RequestAccounting::new("DoGet", Some(&auth()), Some(queue.clone()));
        accounting.set_sql("SELECT 1");
        accounting.set_sql("SELECT 2");
        accounting.push_entry(
            ExecutionLabel::Client,
            &totals(0, 0),
            &totals(1, 1),
            false,
            None,
        );

        drop(accounting);

        let records = queued(&queue);
        assert_eq!(records[0]["sql"], json!("SELECT 1"));
    }

    #[test]
    fn an_empty_sql_text_sets_nothing() {
        let (queue, _metrics) = queue();
        let push = |accounting: &RequestAccounting| {
            accounting.push_entry(
                ExecutionLabel::Client,
                &totals(0, 0),
                &totals(1, 1),
                false,
                None,
            );
        };

        // An empty text alone leaves the record without a text.
        let accounting = RequestAccounting::new("DoGet", Some(&auth()), Some(queue.clone()));
        accounting.set_sql("");
        push(&accounting);
        drop(accounting);

        // An empty text does not count as the first text.
        let accounting = RequestAccounting::new("DoGet", Some(&auth()), Some(queue.clone()));
        accounting.set_sql("");
        accounting.set_sql("SELECT 2");
        accounting.set_sql("SELECT 3");
        push(&accounting);
        drop(accounting);

        let records = queued(&queue);
        assert!(records[0].get("sql").is_none(), "{}", records[0]);
        assert_eq!(records[0]["sql_truncated"], json!(false));
        assert_eq!(records[0]["sql_redacted"], json!(false));
        assert_eq!(records[1]["sql"], json!("SELECT 2"));
    }

    #[test]
    fn the_record_carries_the_first_error_type_by_name() {
        use libduckdb_sys as ffi;

        let (queue, _metrics) = queue();
        let accounting = RequestAccounting::new("DoGet", Some(&auth()), Some(queue.clone()));
        accounting.set_error_type(ffi::duckdb_error_type_DUCKDB_ERROR_CONSTRAINT);
        accounting.set_error_type(ffi::duckdb_error_type_DUCKDB_ERROR_TRANSACTION);
        accounting.set_error_type(ffi::duckdb_error_type_DUCKDB_INVALID_CONFIGURATION);
        accounting.push_entry(
            ExecutionLabel::Client,
            &totals(0, 0),
            &totals(1, 1),
            false,
            None,
        );

        drop(accounting);

        assert_eq!(queued(&queue)[0]["error_type"], json!("CONSTRAINT"));
    }

    #[test]
    fn a_first_failure_of_invalid_configuration_is_kept() {
        use libduckdb_sys as ffi;

        let (queue, _metrics) = queue();
        let accounting = RequestAccounting::new("DoGet", Some(&auth()), Some(queue.clone()));
        accounting.set_error_type(ffi::duckdb_error_type_DUCKDB_INVALID_CONFIGURATION);
        accounting.set_error_type(ffi::duckdb_error_type_DUCKDB_ERROR_CONSTRAINT);
        accounting.push_entry(
            ExecutionLabel::Client,
            &totals(0, 0),
            &totals(1, 1),
            false,
            None,
        );

        drop(accounting);

        assert_eq!(
            queued(&queue)[0]["error_type"],
            json!("INVALID_CONFIGURATION")
        );
    }

    #[test]
    fn a_request_that_sets_no_error_type_omits_it() {
        let (queue, _metrics) = queue();
        let accounting = RequestAccounting::new("DoGet", Some(&auth()), Some(queue.clone()));
        accounting.push_entry(
            ExecutionLabel::Client,
            &totals(0, 0),
            &totals(1, 1),
            false,
            None,
        );

        drop(accounting);

        assert!(queued(&queue)[0].get("error_type").is_none());
    }

    #[test]
    fn ended_at_is_the_time_of_the_drop() {
        let (queue, _metrics) = queue();
        let accounting = RequestAccounting::new("DoGet", Some(&auth()), Some(queue.clone()));
        accounting.push_entry(
            ExecutionLabel::Client,
            &totals(0, 0),
            &totals(1, 1),
            false,
            None,
        );

        let before = chrono::Utc::now();
        drop(accounting);
        let after = chrono::Utc::now();

        let records = queued(&queue);
        let text = records[0]["ended_at"].as_str().expect("ended_at");
        // `YYYY-MM-DDTHH:MM:SS.mmmZ`
        assert_eq!(text.len(), 24);
        assert!(text.ends_with('Z'));
        let ended_at = chrono::DateTime::parse_from_rfc3339(text).expect("RFC 3339");
        assert!(ended_at >= before - chrono::Duration::milliseconds(1));
        assert!(ended_at <= after);
    }

    #[test]
    fn the_progress_handle_outlives_the_accounting() {
        let accounting = RequestAccounting::new("DoGet", None, None);
        let progress = accounting.progress();
        accounting.attempt_opened(ExecutionLabel::Client, &totals(10, 0));
        assert_eq!(progress.figures().open, Some(totals(10, 0)));
        accounting.push_entry(
            ExecutionLabel::Client,
            &totals(10, 0),
            &totals(40, 77),
            false,
            None,
        );

        drop(accounting);

        assert_eq!(
            progress.figures(),
            ProgressFigures {
                closed_cpu_ns: 30,
                closed_peak_bytes: 77,
                open: None,
            }
        );
    }

    #[test]
    fn an_oversized_record_is_counted_and_not_queued() {
        let (queue, metrics) = queue();
        let accounting = RequestAccounting::new("DoPut", Some(&auth()), Some(queue.clone()));
        for _ in 0..25_000 {
            accounting.push_entry(
                ExecutionLabel::Client,
                &totals(0, 0),
                &totals(1, 1),
                false,
                None,
            );
        }

        // The entries stored before the bound was passed are released.
        {
            let state = accounting.state();
            assert!(state.overflowed);
            assert!(state.entries.is_empty());
        }

        drop(accounting);

        assert!(queued(&queue).is_empty());
        assert_eq!(metrics.snapshot().usage_records_dropped.oversized, 1);
    }

    fn node(children: Vec<BreakdownNode>) -> BreakdownNode {
        BreakdownNode {
            operator_type: "PROJECTION".to_owned(),
            operator_name: "node".to_owned(),
            operator_cpu_time: 0.25,
            operator_timing: 0.5,
            operator_cardinality: 7,
            operator_bytes_read: 8,
            operator_bytes_written: 9,
            children,
        }
    }

    /// A breakdown of `levels` levels with one node at each.
    fn chain(levels: usize) -> BreakdownNode {
        (1..levels).fold(node(vec![]), |below, _| node(vec![below]))
    }

    /// A breakdown of two levels with `leaves` nodes at the second.
    fn wide(leaves: usize) -> BreakdownNode {
        node((0..leaves).map(|_| node(vec![])).collect())
    }

    fn levels_of(breakdown: &Value) -> usize {
        1 + breakdown["children"]
            .as_array()
            .expect("children")
            .iter()
            .map(levels_of)
            .max()
            .unwrap_or(0)
    }

    fn push(accounting: &RequestAccounting, breakdown: Option<BreakdownNode>) -> u64 {
        accounting.push_entry(
            ExecutionLabel::Client,
            &totals(0, 0),
            &totals(1_000_000_000, 1),
            false,
            breakdown,
        )
    }

    /// The bytes the accounting counts for the entry `push` stores under a
    /// one-digit attempt id.
    fn counted_bytes(breakdown: Option<&BreakdownNode>) -> usize {
        let bare = Entry::from_reads(
            0,
            ExecutionLabel::Client,
            &totals(0, 0),
            &totals(1_000_000_000, 1),
            false,
            None,
        );
        record::serialized_len(&bare)
            + 1
            + breakdown.map_or(0, |root| {
                record::BREAKDOWN_MEMBER_BYTES + record::serialized_len(root)
            })
    }

    #[test]
    fn the_accounting_stores_within_the_specified_bounds() {
        let limits = RequestAccounting::new("DoGet", None, None).limits;

        assert_eq!(limits.breakdown_levels, 48);
        assert_eq!(limits.entries_bytes_with_breakdown, 2_097_152);
        assert_eq!(limits.entries_bytes, 4_194_304);
    }

    #[test]
    fn depth_counts_the_root_as_the_first_level() {
        assert!(!node(vec![]).is_deeper_than(1));
        assert!(node(vec![]).is_deeper_than(0));
        assert!(!chain(48).is_deeper_than(48));
        assert!(chain(49).is_deeper_than(48));
        // The deepest branch decides.
        let uneven = node(vec![chain(2), chain(5), chain(1)]);
        assert!(!uneven.is_deeper_than(6));
        assert!(uneven.is_deeper_than(5));
    }

    #[test]
    fn a_breakdown_of_48_levels_is_stored() {
        let (queue, _metrics) = queue();
        let accounting = RequestAccounting::new("DoGet", Some(&auth()), Some(queue.clone()));
        push(&accounting, Some(chain(48)));

        drop(accounting);

        // `queued` parses with the nesting limit of 128 the API's parser has.
        let records = queued(&queue);
        assert_eq!(records[0]["breakdown_omitted"], json!(false));
        assert_eq!(levels_of(&records[0]["entries"][0]["breakdown"]), 48);
    }

    #[test]
    fn a_breakdown_deeper_than_48_levels_is_omitted() {
        let (queue, metrics) = queue();
        let accounting = RequestAccounting::new("DoGet", Some(&auth()), Some(queue.clone()));
        push(&accounting, Some(chain(48)));
        push(&accounting, Some(chain(49)));
        push(&accounting, Some(chain(2)));

        drop(accounting);

        let records = queued(&queue);
        assert_eq!(records[0]["breakdown_omitted"], json!(true));
        let entries = records[0]["entries"].as_array().expect("entries");
        assert_eq!(entries.len(), 3);
        assert_eq!(levels_of(&entries[0]["breakdown"]), 48);
        // The entry keeps its figures.
        assert!(entries[1].get("breakdown").is_none());
        assert_eq!(entries[1]["attempt_id"], json!(1));
        assert_eq!(entries[1]["cpu_seconds"], json!(1.0));
        assert_eq!(levels_of(&entries[2]["breakdown"]), 2);
        assert_eq!(metrics.snapshot().usage_records_dropped.oversized, 0);
    }

    #[test]
    fn a_breakdown_that_takes_the_entries_past_their_bound_is_omitted() {
        let large = wide(20);
        let small = node(vec![]);
        let with_large = counted_bytes(Some(&large));
        // Without the large breakdown, a later entry and its small one fit.
        assert!(counted_bytes(None) + counted_bytes(Some(&small)) < with_large);

        for (bound, large_is_kept) in [(with_large, true), (with_large - 1, false)] {
            let (queue, _metrics) = queue();
            let accounting = RequestAccounting::new("DoGet", Some(&auth()), Some(queue.clone()))
                .with_limits(Limits {
                    entries_bytes_with_breakdown: bound,
                    ..Limits::default()
                });
            push(&accounting, Some(large.clone()));
            push(&accounting, Some(small.clone()));

            drop(accounting);

            let records = queued(&queue);
            let entries = records[0]["entries"].as_array().expect("entries");
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].get("breakdown").is_some(), large_is_kept);
            assert_eq!(entries[0]["cpu_seconds"], json!(1.0));
            // Each entry is tested by itself: the small breakdown is stored
            // where it fits, and omitted where the large one took the room.
            assert_eq!(entries[1].get("breakdown").is_some(), !large_is_kept);
            assert_eq!(records[0]["breakdown_omitted"], json!(true));
        }
    }

    #[test]
    fn breakdowns_are_stored_up_to_2_097_152_bytes_of_entries() {
        let (queue, metrics) = queue();
        let accounting = RequestAccounting::new("DoGet", Some(&auth()), Some(queue.clone()));
        let breakdown = wide(2_000);
        // Attempt ids 0 to 9 keep every entry the same size.
        let each = counted_bytes(Some(&breakdown));
        let fitting = 2_097_152 / each;
        assert!((2..10).contains(&fitting));
        for _ in 0..10 {
            push(&accounting, Some(breakdown.clone()));
        }

        drop(accounting);

        let records = queued(&queue);
        assert_eq!(records[0]["breakdown_omitted"], json!(true));
        let kept = records[0]["entries"]
            .as_array()
            .expect("entries")
            .iter()
            .map(|entry| entry.get("breakdown").is_some())
            .collect::<Vec<_>>();
        let expected = (0..10).map(|index| index < fitting).collect::<Vec<_>>();
        assert_eq!(kept, expected);
        assert_eq!(metrics.snapshot().usage_records_dropped.oversized, 0);
    }

    #[test]
    fn an_entry_that_takes_the_entries_past_their_bound_ends_storage() {
        let limits = Limits {
            entries_bytes: 3 * counted_bytes(None),
            ..Limits::default()
        };

        // Three entries take the entries to the bound, and are stored.
        let (stored_queue, stored_metrics) = queue();
        let accounting = RequestAccounting::new("DoPut", Some(&auth()), Some(stored_queue.clone()))
            .with_limits(limits);
        for _ in 0..3 {
            push(&accounting, None);
        }
        drop(accounting);
        let records = queued(&stored_queue);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["entries"].as_array().expect("entries").len(), 3);
        assert_eq!(stored_metrics.snapshot().usage_records_dropped.oversized, 0);

        // A fourth passes it. Neither it nor a later entry is stored, and
        // the request's record is discarded and counted.
        let (queue, metrics) = queue();
        let accounting =
            RequestAccounting::new("DoPut", Some(&auth()), Some(queue.clone())).with_limits(limits);
        let ids = (0..6).map(|_| push(&accounting, None)).collect::<Vec<_>>();
        assert_eq!(ids, vec![0, 1, 2, 3, 4, 5]);
        assert!(accounting.state().entries.is_empty());
        // The progress figures cover every attempt.
        assert_eq!(accounting.progress().figures().closed_cpu_ns, 6_000_000_000);
        assert_eq!(metrics.snapshot().usage_records_dropped.oversized, 0);

        drop(accounting);

        assert!(queued(&queue).is_empty());
        let drops = metrics.snapshot().usage_records_dropped;
        assert_eq!(
            (drops.queue_full, drops.oversized, drops.refused),
            (0, 1, 0)
        );
    }

    #[test]
    fn the_running_size_estimates_the_serialized_entries() {
        let (queue, _metrics) = queue();
        let accounting = RequestAccounting::new("DoGet", Some(&auth()), Some(queue.clone()));
        push(&accounting, Some(wide(3)));
        push(&accounting, None);
        push(&accounting, Some(chain(49)));
        push(&accounting, Some(chain(4)));

        let state = accounting.state();
        // The estimate counts a separator after every entry, and the array
        // has one fewer and two brackets.
        assert_eq!(
            state.entries_bytes + 1,
            serde_json::to_vec(&state.entries).expect("JSON").len()
        );
    }

    #[test]
    fn progress_follows_the_label_1_attempts() {
        let accounting = RequestAccounting::new("DoGet", None, None);
        assert_eq!(accounting.progress().figures(), ProgressFigures::default());

        // A label-0 attempt enters no progress figure.
        accounting.attempt_opened(ExecutionLabel::SwanLake, &totals(100, 0));
        accounting.push_entry(
            ExecutionLabel::SwanLake,
            &totals(100, 0),
            &totals(150, 900),
            false,
            None,
        );
        assert_eq!(accounting.progress().figures(), ProgressFigures::default());

        let first_open = totals(150, 0);
        accounting.attempt_opened(ExecutionLabel::Client, &first_open);
        let progress = accounting.progress().figures();
        assert_eq!(progress.open, Some(first_open));
        assert_eq!(progress.cpu_ns(None), 0);
        assert_eq!(progress.cpu_ns(Some(&totals(180, 0))), 30);

        accounting.push_entry(
            ExecutionLabel::Client,
            &first_open,
            &totals(200, 500),
            false,
            None,
        );
        let progress = accounting.progress().figures();
        assert_eq!(
            progress,
            ProgressFigures {
                closed_cpu_ns: 50,
                closed_peak_bytes: 500,
                open: None,
            }
        );
        // With no attempt open, a later read adds nothing.
        assert_eq!(progress.cpu_ns(Some(&totals(999, 0))), 50);

        let second_open = totals(200, 0);
        accounting.attempt_opened(ExecutionLabel::Client, &second_open);
        assert_eq!(
            accounting
                .progress()
                .figures()
                .cpu_ns(Some(&totals(210, 0))),
            60
        );
        accounting.push_entry(
            ExecutionLabel::Client,
            &second_open,
            &totals(275, 300),
            false,
            None,
        );
        assert_eq!(
            accounting.progress().figures(),
            ProgressFigures {
                closed_cpu_ns: 125,
                closed_peak_bytes: 500,
                open: None,
            }
        );
    }
}
