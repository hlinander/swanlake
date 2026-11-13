//! Request accounting: one request's identity, its entries, and its progress
//! figures, from admission until its record is queued.

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
    pub bytes_written: u64,
    /// The connection's part of `cpu_seconds`.
    pub connection_cpu_seconds: f64,
    pub connection_bytes_read: u64,
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
            bytes_written: database.bytes_written,
            connection_cpu_seconds: seconds_from_ns(connection.cpu_ns),
            connection_bytes_read: connection.bytes_read,
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

#[derive(Default)]
struct State {
    next_attempt_id: u64,
    entries: Vec<Entry>,
    sql: Option<SqlText>,
    error_type: Option<&'static str>,
}

/// One request's identity, entries, and progress figures.
///
/// The request's owners share it in an `Arc`. When the last owner drops it,
/// it serializes the request's record and pushes it onto the queue. A request
/// with no entry, a session without duckvis authentication, and a process
/// without a queue produce no record.
pub struct RequestAccounting {
    request_id: Uuid,
    endpoint: String,
    destination: Option<Destination>,
    state: Mutex<State>,
    progress: Progress,
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
            state: Mutex::new(State::default()),
            progress: Progress::default(),
        }
    }

    pub fn request_id(&self) -> Uuid {
        self.request_id
    }

    /// Records the SQL text the client sent. The first text set is the
    /// request's; later calls change nothing.
    pub fn set_sql(&self, sql: &str) {
        if self.destination.is_none() {
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
    pub fn push_entry(
        &self,
        label: ExecutionLabel,
        opening: &ResourceTotals,
        closing: &ResourceTotals,
        abandoned: bool,
        breakdown: Option<BreakdownNode>,
    ) -> u64 {
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
        if self.destination.is_some() {
            state.entries.push(Entry::from_reads(
                attempt_id, label, opening, closing, abandoned, breakdown,
            ));
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
            },
            database: UsageTotals {
                cpu_ns: 5_000_000_000,
                bytes_read: 1_000,
                bytes_written: 500,
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
            },
            database: UsageTotals {
                cpu_ns: 7_500_000_000,
                bytes_read: 3_000,
                bytes_written: 800,
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
                bytes_written: 300,
                connection_cpu_seconds: 0.75,
                connection_bytes_read: 64,
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
            },
            database: UsageTotals {
                cpu_ns: 9,
                bytes_read: 9,
                bytes_written: 9,
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

        drop(accounting);

        assert!(queued(&queue).is_empty());
        assert_eq!(metrics.snapshot().usage_records_dropped.oversized, 1);
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
