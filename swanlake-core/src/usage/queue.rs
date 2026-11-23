//! The process's in-memory queue of serialized records, and the task that
//! delivers batches from its head to the duckvis API.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::sync::Notify;
use tracing::warn;

use super::record::{Serialized, MAX_RECORD_BYTES};
use crate::duckvis::DuckvisAuth;
use crate::metrics::{Metrics, UsageRecordDrop};

/// Largest total of serialized record bytes the queue holds.
pub const MAX_QUEUE_BYTES: usize = 67_108_864;

/// The most records one batch holds, which is the number of a body's records
/// the API handles.
const MAX_BATCH_RECORDS: usize = 256;

/// The most bytes one batch's body holds: the API's body limit, which is the
/// record bound.
const MAX_BATCH_BYTES: usize = MAX_RECORD_BYTES;

/// The wait before the first resend of a batch.
const FIRST_RETRY_WAIT: Duration = Duration::from_secs(1);

/// The longest wait between two sends of a batch.
const MAX_RETRY_WAIT: Duration = Duration::from_secs(60);

/// The number of 401-after-re-mint and 403 responses to one batch at which
/// the batch's records are discarded.
const MAX_DENIALS: u32 = 5;

/// The queue of serialized records awaiting delivery. Clones share one queue.
///
/// The queue exists in memory only, and a process that exits loses what it
/// holds.
#[derive(Clone)]
pub struct UsageQueue {
    inner: Arc<Inner>,
}

struct Inner {
    max_bytes: usize,
    pending: Mutex<Pending>,
    /// Wakes the delivery task when a record arrives.
    arrived: Notify,
    metrics: Metrics,
}

#[derive(Default)]
struct Pending {
    /// Each record with the time at which it was pushed.
    records: VecDeque<(Bytes, Instant)>,
    bytes: usize,
}

impl UsageQueue {
    /// Creates an empty queue bounded at [`MAX_QUEUE_BYTES`] that counts its
    /// drops in `metrics`.
    pub fn new(metrics: Metrics) -> Self {
        Self::with_max_bytes(metrics, MAX_QUEUE_BYTES)
    }

    fn with_max_bytes(metrics: Metrics, max_bytes: usize) -> Self {
        Self {
            inner: Arc::new(Inner {
                max_bytes,
                pending: Mutex::new(Pending::default()),
                arrived: Notify::new(),
                metrics,
            }),
        }
    }

    /// Queues a serialized record, or counts the record that passed its size
    /// bound. Never blocks.
    pub(super) fn accept(&self, serialized: Serialized) {
        match serialized {
            Serialized::Record(record) => self.push(record),
            Serialized::Oversized => self.count_drop(UsageRecordDrop::Oversized),
        }
    }

    /// Appends `record`. A record that would take the queue past its bound is
    /// discarded and counted. Never blocks.
    fn push(&self, record: Bytes) {
        self.push_at(record, Instant::now());
    }

    /// [`Self::push`] at the time `pushed_at`, from which the metrics measure
    /// the record's age once it is the head.
    fn push_at(&self, record: Bytes, pushed_at: Instant) {
        {
            let mut pending = self.pending();
            let bytes = pending.bytes.saturating_add(record.len());
            if bytes > self.inner.max_bytes {
                drop(pending);
                self.count_drop(UsageRecordDrop::QueueFull);
                return;
            }
            pending.bytes = bytes;
            pending.records.push_back((record, pushed_at));
            self.report(&pending);
        }
        self.inner.arrived.notify_one();
    }

    /// The batch at the head, once the queue holds a record: the head record
    /// and each record behind it while the batch holds at most
    /// [`MAX_BATCH_RECORDS`] records and its body at most
    /// [`MAX_BATCH_BYTES`] bytes. The records stay queued.
    async fn head_batch(&self) -> Vec<Bytes> {
        loop {
            {
                let pending = self.pending();
                let mut batch = Vec::new();
                let mut body_bytes = 0;
                for (record, _) in pending.records.iter().take(MAX_BATCH_RECORDS) {
                    // One line feed separates a record from the one ahead.
                    let bytes = body_bytes + record.len() + usize::from(!batch.is_empty());
                    if !batch.is_empty() && bytes > MAX_BATCH_BYTES {
                        break;
                    }
                    body_bytes = bytes;
                    batch.push(record.clone());
                }
                if !batch.is_empty() {
                    return batch;
                }
            }
            self.inner.arrived.notified().await;
        }
    }

    /// Removes the first `records` records.
    fn remove_head(&self, records: usize) {
        let mut pending = self.pending();
        for _ in 0..records {
            if let Some((record, _)) = pending.records.pop_front() {
                pending.bytes -= record.len();
            }
        }
        self.report(&pending);
    }

    /// Publishes the queue's size and its head's push time to the metrics.
    /// Called with the queue locked, so the reports arrive in order.
    fn report(&self, pending: &Pending) {
        self.inner.metrics.set_usage_queue(
            pending.bytes as u64,
            pending.records.front().map(|(_, pushed_at)| *pushed_at),
        );
    }

    fn count_drop(&self, reason: UsageRecordDrop) {
        self.inner.metrics.record_usage_record_dropped(reason);
    }

    fn pending(&self) -> MutexGuard<'_, Pending> {
        self.inner
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    #[cfg(test)]
    pub(crate) fn snapshot(&self) -> Vec<Bytes> {
        self.pending()
            .records
            .iter()
            .map(|(record, _)| record.clone())
            .collect()
    }
}

/// A batch's body: its records joined by one line feed. A serialized record
/// holds no line feed, so the API reads the records back by splitting there.
fn body_of(batch: &[Bytes]) -> Bytes {
    batch.join(&b'\n').into()
}

/// What a response to a batch's POST does to the batch's records.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Disposition {
    /// 200 with the status of each record the API handled, in the batch's
    /// order: 204 for a record it holds, any other for a record it refuses.
    /// The API handled no record behind them.
    Handled(Vec<u16>),
    /// 400, 413, or 422: the API refuses the same bytes again.
    Refused,
    /// 401 after the token re-mint, or 403.
    Denied,
    /// Any other response, or none.
    Retry,
}

/// `response` is the status and body `DuckvisAuth::post_usage_records`
/// returns for a batch of `records` records. Its status is a 401 only after
/// the token re-mint. It is `None` when the token mint or the send failed or
/// the request timed out.
fn disposition(response: Option<(u16, &[u8])>, records: usize) -> Disposition {
    match response {
        Some((200, body)) => match serde_json::from_slice::<Vec<u16>>(body) {
            Ok(statuses) if (1..=records).contains(&statuses.len()) => {
                Disposition::Handled(statuses)
            }
            _ => Disposition::Retry,
        },
        Some((400 | 413 | 422, _)) => Disposition::Refused,
        Some((401 | 403, _)) => Disposition::Denied,
        _ => Disposition::Retry,
    }
}

/// Sends the batch at the head until the API handles records of it or
/// refuses it, or denies it for the fifth time, then removes the records the
/// API handled or the batch's records. Every send carries the same bytes.
/// Between two sends it waits 1 second, then twice the previous wait, up to
/// 60 seconds.
async fn deliver_batch<S, SendFuture, W, WaitFuture>(queue: &UsageQueue, send: &S, wait: &W)
where
    S: Fn(Bytes) -> SendFuture,
    SendFuture: Future<Output = Option<(u16, Bytes)>>,
    W: Fn(Duration) -> WaitFuture,
    WaitFuture: Future<Output = ()>,
{
    let batch = queue.head_batch().await;
    let body = body_of(&batch);
    let mut retry_wait = FIRST_RETRY_WAIT;
    let mut denials = 0;
    let (removed, refused) = loop {
        let response = send(body.clone()).await;
        let status = response.as_ref().map(|(status, _)| *status);
        let mut disposition = disposition(
            response
                .as_ref()
                .map(|(status, body)| (*status, body.as_ref())),
            batch.len(),
        );
        if disposition == Disposition::Denied {
            denials += 1;
            disposition = if denials >= MAX_DENIALS {
                Disposition::Refused
            } else {
                Disposition::Retry
            };
        }
        match disposition {
            Disposition::Handled(statuses) => {
                let refused = statuses.iter().filter(|status| **status != 204).count();
                if refused > 0 {
                    warn!(
                        refused,
                        records = statuses.len(),
                        "duckvis API refused usage records; discarding them"
                    );
                }
                break (statuses.len(), refused);
            }
            Disposition::Refused => {
                warn!(
                    status,
                    bytes = body.len(),
                    records = batch.len(),
                    "duckvis API refused a usage record batch; discarding it"
                );
                break (batch.len(), batch.len());
            }
            Disposition::Denied | Disposition::Retry => {
                warn!(
                    status,
                    retry_in_secs = retry_wait.as_secs(),
                    "usage record delivery failed; retrying"
                );
                wait(retry_wait).await;
                retry_wait = retry_wait.saturating_mul(2).min(MAX_RETRY_WAIT);
            }
        }
    };
    for _ in 0..refused {
        queue.count_drop(UsageRecordDrop::Refused);
    }
    queue.remove_head(removed);
}

/// Creates the process's queue and spawns the task that delivers its records
/// to `{api}/v1/usage/requests` through `auth`, one batch at a time and in
/// order. The task runs until the runtime shuts down and flushes nothing
/// then.
///
/// Must be called within a Tokio runtime.
pub fn spawn_delivery(auth: Arc<DuckvisAuth>, metrics: &Metrics) -> UsageQueue {
    let queue = UsageQueue::new(metrics.clone());
    let delivery_queue = queue.clone();
    tokio::spawn(async move {
        let send = |body: Bytes| {
            let auth = Arc::clone(&auth);
            async move {
                auth.post_usage_records(body)
                    .await
                    .ok()
                    .map(|(status, body)| (status.as_u16(), body))
            }
        };
        loop {
            deliver_batch(&delivery_queue, &send, &tokio::time::sleep).await;
        }
    });
    queue
}

#[cfg(test)]
mod tests {
    use std::io::{BufRead, BufReader, Read, Write};
    use std::net::TcpListener;

    use super::*;

    fn queue_with_max_bytes(max_bytes: usize) -> (UsageQueue, Metrics) {
        let metrics = Metrics::new(100, 8);
        (
            UsageQueue::with_max_bytes(metrics.clone(), max_bytes),
            metrics,
        )
    }

    fn dropped(metrics: &Metrics) -> (u64, u64, u64) {
        let dropped = metrics.snapshot().usage_records_dropped;
        (dropped.queue_full, dropped.oversized, dropped.refused)
    }

    /// A 200 response whose body is `statuses`.
    fn handled(statuses: &'static str) -> Option<(u16, Bytes)> {
        Some((200, Bytes::from_static(statuses.as_bytes())))
    }

    /// A response of `status` with an empty body.
    fn status(status: u16) -> Option<(u16, Bytes)> {
        Some((status, Bytes::new()))
    }

    /// A stand-in for the API and the clock: answers each send with the next
    /// scripted response and records every body and every wait.
    #[derive(Default)]
    struct Script {
        responses: Mutex<VecDeque<Option<(u16, Bytes)>>>,
        bodies: Mutex<Vec<Bytes>>,
        waits: Mutex<Vec<Duration>>,
    }

    impl Script {
        fn new(responses: impl IntoIterator<Item = Option<(u16, Bytes)>>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                ..Self::default()
            }
        }

        async fn deliver_batch(&self, queue: &UsageQueue) {
            let send = |body: Bytes| {
                self.bodies.lock().expect("bodies").push(body);
                let response = self
                    .responses
                    .lock()
                    .expect("responses")
                    .pop_front()
                    .expect("a scripted response for every send");
                std::future::ready(response)
            };
            let wait = |duration: Duration| {
                self.waits.lock().expect("waits").push(duration);
                std::future::ready(())
            };
            deliver_batch(queue, &send, &wait).await;
        }

        fn bodies(&self) -> Vec<Bytes> {
            self.bodies.lock().expect("bodies").clone()
        }

        fn waits_secs(&self) -> Vec<u64> {
            self.waits
                .lock()
                .expect("waits")
                .iter()
                .map(Duration::as_secs)
                .collect()
        }
    }

    #[test]
    fn responses_map_to_the_delivery_table() {
        let of = |status: u16, body: &'static str, records: usize| {
            disposition(Some((status, body.as_bytes())), records)
        };
        assert_eq!(of(200, "[204]", 1), Disposition::Handled(vec![204]));
        assert_eq!(
            of(200, "[204,422,400]", 3),
            Disposition::Handled(vec![204, 422, 400])
        );
        // The API handled the first two records of five.
        assert_eq!(
            of(200, "[204,204]", 5),
            Disposition::Handled(vec![204, 204])
        );
        // A 200 that holds no status, more statuses than the batch holds
        // records, or no status list.
        for body in ["[]", "[204,204]", "", "{}", "204", "[\"204\"]", "[204"] {
            assert_eq!(of(200, body, 1), Disposition::Retry, "{body}");
        }
        for status in [400, 413, 422] {
            assert_eq!(of(status, "", 1), Disposition::Refused);
        }
        for status in [401, 403] {
            assert_eq!(of(status, "", 1), Disposition::Denied);
        }
        for status in [
            100, 201, 204, 299, 301, 402, 404, 408, 409, 429, 500, 502, 503, 504,
        ] {
            assert_eq!(of(status, "[204]", 1), Disposition::Retry);
        }
        assert_eq!(disposition(None, 1), Disposition::Retry);
    }

    #[test]
    fn a_push_past_the_bound_is_discarded_and_counted() {
        let (queue, metrics) = queue_with_max_bytes(10);

        queue.push(Bytes::from_static(b"123456"));
        queue.push(Bytes::from_static(b"1234"));
        assert_eq!(queue.snapshot().len(), 2);
        assert_eq!(dropped(&metrics), (0, 0, 0));

        // The queue holds exactly its bound, so one more byte passes it.
        queue.push(Bytes::from_static(b"1"));
        queue.push(Bytes::from_static(b"12345678901"));
        assert_eq!(
            queue.snapshot(),
            vec![Bytes::from_static(b"123456"), Bytes::from_static(b"1234")]
        );
        assert_eq!(dropped(&metrics), (2, 0, 0));

        // Removing the head frees its bytes.
        queue.remove_head(1);
        queue.push(Bytes::from_static(b"abcdef"));
        assert_eq!(
            queue.snapshot(),
            vec![Bytes::from_static(b"1234"), Bytes::from_static(b"abcdef")]
        );
        assert_eq!(dropped(&metrics), (2, 0, 0));
    }

    #[test]
    fn the_production_bound_is_64_mib() {
        let queue = UsageQueue::new(Metrics::new(100, 8));
        assert_eq!(queue.inner.max_bytes, 64 * 1024 * 1024);
    }

    #[test]
    fn an_oversized_record_is_counted_and_not_queued() {
        let (queue, metrics) = queue_with_max_bytes(10);

        queue.accept(Serialized::Oversized);

        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 1, 0));
    }

    #[tokio::test]
    async fn a_batch_holds_the_queued_records_and_a_success_removes_them() {
        let (queue, metrics) = queue_with_max_bytes(100);
        queue.push(Bytes::from_static(b"first"));
        queue.push(Bytes::from_static(b"second"));
        let script = Script::new([handled("[204,204]"), handled("[204]")]);

        script.deliver_batch(&queue).await;
        assert!(queue.snapshot().is_empty());

        // A record that arrives later travels in its own batch.
        queue.push(Bytes::from_static(b"third"));
        script.deliver_batch(&queue).await;

        assert!(queue.snapshot().is_empty());
        assert_eq!(
            script.bodies(),
            vec![
                Bytes::from_static(b"first\nsecond"),
                Bytes::from_static(b"third")
            ]
        );
        assert!(script.waits_secs().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 0));
    }

    #[tokio::test]
    async fn a_batch_holds_at_most_256_records() {
        let (queue, _metrics) = queue_with_max_bytes(MAX_QUEUE_BYTES);
        for _ in 0..300 {
            queue.push(Bytes::from_static(b"{}"));
        }
        let script = Script::new([Some((
            200,
            Bytes::from(serde_json::to_vec(&vec![204; 256]).expect("statuses")),
        ))]);

        script.deliver_batch(&queue).await;

        assert_eq!(queue.snapshot().len(), 44);
        let bodies = script.bodies();
        assert_eq!(bodies[0].split(|byte| *byte == b'\n').count(), 256);
        assert_eq!(MAX_BATCH_RECORDS, 256);
    }

    #[tokio::test]
    async fn a_batch_body_holds_at_most_the_body_bound() {
        let (queue, _metrics) = queue_with_max_bytes(MAX_QUEUE_BYTES);
        // The first two records and their line feed fill the bound exactly.
        queue.push(Bytes::from(vec![b'a'; MAX_BATCH_BYTES - 10]));
        queue.push(Bytes::from_static(b"123456789"));
        queue.push(Bytes::from_static(b"c"));
        // A record at the bound travels alone.
        queue.push(Bytes::from(vec![b'd'; MAX_BATCH_BYTES]));
        queue.push(Bytes::from_static(b"e"));
        let script = Script::new([handled("[204,204]"), handled("[204]"), handled("[204]")]);

        script.deliver_batch(&queue).await;
        script.deliver_batch(&queue).await;
        script.deliver_batch(&queue).await;

        let bodies = script.bodies();
        assert_eq!(bodies[0].len(), MAX_BATCH_BYTES);
        assert!(bodies[0].ends_with(b"a\n123456789"));
        assert_eq!(bodies[1], Bytes::from_static(b"c"));
        assert_eq!(bodies[2], Bytes::from(vec![b'd'; MAX_BATCH_BYTES]));
        assert_eq!(queue.snapshot(), vec![Bytes::from_static(b"e")]);
        assert_eq!(MAX_BATCH_BYTES, 4_194_304);
    }

    #[tokio::test]
    async fn the_records_behind_the_handled_ones_stay_queued() {
        let (queue, metrics) = queue_with_max_bytes(100);
        queue.push(Bytes::from_static(b"first"));
        queue.push(Bytes::from_static(b"second"));
        queue.push(Bytes::from_static(b"third"));
        let script = Script::new([handled("[204,204]"), handled("[204]")]);

        script.deliver_batch(&queue).await;
        assert_eq!(queue.snapshot(), vec![Bytes::from_static(b"third")]);
        script.deliver_batch(&queue).await;

        assert!(queue.snapshot().is_empty());
        assert_eq!(
            script.bodies(),
            vec![
                Bytes::from_static(b"first\nsecond\nthird"),
                Bytes::from_static(b"third")
            ]
        );
        assert!(script.waits_secs().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 0));
    }

    #[tokio::test]
    async fn a_handled_record_the_api_refuses_is_discarded_and_counted() {
        let (queue, metrics) = queue_with_max_bytes(100);
        queue.push(Bytes::from_static(b"stored"));
        queue.push(Bytes::from_static(b"unresolved"));
        queue.push(Bytes::from_static(b"unreadable"));
        queue.push(Bytes::from_static(b"unhandled"));
        let script = Script::new([handled("[204,422,400]")]);

        script.deliver_batch(&queue).await;

        assert_eq!(queue.snapshot(), vec![Bytes::from_static(b"unhandled")]);
        assert!(script.waits_secs().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 2));
    }

    #[tokio::test]
    async fn a_refusal_discards_and_counts_the_batch() {
        for refusal in [400, 413, 422] {
            let (queue, metrics) = queue_with_max_bytes(100);
            queue.push(Bytes::from_static(b"refused"));
            queue.push(Bytes::from_static(b"with it"));
            let script = Script::new([status(refusal)]);

            script.deliver_batch(&queue).await;

            assert!(queue.snapshot().is_empty());
            assert_eq!(script.bodies().len(), 1);
            assert!(script.waits_secs().is_empty());
            assert_eq!(dropped(&metrics), (0, 0, 2));
        }
    }

    #[tokio::test]
    async fn a_retry_resends_identical_bytes_and_delivers_once() {
        let (queue, metrics) = queue_with_max_bytes(100);
        queue.push(Bytes::from_static(b"{\"request_id\":\"r\"}"));
        let script = Script::new([status(503), None, status(500), handled("[204]")]);

        script.deliver_batch(&queue).await;

        let bodies = script.bodies();
        assert_eq!(bodies.len(), 4);
        assert!(bodies
            .iter()
            .all(|body| body == &Bytes::from_static(b"{\"request_id\":\"r\"}")));
        assert_eq!(script.waits_secs(), vec![1, 2, 4]);
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 0));
    }

    #[tokio::test]
    async fn a_200_without_a_status_list_is_sent_again() {
        let (queue, metrics) = queue_with_max_bytes(100);
        queue.push(Bytes::from_static(b"record"));
        let script = Script::new([
            handled("[]"),
            handled("[204,204]"),
            handled(""),
            status(204),
            handled("[204]"),
        ]);

        script.deliver_batch(&queue).await;

        assert_eq!(script.bodies().len(), 5);
        assert_eq!(script.waits_secs(), vec![1, 2, 4, 8]);
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 0));
    }

    #[tokio::test]
    async fn the_fifth_denial_discards_and_counts_the_batch() {
        for denials in [[401; 5], [403; 5], [401, 403, 403, 401, 403]] {
            let (queue, metrics) = queue_with_max_bytes(100);
            queue.push(Bytes::from_static(b"denied"));
            queue.push(Bytes::from_static(b"with it"));
            let script = Script::new(denials.map(status));

            script.deliver_batch(&queue).await;

            assert!(queue.snapshot().is_empty());
            let bodies = script.bodies();
            assert_eq!(bodies.len(), 5);
            assert!(bodies
                .iter()
                .all(|body| body == &Bytes::from_static(b"denied\nwith it")));
            // The fifth response discards without a further wait.
            assert_eq!(script.waits_secs(), vec![1, 2, 4, 8]);
            assert_eq!(dropped(&metrics), (0, 0, 2));
        }
    }

    #[tokio::test]
    async fn denials_count_across_other_failures() {
        let (queue, metrics) = queue_with_max_bytes(100);
        queue.push(Bytes::from_static(b"denied"));
        let script = Script::new([
            status(403),
            status(503),
            status(401),
            None,
            status(403),
            status(500),
            status(403),
            status(429),
            status(401),
        ]);

        script.deliver_batch(&queue).await;

        assert_eq!(script.bodies().len(), 9);
        assert_eq!(script.waits_secs(), vec![1, 2, 4, 8, 16, 32, 60, 60]);
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 1));
    }

    #[tokio::test]
    async fn four_denials_then_a_success_deliver_the_record() {
        let (queue, metrics) = queue_with_max_bytes(100);
        queue.push(Bytes::from_static(b"record"));
        let script = Script::new([
            status(403),
            status(401),
            status(403),
            status(401),
            handled("[204]"),
        ]);

        script.deliver_batch(&queue).await;

        assert_eq!(script.bodies().len(), 5);
        assert_eq!(script.waits_secs(), vec![1, 2, 4, 8]);
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 0));
    }

    #[tokio::test]
    async fn each_batch_counts_its_own_denials_and_waits() {
        let (queue, metrics) = queue_with_max_bytes(100);
        let script = Script::new([
            status(403),
            status(403),
            status(403),
            status(403),
            handled("[204]"),
            status(403),
            handled("[204]"),
        ]);

        queue.push(Bytes::from_static(b"first"));
        script.deliver_batch(&queue).await;
        queue.push(Bytes::from_static(b"second"));
        script.deliver_batch(&queue).await;

        // The second batch's wait starts at 1 second, and its one denial is
        // its first.
        assert_eq!(script.waits_secs(), vec![1, 2, 4, 8, 1]);
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 0));
    }

    #[test]
    fn the_metrics_report_queued_bytes_and_the_head_age() {
        let (queue, metrics) = queue_with_max_bytes(10);
        let start = Instant::now();
        let at = |millis: u64| start + Duration::from_millis(millis);
        let state = |millis: u64| {
            let state = metrics.usage_queue_at(at(millis));
            (state.bytes, state.head_age_ms)
        };
        // An empty queue has no head age, whatever the time.
        assert_eq!(state(0), (0, 0));
        assert_eq!(state(5_000), (0, 0));

        queue.push_at(Bytes::from_static(b"123456"), at(0));
        queue.push_at(Bytes::from_static(b"1234"), at(30));
        // A discarded push changes neither figure.
        queue.push_at(Bytes::from_static(b"1"), at(40));
        assert_eq!(dropped(&metrics), (1, 0, 0));
        // The age runs from the head's push, not from a later one.
        assert_eq!(state(0), (10, 0));
        assert_eq!(state(100), (10, 100));
        assert_eq!(state(75_000), (10, 75_000));

        // The next record becomes the head with its own, shorter age.
        queue.remove_head(1);
        assert_eq!(state(100), (4, 70));

        queue.remove_head(1);
        assert_eq!(state(100), (0, 0));

        // A record pushed onto the drained queue is the head from its push.
        queue.push_at(Bytes::from_static(b"12"), at(200));
        assert_eq!(state(260), (2, 60));
    }

    #[tokio::test]
    async fn the_head_keeps_its_age_while_it_is_sent_again() {
        let (queue, metrics) = queue_with_max_bytes(100);
        let start = Instant::now();
        queue.push_at(Bytes::from_static(b"head"), start);
        queue.push_at(
            Bytes::from_static(b"tail"),
            start + Duration::from_millis(400),
        );
        let ages_while_waiting = Mutex::new(Vec::new());
        // The last response handles the head alone, so the tail stays.
        let responses = Mutex::new(VecDeque::from([status(503), status(403), handled("[204]")]));

        let send = |_body: Bytes| {
            std::future::ready(responses.lock().expect("responses").pop_front().flatten())
        };
        let wait = |_duration: Duration| {
            let state = metrics.usage_queue_at(start + Duration::from_millis(1_000));
            ages_while_waiting
                .lock()
                .expect("ages")
                .push((state.bytes, state.head_age_ms));
            std::future::ready(())
        };
        deliver_batch(&queue, &send, &wait).await;

        // A failed send does not restart the head's age.
        assert_eq!(
            *ages_while_waiting.lock().expect("ages"),
            vec![(8, 1_000), (8, 1_000)]
        );
        let after = metrics.usage_queue_at(start + Duration::from_millis(1_000));
        assert_eq!((after.bytes, after.head_age_ms), (4, 600));
    }

    #[tokio::test]
    async fn the_wait_doubles_to_60_seconds() {
        let (queue, _metrics) = queue_with_max_bytes(100);
        queue.push(Bytes::from_static(b"record"));
        let script = Script::new(
            std::iter::repeat_n(status(503), 9).chain(std::iter::once(handled("[204]"))),
        );

        script.deliver_batch(&queue).await;

        assert_eq!(script.waits_secs(), vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
    }

    #[tokio::test]
    async fn a_failing_batch_stays_queued_and_unchanged_while_it_waits() {
        let (queue, _metrics) = queue_with_max_bytes(100);
        queue.push(Bytes::from_static(b"head"));
        queue.push(Bytes::from_static(b"tail"));
        let seen_while_waiting = Mutex::new(Vec::new());
        let bodies = Mutex::new(Vec::new());
        let responses = Mutex::new(VecDeque::from([status(503), handled("[204,204]")]));

        let send = |body: Bytes| {
            bodies.lock().expect("bodies").push(body);
            std::future::ready(responses.lock().expect("responses").pop_front().flatten())
        };
        let wait = |_duration: Duration| {
            seen_while_waiting
                .lock()
                .expect("seen")
                .push(queue.snapshot());
            queue.push(Bytes::from_static(b"late"));
            std::future::ready(())
        };
        deliver_batch(&queue, &send, &wait).await;

        assert_eq!(
            *seen_while_waiting.lock().expect("seen"),
            vec![vec![
                Bytes::from_static(b"head"),
                Bytes::from_static(b"tail")
            ]]
        );
        // The resend holds the records of the first send and not the record
        // that arrived during the wait.
        assert_eq!(
            *bodies.lock().expect("bodies"),
            vec![Bytes::from_static(b"head\ntail"); 2]
        );
        assert_eq!(queue.snapshot(), vec![Bytes::from_static(b"late")]);
    }

    #[tokio::test]
    async fn delivery_waits_for_a_record_to_arrive() {
        let (queue, _metrics) = queue_with_max_bytes(100);
        let script = Arc::new(Script::new([handled("[204]")]));

        let delivery = tokio::spawn({
            let queue = queue.clone();
            let script = Arc::clone(&script);
            async move { script.deliver_batch(&queue).await }
        });
        tokio::task::yield_now().await;
        assert!(script.bodies().is_empty());

        queue.push(Bytes::from_static(b"late"));
        delivery.await.expect("delivery task");

        assert_eq!(script.bodies(), vec![Bytes::from_static(b"late")]);
        assert!(queue.snapshot().is_empty());
    }

    /// One request the stand-in API received.
    #[derive(Debug, Clone, PartialEq, Eq)]
    struct Received {
        path: String,
        authorization: Option<String>,
        content_type: Option<String>,
        body: Vec<u8>,
    }

    /// A scripted answer to a usage POST: its status and body.
    type Answer = (u16, &'static str);

    /// The answer that reports one handled record, which the API holds.
    const STORED: Answer = (200, "[204]");

    /// A scripted answer that makes the stand-in API hold a usage POST open
    /// and never answer it.
    const STALL: Answer = (0, "");

    /// How the stand-in API departs from answering every request at once.
    #[derive(Default)]
    struct Behavior {
        /// The token mint, counted from 1, that is held open and never
        /// answered.
        stalled_mint: Option<usize>,
        /// How long every answer is held back.
        answer_delay: Duration,
    }

    /// A local HTTP listener standing in for the duckvis API. It mints
    /// `token-1`, `token-2`, … at the token route and answers each usage POST
    /// with the next scripted answer.
    struct StandInApi {
        url: String,
        received: Arc<Mutex<Vec<Received>>>,
    }

    impl StandInApi {
        fn start(usage_answers: impl IntoIterator<Item = Answer>) -> Self {
            Self::start_with(usage_answers, Behavior::default())
        }

        fn start_with(usage_answers: impl IntoIterator<Item = Answer>, behavior: Behavior) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let url = format!("http://{}", listener.local_addr().expect("local addr"));
            let received = Arc::new(Mutex::new(Vec::new()));
            let seen = Arc::clone(&received);
            let mut usage_answers = usage_answers.into_iter().collect::<VecDeque<_>>();
            std::thread::spawn(move || {
                let mut minted = 0;
                let mut stalled = Vec::new();
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { break };
                    let request = read_request(&mut stream);
                    let is_mint = request.path == "/v1/auth/oauth/token";
                    let answer = if is_mint {
                        minted += 1;
                        (
                            200,
                            format!(r#"{{"access_token":"token-{minted}","expires_in":600}}"#),
                        )
                    } else {
                        let (status, body) = usage_answers.pop_front().unwrap_or((500, ""));
                        (status, body.to_owned())
                    };
                    seen.lock().expect("received").push(request);
                    if (!is_mint && answer.0 == STALL.0)
                        || (is_mint && behavior.stalled_mint == Some(minted))
                    {
                        stalled.push(stream);
                        continue;
                    }
                    std::thread::sleep(behavior.answer_delay);
                    let (status, body) = answer;
                    let response = format!(
                        "HTTP/1.1 {status} Scripted\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    // A client that has gone away is not this listener's failure.
                    let _ = stream.write_all(response.as_bytes());
                }
            });
            Self { url, received }
        }

        fn auth(&self) -> Arc<DuckvisAuth> {
            auth_for(self.url.clone())
        }

        fn usage_posts(&self) -> Vec<Received> {
            self.received
                .lock()
                .expect("received")
                .iter()
                .filter(|request| request.path == "/v1/usage/requests")
                .cloned()
                .collect()
        }

        fn token_mints(&self) -> usize {
            self.received
                .lock()
                .expect("received")
                .iter()
                .filter(|request| request.path == "/v1/auth/oauth/token")
                .count()
        }
    }

    fn read_request(stream: &mut std::net::TcpStream) -> Received {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).expect("request line");
        let path = request_line
            .split_whitespace()
            .nth(1)
            .expect("request path")
            .to_owned();
        let mut authorization = None;
        let mut content_type = None;
        let mut content_length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).expect("header line");
            let line = line.trim_end();
            if line.is_empty() {
                break;
            }
            let (name, value) = line.split_once(':').expect("header");
            let value = value.trim().to_owned();
            match name.to_ascii_lowercase().as_str() {
                "authorization" => authorization = Some(value),
                "content-type" => content_type = Some(value),
                "content-length" => content_length = value.parse().expect("content length"),
                _ => {}
            }
        }
        let mut body = vec![0; content_length];
        reader.read_exact(&mut body).expect("request body");
        Received {
            path,
            authorization,
            content_type,
            body,
        }
    }

    fn auth_for(api_url: String) -> Arc<DuckvisAuth> {
        Arc::new(DuckvisAuth {
            api_url,
            issuer: "https://api.duckvis.test".to_owned(),
            client_id: "swanlake-test".to_owned(),
            signing_key: ed25519_dalek::SigningKey::from_bytes(&[0x42; 32]),
            client: reqwest::Client::new(),
            sa_token: tokio::sync::Mutex::new(None),
            jwks: tokio::sync::RwLock::new(crate::duckvis::jwks::JwksCache::new(300)),
            read_only: false,
        })
    }

    /// Delivers the batch at the head of `queue` through `auth`, with `limit`
    /// on each send, recording each wait instead of sleeping.
    async fn deliver_batch_within(
        queue: &UsageQueue,
        auth: &Arc<DuckvisAuth>,
        limit: Duration,
    ) -> Vec<u64> {
        let waits = Mutex::new(Vec::new());
        let send = |body: Bytes| {
            let auth = Arc::clone(auth);
            async move {
                auth.post_usage_records_within(body, limit)
                    .await
                    .ok()
                    .map(|(status, body)| (status.as_u16(), body))
            }
        };
        let wait = |duration: Duration| {
            waits.lock().expect("waits").push(duration.as_secs());
            std::future::ready(())
        };
        deliver_batch(queue, &send, &wait).await;
        waits.into_inner().expect("waits")
    }

    /// [`deliver_batch_within`] the production limit.
    async fn deliver_batch_through(queue: &UsageQueue, auth: &Arc<DuckvisAuth>) -> Vec<u64> {
        deliver_batch_within(queue, auth, crate::duckvis::api::USAGE_RECORD_TIMEOUT).await
    }

    /// A request's record as its accounting queues it.
    fn queue_one_record(queue: &UsageQueue) -> Bytes {
        use super::super::accounting::{
            ExecutionLabel, RequestAccounting, ResourceTotals, UsageTotals,
        };
        let auth = crate::session::SessionAuth {
            subject: "subject-1".to_owned(),
            project_id: "project-1".to_owned(),
            writer: false,
        };
        let accounting = RequestAccounting::new("DoGet", Some(&auth), Some(queue.clone()));
        accounting.set_sql("SELECT 42");
        accounting.push_entry(
            ExecutionLabel::Client,
            &ResourceTotals::default(),
            &ResourceTotals {
                database: UsageTotals {
                    cpu_ns: 2_000_000_000,
                    ..UsageTotals::default()
                },
                ..ResourceTotals::default()
            },
            false,
            None,
        );
        drop(accounting);
        queue.snapshot().pop().expect("one queued record")
    }

    #[tokio::test]
    async fn a_503_then_a_200_delivers_the_record_once() {
        let api = StandInApi::start([(503, ""), STORED]);
        let (queue, metrics) = queue_with_max_bytes(MAX_QUEUE_BYTES);
        let record = queue_one_record(&queue);

        let waits = deliver_batch_through(&queue, &api.auth()).await;

        assert_eq!(waits, vec![1]);
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 0));
        let posts = api.usage_posts();
        assert_eq!(posts.len(), 2);
        for post in &posts {
            assert_eq!(post.body, record);
            assert_eq!(post.authorization.as_deref(), Some("Bearer token-1"));
            assert_eq!(post.content_type.as_deref(), Some("application/x-ndjson"));
        }
        // Both sends used the one cached token.
        assert_eq!(api.token_mints(), 1);
        let sent: serde_json::Value = serde_json::from_slice(&posts[0].body).expect("JSON body");
        assert_eq!(sent["project_id"], serde_json::json!("project-1"));
        assert_eq!(sent["entries"][0]["cpu_seconds"], serde_json::json!(2.0));
    }

    #[tokio::test]
    async fn a_batch_is_one_post_and_its_response_decides_each_record() {
        let api = StandInApi::start([(200, "[422,204]"), STORED]);
        let (queue, metrics) = queue_with_max_bytes(MAX_QUEUE_BYTES);
        let refused = queue_one_record(&queue);
        queue.push(Bytes::from_static(b"{\"stored\":true}"));
        queue.push(Bytes::from_static(b"{\"unhandled\":true}"));
        let auth = api.auth();

        let waits = deliver_batch_through(&queue, &auth).await;
        assert!(waits.is_empty());
        assert_eq!(
            queue.snapshot(),
            vec![Bytes::from_static(b"{\"unhandled\":true}")]
        );
        assert_eq!(dropped(&metrics), (0, 0, 1));

        deliver_batch_through(&queue, &auth).await;
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 1));
        let bodies = api
            .usage_posts()
            .into_iter()
            .map(|post| post.body)
            .collect::<Vec<_>>();
        assert_eq!(
            bodies,
            vec![
                [
                    refused.as_ref(),
                    b"{\"stored\":true}",
                    b"{\"unhandled\":true}"
                ]
                .join(&b'\n'),
                b"{\"unhandled\":true}".to_vec()
            ]
        );
    }

    #[tokio::test]
    async fn a_422_discards_the_batch_and_delivery_moves_on() {
        let api = StandInApi::start([(422, ""), STORED]);
        let (queue, metrics) = queue_with_max_bytes(MAX_QUEUE_BYTES);
        let refused = queue_one_record(&queue);
        let auth = api.auth();

        let waits = deliver_batch_through(&queue, &auth).await;
        assert!(waits.is_empty());
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 1));

        queue.push(Bytes::from_static(b"{\"next\":true}"));
        deliver_batch_through(&queue, &auth).await;
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 1));
        let bodies = api
            .usage_posts()
            .into_iter()
            .map(|post| post.body)
            .collect::<Vec<_>>();
        assert_eq!(bodies, vec![refused.to_vec(), b"{\"next\":true}".to_vec()]);
    }

    #[tokio::test]
    async fn a_401_re_mints_the_token_once_and_resends() {
        let api = StandInApi::start([(401, ""), STORED]);
        let (queue, _metrics) = queue_with_max_bytes(MAX_QUEUE_BYTES);
        let record = queue_one_record(&queue);

        let waits = deliver_batch_through(&queue, &api.auth()).await;

        assert!(waits.is_empty());
        assert!(queue.snapshot().is_empty());
        assert_eq!(api.token_mints(), 2);
        let posts = api.usage_posts();
        assert_eq!(
            posts
                .iter()
                .map(|post| post.authorization.as_deref())
                .collect::<Vec<_>>(),
            vec![Some("Bearer token-1"), Some("Bearer token-2")]
        );
        assert!(posts.iter().all(|post| post.body == record));
    }

    #[tokio::test]
    async fn post_usage_records_returns_the_status_and_body() {
        let api = StandInApi::start([(200, "[204,422]")]);

        let response = api
            .auth()
            .post_usage_records(Bytes::from_static(b"{}\n{}"))
            .await;

        assert_eq!(
            response,
            Ok((reqwest::StatusCode::OK, Bytes::from_static(b"[204,422]")))
        );
    }

    #[tokio::test]
    async fn post_usage_records_returns_the_response_after_one_re_mint() {
        let api = StandInApi::start([(401, ""), (401, "")]);

        let response = api
            .auth()
            .post_usage_records(Bytes::from_static(b"{}"))
            .await;

        assert_eq!(
            response,
            Ok((reqwest::StatusCode::UNAUTHORIZED, Bytes::new()))
        );
        assert_eq!(api.usage_posts().len(), 2);
        assert_eq!(api.token_mints(), 2);
    }

    #[tokio::test]
    async fn a_response_that_never_arrives_times_out() {
        let api = StandInApi::start([STALL]);

        let started = std::time::Instant::now();
        let response = api
            .auth()
            .post_usage_records_within(Bytes::from_static(b"{}"), Duration::from_millis(200))
            .await;

        assert_eq!(response, Err(crate::duckvis::DuckvisError::Unavailable));
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert_eq!(api.usage_posts().len(), 1);
        assert_eq!(
            crate::duckvis::api::USAGE_RECORD_TIMEOUT,
            Duration::from_secs(30)
        );
    }

    #[tokio::test]
    async fn a_token_mint_that_never_answers_times_out() {
        let api = StandInApi::start_with(
            [STORED],
            Behavior {
                stalled_mint: Some(1),
                ..Behavior::default()
            },
        );

        let started = std::time::Instant::now();
        let response = api
            .auth()
            .post_usage_records_within(Bytes::from_static(b"{}"), Duration::from_millis(200))
            .await;

        assert_eq!(response, Err(crate::duckvis::DuckvisError::Unavailable));
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert_eq!(api.token_mints(), 1);
        assert!(api.usage_posts().is_empty());
    }

    #[tokio::test]
    async fn a_re_mint_that_never_answers_times_out() {
        let api = StandInApi::start_with(
            [(401, ""), STORED],
            Behavior {
                stalled_mint: Some(2),
                ..Behavior::default()
            },
        );

        let started = std::time::Instant::now();
        let response = api
            .auth()
            .post_usage_records_within(Bytes::from_static(b"{}"), Duration::from_millis(200))
            .await;

        assert_eq!(response, Err(crate::duckvis::DuckvisError::Unavailable));
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert_eq!(api.token_mints(), 2);
        assert_eq!(api.usage_posts().len(), 1);
    }

    #[tokio::test]
    async fn one_limit_covers_the_mint_and_the_send_together() {
        // Each answer arrives 300 ms after its request, which is within the
        // limit, and the two together take at least 600 ms, which is not.
        let api = StandInApi::start_with(
            [STORED],
            Behavior {
                answer_delay: Duration::from_millis(300),
                ..Behavior::default()
            },
        );

        let response = api
            .auth()
            .post_usage_records_within(Bytes::from_static(b"{}"), Duration::from_millis(550))
            .await;

        assert_eq!(response, Err(crate::duckvis::DuckvisError::Unavailable));
        assert_eq!(api.token_mints(), 1);
        // The mint was answered and the POST was sent with its token, so
        // the limit ended the send and not the mint.
        let posts = api.usage_posts();
        assert_eq!(posts.len(), 1, "the POST was sent before the limit passed");
        assert_eq!(posts[0].authorization.as_deref(), Some("Bearer token-1"));
    }

    #[tokio::test]
    async fn a_send_that_passes_the_limit_is_sent_again() {
        let api = StandInApi::start_with(
            [STORED],
            Behavior {
                stalled_mint: Some(1),
                ..Behavior::default()
            },
        );
        let (queue, metrics) = queue_with_max_bytes(MAX_QUEUE_BYTES);
        let record = queue_one_record(&queue);

        let waits = deliver_batch_within(&queue, &api.auth(), Duration::from_millis(200)).await;

        // The first send timed out in its mint; the second minted and sent.
        assert_eq!(waits, vec![1]);
        assert_eq!(api.token_mints(), 2);
        let posts = api.usage_posts();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].body, record);
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 0));
    }

    #[tokio::test]
    async fn a_fifth_403_discards_the_batch() {
        let api = StandInApi::start([
            (403, ""),
            (403, ""),
            (403, ""),
            (403, ""),
            (403, ""),
            STORED,
        ]);
        let (queue, metrics) = queue_with_max_bytes(MAX_QUEUE_BYTES);
        let denied = queue_one_record(&queue);
        let auth = api.auth();

        let waits = deliver_batch_through(&queue, &auth).await;

        assert_eq!(waits, vec![1, 2, 4, 8]);
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 1));
        let posts = api.usage_posts();
        assert_eq!(posts.len(), 5);
        assert!(posts.iter().all(|post| post.body == denied));
        // A 403 re-mints no token.
        assert_eq!(api.token_mints(), 1);

        queue.push(Bytes::from_static(b"{\"next\":true}"));
        deliver_batch_through(&queue, &auth).await;
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 1));
    }

    #[tokio::test]
    async fn an_unreachable_api_is_a_failure_to_send() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        drop(listener);

        let response = auth_for(url)
            .post_usage_records(Bytes::from_static(b"{}"))
            .await;

        assert_eq!(response, Err(crate::duckvis::DuckvisError::Unavailable));
    }

    #[tokio::test]
    async fn spawned_delivery_drains_the_queue() {
        let api = StandInApi::start([(200, "[204,204]")]);
        let metrics = Metrics::new(100, 8);
        let queue = spawn_delivery(api.auth(), &metrics);

        // The delivery task first runs when this test awaits, so it finds
        // both records queued.
        queue.push(Bytes::from_static(b"{\"n\":1}"));
        queue.push(Bytes::from_static(b"{\"n\":2}"));

        for _ in 0..500 {
            if queue.snapshot().is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(queue.snapshot().is_empty());
        let bodies = api
            .usage_posts()
            .into_iter()
            .map(|post| post.body)
            .collect::<Vec<_>>();
        assert_eq!(bodies, vec![b"{\"n\":1}\n{\"n\":2}".to_vec()]);
    }
}
