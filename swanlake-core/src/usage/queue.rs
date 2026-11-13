//! The process's in-memory queue of serialized records, and the task that
//! delivers its head to the duckvis API.

use std::collections::VecDeque;
use std::future::Future;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::Notify;
use tracing::warn;

use super::record::Serialized;
use crate::duckvis::DuckvisAuth;
use crate::metrics::{now_millis, Metrics, UsageRecordDrop};

/// Largest total of serialized record bytes the queue holds.
pub const MAX_QUEUE_BYTES: usize = 67_108_864;

/// The wait before the first resend of a record.
const FIRST_RETRY_WAIT: Duration = Duration::from_secs(1);

/// The longest wait between two sends of a record.
const MAX_RETRY_WAIT: Duration = Duration::from_secs(60);

/// The number of 401-after-re-mint and 403 responses to one record at which
/// the record is discarded.
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
    /// Each record with the Unix milliseconds at which it was queued.
    records: VecDeque<(Bytes, u64)>,
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
        {
            let mut pending = self.pending();
            let bytes = pending.bytes.saturating_add(record.len());
            if bytes > self.inner.max_bytes {
                drop(pending);
                self.count_drop(UsageRecordDrop::QueueFull);
                return;
            }
            pending.bytes = bytes;
            pending.records.push_back((record, now_millis()));
            self.report(&pending);
        }
        self.inner.arrived.notify_one();
    }

    /// The record at the head, once one exists. The record stays queued.
    async fn head(&self) -> Bytes {
        loop {
            if let Some((record, _)) = self.pending().records.front() {
                return record.clone();
            }
            self.inner.arrived.notified().await;
        }
    }

    fn remove_head(&self) {
        let mut pending = self.pending();
        if let Some((record, _)) = pending.records.pop_front() {
            pending.bytes -= record.len();
        }
        self.report(&pending);
    }

    /// Publishes the queue's size and its head's queue time to the metrics.
    /// Called with the queue locked, so the reports arrive in order.
    fn report(&self, pending: &Pending) {
        self.inner.metrics.set_usage_queue(
            pending.bytes as u64,
            pending
                .records
                .front()
                .map(|(_, queued_at_ms)| *queued_at_ms),
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
    pub(super) fn snapshot(&self) -> Vec<Bytes> {
        self.pending()
            .records
            .iter()
            .map(|(record, _)| record.clone())
            .collect()
    }
}

/// What a response to a record's POST does to the record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Disposition {
    /// 2xx: the API holds the record.
    Delivered,
    /// 400, 413, or 422: the API refuses the same bytes again.
    Refused,
    /// 401 after the token re-mint, or 403.
    Denied,
    /// Any other status, or no response.
    Retry,
}

/// `status` is the status `DuckvisAuth::post_usage_record` returns, which is
/// a 401 only after the token re-mint, or `None` when the token mint or the
/// send failed or the request timed out.
fn disposition(status: Option<u16>) -> Disposition {
    match status {
        Some(200..=299) => Disposition::Delivered,
        Some(400 | 413 | 422) => Disposition::Refused,
        Some(401 | 403) => Disposition::Denied,
        _ => Disposition::Retry,
    }
}

/// Sends the head record until the API accepts or refuses it, or denies it
/// for the fifth time, then removes it. Every send carries the same bytes.
/// Between two sends it waits 1 second, then twice the previous wait, up to
/// 60 seconds.
async fn deliver_head<S, SendFuture, W, WaitFuture>(queue: &UsageQueue, send: &S, wait: &W)
where
    S: Fn(Bytes) -> SendFuture,
    SendFuture: Future<Output = Option<u16>>,
    W: Fn(Duration) -> WaitFuture,
    WaitFuture: Future<Output = ()>,
{
    let record = queue.head().await;
    let mut retry_wait = FIRST_RETRY_WAIT;
    let mut denials = 0;
    loop {
        let status = send(record.clone()).await;
        let mut disposition = disposition(status);
        if disposition == Disposition::Denied {
            denials += 1;
            disposition = if denials >= MAX_DENIALS {
                Disposition::Refused
            } else {
                Disposition::Retry
            };
        }
        match disposition {
            Disposition::Delivered => break,
            Disposition::Refused => {
                warn!(
                    status,
                    bytes = record.len(),
                    "duckvis API refused a usage record; discarding it"
                );
                queue.count_drop(UsageRecordDrop::Refused);
                break;
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
    }
    queue.remove_head();
}

/// Creates the process's queue and spawns the task that delivers its records
/// to `{api}/v1/usage/requests` through `auth`, one at a time and in order.
/// The task runs until the runtime shuts down and flushes nothing then.
///
/// Must be called within a Tokio runtime.
pub fn spawn_delivery(auth: Arc<DuckvisAuth>, metrics: &Metrics) -> UsageQueue {
    let queue = UsageQueue::new(metrics.clone());
    let delivery_queue = queue.clone();
    tokio::spawn(async move {
        let send = |record: Bytes| {
            let auth = Arc::clone(&auth);
            async move {
                auth.post_usage_record(record)
                    .await
                    .ok()
                    .map(|status| status.as_u16())
            }
        };
        loop {
            deliver_head(&delivery_queue, &send, &tokio::time::sleep).await;
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

    /// A stand-in for the API and the clock: answers each send with the next
    /// scripted status and records every body and every wait.
    #[derive(Default)]
    struct Script {
        statuses: Mutex<VecDeque<Option<u16>>>,
        bodies: Mutex<Vec<Bytes>>,
        waits: Mutex<Vec<Duration>>,
    }

    impl Script {
        fn new(statuses: impl IntoIterator<Item = Option<u16>>) -> Self {
            Self {
                statuses: Mutex::new(statuses.into_iter().collect()),
                ..Self::default()
            }
        }

        async fn deliver_head(&self, queue: &UsageQueue) {
            let send = |body: Bytes| {
                self.bodies.lock().expect("bodies").push(body);
                let status = self
                    .statuses
                    .lock()
                    .expect("statuses")
                    .pop_front()
                    .expect("a scripted status for every send");
                std::future::ready(status)
            };
            let wait = |duration: Duration| {
                self.waits.lock().expect("waits").push(duration);
                std::future::ready(())
            };
            deliver_head(queue, &send, &wait).await;
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
    fn statuses_map_to_the_delivery_table() {
        for status in [200, 201, 204, 299] {
            assert_eq!(disposition(Some(status)), Disposition::Delivered);
        }
        for status in [400, 413, 422] {
            assert_eq!(disposition(Some(status)), Disposition::Refused);
        }
        for status in [401, 403] {
            assert_eq!(disposition(Some(status)), Disposition::Denied);
        }
        for status in [100, 301, 402, 404, 408, 409, 429, 500, 502, 503, 504] {
            assert_eq!(disposition(Some(status)), Disposition::Retry);
        }
        assert_eq!(disposition(None), Disposition::Retry);
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
        queue.remove_head();
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
    async fn a_success_removes_the_record() {
        let (queue, metrics) = queue_with_max_bytes(100);
        queue.push(Bytes::from_static(b"first"));
        queue.push(Bytes::from_static(b"second"));
        let script = Script::new([Some(204), Some(200)]);

        script.deliver_head(&queue).await;
        assert_eq!(queue.snapshot(), vec![Bytes::from_static(b"second")]);
        script.deliver_head(&queue).await;

        assert!(queue.snapshot().is_empty());
        assert_eq!(
            script.bodies(),
            vec![Bytes::from_static(b"first"), Bytes::from_static(b"second")]
        );
        assert!(script.waits_secs().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 0));
    }

    #[tokio::test]
    async fn a_refusal_discards_and_counts_the_record() {
        for status in [400, 413, 422] {
            let (queue, metrics) = queue_with_max_bytes(100);
            queue.push(Bytes::from_static(b"refused"));
            queue.push(Bytes::from_static(b"next"));
            let script = Script::new([Some(status)]);

            script.deliver_head(&queue).await;

            assert_eq!(queue.snapshot(), vec![Bytes::from_static(b"next")]);
            assert_eq!(script.bodies().len(), 1);
            assert!(script.waits_secs().is_empty());
            assert_eq!(dropped(&metrics), (0, 0, 1));
        }
    }

    #[tokio::test]
    async fn a_retry_resends_identical_bytes_and_delivers_once() {
        let (queue, metrics) = queue_with_max_bytes(100);
        queue.push(Bytes::from_static(b"{\"request_id\":\"r\"}"));
        let script = Script::new([Some(503), None, Some(500), Some(204)]);

        script.deliver_head(&queue).await;

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
    async fn the_fifth_denial_discards_and_counts_the_record() {
        for denials in [[401; 5], [403; 5], [401, 403, 403, 401, 403]] {
            let (queue, metrics) = queue_with_max_bytes(100);
            queue.push(Bytes::from_static(b"denied"));
            queue.push(Bytes::from_static(b"next"));
            let script = Script::new(denials.map(Some));

            script.deliver_head(&queue).await;

            assert_eq!(queue.snapshot(), vec![Bytes::from_static(b"next")]);
            let bodies = script.bodies();
            assert_eq!(bodies.len(), 5);
            assert!(bodies
                .iter()
                .all(|body| body == &Bytes::from_static(b"denied")));
            // The fifth response discards without a further wait.
            assert_eq!(script.waits_secs(), vec![1, 2, 4, 8]);
            assert_eq!(dropped(&metrics), (0, 0, 1));
        }
    }

    #[tokio::test]
    async fn denials_count_across_other_failures() {
        let (queue, metrics) = queue_with_max_bytes(100);
        queue.push(Bytes::from_static(b"denied"));
        let script = Script::new([
            Some(403),
            Some(503),
            Some(401),
            None,
            Some(403),
            Some(500),
            Some(403),
            Some(429),
            Some(401),
        ]);

        script.deliver_head(&queue).await;

        assert_eq!(script.bodies().len(), 9);
        assert_eq!(script.waits_secs(), vec![1, 2, 4, 8, 16, 32, 60, 60]);
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 1));
    }

    #[tokio::test]
    async fn four_denials_then_a_success_deliver_the_record() {
        let (queue, metrics) = queue_with_max_bytes(100);
        queue.push(Bytes::from_static(b"record"));
        let script = Script::new([Some(403), Some(401), Some(403), Some(401), Some(204)]);

        script.deliver_head(&queue).await;

        assert_eq!(script.bodies().len(), 5);
        assert_eq!(script.waits_secs(), vec![1, 2, 4, 8]);
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 0));
    }

    #[tokio::test]
    async fn each_record_counts_its_own_denials_and_waits() {
        let (queue, metrics) = queue_with_max_bytes(100);
        queue.push(Bytes::from_static(b"first"));
        queue.push(Bytes::from_static(b"second"));
        let script = Script::new([
            Some(403),
            Some(403),
            Some(403),
            Some(403),
            Some(204),
            Some(403),
            Some(204),
        ]);

        script.deliver_head(&queue).await;
        script.deliver_head(&queue).await;

        // The second record's wait starts at 1 second, and its one denial
        // is its first.
        assert_eq!(script.waits_secs(), vec![1, 2, 4, 8, 1]);
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 0));
    }

    #[test]
    fn the_metrics_report_queued_bytes_and_the_head_age() {
        let (queue, metrics) = queue_with_max_bytes(10);
        let state = |metrics: &Metrics| metrics.snapshot().usage_queue;
        assert_eq!((state(&metrics).bytes, state(&metrics).head_age_ms), (0, 0));

        queue.push(Bytes::from_static(b"123456"));
        std::thread::sleep(Duration::from_millis(30));
        queue.push(Bytes::from_static(b"1234"));
        // A discarded push changes neither figure.
        queue.push(Bytes::from_static(b"1"));
        assert_eq!(state(&metrics).bytes, 10);
        let head_age_ms = state(&metrics).head_age_ms;
        assert!((30..30_000).contains(&head_age_ms));

        // The next record becomes the head with its own, shorter age.
        queue.remove_head();
        assert_eq!(state(&metrics).bytes, 4);
        assert!(state(&metrics).head_age_ms < head_age_ms);

        queue.remove_head();
        assert_eq!((state(&metrics).bytes, state(&metrics).head_age_ms), (0, 0));
    }

    #[tokio::test]
    async fn the_wait_doubles_to_60_seconds() {
        let (queue, _metrics) = queue_with_max_bytes(100);
        queue.push(Bytes::from_static(b"record"));
        let script =
            Script::new(std::iter::repeat_n(Some(503), 9).chain(std::iter::once(Some(204))));

        script.deliver_head(&queue).await;

        assert_eq!(script.waits_secs(), vec![1, 2, 4, 8, 16, 32, 60, 60, 60]);
    }

    #[tokio::test]
    async fn a_failing_record_stays_at_the_head_while_it_waits() {
        let (queue, _metrics) = queue_with_max_bytes(100);
        queue.push(Bytes::from_static(b"head"));
        queue.push(Bytes::from_static(b"tail"));
        let seen_while_waiting = Mutex::new(Vec::new());
        let statuses = Mutex::new(VecDeque::from([Some(503), Some(204)]));

        let send = |_body: Bytes| {
            std::future::ready(statuses.lock().expect("statuses").pop_front().flatten())
        };
        let wait = |_duration: Duration| {
            seen_while_waiting
                .lock()
                .expect("seen")
                .push(queue.snapshot());
            std::future::ready(())
        };
        deliver_head(&queue, &send, &wait).await;

        assert_eq!(
            *seen_while_waiting.lock().expect("seen"),
            vec![vec![
                Bytes::from_static(b"head"),
                Bytes::from_static(b"tail")
            ]]
        );
        assert_eq!(queue.snapshot(), vec![Bytes::from_static(b"tail")]);
    }

    #[tokio::test]
    async fn delivery_waits_for_a_record_to_arrive() {
        let (queue, _metrics) = queue_with_max_bytes(100);
        let script = Arc::new(Script::new([Some(204)]));

        let delivery = tokio::spawn({
            let queue = queue.clone();
            let script = Arc::clone(&script);
            async move { script.deliver_head(&queue).await }
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

    /// A scripted status that makes the stand-in API hold a usage POST open
    /// and never answer it.
    const STALL: u16 = 0;

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
    /// with the next scripted status.
    struct StandInApi {
        url: String,
        received: Arc<Mutex<Vec<Received>>>,
    }

    impl StandInApi {
        fn start(usage_statuses: impl IntoIterator<Item = u16>) -> Self {
            Self::start_with(usage_statuses, Behavior::default())
        }

        fn start_with(usage_statuses: impl IntoIterator<Item = u16>, behavior: Behavior) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let url = format!("http://{}", listener.local_addr().expect("local addr"));
            let received = Arc::new(Mutex::new(Vec::new()));
            let seen = Arc::clone(&received);
            let mut usage_statuses = usage_statuses.into_iter().collect::<VecDeque<_>>();
            std::thread::spawn(move || {
                let mut minted = 0;
                let mut stalled = Vec::new();
                for stream in listener.incoming() {
                    let Ok(mut stream) = stream else { break };
                    let request = read_request(&mut stream);
                    let (status, body) = if request.path == "/v1/auth/oauth/token" {
                        minted += 1;
                        (
                            200,
                            format!(r#"{{"access_token":"token-{minted}","expires_in":600}}"#),
                        )
                    } else {
                        (usage_statuses.pop_front().unwrap_or(500), String::new())
                    };
                    let is_mint = request.path == "/v1/auth/oauth/token";
                    seen.lock().expect("received").push(request);
                    if status == STALL || (is_mint && behavior.stalled_mint == Some(minted)) {
                        stalled.push(stream);
                        continue;
                    }
                    std::thread::sleep(behavior.answer_delay);
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

    /// Delivers the head of `queue` through `auth`, recording each wait
    /// instead of sleeping.
    async fn deliver_head_through(queue: &UsageQueue, auth: &Arc<DuckvisAuth>) -> Vec<u64> {
        let waits = Mutex::new(Vec::new());
        let send = |record: Bytes| {
            let auth = Arc::clone(auth);
            async move {
                auth.post_usage_record(record)
                    .await
                    .ok()
                    .map(|status| status.as_u16())
            }
        };
        let wait = |duration: Duration| {
            waits.lock().expect("waits").push(duration.as_secs());
            std::future::ready(())
        };
        deliver_head(queue, &send, &wait).await;
        waits.into_inner().expect("waits")
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
    async fn a_503_then_a_204_delivers_the_record_once() {
        let api = StandInApi::start([503, 204]);
        let (queue, metrics) = queue_with_max_bytes(MAX_QUEUE_BYTES);
        let record = queue_one_record(&queue);

        let waits = deliver_head_through(&queue, &api.auth()).await;

        assert_eq!(waits, vec![1]);
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 0));
        let posts = api.usage_posts();
        assert_eq!(posts.len(), 2);
        for post in &posts {
            assert_eq!(post.body, record);
            assert_eq!(post.authorization.as_deref(), Some("Bearer token-1"));
            assert_eq!(post.content_type.as_deref(), Some("application/json"));
        }
        // Both sends used the one cached token.
        assert_eq!(api.token_mints(), 1);
        let sent: serde_json::Value = serde_json::from_slice(&posts[0].body).expect("JSON body");
        assert_eq!(sent["project_id"], serde_json::json!("project-1"));
        assert_eq!(sent["entries"][0]["cpu_seconds"], serde_json::json!(2.0));
    }

    #[tokio::test]
    async fn a_422_discards_the_record_and_delivery_moves_on() {
        let api = StandInApi::start([422, 204]);
        let (queue, metrics) = queue_with_max_bytes(MAX_QUEUE_BYTES);
        let refused = queue_one_record(&queue);
        queue.push(Bytes::from_static(b"{\"next\":true}"));
        let auth = api.auth();

        let waits = deliver_head_through(&queue, &auth).await;
        assert!(waits.is_empty());
        assert_eq!(
            queue.snapshot(),
            vec![Bytes::from_static(b"{\"next\":true}")]
        );
        assert_eq!(dropped(&metrics), (0, 0, 1));

        deliver_head_through(&queue, &auth).await;
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
        let api = StandInApi::start([401, 204]);
        let (queue, _metrics) = queue_with_max_bytes(MAX_QUEUE_BYTES);
        let record = queue_one_record(&queue);

        let waits = deliver_head_through(&queue, &api.auth()).await;

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
    async fn post_usage_record_returns_the_status_after_one_re_mint() {
        let api = StandInApi::start([401, 401]);

        let status = api
            .auth()
            .post_usage_record(Bytes::from_static(b"{}"))
            .await;

        assert_eq!(status, Ok(reqwest::StatusCode::UNAUTHORIZED));
        assert_eq!(api.usage_posts().len(), 2);
        assert_eq!(api.token_mints(), 2);
    }

    #[tokio::test]
    async fn a_response_that_never_arrives_times_out() {
        let api = StandInApi::start([STALL]);

        let started = std::time::Instant::now();
        let status = api
            .auth()
            .post_usage_record_within(Bytes::from_static(b"{}"), Duration::from_millis(200))
            .await;

        assert_eq!(status, Err(crate::duckvis::DuckvisError::Unavailable));
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
            [204],
            Behavior {
                stalled_mint: Some(1),
                ..Behavior::default()
            },
        );

        let started = std::time::Instant::now();
        let status = api
            .auth()
            .post_usage_record_within(Bytes::from_static(b"{}"), Duration::from_millis(200))
            .await;

        assert_eq!(status, Err(crate::duckvis::DuckvisError::Unavailable));
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert_eq!(api.token_mints(), 1);
        assert!(api.usage_posts().is_empty());
    }

    #[tokio::test]
    async fn a_re_mint_that_never_answers_times_out() {
        let api = StandInApi::start_with(
            [401, 204],
            Behavior {
                stalled_mint: Some(2),
                ..Behavior::default()
            },
        );

        let started = std::time::Instant::now();
        let status = api
            .auth()
            .post_usage_record_within(Bytes::from_static(b"{}"), Duration::from_millis(200))
            .await;

        assert_eq!(status, Err(crate::duckvis::DuckvisError::Unavailable));
        assert!(started.elapsed() >= Duration::from_millis(200));
        assert_eq!(api.token_mints(), 2);
        assert_eq!(api.usage_posts().len(), 1);
    }

    #[tokio::test]
    async fn one_limit_covers_the_mint_and_the_send_together() {
        // Each answer arrives within the limit, and the two together do not.
        let api = StandInApi::start_with(
            [204],
            Behavior {
                answer_delay: Duration::from_millis(300),
                ..Behavior::default()
            },
        );

        let status = api
            .auth()
            .post_usage_record_within(Bytes::from_static(b"{}"), Duration::from_millis(450))
            .await;

        assert_eq!(status, Err(crate::duckvis::DuckvisError::Unavailable));
        assert_eq!(api.token_mints(), 1);
    }

    #[tokio::test]
    async fn a_send_that_passes_the_limit_is_sent_again() {
        let api = StandInApi::start_with(
            [204],
            Behavior {
                stalled_mint: Some(1),
                ..Behavior::default()
            },
        );
        let (queue, metrics) = queue_with_max_bytes(MAX_QUEUE_BYTES);
        let record = queue_one_record(&queue);
        let auth = api.auth();
        let waits = Mutex::new(Vec::new());
        let send = |record: Bytes| {
            let auth = Arc::clone(&auth);
            async move {
                auth.post_usage_record_within(record, Duration::from_millis(200))
                    .await
                    .ok()
                    .map(|status| status.as_u16())
            }
        };
        let wait = |duration: Duration| {
            waits.lock().expect("waits").push(duration.as_secs());
            std::future::ready(())
        };

        deliver_head(&queue, &send, &wait).await;

        // The first send timed out in its mint; the second minted and sent.
        assert_eq!(*waits.lock().expect("waits"), vec![1]);
        assert_eq!(api.token_mints(), 2);
        let posts = api.usage_posts();
        assert_eq!(posts.len(), 1);
        assert_eq!(posts[0].body, record);
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 0));
    }

    #[tokio::test]
    async fn a_fifth_403_discards_the_record() {
        let api = StandInApi::start([403, 403, 403, 403, 403, 204]);
        let (queue, metrics) = queue_with_max_bytes(MAX_QUEUE_BYTES);
        let denied = queue_one_record(&queue);
        queue.push(Bytes::from_static(b"{\"next\":true}"));
        let auth = api.auth();

        let waits = deliver_head_through(&queue, &auth).await;

        assert_eq!(waits, vec![1, 2, 4, 8]);
        assert_eq!(
            queue.snapshot(),
            vec![Bytes::from_static(b"{\"next\":true}")]
        );
        assert_eq!(dropped(&metrics), (0, 0, 1));
        let posts = api.usage_posts();
        assert_eq!(posts.len(), 5);
        assert!(posts.iter().all(|post| post.body == denied));
        // A 403 re-mints no token.
        assert_eq!(api.token_mints(), 1);

        deliver_head_through(&queue, &auth).await;
        assert!(queue.snapshot().is_empty());
        assert_eq!(dropped(&metrics), (0, 0, 1));
    }

    #[tokio::test]
    async fn an_unreachable_api_is_a_failure_to_send() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let url = format!("http://{}", listener.local_addr().expect("local addr"));
        drop(listener);

        let status = auth_for(url)
            .post_usage_record(Bytes::from_static(b"{}"))
            .await;

        assert_eq!(status, Err(crate::duckvis::DuckvisError::Unavailable));
    }

    #[tokio::test]
    async fn spawned_delivery_drains_the_queue() {
        let api = StandInApi::start([204, 204]);
        let metrics = Metrics::new(100, 8);
        let queue = spawn_delivery(api.auth(), &metrics);

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
        assert_eq!(bodies, vec![b"{\"n\":1}".to_vec(), b"{\"n\":2}".to_vec()]);
    }
}
